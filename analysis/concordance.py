"""Conciliación entre un IDS y el análisis de LogScope.

Permite validar el análisis de un caso contra un motor de detección
independiente. Snort opera sobre el flujo de red (firmas de paquete) y
LogScope sobre el registro de eventos (métricas y correlación): no miden
lo mismo, así que la comparación no es de cifras, sino de **hechos**.

Se responden tres preguntas:

  * ¿Coinciden?     behavedades detectados por ambos instrumentos.
  * ¿Cuándo?        desfase temporal entre la alerta del IDS y el evento.
  * ¿Y en exclusiva? comportamientos que solo uno de los dos identifica.

Acepta dos formatos de entrada:

  * el resumen por combinaciones (`alertas_resumen.csv`), y
  * el log crudo de alertas del IDS (`alert_fast.txt`).
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

# Firma -> (nombre legible, criterio de deteccion)
FIRMAS: dict[str, tuple[str, str]] = {
    "JKS-ESCANEO": ("Escaneo de puertos externo", "perimetro"),
    "JKS-PERIMETRO": ("Conexión bloqueada en el perímetro", "perimetro"),
    "JKS-EXFILITRACION": ("Transferencia saliente anómala sobre TLS", "volumen"),
    "JKS-C2": ("Canal de mando y control", "volumen"),
    "JKS-SSH-SALIDA": ("Intento de salida por SSH", "egress"),
    "JKS-MOV-LATERAL": ("Conexión SMB entre servidores internos", "lateral"),
    "JKS-BD": ("Conexión a base de datos desde usuarios", "lateral"),
    "JKS-BEACON": ("Conexiones repetidas al mismo destino externo", "volumen"),
}

# Firma generica cuando el IDS no usa las nuestras (por ejemplo, la
# comunidad de Snort): se describe por el prefijo del identificador.
PREFIJOS = {
    "1000001": "JKS-ESCANEO",
    "1000002": "JKS-PERIMETRO",
    "1000003": "JKS-EXFILITRACION",
    "1000004": "JKS-C2",
    "1000005": "JKS-SSH-SALIDA",
    "1000006": "JKS-MOV-LATERAL",
    "1000007": "JKS-BD",
    "1000008": "JKS-BEACON",
}

PATRON_ALERTA = re.compile(
    r"^(?P<ts>\d\d/\d\d-\d\d:\d\d:\d\d\.\d+)\s+\[\*\*\]\s+\[1:(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r'"(?P<msg>[^"]+)"\s+\[\*\*\].*?\{TCP\}\s+(?P<src>[\d.]+):(?P<sport>\d+)\s+->\s+'
    r"(?P<dst>[\d.]+):(?P<dport>\d+)"
)


def _firma_de(sid: str, mensaje: str) -> str:
    """Deduce la firma a partir del mensaje o del identificador de regla."""
    coincidencia = re.search(r'"(JKS-[A-Z0-9-]+)', mensaje)
    if coincidencia:
        return coincidencia.group(1)
    return PREFIJOS.get(sid, f"SID-{sid}")


def parse_snort_timestamp(texto: str, tz: timezone) -> float:
    """Convierte 'MM/DD-HH:MM:SS.ffffff' (hora del IDS) a epoch."""
    try:
        mes, resto = texto.split("/")
        dia, hora = resto.split("-")
        h, m, s = hora.split(":")
        segundos = float(s)
        momento = datetime(
            year=2025,
            month=int(mes),
            day=int(dia),
            hour=int(h),
            minute=int(m),
            second=int(segundos),
            microsecond=int((segundos % 1) * 1_000_000),
            tzinfo=tz,
        )
        return momento.timestamp()
    except (ValueError, AttributeError):
        return 0.0


def parse_resumen_csv(contenido: str, tz: timezone) -> list[dict[str, Any]]:
    """Lee el resumen por combinaciones (regla, origen, destino)."""
    filas: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(contenido))
    for fila in reader:
        firma = (fila.get("firma") or "").split()[0]
        filas.append(
            {
                "sid": fila.get("sid", ""),
                "firma": firma,
                "origen": fila.get("origen", ""),
                "destino": fila.get("destino", ""),
                "epoch": parse_snort_timestamp(fila.get("primera_deteccion", ""), tz),
                "primera": fila.get("primera_deteccion", ""),
                "ultima": fila.get("ultima_deteccion", ""),
                "alertas": int(fila.get("alertas") or 0),
            }
        )
    return filas


def parse_alert_log(contenido: str, tz: timezone) -> list[dict[str, Any]]:
    """Lee un log crudo de alertas y lo agrupa por combinacion."""
    grupos: dict[tuple[str, str, str], dict[str, Any]] = {}
    for linea in contenido.splitlines():
        coincidencia = PATRON_ALERTA.match(linea)
        if not coincidencia:
            continue
        sid = coincidencia.group("sid")
        firma = _firma_de(sid, coincidencia.group("msg"))
        clave = (firma, coincidencia.group("src"), coincidencia.group("dst"))
        epoch = parse_snort_timestamp(coincidencia.group("ts"), tz)
        if clave not in grupos:
            grupos[clave] = {
                "sid": sid,
                "firma": firma,
                "origen": clave[1],
                "destino": clave[2],
                "epoch": epoch,
                "primera": coincidencia.group("ts"),
                "ultima": coincidencia.group("ts"),
                "alertas": 0,
            }
        grupo = grupos[clave]
        grupo["alertas"] += 1
        if epoch and (not grupo["epoch"] or epoch < grupo["epoch"]):
            grupo["epoch"] = epoch
            grupo["primera"] = coincidencia.group("ts")
        if epoch > grupo["epoch"]:
            grupo["ultima"] = coincidencia.group("ts")
    return list(grupos.values())


def detectar_formato(contenido: str) -> str:
    """Distingue el resumen CSV del log crudo de alertas."""
    if PATRON_ALERTA.search(contenido):
        return "alert_log"
    if "sid,firma,origen,destino" in contenido or re.search(r"^sid,", contenido, re.M):
        return "resumen_csv"
    return "desconocido"


def parse_ids(contenido: str, tz: timezone) -> tuple[str, list[dict[str, Any]]]:
    """Interpreta la entrada del IDS y devuelve (formato, combinaciones)."""
    formato = detectar_formato(contenido)
    if formato == "alert_log":
        return formato, parse_alert_log(contenido, tz)
    if formato == "resumen_csv":
        return formato, parse_resumen_csv(contenido, tz)
    raise ValueError(
        "No se reconoce el formato. Se espera el resumen por combinaciones "
        "(sid,firma,origen,destino,...) o un log de alertas de Snort."
    )


def _indice_por_par(eventos: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    indice: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for evento in eventos:
        indice[(evento.get("src_ip", ""), evento.get("dst_ip", ""))].append(evento)
    return indice


def reconcile(
    combinaciones: list[dict[str, Any]],
    events: list[dict[str, Any]],
    metrics: dict[str, Any],
    ventana: int = 120,
) -> dict[str, Any]:
    """Cruza las detecciones del IDS con los eventos del registro."""
    indice = _indice_por_par(events)
    anomalos = {
        (o.get("src"), o.get("dst")): o for o in metrics.get("volume_outliers", [])
    }

    filas: list[dict[str, Any]] = []
    for deteccion in combinaciones:
        par = (deteccion["origen"], deteccion["destino"])
        candidatos = indice.get(par, [])
        mas_proximo = None
        delta = None
        for evento in candidatos:
            if not evento.get("ts_epoch") or not deteccion.get("epoch"):
                continue
            diferencia = abs(evento["ts_epoch"] - deteccion["epoch"])
            if delta is None or diferencia < delta:
                delta = diferencia
                mas_proximo = evento

        if mas_proximo is not None and delta is not None and delta <= ventana:
            estado = "coincide"
        elif par in anomalos:
            estado = "coincide (umbral de volumen)"
        elif candidatos:
            estado = "mismo par, instante distinto"
        else:
            estado = "sin registro equivalente"

        nombre, criterio = FIRMAS.get(deteccion["firma"], (deteccion["firma"], ""))
        filas.append(
            {
                "sid": deteccion["sid"],
                "firma": deteccion["firma"],
                "comportamiento": nombre,
                "criterio": criterio,
                "origen": deteccion["origen"],
                "destino": deteccion["destino"],
                "primera_deteccion_ids": deteccion["primera"],
                "alertas_ids": deteccion["alertas"],
                "evento_log": mas_proximo.get("event_id", "") if mas_proximo else "",
                "instante_log": mas_proximo.get("iso_local", "") if mas_proximo else "",
                "delta_segundos": int(delta) if delta is not None else None,
                "bytes_registro": mas_proximo.get("bytes_out", 0) if mas_proximo else 0,
                "criterio_logscope": "anomalia de volumen" if par in anomalos else "",
                "estado": estado,
            }
        )

    estados = Counter(f["estado"] for f in filas)
    concordantes = sum(v for k, v in estados.items() if k.startswith("coincide"))
    firmas_concordadas = {f["firma"] for f in filas if f["estado"].startswith("coincide")}
    firmas_totales = {f["firma"] for f in filas}
    pares_ids = {(f["origen"], f["destino"]) for f in filas}
    solo_logscope = [o for par, o in anomalos.items() if par not in pares_ids]

    por_firma: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"combinaciones": 0, "concordantes": 0, "alertas": 0}
    )
    for fila in filas:
        d = por_firma[fila["firma"]]
        d["combinaciones"] += 1
        d["alertas"] += fila["alertas_ids"]
        if fila["estado"].startswith("coincide"):
            d["concordantes"] += 1
    for firma, d in por_firma.items():
        nombre, criterio = FIRMAS.get(firma, (firma, ""))
        d["nombre"] = nombre
        d["criterio"] = criterio
        d["estado"] = "coincide" if d["concordantes"] == d["combinaciones"] else "parcial"

    deltas = [f["delta_segundos"] for f in filas if f["delta_segundos"] is not None]
    return {
        "resumen": {
            "combinaciones_ids": len(filas),
            "concordantes": concordantes,
            "tasa_concordancia": round(concordantes / len(filas), 4) if filas else 0.0,
            "firmas_ids": len(firmas_totales),
            "firmas_concordantes": len(firmas_concordadas),
            "firmas_sin_concordancia": sorted(firmas_totales - firmas_concordadas),
            "alertas_ids": sum(f["alertas_ids"] for f in filas),
            "delta_maximo": max(deltas) if deltas else None,
            "delta_medio": round(sum(deltas) / len(deltas), 1) if deltas else None,
            "ventana_concordancia": ventana,
            "estados": dict(estados),
        },
        "anomalias_solo_logscope": [
            {
                "event_id": o.get("event_id", ""),
                "src": o.get("src", ""),
                "dst": o.get("dst", ""),
                "bytes_out": o.get("bytes_out", 0),
                "ratio_vs_p95": o.get("ratio_vs_p95", 0),
            }
            for o in solo_logscope
        ],
        "por_firma": [dict(firma=firma, **d) for firma, d in sorted(por_firma.items())],
        "detalle": filas,
    }


def tz_from_offset(offset: str) -> timezone:
    """Construye una zona horaria a partir de un desplazamiento '-03:00'."""
    try:
        signo = -1 if offset.startswith("-") else 1
        horas = int(offset[1:3])
        minutos = int(offset[4:6])
        return timezone(signo * timedelta(hours=horas, minutes=minutos))
    except (ValueError, IndexError):
        return UTC


# ---------------------------------------------------------------------------
# Informe en Markdown
# ---------------------------------------------------------------------------
def _numero(valor: Any) -> str:
    """Formato numerico espanol: punto para los miles, coma para los decimales."""
    if isinstance(valor, bool):
        return "sí" if valor else "no"
    if isinstance(valor, float):
        if valor == int(valor):
            return f"{int(valor):,}".replace(",", ".")
        return f"{valor:,.1f}".replace(",", "\u0001").replace(".", ",").replace("\u0001", ".")
    if isinstance(valor, int):
        return f"{valor:,}".replace(",", ".")
    return str(valor)


def _markdown_tabla(cabeceras: list[str], filas: list[list[Any]]) -> list[str]:
    lineas = ["| " + " | ".join(cabeceras) + " |",
              "|" + "|".join("---" for _ in cabeceras) + "|"]
    for fila in filas:
        celdas = [str(celda).replace("|", "/") for celda in fila]
        lineas.append("| " + " | ".join(celdas) + " |")
    return lineas


def render_markdown(resultado: dict[str, Any], nombre: str = "", generado: str = "") -> str:
    """Genera el informe de conciliacion en Markdown, listo para pegar."""
    resumen = resultado.get("resumen", {})
    lineas: list[str] = ["# Conciliación entre Snort y LogScope", ""]

    if nombre:
        lineas += [f"**Caso:** {nombre}"]
    if resultado.get("fichero"):
        lineas += [f"**Log del IDS:** `{resultado['fichero']}` (formato `{resultado.get('formato', '-')}`)"]
    if generado:
        lineas += [f"**Generado:** {generado}"]
    lineas += [""]

    total = resumen.get("combinaciones_ids", 0)
    concordantes = resumen.get("concordantes", 0)
    porcentaje = (resumen.get("tasa_concordancia") or 0) * 100
    delta = resumen.get("delta_maximo")
    lineas += ["## Resumen", ""]
    lineas += _markdown_tabla(
        ["Métrica", "Valor"],
        [
            ["Combinaciones detectadas por el IDS", _numero(total)],
            [
                "Concordantes con el análisis del registro",
                f"{_numero(concordantes)} ({_numero(porcentaje)} %)",
            ],
            [
                "Firmas del IDS concordantes",
                f"{_numero(resumen.get('firmas_concordantes', 0))} "
                f"de {_numero(resumen.get('firmas_ids', 0))}",
            ],
            [
                "Desfase temporal máximo",
                "n/d" if delta is None else f"{_numero(delta)} s",
            ],
            ["Alertas totales del IDS", _numero(resumen.get("alertas_ids", 0))],
            [
                "Anomalías detectadas solo en el registro",
                len(resultado.get("anomalias_solo_logscope", [])),
            ],
        ],
    )
    lineas.append("")

    firmas = resultado.get("por_firma", [])
    if firmas:
        lineas += ["## Concordancia por firma", ""]
        lineas += _markdown_tabla(
            ["Firma", "Comportamiento", "Criterio", "Combinaciones", "Concordantes", "Alertas", "Estado"],
            [
                [
                    f["firma"],
                    f.get("nombre", ""),
                    f.get("criterio", ""),
                    _numero(f["combinaciones"]),
                    _numero(f["concordantes"]),
                    _numero(f["alertas"]),
                    f["estado"],
                ]
                for f in firmas
            ],
        )
        lineas.append("")

    detalle = resultado.get("detalle", [])
    if detalle:
        lineas += ["## Detalle por combinación", ""]
        lineas += _markdown_tabla(
            [
                "Firma",
                "Origen",
                "Destino",
                "1ª detección (IDS)",
                "Evento (registro)",
                "Instante (registro)",
                "Δ",
                "Estado",
            ],
            [
                [
                    d["firma"],
                    d["origen"],
                    d["destino"],
                    d.get("primera_deteccion_ids", ""),
                    d.get("evento_log") or "-",
                    (d.get("instante_log") or "").replace("T", " "),
                    "-" if d.get("delta_segundos") is None else f"{d['delta_segundos']} s",
                    d["estado"],
                ]
                for d in detalle
            ],
        )
        lineas.append("")

    solo = resultado.get("anomalias_solo_logscope", [])
    if solo:
        lineas += ["## Comportamientos visibles solo en el registro", ""]
        lineas += _markdown_tabla(
            ["Evento", "Origen", "Destino", "Bytes", "Ratio sobre el p95"],
            [
                [
                    o["event_id"],
                    o["src"],
                    o["dst"],
                    _numero(o.get("bytes_out", 0)),
                    _numero(o.get("ratio_vs_p95", 0)),
                ]
                for o in solo
            ],
        )
        lineas.append("")

    lineas += [
        "## Alcance de la validación",
        "",
        "La concordancia entre ambos instrumentos acredita la coherencia interna de dos "
        "metodologías de análisis aplicadas al mismo material —el emparejamiento de firmas "
        "sobre paquetes del IDS y el cálculo determinista sobre el registro—, y no una "
        "confirmación independiente del hecho: el origen de los datos es común.",
        "",
        "La validación tampoco es simétrica: el IDS coincide en todo lo que ocurre en la red, "
        "pero no puede ver los hallazgos de registro —flujos imposibles, direcciones sin "
        "activo asociado, correlaciones no resolubles del SIEM o saltos sin evidencia entre "
        "hosts—, que son precisamente los que aporta el análisis del registro.",
        "",
    ]
    return "\n".join(lineas)
