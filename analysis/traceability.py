"""Trazabilidad: de la alerta al hallazgo, pasando por la evidencia.

Responde a la pregunta que siempre aparece en la revision de un informe:
*¿como sabe usted que este hallazgo y esta alerta hablan del mismo hecho?*

La respuesta es que ambos citan los mismos identificadores de evento, y esos
identificadores se pueden abrir y comprobar en el registro original. Este
modulo construye esa cadena de forma explicita:

    alerta  ->  evidencia que declara  ->  eventos que son en realidad
             ->  hallazgos que la recogen  ->  hechos cercanos que
                                            ninguna alerta cubrio

El ultimo eslabon es el mas util: muestra, para cada alerta, que ocurrio de
verdad en su ventana temporal y que no llego a alertarse.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

# Ventana alrededor de la alerta para buscar hechos no alertados.
VENTANA_MINUTOS = 10


def _instante(texto: str) -> float:
    if not texto:
        return 0.0
    try:
        return datetime.fromisoformat(str(texto).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def build_traceability(
    events: list[dict[str, Any]],
    metrics: dict[str, Any],
    integrity: dict[str, Any],
    report: dict[str, Any] | None = None,
    falsos_negativos: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Construye la matriz de trazabilidad alerta -> evidencia -> hallazgo."""
    por_id = {e["event_id"]: e for e in events}
    alertas = sorted(
        (e for e in events if e["source_type"] == "siem"),
        key=lambda e: e["event_id"],
    )
    hallazgos = (report or {}).get("findings", [])

    # --- referencias declaradas, con su estado -------------------------------
    no_resolubles: dict[str, list[str]] = {}
    benignas: dict[str, list[str]] = {}
    inexistentes: dict[str, list[str]] = {}
    for item in integrity.get("siem_correlation", {}).get("unresolved_placeholders", []):
        no_resolubles.setdefault(item["alert_id"], []).append(item["reference"])
    for item in integrity.get("siem_correlation", {}).get("benign_citations", []):
        benignas.setdefault(item["alert_id"], []).append(item["reference"])
    for item in integrity.get("siem_correlation", {}).get("missing_references", []):
        inexistentes.setdefault(item["alert_id"], []).append(item["reference"])

    # --- hechos no alertados, para buscar los cercanos a cada alerta ---------
    no_alertados = falsos_negativos or []

    filas: list[dict[str, Any]] = []
    for alerta in alertas:
        identificador = alerta["event_id"]
        raw = alerta.get("raw", {}) or {}
        declaradas = [r.strip() for r in raw.get("related_event_ids", "").split(";") if r.strip()]

        referencias = []
        ids_resueltos: list[str] = []
        for referencia in declaradas:
            if referencia in no_resolubles.get(identificador, []):
                estado = "no resoluble"
            elif referencia in benignas.get(identificador, []):
                estado = "evento benigno"
            elif referencia in inexistentes.get(identificador, []):
                estado = "inexistente"
            elif referencia in por_id:
                estado = "válida"
                ids_resueltos.append(referencia)
            else:
                estado = "no encontrada"
            evento = por_id.get(referencia)
            referencias.append(
                {
                    "referencia": referencia,
                    "estado": estado,
                    "tipo": (evento or {}).get("event_type", ""),
                    "severidad": (evento or {}).get("severity", ""),
                    "instante": (evento or {}).get("iso_local", ""),
                    "detalle": (evento or {}).get("detail", ""),
                }
            )

        # Hallazgos que recogen esta alerta o su evidencia.
        recogidos = []
        for hallazgo in hallazgos:
            evidencia = hallazgo.get("evidence", [])
            coincide = identificador in evidencia or any(i in evidencia for i in ids_resueltos)
            if coincide:
                recogidos.append(
                    {
                        "id": hallazgo.get("id", ""),
                        "titulo": hallazgo.get("title", ""),
                        "severidad": hallazgo.get("severity", ""),
                        "por_que": (
                            "recoge la propia alerta"
                            if identificador in evidencia
                            else "recoge su evidencia"
                        ),
                    }
                )

        # Hechos que ocurrieron cerca y que ninguna alerta cubrio.
        instante_alerta = _instante(alerta.get("iso_utc", ""))
        cercanos = []
        if instante_alerta:
            for hecho in no_alertados:
                instante_hecho = _instante(hecho.get("instante", ""))
                if not instante_hecho:
                    continue
                delta = abs(instante_hecho - instante_alerta)
                if delta <= VENTANA_MINUTOS * 60:
                    cercanos.append(
                        {
                            "evento": hecho.get("evento", ""),
                            "tipo": hecho.get("tipo", ""),
                            "severidad": hecho.get("severidad", ""),
                            "instante": hecho.get("instante", ""),
                            "minutos": int(delta // 60),
                            "detalle": hecho.get("detalle", ""),
                        }
                    )
            cercanos.sort(key=lambda c: c["minutos"])

        filas.append(
            {
                "alerta": identificador,
                "instante": alerta.get("iso_utc", ""),
                "severidad": alerta.get("severity", ""),
                "tactica": raw.get("tactic", ""),
                "tecnica": raw.get("technique_id", ""),
                "descripcion": raw.get("description", ""),
                "referencias": referencias,
                "ids_resueltos": ids_resueltos,
                "hallazgos": recogidos,
                "hechos_no_alertados": cercanos,
            }
        )

    # --- resumen por hallazgo: que alertas lo sustentan -----------------------
    por_hallazgo: dict[str, dict[str, Any]] = {}
    for fila in filas:
        for hallazgo in fila["hallazgos"]:
            entrada = por_hallazgo.setdefault(
                hallazgo["id"],
                {
                    "id": hallazgo["id"],
                    "titulo": hallazgo["titulo"],
                    "severidad": hallazgo["severidad"],
                    "alertas": [],
                },
            )
            entrada["alertas"].append(fila["alerta"])

    return {
        "alertas": filas,
        "hallazgos": sorted(por_hallazgo.values(), key=lambda h: h["id"]),
        "resumen": {
            "alertas": len(filas),
            "alertas_con_hallazgo": sum(1 for f in filas if f["hallazgos"]),
            "alertas_sin_hallazgo": sum(1 for f in filas if not f["hallazgos"]),
            "hallazgos": len(por_hallazgo),
            "hallazgos_sin_alerta": sum(
                1 for h in hallazgos if h.get("id") and h["id"] not in por_hallazgo
            ),
        },
    }
