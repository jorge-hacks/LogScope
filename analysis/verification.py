"""Verificacion de las alertas del SIEM: falsos positivos y falsos negativos.

Responde de forma automatica a la pregunta que se le plantea al analista al
revisar un paquete de alertas: *¿cual de estas alertas se sostiene y cual no?*

Dos comprobaciones independientes, sobre los registros originales:

  1. SENAL. Para cada alerta se busca en el corpus un evento tecnico
     correlacionable dentro de su ventana temporal (rafaga de fallos,
     deteccion de malware, volumen anomalo, etc.). Si no existe, la alerta
     no tiene nada que la respalde.

  2. REFERENCIAS. Se abre el campo `related_event_ids` de cada alerta y se
     busca cada identificador en el corpus. Una referencia puede no
     resolverse (llega con un signo de interrogacion), no existir, o
     apuntar a un evento benigno que no prueba lo que la alerta afirma.

Una alerta se considera **falso positivo** cuando le falta la senal, o
cuando su propia evidencia no sostiene lo que afirma. Una alerta sostenida
es un **verdadero positivo**.

En sentido inverso, un **falso negativo** es un evento de gravedad relevante
que ninguna de las alertas menciona. Se detecta de forma objetiva: se
recorren los eventos de severidad alta o critica y se comprueba si su
identificador aparece en alguna referencia de alerta.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

# Tipos de evento que, por si solos, no prueban una intrusion.
BENIGNOS = {
    "service_start",
    "service_stop",
    "heartbeat",
    "scheduled_job",
    "user_login",
    "login",
    "logout",
}


# Mapear comportamiento del evento -> tecnicas ATT&CK que lo cubririan.
# Se usa para decidir si una alerta "cubre" un evento, en lugar de fiarse
# solo de la proximidad temporal: estar cerca en el tiempo no es estar
#covered por esa alerta.
TECNICAS_POR_COMPORTAMIENTO: dict[str, set[str]] = {
    "process_creation": {"T1059.001", "T1059", "T1204.002", "T1047"},
    "scheduled_task_created": {"T1053", "T1053.005"},
    "scheduled_task_executed": {"T1053", "T1053.005"},
    "web_file_modified": {"T1505.003"},
    "webshell_execution": {"T1505.003"},
    "service_account_shell": {"T1078", "T1098"},
    "remote_service_created": {"T1543.003", "T1021.002"},
    "sensitive_file_access": {"T1005", "T1213", "T1530"},
    "archive_created": {"T1005", "T1560"},
    "large_outbound_transfer": {"T1041", "T1041.001", "T1567"},
    "account_lockout": {"T1110"},
    "service_start": {"T1078"},
}

# Amenazas de antivirus y la tecnica que las cubriria.
TECNICAS_POR_AMENAZA: dict[str, set[str]] = {
    "Backdoor.WebShell": {"T1505.003"},
    "HackTool.CredDump": {"T1003", "T1003.001"},
    "Trojan.Generic.DLL": {"T1027", "T1218"},
    "PowerShell.Downloader": {"T1059.001", "T1105"},
    "PUA.RemoteAdmin": {"T1219"},
}

# Gravedad minima para considerar un evento no alertado como falso negativo.
GRAVEDAD_FN = {"HIGH", "CRITICAL"}


def _severidad_penalizada(severidad: str) -> int:
    orden = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return orden.get(str(severidad).upper(), 0)


def verify_alerts(
    events: list[dict[str, Any]],
    metrics: dict[str, Any],
    integrity: dict[str, Any],
) -> dict[str, Any]:
    """Clasifica cada alerta como sostenida o no, y lista los falsos negativos."""
    por_id = {e["event_id"]: e for e in events}
    alertas = sorted(
        (e for e in events if e["source_type"] == "siem"),
        key=lambda e: e["event_id"],
    )

    # --- referencias por alerta -------------------------------------------------
    placeholders: dict[str, list[str]] = {}
    benignas: dict[str, list[str]] = {}
    inexistentes: dict[str, list[str]] = {}
    for item in integrity.get("siem_correlation", {}).get("unresolved_placeholders", []):
        placeholders.setdefault(item["alert_id"], []).append(item["reference"])
    for item in integrity.get("siem_correlation", {}).get("benign_citations", []):
        benignas.setdefault(item["alert_id"], []).append(item["reference"])
    for item in integrity.get("siem_correlation", {}).get("missing_references", []):
        inexistentes.setdefault(item["alert_id"], []).append(item["reference"])

    # --- senal correlacionada por alerta ---------------------------------------
    senal: dict[str, dict[str, Any]] = {}
    for item in metrics.get("detection", {}).get("per_alert", []):
        if item.get("signal"):
            senal[item["alert_id"]] = item["signal"]

    # --- identificadores efectivamente mencionados por alguna alerta -------------
    mencionados: set[str] = set()
    for alerta in alertas:
        for referencia in (alerta.get("raw", {}) or {}).get("related_event_ids", "").split(";"):
            referencia = referencia.strip()
            if referencia and not referencia.endswith("?"):
                mencionados.add(referencia)

    filas: list[dict[str, Any]] = []
    for alerta in alertas:
        identificador = alerta["event_id"]
        raw = alerta.get("raw", {}) or {}
        referencias = [r.strip() for r in raw.get("related_event_ids", "").split(";") if r.strip()]
        validas = [
            r for r in referencias if r in por_id and not r.endswith("?")
        ]
        sin_resolver = placeholders.get(identificador, [])
        cita_benigna = benignas.get(identificador, [])
        cita_inexistente = inexistentes.get(identificador, [])
        tiene_senal = identificador in senal

        motivos: list[str] = []
        defectos: list[str] = []
        if not tiene_senal:
            motivos.append("no hay ninguna senal tecnica correlacionada en su ventana")
        if sin_resolver:
            defectos.append(
                f"{len(sin_resolver)} referencia(s) no resolubles ({', '.join(sin_resolver)})"
            )
        if cita_inexistente:
            defectos.append(
                f"{len(cita_inexistente)} referencia(s) inexistente(s) ({', '.join(cita_inexistente)})"
            )
        if cita_benigna:
            defectos.append(
                f"cita como evidencia {len(cita_benigna)} evento(s) benigno(s) "
                f"({', '.join(cita_benigna)})"
            )
        if not referencias:
            defectos.append("no declara ninguna referencia")

        # Tres niveles. Una referencia rota no convierte una alerta verdadera
        # en falsa: la senal correlacionada es la que sostiene el hecho.
        if not tiene_senal:
            veredicto = "FALSO POSITIVO"
            motivos = motivos + defectos
        elif defectos:
            veredicto = "VERDADERO POSITIVO CON EVIDENCIA DEFICIENTE"
            motivos = defectos
        else:
            veredicto = "VERDADERO POSITIVO"
            motivos = []

        severidad_real = None
        if tiene_senal:
            evento = por_id.get(senal[identificador].get("event_id", ""))
            if evento:
                severidad_real = evento.get("severidad", "")

        filas.append(
            {
                "alerta": identificador,
                "instante": alerta.get("iso_utc", ""),
                "severidad_declarada": alerta.get("severity", ""),
                "tecnica_declarada": raw.get("technique_id", ""),
                "tactica_declarada": raw.get("tactic", ""),
                "severidad_real": severidad_real or "",
                "senal": tiene_senal,
                "senal_tipo": senal.get(identificador, {}).get("kind", ""),
                "senal_evento": senal.get(identificador, {}).get("event_id", ""),
                "mttd_segundos": next(
                    (
                        a.get("mttd_seconds")
                        for a in metrics.get("detection", {}).get("per_alert", [])
                        if a.get("alert_id") == identificador
                    ),
                    None,
                ),
                "referencias": referencias,
                "referencias_validas": validas,
                "referencias_no_resolubles": sin_resolver,
                "referencias_benignas": cita_benigna,
                "referencias_inexistentes": cita_inexistente,
                "veredicto": veredicto,
                "motivos": motivos,
            }
        )

    # --- falsos negativos: hechos relevantes que ninguna alerta cubrio --------
    # Ventana de cobertura de una alerta: diez minutos antes y una hora
    # despues, que es el mismo intervalo con el que se correlaciona la senal.
    # La ventana puede ser amplia porque ademas se exige que la tecnica
    # declarada por la alerta corresponda al comportamiento del evento.
    ventanas: list[tuple[float, float]] = []
    for item in metrics.get("detection", {}).get("per_alert", []):
        instante = item.get("ts")
        if not instante:
            continue
        marca = datetime.fromisoformat(str(instante).replace("Z", "+00:00")).timestamp()
        ventanas.append((marca - 600, marca + 3600))

    # Tecnicas declaradas por cada alerta.
    tecnicas_por_alerta: dict[str, set[str]] = {}
    for alerta in alertas:
        raw = alerta.get("raw", {}) or {}
        tecnica = str(raw.get("technique_id", "")).strip()
        if tecnica:
            tecnicas_por_alerta[alerta["event_id"]] = {tecnica}

    def tecnicas_que_cubren(evento: dict[str, Any]) -> set[str]:
        """Tecnicas ATT&CK que cubririan este evento, segun su naturaleza."""
        tipo = str(evento.get("event_type", ""))
        conjunto = set(TECNICAS_POR_COMPORTAMIENTO.get(tipo, set()))
        if evento.get("source_type") == "antivirus":
            amenaza = str((evento.get("raw", {}) or {}).get("threat_name", ""))
            conjunto |= TECNICAS_POR_AMENAZA.get(amenaza, set())
        return conjunto

    def cubierto(evento: dict[str, Any]) -> bool:
        """Una alerta cubre al evento si lo referencia, o si declara la
        tecnica que corresponde a ese comportamiento dentro de su ventana."""
        identificador = evento["event_id"]
        if identificador in mencionados:
            return True
        instante = evento.get("ts_epoch") or 0
        if not instante:
            return False
        candidatas = tecnicas_que_cubren(evento)
        if not candidatas:
            return False
        for alerta in alertas:
            if not any(inicio <= instante <= fin for inicio, fin in ventanas):
                continue
            if tecnicas_por_alerta.get(alerta["event_id"], set()) & candidatas:
                return True
        return False

    falsos_negativos: list[dict[str, Any]] = []
    for evento in events:
        # Las propias alertas del SIEM no son hechos no alertados.
        if evento.get("source_type") == "siem":
            continue
        if evento["event_id"] in mencionados:
            continue
        if cubierto(evento):
            continue
        severidad = evento.get("severity", "").upper()
        es_perimetro = (
            evento.get("source_type") == "firewall"
            and str((evento.get("raw", {}) or {}).get("action", "")).upper() == "DENY"
        )
        if severidad not in GRAVEDAD_FN and not es_perimetro:
            continue
        if es_perimetro:
            motivo = "conexion bloqueada en el perimetro que ninguna alerta menciona"
        else:
            motivo = f"evento de severidad {severidad.lower()} que ninguna alerta menciona"
        falsos_negativos.append(
            {
                "evento": evento["event_id"],
                "instante": evento.get("iso_utc", ""),
                "tipo": evento.get("event_type", ""),
                "severidad": evento.get("severity", ""),
                "host": evento.get("host", ""),
                "detalle": evento.get("detail", ""),
                "fuente": evento.get("source_type", ""),
                "motivo": motivo,
            }
        )

    insostenibles = [f for f in filas if f["veredicto"] == "FALSO POSITIVO"]
    sostenidas = [f for f in filas if f["veredicto"] == "VERDADERO POSITIVO"]
    deficientes = [f for f in filas if f["veredicto"] == "VERDADERO POSITIVO CON EVIDENCIA DEFICIENTE"]

    return {
        "alertas": {
            "total": len(filas),
            "verdaderos_positivos": len(sostenidas),
            "verdaderos_con_evidencia_deficiente": len(deficientes),
            "falsos_positivos": len(insostenibles),
            "tasa_verificacion": round((len(sostenidas) + len(deficientes)) / len(filas), 4) if filas else 0.0,
            "sin_senal": sum(1 for f in filas if not f["senal"]),
            "con_referencia_no_resoluble": sum(1 for f in filas if f["referencias_no_resolubles"]),
            "con_referencia_benigna": sum(1 for f in filas if f["referencias_benignas"]),
        },
        "falsos_positivos": [
            {
                "alerta": f["alerta"],
                "severidad_declarada": f["severidad_declarada"],
                "motivos": f["motivos"],
            }
            for f in insostenibles
        ],
        "falsos_negativos": falsos_negativos,
        "detalle": filas,
    }
