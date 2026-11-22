"""Tests de la trazabilidad alerta -> evidencia -> hallazgo."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from analysis.traceability import build_traceability

TZ = timezone(timedelta(hours=-3))
BASE = datetime(2025, 3, 23, 0, 35, 0, tzinfo=TZ)


def _alerta(identificador, referencias, ts=BASE):
    return {
        "event_id": identificador,
        "ts_epoch": ts.timestamp(),
        "iso_utc": ts.isoformat(),
        "source_type": "siem",
        "severity": "MEDIUM",
        "event_type": "",
        "raw": {
            "related_event_ids": ";".join(referencias),
            "technique_id": "T1071.001",
            "tactic": "Command and Control",
            "description": "nuevo intento de conexion externa",
        },
    }


def _evento(identificador, ts, tipo="scheduled_task_executed", severidad="HIGH"):
    return {
        "event_id": identificador,
        "ts_epoch": ts.timestamp(),
        "iso_utc": ts.isoformat(),
        "source_type": "system",
        "severity": severidad,
        "event_type": tipo,
        "host": "WS-014",
        "detail": "detalle",
        "raw": {},
    }


def _integridad(placeholders=None, benignas=None):
    return {
        "siem_correlation": {
            "unresolved_placeholders": [{"alert_id": a, "reference": r} for a, r in (placeholders or [])],
            "benign_citations": [{"alert_id": a, "reference": r} for a, r in (benignas or [])],
            "missing_references": [],
        }
    }


def test_las_referencias_se_clasifican_por_su_estado():
    eventos = [
        _alerta("SIEM-0009", ["SYS-00010", "FW-000?"]),
        _evento("SYS-00010", BASE - timedelta(days=3), tipo="scheduled_task_created"),
    ]
    integridad = _integridad(placeholders=[("SIEM-0009", "FW-000?")])
    resultado = build_traceability(eventos, {}, integridad)
    fila = resultado["alertas"][0]
    estados = {r["referencia"]: r["estado"] for r in fila["referencias"]}
    assert estados["SYS-00010"] == "válida"
    assert estados["FW-000?"] == "no resoluble"


def test_un_hallazgo_se_asigna_a_la_alerta_que_lo_cita():
    eventos = [_alerta("SIEM-0009", ["SYS-00010"])]
    informe = {"findings": [{"id": "H-08", "title": "Alerta mal asociada", "severity": "MEDIUM", "evidence": ["SIEM-0009", "SYS-00010"]}]}
    resultado = build_traceability(eventos, {}, _integridad(), report=informe)
    fila = resultado["alertas"][0]
    assert [h["id"] for h in fila["hallazgos"]] == ["H-08"]
    assert fila["hallazgos"][0]["por_que"] == "recoge la propia alerta"


def test_un_hallazgo_que_cita_la_evidencia_tambien_se_asigna():
    eventos = [_alerta("SIEM-0009", ["SYS-00010"]), _evento("SYS-00010", BASE)]
    informe = {"findings": [{"id": "H-08", "title": "x", "severity": "MEDIUM", "evidence": ["SYS-00010"]}]}
    resultado = build_traceability(eventos, {}, _integridad(), report=informe)
    fila = resultado["alertas"][0]
    assert [h["id"] for h in fila["hallazgos"]] == ["H-08"]
    assert fila["hallazgos"][0]["por_que"] == "recoge su evidencia"


def test_los_hechos_no_alertados_cercanos_se_listan():
    eventos = [_alerta("SIEM-0009", ["SYS-00010"])]
    no_alertados = [
        {
            "evento": "FW-00097",
            "instante": (BASE - timedelta(minutes=3)).isoformat(),
            "tipo": "OUTBOUND_SSH_BLOCK",
            "severidad": "INFO",
            "detalle": "salida ssh bloqueada",
        }
    ]
    resultado = build_traceability(eventos, {}, _integridad(), falsos_negativos=no_alertados)
    cercanos = resultado["alertas"][0]["hechos_no_alertados"]
    assert [c["evento"] for c in cercanos] == ["FW-00097"]
    assert cercanos[0]["minutos"] == 3


def test_un_hecho_lejano_no_se_lista():
    eventos = [_alerta("SIEM-0009", ["SYS-00010"])]
    no_alertados = [
        {
            "evento": "FW-00099",
            "instante": (BASE - timedelta(hours=5)).isoformat(),
            "tipo": "rule",
            "severity": "INFO",
            "detalle": "d",
        }
    ]
    resultado = build_traceability(eventos, {}, _integridad(), falsos_negativos=no_alertados)
    assert resultado["alertas"][0]["hechos_no_alertados"] == []


def test_el_resumen_cuadra():
    eventos = [_alerta("SIEM-0009", ["SYS-00010"]), _alerta("SIEM-0002", ["AUTH-000?"])]
    informe = {"findings": [{"id": "H-08", "title": "x", "severity": "MEDIUM", "evidence": ["SIEM-0009"]}]}
    resultado = build_traceability(eventos, {}, _integridad(), report=informe)
    resumen = resultado["resumen"]
    assert resumen["alertas"] == 2
    assert resumen["alertas_con_hallazgo"] == 1
    assert resumen["alertas_sin_hallazgo"] == 1
    assert resumen["hallazgos"] == 1
