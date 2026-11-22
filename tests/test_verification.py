"""Tests de la verificacion de alertas: falsos positivos y falsos negativos."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from analysis.verification import verify_alerts

TZ = timezone(timedelta(hours=-3))
BASE = datetime(2025, 3, 20, 2, 26, 0, tzinfo=TZ)


def _alerta(identificador, ts, referencias, tecnica="T1059.001", severidad="HIGH"):
    return {
        "event_id": identificador,
        "ts_epoch": ts.timestamp(),
        "iso_utc": ts.isoformat(),
        "source_type": "siem",
        "severity": severidad,
        "event_type": "",
        "raw": {
            "related_event_ids": ";".join(referencias),
            "technique_id": tecnica,
            "tactic": "Execution",
        },
    }


def _evento(identificador, ts, tipo="process_creation", severidad="HIGH", source="system"):
    return {
        "event_id": identificador,
        "ts_epoch": ts.timestamp(),
        "iso_utc": ts.isoformat(),
        "source_type": source,
        "severity": severidad,
        "event_type": tipo,
        "host": "SRV-01",
        "detail": "detalle",
        "raw": {"action": "ALLOW"},
    }


def _metricas(con_alerta: str | None = None, segundos: int = 420):
    per_alert = []
    for identificador in ("SIEM-0001", "SIEM-0002", "SIEM-0003"):
        if identificador == con_alerta:
            per_alert.append(
                {
                    "alert_id": identificador,
                    "ts": BASE.isoformat(),
                    "severity": "HIGH",
                    "mttd_seconds": segundos,
                    "mttd_human": "7m 0s",
                    "signal": {
                        "kind": "malware_detection",
                        "event_id": "AV-00001",
                        "iso": BASE.isoformat(),
                        "detail": "deteccion",
                    },
                }
            )
        else:
            per_alert.append(
                {
                    "alert_id": identificador,
                    "ts": BASE.isoformat(),
                    "severity": "HIGH",
                    "mttd_seconds": None,
                    "mttd_human": "sin senal correlacionada",
                    "signal": None,
                }
            )
    return {"detection": {"per_alert": per_alert}}


def _integridad(placeholders=None, benignas=None, inexistentes=None):
    return {
        "siem_correlation": {
            "unresolved_placeholders": [{"alert_id": a, "reference": r} for a, r in (placeholders or [])],
            "benign_citations": [{"alert_id": a, "reference": r} for a, r in (benignas or [])],
            "missing_references": [{"alert_id": a, "reference": r} for a, r in (inexistentes or [])],
        }
    }


def test_una_alerta_con_senal_y_referencia_valida_es_verdadero_positivo():
    eventos = [
        _alerta("SIEM-0001", BASE, ["AV-00001"]),
        _evento("AV-00001", BASE, tipo="malware_detection", severidad="HIGH", source="antivirus"),
    ]
    resultado = verify_alerts(eventos, _metricas("SIEM-0001"), _integridad())
    fila = resultado["detalle"][0]
    assert fila["veredicto"] == "VERDADERO POSITIVO"
    assert fila["senal"] is True
    assert resultado["alertas"]["falsos_positivos"] == 0


def test_una_alerta_sin_senal_es_falso_positivo():
    eventos = [_alerta("SIEM-0001", BASE, ["AV-00001"])]
    resultado = verify_alerts(eventos, _metricas(), _integridad())
    fila = resultado["detalle"][0]
    assert fila["veredicto"] == "FALSO POSITIVO"
    assert any("senal" in motivo for motivo in fila["motivos"])
    assert resultado["alertas"]["falsos_positivos"] == 1


def test_una_referencia_no_resoluble_no_convierte_en_falsa_la_alerta():
    """Con senal correlacionada, la alerta es verdadera aunque su referencia este rota."""
    eventos = [_alerta("SIEM-0001", BASE, ["AUTH-000?"])]
    resultado = verify_alerts(eventos, _metricas("SIEM-0001"), _integridad(placeholders=[("SIEM-0001", "AUTH-000?")]))
    fila = resultado["detalle"][0]
    assert fila["veredicto"] == "VERDADERO POSITIVO CON EVIDENCIA DEFICIENTE"
    assert resultado["alertas"]["falsos_positivos"] == 0
    assert resultado["alertas"]["verdaderos_con_evidencia_deficiente"] == 1


def test_una_cita_a_evento_benigno_es_deficiencia_de_evidencia():
    eventos = [_alerta("SIEM-0001", BASE, ["SYS-00001"])]
    integridad = _integridad(benignas=[("SIEM-0001", "SYS-00001")])
    resultado = verify_alerts(eventos, _metricas("SIEM-0001"), integridad)
    fila = resultado["detalle"][0]
    assert fila["veredicto"] == "VERDADERO POSITIVO CON EVIDENCIA DEFICIENTE"
    assert fila["referencias_benignas"] == ["SYS-00001"]


def test_una_alerta_si_misma_no_es_un_falso_negativo():
    """Las alertas del SIEM no son hechos no alertados."""
    eventos = [_alerta("SIEM-0001", BASE, ["AUTH-000?"])]
    resultado = verify_alerts(eventos, _metricas("SIEM-0001"), _integridad())
    assert all(f["evento"] != "SIEM-0001" for f in resultado["falsos_negativos"])


def test_un_evento_grave_no_citado_es_falso_negativo():
    eventos = [
        _alerta("SIEM-0001", BASE, ["AV-00001"]),
        _evento("AV-00004", BASE + timedelta(minutes=40), tipo="hacktool", severidad="CRITICAL", source="antivirus"),
    ]
    resultado = verify_alerts(eventos, _metricas("SIEM-0001"), _integridad())
    ids = [f["evento"] for f in resultado["falsos_negativos"]]
    assert "AV-00004" in ids


def test_un_evento_cubierto_por_la_tecnica_de_la_alerta_no_es_falso_negativo():
    """La tecnica declarada cubre el comportamiento aunque no se cite el evento."""
    eventos = [
        _alerta("SIEM-0001", BASE, ["AV-00001"], tecnica="T1059.001"),
        _evento("SYS-00009", BASE + timedelta(minutes=1), tipo="process_creation", severidad="HIGH"),
    ]
    resultado = verify_alerts(eventos, _metricas("SIEM-0001"), _integridad())
    assert all(f["evento"] != "SYS-00009" for f in resultado["falsos_negativos"])


def test_una_conexion_denegada_del_perimetro_es_falso_negativo():
    eventos = [
        _alerta("SIEM-0001", BASE, ["AV-00001"]),
        {
            **_evento("FW-00099", BASE + timedelta(hours=5), tipo="rule", severidad="INFO", source="firewall"),
            "raw": {"action": "DENY"},
        },
    ]
    resultado = verify_alerts(eventos, _metricas("SIEM-0001"), _integridad())
    ids = [f["evento"] for f in resultado["falsos_negativos"]]
    assert "FW-00099" in ids


def test_el_resumen_cuadra():
    eventos = [
        _alerta("SIEM-0001", BASE, ["AV-00001"]),
        _alerta("SIEM-0002", BASE, ["AUTH-000?"]),
        _alerta("SIEM-0003", BASE, ["AV-00001"]),
    ]
    resultado = verify_alerts(eventos, _metricas("SIEM-0001"), _integridad(placeholders=[("SIEM-0002", "AUTH-000?")]))
    # SIEM-0001 tiene senal y referencia valida: verdadero positivo.
    # SIEM-0002 no tiene senal: falso positivo, pese a su referencia rota.
    # SIEM-0003 no tiene senal: falso positivo.
    resumen = resultado["alertas"]
    assert resumen["total"] == 3
    assert resumen["verdaderos_positivos"] == 1
    assert resumen["verdaderos_con_evidencia_deficiente"] == 0
    assert resumen["falsos_positivos"] == 2
    assert resumen["tasa_verificacion"] == pytest.approx(1 / 3, abs=0.001)
