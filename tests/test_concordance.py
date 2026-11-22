"""Tests de la conciliacion con un IDS externo."""

from __future__ import annotations

from datetime import timedelta, timezone

import pytest

from analysis.concordance import parse_ids, reconcile, tz_from_offset

TZ = timezone(timedelta(hours=-3))

RESUMEN_CSV = """sid,firma,origen,destino,primera_deteccion,ultima_deteccion,alertas
1000003,JKS-EXFILITRACION Transferencia saliente,10.10.30.31,203.0.113.10,03/22-03:42:00.036649,03/22-03:51:00.000000,17027
1000006,JKS-MOV-LATERAL Conexion SMB,10.10.30.21,10.10.30.31,03/21-01:31:00.000000,03/21-01:31:01.000000,2
"""

ALERT_LOG = """03/22-03:42:00.036649 [**] [1:1000003:1] "JKS-EXFILITRACION Transferencia saliente" [**] [Priority: 0] {TCP} 10.10.30.31:55110 -> 203.0.113.10:443
03/21-01:31:00.000000 [**] [1:1000006:1] "JKS-MOV-LATERAL Conexion SMB" [**] [Priority: 0] {TCP} 10.10.30.21:50211 -> 10.10.30.31:445
03/21-01:31:00.000100 [**] [1:1000006:1] "JKS-MOV-LATERAL Conexion SMB" [**] [Priority: 0] {TCP} 10.10.30.21:50211 -> 10.10.30.31:445
"""


def _eventos() -> list[dict]:
    from datetime import datetime

    base = datetime(2025, 3, 22, 3, 42, 0, 36649, tzinfo=TZ)
    lateral = datetime(2025, 3, 21, 1, 31, 0, tzinfo=TZ)
    return [
        {
            "event_id": "FW-00095",
            "src_ip": "10.10.30.31",
            "dst_ip": "203.0.113.10",
            "ts_epoch": base.timestamp(),
            "iso_local": base.isoformat(),
            "bytes_out": 7_420_000,
        },
        {
            "event_id": "NF-00128",
            "src_ip": "10.10.30.21",
            "dst_ip": "10.10.30.31",
            "ts_epoch": lateral.timestamp(),
            "iso_local": lateral.isoformat(),
            "bytes_out": 320_000,
        },
    ]


def _metrics() -> dict:
    return {
        "volume_outliers": [
            {
                "event_id": "FW-00095",
                "src": "10.10.30.31",
                "dst": "203.0.113.10",
                "bytes_out": 7_420_000,
            }
        ]
    }


def test_detecta_el_formato_del_resumen():
    formato, filas = parse_ids(RESUMEN_CSV, TZ)
    assert formato == "resumen_csv"
    assert len(filas) == 2
    assert filas[0]["firma"] == "JKS-EXFILITRACION"


def test_detecta_el_formato_del_log_crudo():
    formato, filas = parse_ids(ALERT_LOG, TZ)
    assert formato == "alert_log"
    assert len(filas) == 2  # agrupado por combinacion
    exfil = next(f for f in filas if f["firma"] == "JKS-EXFILITRACION")
    assert exfil["alertas"] == 1


def test_rechaza_un_formato_desconocido():
    with pytest.raises(ValueError, match="No se reconoce el formato"):
        parse_ids("hola mundo\n", TZ)


def test_concilia_con_desfase_cero():
    _, filas = parse_ids(RESUMEN_CSV, TZ)
    resultado = reconcile(filas, _eventos(), _metrics())
    resumen = resultado["resumen"]
    assert resumen["combinaciones_ids"] == 2
    assert resumen["concordantes"] == 2
    assert resumen["tasa_concordancia"] == 1.0
    assert resumen["delta_maximo"] == 0
    assert resumen["firmas_sin_concordancia"] == []


def test_asigna_el_evento_del_log_a_cada_deteccion():
    _, filas = parse_ids(RESUMEN_CSV, TZ)
    resultado = reconcile(filas, _eventos(), _metrics())
    detalle = {d["firma"]: d for d in resultado["detalle"]}
    assert detalle["JKS-EXFILITRACION"]["evento_log"] == "FW-00095"
    assert detalle["JKS-MOV-LATERAL"]["evento_log"] == "NF-00128"
    assert detalle["JKS-EXFILITRACION"]["bytes_registro"] == 7_420_000


def test_una_deteccion_sin_registro_queda_sin_concorrelato():
    _, filas = parse_ids(
        "sid,firma,origen,destino,primera_deteccion,ultima_deteccion,alertas\n"
        "1000001,JKS-ESCANEO Escaneo,10.0.0.1,10.0.0.2,03/19-05:54:00.000000,03/19-05:54:00.000000,1\n",
        TZ,
    )
    resultado = reconcile(filas, _eventos(), _metrics())
    assert resultado["resumen"]["concordantes"] == 0
    assert resultado["detalle"][0]["estado"] == "sin registro equivalente"


def test_una_anomalia_solo_del_registro_se_reporta():
    metrics = _metrics()
    metrics["volume_outliers"].append(
        {"event_id": "NF-99999", "src": "10.9.9.9", "dst": "10.9.9.10", "bytes_out": 999}
    )
    _, filas = parse_ids(RESUMEN_CSV, TZ)
    resultado = reconcile(filas, _eventos(), metrics)
    assert len(resultado["anomalias_solo_logscope"]) == 1
    assert resultado["anomalias_solo_logscope"][0]["event_id"] == "NF-99999"


def test_tz_from_offset():
    assert tz_from_offset("-03:00").utcoffset(None) == timedelta(hours=-3)
    assert tz_from_offset("+02:00").utcoffset(None) == timedelta(hours=2)
    assert tz_from_offset("basura").utcoffset(None) == timedelta(0)
