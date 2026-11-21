"""Tests de ingesta y normalizacion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ingest import detect_profile, ingest_paths, parse_timestamp
from ingest.profiles import normalize_severity

SAMPLE_AUTH = """event_id,timestamp,username,source_ip,destination_host,event_type,result,details
AUTH-1,2025-03-20T01:02:00-03:00,mfuentes,198.51.100.42,JKS-VPN01,vpn_login,FAILURE,Credenciales invalidas
AUTH-2,2025-03-20T01:21:00-03:00,mfuentes,198.51.100.42,JKS-VPN01,vpn_login,SUCCESS,Acceso VPN
"""

SAMPLE_FIREWALL = """event_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,action,rule_name,bytes_sent,bytes_received,application,username
FW-1,2025-03-20T02:14:00-03:00,10.10.20.14,53122,198.51.100.42,443,TCP,ALLOW,USER_WEB_EGRESS,184200,1200,TLS,mfuentes
"""

SAMPLE_GENERIC = """timestamp,event,user,source_ip,destination_ip,severity,message
2025-03-21T02:00:00Z,login,jrojas,10.10.20.27,10.10.30.21,low,inicio de sesion
"""


def test_detect_profile_by_fingerprint():
    columns = ["event_id", "timestamp", "username", "source_ip", "event_type", "result"]
    assert detect_profile(columns).name == "authentication"
    columns = ["flow_id", "start_time", "src_ip", "dst_ip", "dst_port", "bytes", "direction"]
    assert detect_profile(columns).name == "netflow"
    columns = ["alert_id", "timestamp", "tactic", "technique_id", "severity"]
    assert detect_profile(columns).name == "siem"


def test_detect_falls_back_to_generic():
    profile = detect_profile(["timestamp", "event", "user", "source_ip"])
    assert profile.name == "generic"
    assert profile.timestamp_column == "timestamp"
    assert profile.actor_column == "user"
    assert profile.src_ip_column == "source_ip"


def test_parse_timestamp_with_and_without_offset():
    _, epoch = parse_timestamp("2025-03-20T01:02:00-03:00")
    assert epoch > 0
    text, epoch_naive = parse_timestamp("2025-03-20 01:02:00")
    assert epoch_naive > 0
    assert text == "2025-03-20 01:02:00"
    assert parse_timestamp("no es una fecha")[1] == 0.0


def test_normalize_severity_aliases():
    assert normalize_severity("critical") == "CRITICAL"
    assert normalize_severity("Warning") == "MEDIUM"
    assert normalize_severity("") == "INFO"
    assert normalize_severity(None) == "INFO"


def test_ingest_orders_events_and_normalizes(tmp_path: Path):
    (tmp_path / "auth.csv").write_text(SAMPLE_AUTH, encoding="utf-8")
    (tmp_path / "fw.csv").write_text(SAMPLE_FIREWALL, encoding="utf-8")

    result = ingest_paths([tmp_path / "auth.csv", tmp_path / "fw.csv"], tmp_path / "work")

    assert result.count == 3
    assert {e["source_type"] for e in result.events} == {"authentication", "firewall"}
    # Orden cronologico aunque los ficheros se listes al reves.
    epochs = [e["ts_epoch"] for e in result.events]
    assert epochs == sorted(epochs)


def test_ingest_extracts_zip(tmp_path: Path):
    import zipfile

    zip_path = tmp_path / "logs.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("logs/auth.csv", SAMPLE_AUTH)
        archive.writestr("logs/fw.csv", SAMPLE_FIREWALL)

    result = ingest_paths([zip_path], tmp_path / "work")
    assert result.count == 3
    assert len(result.files) == 2


def test_ingest_reports_unreadable_files_without_crashing(tmp_path: Path):
    # Un fichero que no es texto UTF-8 valido debe reportarse como error
    # sin tumbar el resto de la ingesta.
    broken = tmp_path / "binario.csv"
    broken.write_bytes(b"\xff\xfe\x00\x01\x02not-utf8\x80")
    (tmp_path / "auth.csv").write_text(SAMPLE_AUTH, encoding="utf-8")

    result = ingest_paths([broken, tmp_path / "auth.csv"], tmp_path / "work")
    assert result.count == 2
    assert result.errors
    assert "binario.csv" in result.errors[0]


def test_unknown_columns_use_the_generic_fallback(tmp_path: Path):
    # Un CSV valido pero con columnas desconocidas se indexa igual, en vez de
    # descartarse: el perfil generico infiere los campos.
    odd = tmp_path / "raro.csv"
    odd.write_text("columna_a,columna_b\n1,2\n3,4\n", encoding="utf-8")
    result = ingest_paths([odd], tmp_path / "work")
    assert result.count == 2
    assert result.files[0]["matched_by"] == "fallback"
    assert result.files[0]["profile"] == "generic"


def test_generic_profile_maps_columns(tmp_path: Path):
    (tmp_path / "g.csv").write_text(SAMPLE_GENERIC, encoding="utf-8")
    result = ingest_paths([tmp_path / "g.csv"], tmp_path / "work")
    event = result.events[0]
    assert event["source_type"] == "generic"
    assert event["actor"] == "jrojas"
    assert event["src_ip"] == "10.10.20.27"
    assert event["severity"] == "LOW"


def test_events_jsonl_roundtrip(tmp_path: Path):
    from ingest import read_events, write_events

    (tmp_path / "auth.csv").write_text(SAMPLE_AUTH, encoding="utf-8")
    result = ingest_paths([tmp_path / "auth.csv"], tmp_path / "work")
    target = write_events(result.events, tmp_path / "work" / "normalized" / "events.jsonl")
    restored = read_events(target)
    assert len(restored) == len(result.events)
    assert json.loads(target.read_text(encoding="utf-8").splitlines()[0])["event_id"] == "AUTH-1"


@pytest.mark.parametrize("value", ["", None, "   "])
def test_empty_fields_do_not_crash(value):
    from ingest.normalize import _clean, _to_int

    assert _clean(value) == ""
    assert _to_int(value) == 0
