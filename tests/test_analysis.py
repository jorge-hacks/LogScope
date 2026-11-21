"""Tests de las metricas deterministas y de la auditoria de integridad."""

from __future__ import annotations

from pathlib import Path

from analysis import audit_integrity, compute_metrics

RAW = """event_id,timestamp,username,source_ip,destination_host,event_type,result,details
AUTH-1,2025-03-20T01:02:00-03:00,mfuentes,198.51.100.42,JKS-VPN01,vpn_login,FAILURE,mal
AUTH-2,2025-03-20T01:04:00-03:00,mfuentes,198.51.100.42,JKS-VPN01,vpn_login,FAILURE,mal
AUTH-3,2025-03-20T01:06:00-03:00,mfuentes,198.51.100.42,JKS-VPN01,vpn_login,FAILURE,mal
AUTH-4,2025-03-20T01:21:00-03:00,mfuentes,198.51.100.42,JKS-VPN01,vpn_login,SUCCESS,ok
AUTH-5,2025-03-20T09:00:00-03:00,jrojas,10.10.20.27,JKS-SRV-APP01,interactive_logon,SUCCESS,normal
"""

SYSTEM = """event_id,timestamp,hostname,host_ip,log_source,event_type,severity,message,username
SYS-1,2025-03-19T08:00:00-03:00,JKS-SRV-APP01,10.10.30.21,Linux-Audit,service_start,INFO,Servicio web iniciado,
SYS-2,2025-03-26T09:15:00-03:00,JKS-SRV-APP01,10.10.30.21,Linux-Audit,service_stop,INFO,Parada de emergencia,
"""

SIEM = """alert_id,timestamp,tactic,technique_id,technique_name,source_ip,destination_or_host,username,severity,related_event_ids,description
SIEM-1,2025-03-20T01:18:00-03:00,Credential Access,T1110.003,Password Spraying,198.51.100.42,JKS-VPN01,mfuentes,HIGH,AUTH-000?,fallos
SIEM-2,2025-03-24T02:14:00-03:00,Execution,T1505.003,Web Shell,10.10.30.21,JKS-SRV-APP01,svc_backup,CRITICAL,AV-000?;SYS-1,web shell
"""

NETFLOW = """flow_id,start_time,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,direction,application
NF-1,2025-03-20T10:00:00-03:00,10.10.20.14,10.10.30.21,50000,443,TCP,100,1000,EAST_WEST,business-traffic
NF-2,2025-03-22T03:42:00-03:00,10.10.30.31,203.0.113.201,55110,443,TCP,8244,7420000,OUTBOUND,unknown-encrypted
NF-3,2025-03-20T10:00:00-03:00,10.10.30.21,10.10.30.21,50001,445,TCP,50,900,EAST_WEST,business-traffic
NF-4,2025-03-20T11:00:00-03:00,10.10.20.14,10.10.30.21,50002,443,TCP,100,1100,EAST_WEST,business-traffic
NF-5,2025-03-20T12:00:00-03:00,10.10.20.27,10.10.30.21,50003,443,TCP,100,1200,EAST_WEST,business-traffic
NF-6,2025-03-20T13:00:00-03:00,10.10.20.14,10.10.40.15,50004,443,TCP,100,1300,EAST_WEST,business-traffic
NF-7,2025-03-20T14:00:00-03:00,10.10.20.27,10.10.30.21,50005,443,TCP,100,1400,EAST_WEST,business-traffic
NF-8,2025-03-20T15:00:00-03:00,10.10.20.14,10.10.30.21,50006,443,TCP,100,1500,EAST_WEST,business-traffic
NF-9,2025-03-20T16:00:00-03:00,10.10.20.27,10.10.30.21,50007,443,TCP,100,1600,EAST_WEST,business-traffic
NF-10,2025-03-20T17:00:00-03:00,10.10.20.14,10.10.40.15,50008,443,TCP,100,1700,EAST_WEST,business-traffic
"""


def build_events(tmp_path: Path):
    from ingest import ingest_paths

    (tmp_path / "auth.csv").write_text(RAW, encoding="utf-8")
    (tmp_path / "sys.csv").write_text(SYSTEM, encoding="utf-8")
    (tmp_path / "siem.csv").write_text(SIEM, encoding="utf-8")
    (tmp_path / "nf.csv").write_text(NETFLOW, encoding="utf-8")
    paths = [tmp_path / n for n in ("auth.csv", "sys.csv", "siem.csv", "nf.csv")]
    return ingest_paths(paths, tmp_path / "work").events


def test_metrics_window_and_counts(tmp_path: Path):
    events = build_events(tmp_path)
    metrics = compute_metrics(events)
    assert metrics["events"] == len(events)
    assert metrics["window"]["span_seconds"] > 0
    assert metrics["by_source"]["authentication"] == 5


def test_metrics_detect_off_hours(tmp_path: Path):
    events = build_events(tmp_path)
    metrics = compute_metrics(events)
    # AUTH-1..4 son de madrugada en -03:00 (04:02..04:21 UTC) pero el analisis
    # usa la hora local del log: el criterio es la hora del evento.
    assert metrics["off_hours"]["total"] >= 1
    assert 0 <= metrics["off_hours"]["ratio"] <= 1


def test_metrics_flag_volume_outliers(tmp_path: Path):
    events = build_events(tmp_path)
    metrics = compute_metrics(events)
    outliers = metrics["volume_outliers"]
    assert any(o["bytes_out"] == 7_420_000 for o in outliers)


def test_metrics_detect_auth_burst_signal(tmp_path: Path):
    events = build_events(tmp_path)
    metrics = compute_metrics(events)
    bursts = [s for s in metrics["signals"] if s["kind"] == "auth_failure_burst"]
    assert bursts
    assert bursts[0]["actor"] == "mfuentes"


def test_metrics_compute_dwell_time(tmp_path: Path):
    events = build_events(tmp_path)
    metrics = compute_metrics(events)
    assert metrics["containment"]["event_id"] == "SYS-2"
    assert metrics["dwell"]["seconds"] > 0


def test_integrity_flags_unresolved_placeholders(tmp_path: Path):
    events = build_events(tmp_path)
    integrity = audit_integrity(events)
    correlation = integrity["siem_correlation"]
    assert correlation["unresolved_count"] == 2
    assert any(u["reference"] == "AUTH-000?" for u in correlation["unresolved_placeholders"])


def test_integrity_flags_benign_citations(tmp_path: Path):
    events = build_events(tmp_path)
    integrity = audit_integrity(events)
    # SIEM-2 cita SYS-0001, que es un service_start INFO.
    assert integrity["siem_correlation"]["benign_citation_count"] == 1


def test_integrity_flags_tactic_mismatch(tmp_path: Path):
    events = build_events(tmp_path)
    integrity = audit_integrity(events)
    mismatches = integrity["tactic_technique"]["mismatches"]
    assert any(m["alert_id"] == "SIEM-2" for m in mismatches)
    assert mismatches[0]["expected_tactics"] == ["Persistence"]


def test_integrity_detects_single_account_spraying(tmp_path: Path):
    events = build_events(tmp_path)
    integrity = audit_integrity(events)
    candidates = integrity["tactic_technique"]["spraying_candidates"]
    assert candidates
    assert candidates[0]["single_account_guess"] is True


def test_integrity_detects_self_flows(tmp_path: Path):
    events = build_events(tmp_path)
    integrity = audit_integrity(events)
    assert len(integrity["self_flows"]) == 1
    assert integrity["self_flows"][0]["ip"] == "10.10.30.21"
