"""Auditoria de integridad y calidad de los logs.

Comprueba si la telemetria que tenemos es coherente consigo misma: referencias
rotas en las alertas SIEM, eventos citados que en realidad son benignos,
tecnicas ATT&CK mal etiquetadas, huecos en las secuencias de identificadores,
flujos imposible, activos sin propietario.

Todo lo que se reporta aqui es verificable por el lector en el log original.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

# Tactica ATT&CK esperada para las tecnicas que aparecen en logs de SOC.
# Permite detectar etiquetas de tactica incorrectas en el propio SIEM.
TECHNIQUE_TACTICS: dict[str, set[str]] = {
    "T1110": {"Credential Access"},
    "T1110.001": {"Credential Access"},
    "T1110.002": {"Credential Access"},
    "T1110.003": {"Credential Access"},
    "T1110.004": {"Credential Access"},
    "T1003": {"Credential Access"},
    "T1555": {"Credential Access"},
    "T1059": {"Execution"},
    "T1059.001": {"Execution"},
    "T1059.003": {"Execution"},
    "T1204": {"Execution"},
    "T1505.003": {"Persistence"},
    "T1543.003": {"Persistence", "Privilege Escalation"},
    "T1053": {"Execution", "Persistence"},
    "T1053.005": {"Execution", "Persistence"},
    "T1068": {"Privilege Escalation"},
    "T1548": {"Privilege Escalation", "Defense Evasion"},
    "T1078": {"Initial Access", "Defense Evasion", "Persistence", "Privilege Escalation"},
    "T1021": {"Lateral Movement"},
    "T1021.002": {"Lateral Movement"},
    "T1570": {"Lateral Movement"},
    "T1005": {"Collection"},
    "T1039": {"Collection"},
    "T1041": {"Exfiltration"},
    "T1041.001": {"Exfiltration"},
    "T1567": {"Exfiltration"},
    "T1071": {"Command and Control"},
    "T1071.001": {"Command and Control"},
    "T1095": {"Command and Control"},
}

# Tecnicas cuyo nombre en el log es suplantado de forma caracteristica.
# "Password Spraying" en MITRE significa 1 contrasena contra MUCHAS cuentas.
SPRAYING_TECHNIQUE = "T1110.003"

BENIGN_EVENT_TYPES = {
    "service_start",
    "service_stop",
    "heartbeat",
    "scheduled_job",
    "user_login",
    "login",
    "logout",
}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _benign(event: dict[str, Any] | None) -> bool:
    """Considera benigno un evento de severidad baja y tipo trivial."""
    if event is None:
        return False
    if event.get("severity") not in {"INFO", "LOW"}:
        return False
    return event.get("event_type", "").lower() in BENIGN_EVENT_TYPES


def audit_integrity(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {"events": 0}

    by_id = {e["event_id"]: e for e in events}
    alerts = [e for e in events if e["source_type"] == "siem"]

    # --- referencias de las alertas SIEM ------------------------------------
    unresolved: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    benign_citations: list[dict[str, Any]] = []
    valid_citations = 0

    for alert in alerts:
        raw_refs = (alert.get("raw", {}) or {}).get("related_event_ids", "")
        refs = [r.strip() for r in str(raw_refs).split(";") if r.strip()]
        resolved: list[str] = []
        for ref in refs:
            if ref.endswith("?"):
                unresolved.append({"alert_id": alert["event_id"], "reference": ref})
                continue
            if ref in by_id:
                resolved.append(ref)
                valid_citations += 1
                if _benign(by_id[ref]):
                    benign_citations.append(
                        {
                            "alert_id": alert["event_id"],
                            "reference": ref,
                            "referenced_event_type": by_id[ref].get("event_type", ""),
                            "referenced_severity": by_id[ref].get("severity", ""),
                            "referenced_detail": by_id[ref].get("detail", ""),
                        }
                    )
            else:
                missing.append({"alert_id": alert["event_id"], "reference": ref})

    # --- coherencia tactica / tecnica --------------------------------------
    tactic_mismatches: list[dict[str, Any]] = []
    for alert in alerts:
        raw = alert.get("raw", {}) or {}
        tactic = str(raw.get("tactic", "")).strip()
        technique = str(raw.get("technique_id", "")).strip()
        name = str(raw.get("technique_name", "")).strip()
        if technique in TECHNIQUE_TACTICS and tactic and tactic not in TECHNIQUE_TACTICS[technique]:
            tactic_mismatches.append(
                {
                    "alert_id": alert["event_id"],
                    "technique_id": technique,
                    "technique_name": name,
                    "declared_tactic": tactic,
                    "expected_tactics": sorted(TECHNIQUE_TACTICS[technique]),
                }
            )

    # --- deteccion de actividad real frente a la etiquetada ----------------
    spray_candidates = [
        {
            "alert_id": a["event_id"],
            "technique_id": (a.get("raw", {}) or {}).get("technique_id", ""),
            "detail": a["detail"],
        }
        for a in alerts
        if (a.get("raw", {}) or {}).get("technique_id") == SPRAYING_TECHNIQUE
    ]
    if spray_candidates:
        failed_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            if event["source_type"] == "authentication" and event["result"].upper() == "FAILURE":
                failed_by_user[event["actor"]].append(event)
        distinct_users = {u for u, items in failed_by_user.items() if len(items) >= 3}
        for candidate in spray_candidates:
            candidate["distinct_users_with_failures"] = sorted(distinct_users)
            candidate["single_account_guess"] = len(distinct_users) <= 1

    # --- huecos en las secuencias de identificadores ------------------------
    sequence_gaps: list[dict[str, Any]] = []
    by_source_ids: dict[str, list[str]] = defaultdict(list)
    for event in events:
        by_source_ids[event["source_type"]].append(event["event_id"])
    for source, ids in by_source_ids.items():
        numbers = sorted({int(m.group(1)) for i in ids if (m := re.search(r"(\d+)$", i))})
        if len(numbers) < 2:
            continue
        expected = set(range(numbers[0], numbers[-1] + 1))
        gaps = sorted(expected - set(numbers))
        if gaps:
            sequence_gaps.append(
                {
                    "source": source,
                    "first": numbers[0],
                    "last": numbers[-1],
                    "present": len(numbers),
                    "expected": len(expected),
                    "missing": gaps[:40],
                    "missing_count": len(gaps),
                }
            )

    # --- flujos imposibles y duplicados --------------------------------------
    self_flows = [
        {
            "event_id": e["event_id"],
            "source": e["source_type"],
            "ts": e["iso_utc"],
            "ip": e["src_ip"],
        }
        for e in events
        if e["source_type"] in {"netflow", "firewall"} and e["src_ip"] and e["src_ip"] == e["dst_ip"]
    ]

    seen_keys: dict[tuple, str] = {}
    duplicates: list[dict[str, Any]] = []
    for event in events:
        key = (event["ts_epoch"], event["source_type"], event["event_type"], event["src_ip"], event["dst_ip"], event["detail"])
        if key in seen_keys:
            duplicates.append({"event_id": event["event_id"], "duplicate_of": seen_keys[key]})
        else:
            seen_keys[key] = event["event_id"]

    # --- activos sin propietario ----------------------------------------------
    host_ips: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event["host"] and event["src_ip"] and event["source_type"] in {"antivirus", "system"}:
            host_ips[event["host"]].add(event["src_ip"])
    ip_to_host: dict[str, str] = {}
    for host, ips in host_ips.items():
        for ip in ips:
            ip_to_host[ip] = host

    orphan_ips: set[str] = set()
    for event in events:
        for ip in (event["src_ip"], event["dst_ip"]):
            if not ip or not IP_RE.fullmatch(ip):
                continue
            if ip.startswith("10.") or ip.startswith("192.168."):
                if ip not in ip_to_host:
                    orphan_ips.add(ip)
    referenced_hosts = {e["host"] for e in events if e["host"]}
    orphan_hosts = sorted(
        {e["host"] for e in events if e["host"] and e["source_type"] == "authentication"} - referenced_hosts
    )

    # --- detecciones sin atribucion -------------------------------------------
    unattributed = [
        {
            "event_id": e["event_id"],
            "source": e["source_type"],
            "ts": e["iso_utc"],
            "severity": e["severity"],
            "detail": e["detail"],
        }
        for e in events
        if e["source_type"] == "antivirus"
        and e["severity"] in {"HIGH", "CRITICAL"}
        and not e["actor"]
    ]

    # --- cuentas compartidas entre hosts ---------------------------------------
    user_ips: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event["source_type"] == "authentication" and event["actor"] and event["src_ip"]:
            user_ips[event["actor"]].add(event["src_ip"])
    ip_users: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event["source_type"] == "authentication" and event["actor"] and event["src_ip"]:
            ip_users[event["src_ip"]].add(event["actor"])
    shared_ips = [
        {"ip": ip, "users": sorted(users)} for ip, users in ip_users.items() if len(users) > 1
    ]

    findings = {
        "siem_correlation": {
            "alerts": len(alerts),
            "unresolved_placeholders": unresolved,
            "unresolved_count": len(unresolved),
            "missing_references": missing,
            "missing_count": len(missing),
            "benign_citations": benign_citations,
            "benign_citation_count": len(benign_citations),
            "valid_citations": valid_citations,
        },
        "tactic_technique": {
            "mismatches": tactic_mismatches,
            "mismatch_count": len(tactic_mismatches),
            "spraying_candidates": spray_candidates,
        },
        "sequence_gaps": sequence_gaps,
        "self_flows": self_flows,
        "duplicates": duplicates,
        "asset_inventory": {
            "orphan_internal_ips": sorted(orphan_ips),
            "orphan_hosts": orphan_hosts,
        },
        "unattributed_detections": unattributed,
        "shared_source_ips": shared_ips,
    }

    findings["summary"] = {
        "integrity_issues": (
            len(unresolved)
            + len(missing)
            + len(benign_citations)
            + len(tactic_mismatches)
            + len(sequence_gaps)
            + len(self_flows)
            + len(duplicates)
            + len(orphan_ips)
            + len(unattributed)
            + len(shared_ips)
        ),
        "severity": "HIGH"
        if (unresolved or missing or benign_citations or tactic_mismatches)
        else "INFO",
    }
    return findings
