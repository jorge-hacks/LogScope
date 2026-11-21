"""Perfiles de formato de log.

Cada perfil describe como mapear las columnas de un CSV concreto al esquema
unificado de LogScope. La deteccion por fingerprint (ver `detect.py`) elige
el perfil; si ninguno encaja se usa el perfil generico, que infiere los
campos a partir de los nombres de columna.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Profile:
    """Mapeo de columnas de un tipo de log al esquema unificado."""

    name: str
    label: str
    required: frozenset[str]
    id_column: str | None = None
    timestamp_column: str | None = None
    severity_column: str | None = None
    severity_map: dict[str, str] = field(default_factory=dict)
    event_type_column: str | None = None
    actor_column: str | None = None
    host_column: str | None = None
    src_ip_column: str | None = None
    dst_ip_column: str | None = None
    dst_port_column: str | None = None
    action_column: str | None = None
    result_column: str | None = None
    detail_column: str | None = None
    bytes_out_column: str | None = None
    bytes_in_column: str | None = None

    def matches(self, columns: set[str]) -> bool:
        return self.required.issubset(columns)


# Escalado de severidad a los cinco niveles que usa el dashboard.
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_SEVERITY_ALIASES = {
    "": "INFO",
    "info": "INFO",
    "informational": "INFO",
    "debug": "INFO",
    "low": "LOW",
    "minor": "LOW",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "warning": "MEDIUM",
    "warn": "MEDIUM",
    "high": "HIGH",
    "error": "HIGH",
    "critical": "CRITICAL",
    "fatal": "CRITICAL",
    "severe": "CRITICAL",
}

PROFILES: list[Profile] = [
    Profile(
        name="authentication",
        label="Autenticacion",
        required=frozenset({"event_id", "timestamp", "username", "source_ip", "event_type", "result"}),
        id_column="event_id",
        timestamp_column="timestamp",
        event_type_column="event_type",
        actor_column="username",
        host_column="destination_host",
        src_ip_column="source_ip",
        dst_ip_column="destination_host",
        action_column="event_type",
        result_column="result",
        detail_column="details",
    ),
    Profile(
        name="firewall",
        label="Firewall",
        required=frozenset({"event_id", "timestamp", "src_ip", "dst_ip", "dst_port", "action", "rule_name"}),
        id_column="event_id",
        timestamp_column="timestamp",
        event_type_column="rule_name",
        actor_column="username",
        src_ip_column="src_ip",
        dst_ip_column="dst_ip",
        dst_port_column="dst_port",
        action_column="action",
        detail_column="application",
        bytes_out_column="bytes_sent",
        bytes_in_column="bytes_received",
    ),
    Profile(
        name="netflow",
        label="Netflow",
        required=frozenset({"flow_id", "start_time", "src_ip", "dst_ip", "dst_port", "bytes", "direction"}),
        id_column="flow_id",
        timestamp_column="start_time",
        event_type_column="application",
        src_ip_column="src_ip",
        dst_ip_column="dst_ip",
        dst_port_column="dst_port",
        detail_column="direction",
        bytes_out_column="bytes",
    ),
    Profile(
        name="antivirus",
        label="Antivirus / EDR",
        required=frozenset({"event_id", "timestamp", "threat_name", "detection_status", "action_taken"}),
        id_column="event_id",
        timestamp_column="timestamp",
        severity_column="severity",
        event_type_column="threat_name",
        actor_column="associated_user",
        host_column="hostname",
        src_ip_column="host_ip",
        action_column="action_taken",
        result_column="detection_status",
        detail_column="file_path_or_command",
    ),
    Profile(
        name="siem",
        label="Alertas SIEM",
        required=frozenset({"alert_id", "timestamp", "tactic", "technique_id", "severity"}),
        id_column="alert_id",
        timestamp_column="timestamp",
        severity_column="severity",
        event_type_column="technique_name",
        actor_column="username",
        host_column="destination_or_host",
        src_ip_column="source_ip",
        dst_ip_column="destination_or_host",
        detail_column="description",
    ),
    Profile(
        name="system",
        label="Sistema / Auditoria",
        required=frozenset({"event_id", "timestamp", "hostname", "log_source", "event_type", "message"}),
        id_column="event_id",
        timestamp_column="timestamp",
        severity_column="severity",
        event_type_column="event_type",
        actor_column="username",
        host_column="hostname",
        src_ip_column="host_ip",
        detail_column="message",
    ),
]

PROFILES_BY_NAME = {p.name: p for p in PROFILES}


def normalize_severity(value: Any) -> str:
    """Normaliza cualquier etiqueta de severidad a los cinco niveles internos."""
    if value is None:
        return "INFO"
    text = str(value).strip().lower()
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text]
    for alias, level in _SEVERITY_ALIASES.items():
        if alias and alias in text:
            return level
    return "INFO"


def severity_rank(value: str) -> int:
    try:
        return SEVERITY_ORDER.index(str(value).upper())
    except ValueError:
        return 0
