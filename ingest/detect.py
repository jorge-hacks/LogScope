"""Deteccion del tipo de log por fingerprint de cabecera.

No se depende del nombre del fichero: el perfil se elige por las columnas
que aparecen en la cabecera del CSV. Asi el dashboard funciona con logs de
cualquier proveedor, no solo con los de un ejercicio concreto.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .profiles import PROFILES, Profile


class DetectionError(ValueError):
    """El fichero no se puede interpretar como log tabular."""


def read_header(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    """Devuelve (columnas, filas) de un CSV. Tolera BOM UTF-8."""
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                raise DetectionError(f"{path.name}: el CSV no tiene cabecera")
            rows = [dict(row) for row in reader]
            return [f.strip() for f in reader.fieldnames], rows
    except UnicodeDecodeError as exc:
        raise DetectionError(f"{path.name}: no es texto UTF-8 valido") from exc
    except csv.Error as exc:
        raise DetectionError(f"{path.name}: CSV malformado ({exc})") from exc


def detect_profile(columns: list[str]) -> Profile:
    """Elige el perfil cuyo conjunto de columnas requeridas este contenido."""
    colset = {c.strip().lower() for c in columns}
    best: Profile | None = None
    for profile in PROFILES:
        if not profile.matches(colset):
            continue
        if best is None or len(profile.required) > len(best.required):
            best = profile
    if best is not None:
        return best
    return generic_profile(columns)


def generic_profile(columns: list[str]) -> Profile:
    """Perfil de reserva: infiere el mapeo por similitud de nombres de columna."""
    lowered = {c.strip().lower(): c.strip() for c in columns}

    def pick(*candidates: str) -> str | None:
        for candidate in candidates:
            if candidate in lowered:
                return lowered[candidate]
        return None

    return Profile(
        name="generic",
        label="Generico",
        required=frozenset(),
        id_column=pick("event_id", "id", "record_id", "uuid"),
        timestamp_column=pick(
            "timestamp", "time", "@timestamp", "start_time", "datetime", "date_time", "eventtime", "event_time"
        ),
        severity_column=pick("severity", "level", "priority", "risk"),
        event_type_column=pick("event_type", "type", "event", "action", "category", "alert_type"),
        actor_column=pick(
            "username", "user", "account", "src_user", "subject_user", "actor", "principal"
        ),
        host_column=pick("hostname", "host", "destination_host", "device", "computer", "server"),
        src_ip_column=pick("src_ip", "source_ip", "srcip", "client_ip", "origin_ip", "src"),
        dst_ip_column=pick("dst_ip", "destination_ip", "dest_ip", "dst", "target_ip", "server_ip"),
        dst_port_column=pick("dst_port", "dest_port", "destination_port", "dport"),
        action_column=pick("action", "action_taken", "operation", "disposition"),
        result_column=pick("result", "outcome", "status"),
        detail_column=pick(
            "message", "details", "detail", "description", "reason", "command", "file_path_or_command"
        ),
        bytes_out_column=pick("bytes_sent", "bytes_out", "bytes", "bytes_out_total"),
        bytes_in_column=pick("bytes_received", "bytes_in", "bytes_rcvd"),
    )


def detect_and_read(path: Path) -> tuple[Profile, list[dict[str, str]]]:
    """Lee un CSV y devuelve (perfil, filas)."""
    columns, rows = read_header(path)
    if not rows:
        raise DetectionError(f"{path.name}: el CSV no contiene filas")
    return detect_profile(columns), rows
