"""Normalizacion de logs a un esquema unificado.

Cada evento normalizado es un dict plano con las mismas claves, sea cual sea
el origen. Se ordenan por timestamp (los CSV de origen no vienen ordenados
cronologicamente) y se serializan como JSON Lines.
"""

from __future__ import annotations

import ipaddress
import json
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .detect import DetectionError, detect_and_read
from .profiles import Profile, normalize_severity

SCHEMA_VERSION = 1

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M",
]


def parse_timestamp(value: Any) -> tuple[str, float]:
    """Devuelve (cadena original, epoch en segundos). Epoch = 0 si no parsea."""
    if value is None:
        return "", 0.0
    text = str(value).strip()
    if not text:
        return "", 0.0

    iso_candidate = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return text, dt.timestamp()
    except ValueError:
        pass

    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return text, dt.timestamp()
        except ValueError:
            continue
    return text, 0.0


def _to_int(value: Any) -> int:
    if value is None:
        return 0
    text = str(value).strip()
    if not text:
        return 0
    try:
        return int(float(text))
    except ValueError:
        return 0


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def is_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_private(value: str) -> bool:
    """True si la IP es privada/loopback/link-local (no expuesta a internet)."""
    if not is_ip(value):
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


@dataclass
class IngestResult:
    events: list[dict[str, Any]] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.events)


def _row_value(row: dict[str, str], column: str | None) -> str:
    if not column:
        return ""
    for key, value in row.items():
        if key and key.strip().lower() == column.strip().lower():
            return _clean(value)
    return ""


def normalize_row(
    row: dict[str, str], profile: Profile, source_file: str, index: int
) -> dict[str, Any] | None:
    """Convierte una fila cruda en un evento unificado."""
    raw_ts = _row_value(row, profile.timestamp_column)
    ts, epoch = parse_timestamp(raw_ts)

    event_id = _row_value(row, profile.id_column) or f"{profile.name.upper()}-{index:06d}"

    severity = (
        normalize_severity(_row_value(row, profile.severity_column))
        if profile.severity_column
        else "INFO"
    )

    src_ip = _row_value(row, profile.src_ip_column)
    dst_ip = _row_value(row, profile.dst_ip_column)
    host = _row_value(row, profile.host_column)

    # En logs de host, source_ip == IP del propio equipo.
    if profile.name in {"antivirus", "system"} and src_ip and not dst_ip:
        dst_ip = src_ip

    return {
        "ts": ts,
        "ts_epoch": epoch,
        "iso_utc": (
            datetime.fromtimestamp(epoch, tz=UTC).isoformat(timespec="seconds") if epoch else ""
        ),
        "hour": int(datetime.fromtimestamp(epoch, tz=UTC).hour) if epoch else -1,
        "source_file": source_file,
        "source_type": profile.name,
        "source_label": profile.label,
        "event_id": event_id,
        "severity": severity,
        "event_type": _row_value(row, profile.event_type_column),
        "actor": _row_value(row, profile.actor_column),
        "host": host,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": _to_int(_row_value(row, profile.dst_port_column)) or None,
        "action": _row_value(row, profile.action_column),
        "result": _row_value(row, profile.result_column),
        "detail": _row_value(row, profile.detail_column),
        "bytes_out": _to_int(_row_value(row, profile.bytes_out_column)),
        "bytes_in": _to_int(_row_value(row, profile.bytes_in_column)),
        "src_private": is_private(src_ip),
        "dst_private": is_private(dst_ip),
        "raw": {k: _clean(v) for k, v in row.items() if k},
    }


def extract_zip(zip_path: Path, dest: Path) -> list[Path]:
    """Extrae un ZIP de logs ignorando rutas con recorrido de directorios."""
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            name = member.filename
            if member.is_dir():
                continue
            if name.startswith("/") or ".." in Path(name).parts:
                continue
            if not name.lower().endswith((".csv", ".json", ".log", ".txt")):
                continue
            target = dest / Path(name).name
            with archive.open(member) as src, target.open("wb") as out:
                out.write(src.read())
            extracted.append(target)
    return extracted


def ingest_paths(paths: list[Path], workdir: Path) -> IngestResult:
    """Normaliza todos los ficheros indicados a un unico conjunto de eventos."""
    result = IngestResult()

    expanded: list[Path] = []
    for path in paths:
        if path.suffix.lower() == ".zip":
            expanded.extend(extract_zip(path, workdir / "raw" / "extracted"))
        else:
            expanded.append(path)

    for path in expanded:
        try:
            profile, rows = detect_and_read(path)
        except DetectionError as exc:
            result.errors.append(str(exc))
            continue

        converted = 0
        for index, row in enumerate(rows, start=1):
            event = normalize_row(row, profile, path.name, index)
            if event is None:
                continue
            result.events.append(event)
            converted += 1

        result.files.append(
            {
                "file": path.name,
                "profile": profile.name,
                "profile_label": profile.label,
                "rows": converted,
                "bytes": path.stat().st_size,
                "matched_by": "fingerprint" if profile.name != "generic" else "fallback",
            }
        )

    # Orden cronologico: el orden de los ficheros no es fiable.
    result.events.sort(key=lambda e: (e["ts_epoch"], e["source_file"], e["event_id"]))
    return result


def write_events(events: list[dict[str, Any]], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    return path


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
