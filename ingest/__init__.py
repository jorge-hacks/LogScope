"""Ingesta de logs: deteccion de formato y normalizacion a esquema unificado."""

from .detect import DetectionError, detect_and_read, detect_profile, read_header
from .normalize import (
    IngestResult,
    extract_zip,
    ingest_paths,
    normalize_row,
    parse_timestamp,
    read_events,
    write_events,
)
from .profiles import PROFILES, Profile, normalize_severity, severity_rank

__all__ = [
    "DetectionError",
    "IngestResult",
    "PROFILES",
    "Profile",
    "detect_and_read",
    "detect_profile",
    "extract_zip",
    "ingest_paths",
    "normalize_row",
    "normalize_severity",
    "parse_timestamp",
    "read_events",
    "read_header",
    "severity_rank",
    "write_events",
]
