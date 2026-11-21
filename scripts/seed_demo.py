#!/usr/bin/env python
"""Carga un conjunto de logs de ejemplo como analisis pre-indexado.

Uso:
    python scripts/seed_demo.py /ruta/a/logs [nombre]

Los ficheros se copian a un workspace nuevo y se ejecuta la ingesta y el
pre-analisis, pero NO el analisis con opencode (eso se lanza desde la UI).
"""

from __future__ import annotations

import json
import shutil
import sys
import uuid
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analysis import audit_integrity, compute_metrics  # noqa: E402
from ingest import ingest_paths, write_events  # noqa: E402
from server.config import settings  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    source = Path(sys.argv[1]).expanduser().resolve()
    name = sys.argv[2] if len(sys.argv) > 2 else f"Ejemplo {source.name}"

    files = [p for p in sorted(source.rglob("*")) if p.is_file() and p.suffix.lower() in {".csv", ".json", ".log", ".txt"}]
    if not files:
        print(f"No hay ficheros de log en {source}", file=sys.stderr)
        return 1

    analysis_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    root = settings.workspaces_dir / analysis_id
    raw_dir = root / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    copied = []
    for path in files:
        target = raw_dir / path.name
        shutil.copy2(path, target)
        copied.append(target)

    result = ingest_paths(copied, root)
    if not result.events:
        print("No se pudo interpretar ningun fichero", file=sys.stderr)
        return 1

    write_events(result.events, root / "normalized" / "events.jsonl")
    metrics = compute_metrics(result.events)
    integrity = audit_integrity(result.events)
    (root / "analysis").mkdir(parents=True, exist_ok=True)
    (root / "analysis" / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    (root / "analysis" / "integrity.json").write_text(
        json.dumps(integrity, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    (root / "analysis" / "ingest.json").write_text(
        json.dumps({"files": result.files, "errors": result.errors}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    (root / "analysis.json").write_text(
        json.dumps(
            {
                "id": analysis_id,
                "name": name,
                "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "events": result.count,
                "files": len(result.files),
                "model": "",
                "status": "pending",
                "severity": "INFO",
                "sources": metrics.get("by_source", {}),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(f"Analisis {analysis_id} listo con {result.count} eventos.")
    print(f"  workspace: {root}")
    print(f"  abre:      http://{settings.host}:{settings.port}/analysis/{analysis_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
