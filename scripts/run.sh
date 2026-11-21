#!/usr/bin/env bash
# Arranca LogScope.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "No existe el venv. Crea uno con:" >&2
  echo "  uv venv .venv --python 3.13 && uv pip install --python .venv/bin/python -e '.[dev]'" >&2
  exit 1
fi

exec "$ROOT/.venv/bin/python" -m uvicorn server.main:app \
  --host "${LOGSCOPE_HOST:-127.0.0.1}" \
  --port "${LOGSCOPE_PORT:-8000}" \
  --reload
