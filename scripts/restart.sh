#!/usr/bin/env bash
# Reinicia LogScope (app + servidor opencode gestionado) de forma segura.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SELF=$$
for pid in $(pgrep -f "uvicorn server.main:app" 2>/dev/null); do
  [ "$pid" = "$SELF" ] && continue
  kill "$pid" 2>/dev/null && echo "app detenida (PID $pid)"
done

for pid in $(pgrep -x opencode 2>/dev/null); do
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
  case "$cmd" in
    *"serve --port 4099"*) kill "$pid" 2>/dev/null && echo "opencode gestionado detenido (PID $pid)" ;;
  esac
done

sleep 2
mkdir -p logs
nohup "$ROOT/.venv/bin/python" -m uvicorn server.main:app \
  --host 127.0.0.1 --port "${LOGSCOPE_PORT:-8000}" \
  > logs/app.log 2>&1 &

for _ in $(seq 1 30); do
  sleep 1
  if curl -sf "http://127.0.0.1:${LOGSCOPE_PORT:-8000}/api/health" >/dev/null 2>&1; then
    echo "LogScope listo en http://127.0.0.1:${LOGSCOPE_PORT:-8000}"
    exit 0
  fi
done
echo "La app no respondio a tiempo; revisa logs/app.log" >&2
tail -20 logs/app.log >&2
exit 1
