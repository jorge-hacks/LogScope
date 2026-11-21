#!/usr/bin/env bash
# Regenera las capturas de pantalla del README.
#
#   ./scripts/screenshots.sh [analysis_id]
#
# Usa chromium headless sobre la aplicacion en marcha. Si no se indica
# analysis_id, se usa el analisis mas reciente que tenga informe.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE="${LOGSCOPE_URL:-http://127.0.0.1:8000}"
OUT="$ROOT/docs/screenshots"
BROWSER="${CHROME_BIN:-chromium}"

command -v "$BROWSER" >/dev/null || { echo "No se encuentra chromium" >&2; exit 1; }

if [ $# -ge 1 ]; then
  AID="$1"
else
  AID=$(ls -t "$ROOT/workspaces" 2>/dev/null | head -1 || true)
  if [ -z "$AID" ] || [ ! -f "$ROOT/workspaces/$AID/report/report.json" ]; then
    echo "No hay ningun analisis con informe. Pasa el id como argumento." >&2
    exit 1
  fi
fi

mkdir -p "$OUT"

shot() { # url archivo tamaño
  "$BROWSER" --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
    --hide-scrollbars --window-size="$3" --virtual-time-budget=12000 \
    --screenshot="$OUT/$2" "$BASE$1" 2>/dev/null
  printf '  %-26s %s bytes\n' "$2" "$(stat -c%s "$OUT/$2")"
}

echo "Capturando desde $BASE (analisis $AID):"
shot "/"                              01-inicio.png        "1600,1000"
shot "/analysis/$AID"                 02-cronologia.png   "1600,1250"
shot "/analysis/$AID#findings"        03-hallazgos.png    "1600,1250"
shot "/analysis/$AID#attack"          04-attack.png       "1600,780"
shot "/analysis/$AID#siem"            05-reglas-siem.png  "1600,1000"
shot "/analysis/$AID#iocs"            06-iocs.png         "1600,700"
shot "/analysis/$AID#events"          07-eventos.png      "1600,1050"
shot "/analysis/$AID/report"          08-informe.png      "1600,1500"
shot "/settings"                      09-ajustes.png      "1600,820"

echo "Listo en $OUT"
