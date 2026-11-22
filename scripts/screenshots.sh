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
  # Por defecto se captura SIEMPRE el analisis de demostracion: las capturas
  # del README son publicas y no deben contener datos de un caso real.
  AID=$(python3 - "$ROOT" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]) / "workspaces"
candidatos = []
for directorio in sorted(root.iterdir(), reverse=True):
    meta = directorio / "analysis.json"
    if not meta.exists():
        continue
    try:
        datos = json.loads(meta.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        continue
    if datos.get("name", "").lower().startswith("demo"):
        candidatos.append(directorio.name)
print(candidatos[0] if candidatos else "")
PY
)
  if [ -z "$AID" ]; then
    echo "No hay ningun analisis de demostracion (nombre iniciado por 'Demo')." >&2
    echo "Genera el dataset de demo y subelo, o pasa el id como argumento:" >&2
    echo "  python scripts/demo_dataset.py --output /tmp/demo_logs" >&2
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
