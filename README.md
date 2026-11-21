# LogScope

**Analisis forense de logs de seguridad asistido por opencode.**

Sube tus logs (CSV de autenticacion, firewall, netflow, antivirus/EDR, SIEM o
cualquier otro formato tabular), deja que el agente `log-analyst` de opencode
reconstruya el incidente y exporta el informe en Markdown, PDF o CSV.

No es un clon de DefenSight-AI: aquel proyecto delega el analisis en una API
de LLM con RAG vectorial (ChromaDB + sentence-transformers + torch, ~2.5 GB de
dependencias). LogScope usa **opencode** como motor y sustituye el RAG por
herramientas deterministas, que para logs con identificadores de evento son
mas precisas que la similitud semantica.

---

## Como funciona

```
 1. INGERIR          2. MEDIR               3. ANALIZAR              4. ENTREGAR
 ------------        --------------        ----------------------     ------------
 fingerprint     ->  metricas + audit  ->  agente log-analyst   ->  Markdown
 del CSV             deterministas        (opencode, streaming)      PDF
                      en Python                                          CSV
```

La division de trabajo es deliberada: **la aritmetica la hace Python y el
juicio lo hace el modelo**. El agente no estima un MTTD ni resuelve una
referencia SIEM "a ojo"; recibe `metrics.json` e `integrity.json` ya
calculados, y su trabajo es reconstruir la cadena de ataque, mapear ATT&CK
sustentado en evidencia, auditar las reglas de deteccion y priorizar
hallazgos.

---

## Requisitos

| Componente | Version |
|---|---|
| Python | 3.11+ |
| [opencode](https://opencode.ai) | 1.19+ (CLI en el PATH o `LOGSCOPE_OPENCODE_BIN`) |
| Proveedor de modelos | `opencode-go` (configurable) |

LogScope **gestiona su propio servidor headless de opencode** (`opencode
serve`), asi que no hay que arrancar nada a mano.

## Instalacion

```bash
git clone <tu-repo> logscope && cd logscope

uv venv .venv --python 3.13
uv pip install --python .venv/bin/python -e ".[dev]"

cp .env.example .env        # ajusta lo que necesites
./scripts/run.sh            # http://127.0.0.1:8000
```

Con pip clasico:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m uvicorn server.main:app --port 8000
```

## Configuracion

Todo se ajusta por variables de entorno (`.env`, que **nunca** se versiona).

| Variable | Por defecto | Descripcion |
|---|---|---|
| `LOGSCOPE_HOST` / `LOGSCOPE_PORT` | `127.0.0.1` / `8000` | Direccion del dashboard |
| `LOGSCOPE_OPENCODE_BIN` | `opencode` | Ruta al ejecutable de opencode |
| `LOGSCOPE_OPENCODE_PORT` | `4099` | Puerto del servidor headless de opencode |
| `LOGSCOPE_PROVIDER` | `opencode-go` | Unico proveedor admitido |
| `LOGSCOPE_MODEL` | `opencode-go/gpt-6-luna` | Modelo por defecto del analisis |
| `LOGSCOPE_SMALL_MODEL` | `opencode-go/hy4-flash-free` | Modelo auxiliar (titulos, compaction) |
| `LOGSCOPE_AGENT` | `log-analyst` | Agente de opencode que ejecuta el analisis |
| `LOGSCOPE_FALLBACK_MODELS` | `deepseek-v4.1-flash,beam-free` | Cadena de reserva |
| `LOGSCOPE_WORKSPACES` | `workspaces` | Directorio de espacios de trabajo |
| `LOGSCOPE_MAX_UPLOAD_MB` | `64` | Limite por fichero |

## Ciclo de vida de un analisis

```
subir logs ──> indexar (determinista) ──> medir (determinista) ──> analizar (opencode) ──> informe
              eventos, perfiles           MTTD, baseline,       hallazgos, ATT&CK,
                                         integridad            revision SIEM, IOCs
```

Las dos primeras etapas son Python puro y dan resultado **inmediato**: por eso
la pestana de eventos se llena en el momento (333 eventos en el caso EVA_02)
mientras que las de hallazgos, ATT&CK, reglas SIEM e IOCs **dependen del
agente de opencode** y aparecen cuando el informe se escribe y valida.

Detalles que importan en uso real:

- El informe se publica **en cuanto el agente escribe `report.json`** y este
  valida contra el esquema, sin esperar a que termine el turno. Si el agente
  lo reescribe con mejoras, se vuelve a publicar.
- Un turno que se queda colgado (una llamada a herramienta que no se
  resuelve) no bloquea el analisis para siempre: vence
  `LOGSCOPE_ANALYSIS_TIMEOUT` (900 s por defecto) y el informe ya publicado
  se conserva.
- Si la aplicacion se reinicia con un analisis a medias, al arrancar
  **reconcilia** los workspaces: los que tienen un informe valido pasan a
  estado `done`.
- La UI muestra un banner con el estado: sin informe / en curso / informe ya
  disponible con el agente afinando / error.

## Seleccion de modelo

opencode-go rota sus proveedores cada mes, asi que **nada esta codificado a
mano**: el catalogo se lee del propio servidor (`GET /provider`) en cada
peticion y se filtra al proveedor configurado, descartando los modelos sin
soporte de *tool calling* (el servidor de opencode no lo valida y un modelo
sin herramientas rompe al agente).

La UI ofrece tres mecanismos complementarios:

1. **Dropdown dinamico** (analisis y chat), agrupado por tier de coste, con
   coste y ventana de contexto visibles.
2. **Presets**: alias estables (`gratis`, `estandar`, `forense`) que apuntan a
   un modelo concreto. Si el modelo desaparece, reasignas el alias y no hay que
   tocar nada mas. Editables en `/settings`.
3. **Fallback automatico**: si el modelo principal devuelve error
   (`HTTP 500 UnknownError`, tipico de un modelo retirado), se reintenta con el
   siguiente de la cadena y **queda constancia en el informe**.

Jerarquia de precedencia: `UI > variable de entorno > preset > default`.

## El agente

- `.opencode/agent/log-analyst.md`: agente con permisos acotados (lectura,
  edicion dentro del workspace y bash; `webfetch`/`websearch` denegados para
  que no divague) y una lista de verificacion antes de entregar.
- `.opencode/skill/log-forensics/SKILL.md`: metodologia (baseline antes que
  anomalia, cadena por fases, auditoria del propio SIEM, severidad, redaccion
  de vacios de telemetria) y el esquema exacto del informe.

La salida del agente (`report.json`) se valida con Pydantic. Si no valida, el
backend reenvia el mensaje al agente con los errores de validacion para que
lo corrija. El informe solo se publica cuando la estructura es correcta.

## API

| Metodo | Ruta | Descripcion |
|---|---|---|
| `GET` | `/api/health` | Estado de la app y del motor opencode |
| `GET` | `/api/models` | Catalogo vivo de modelos + presets |
| `POST` | `/api/presets` | Guarda los presets |
| `POST` | `/api/upload` | Sube ficheros, normaliza y crea el analisis |
| `GET` | `/api/analysis/{id}` | Metricas, integridad, informe y estado |
| `GET` | `/api/analysis/{id}/events` | Eventos filtrados (fuente, severidad, texto, horario) |
| `GET` | `/api/analysis/{id}/timeline` | Histogramas temporal y por hora |
| `POST` | `/api/analysis/{id}/analyze` | Lanza el analisis |
| `GET` | `/api/analysis/{id}/stream` | SSE con el progreso en vivo |
| `POST` | `/api/analysis/{id}/chat` | Preguntas de seguimiento (SSE) |
| `GET` | `/api/analysis/{id}/export/{md,pdf,findings.csv,events.csv}` | Exportaciones |

Documentacion interactiva en `/docs` (OpenAPI automatico).

## Estructura

```
server/      main.py (FastAPI), oc_client.py, oc_manager.py, schemas.py, config.py
ingest/      detect.py (fingerprint), profiles.py (7 perfiles), normalize.py
analysis/    metrics.py (MTTD, baseline, dwell), integrity.py (calidad y correlacion)
models/      catalog.py (catalogo de modelos y presets)
exporter/    Markdown, PDF (reportlab) y CSV
.opencode/   agent/log-analyst.md y skill/log-forensics/SKILL.md
templates/   base, index, analysis, settings, report
static/      css/theme.css (tema oscuro propio) y js/
scripts/     run.sh, restart.sh, seed_demo.py
tests/       pytest
```

## Formatos de log reconocidos

Se detectan por la **cabecera**, no por el nombre del fichero, asi que
funciona con logs de cualquier proveedor:

| Tipo | Columnas que lo identifican |
|---|---|
| Autenticacion | `event_id, timestamp, username, source_ip, event_type, result` |
| Firewall | `event_id, timestamp, src_ip, dst_ip, dst_port, action, rule_name` |
| Netflow | `flow_id, start_time, src_ip, dst_ip, dst_port, bytes, direction` |
| Antivirus / EDR | `event_id, timestamp, threat_name, detection_status, action_taken` |
| Alertas SIEM | `alert_id, timestamp, tactic, technique_id, severity` |
| Sistema / Auditoria | `event_id, timestamp, hostname, log_source, event_type, message` |
| Generico | cualquiera: infiere los campos por similitud de nombres |

## Metricas deterministas

Las cifras que el informe cita salen de `analysis/metrics.json`, calculadas en
Python sin intervencion del modelo:

| Metrica | Como se obtiene |
|---|---|
| MTTD | Para cada alerta SIEM, la senal tecnica mas reciente dentro de una ventana de 1 h; se reporta mediana, maximo y detalle por alerta |
| Permanencia (dwell) | Primer indicio (`signals`) hasta el ultimo evento de contencion |
| Baseline de volumen | Mediana y desviacion absoluta mediana (MAD). **El p95 no se usa como umbral**: un outlier infla el percentil y deja de detectarse. Umbral = `mediana + 8 x 1.4826 x MAD` |
| Actividad nocturna | Ratio de eventos entre 00:00 y 06:59 por fuente |
| Integridad | Referencias SIEM sin resolver, citas a eventos benignos, referencias inexistentes, incoherencias tactica/tecnica, flujos con origen = destino, activos sin inventario, detecciones sin atribucion |

## Desarrollo

```bash
.venv/bin/pytest              # tests
.venv/bin/ruff check .        # lint
./scripts/restart.sh           # reinicio limpio (app + opencode)
```

Para cargar un conjunto de logs de ejemplo ya indexado (sin ejecutar el
analisis):

```bash
.venv/bin/python scripts/seed_demo.py /ruta/a/logs "Nombre del caso"
```

## Notas de implementacion

Detalles del contrato de opencode (1.x) que la aplicacion respeta:

- La API **v1** no lleva prefijo `/api`: `POST /session`, `POST
  /session/{id}/message`, `GET /event`. La documentacion publicada en
  opencode.ai/docs describe la v2, que no coincide.
- `POST /session` toma `directory` en el **query string**, no en el cuerpo.
- `GET /event` exige `?directory=<dir>` o no llegan los eventos de la sesion.
- El modelo viaja **por mensaje**, asi que puede cambiarse entre mensajes del
  chat sin relanzar el analisis.
- Cualquier ruta desconocida devuelve `200` con el HTML de la web de
  opencode: el cliente valida el `content-type`, no solo el codigo.
- Un modelo inexistente produce `HTTP 500` con `{"name":"UnknownError"}`: es la
  senal que dispara el fallback.

## Licencia

MIT. Ver [LICENSE](LICENSE).
