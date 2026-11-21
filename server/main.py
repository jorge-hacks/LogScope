"""LogScope - dashboard de analisis forense de logs asistido por opencode.

Rutas web (HTML con Jinja2) y API JSON. El analisis se ejecuta en un
servidor headless de opencode y se emite en vivo por SSE.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import hashlib
import io
import json
import shutil
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from analysis import audit_integrity, compute_metrics, hour_histogram, timeline_histogram
from exporter import export_findings_csv, export_pdf, export_report_markdown
from ingest import ingest_paths, write_events
from models import build_catalog
from server.config import Preset, settings
from server.oc_client import ModelUnavailable, OpencodeClient, OpencodeError
from server.oc_manager import manager
from server.schemas import Report

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


def _asset_version() -> str:
    """Huella corta del contenido de static/, para invalidar la cache.

    Sin esto, el navegador puede seguir sirviendo un JS viejo (por ejemplo
    tras corregir un bug) y la interfaz queda a medio actualizar sin que
    haya ningun error visible en consola.
    """
    digest = hashlib.sha1()
    for path in sorted(STATIC_DIR.rglob("*")):
        if path.is_file():
            stat = path.stat()
            digest.update(f"{path.relative_to(STATIC_DIR)}:{stat.st_size}:{int(stat.st_mtime)}".encode())
    return digest.hexdigest()[:10]


ASSET_VERSION = _asset_version()


class NoCacheStaticFiles(StaticFiles):
    """Sirve los estaticos indicando siempre que se revaliden."""

    def file_response(self, *args, **kwargs):  # type: ignore[override]
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Arranca y para el servidor headless de opencode junto a la aplicacion."""
    settings.workspaces_dir.mkdir(parents=True, exist_ok=True)
    try:
        await manager.ensure_running()
    except OpencodeError as exc:
        print(f"[logscope] opencode no disponible al arrancar: {exc}")
    yield
    await manager.stop()


app = FastAPI(
    title="LogScope",
    description="Analisis forense de logs de seguridad asistido por opencode",
    version="0.1.0",
    lifespan=lifespan,
)
app.mount("/static", NoCacheStaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["asset"] = lambda path: f"{path}?v={ASSET_VERSION}"


@app.middleware("http")
async def no_cache_html(request: Request, call_next):
    """Las paginas nunca se cachean: si no, el usuario puede ver HTML viejo
    que apunte a scripts que ya no existen."""
    response = await call_next(request)
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response


# ---------------------------------------------------------------------------
# Estado en memoria de las ejecuciones
# ---------------------------------------------------------------------------
@dataclass
class RunState:
    analysis_id: str
    status: str = "idle"  # idle | running | done | error
    model: str = ""
    session_id: str = ""
    error: str = ""
    notes: list[str] = field(default_factory=list)
    stream: list[dict[str, Any]] = field(default_factory=list)
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    task: asyncio.Task | None = None


RUNS: dict[str, RunState] = {}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def workspace_path(analysis_id: str) -> Path:
    return settings.workspaces_dir / analysis_id


def list_analyses() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if not settings.workspaces_dir.exists():
        return items
    for directory in sorted(settings.workspaces_dir.iterdir(), reverse=True):
        if not directory.is_dir() or directory.name.startswith("."):
            continue
        meta_path = directory / "analysis.json"
        meta: dict[str, Any] = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                meta = {}
        items.append(
            {
                "id": directory.name,
                "name": meta.get("name", directory.name),
                "created_at": meta.get("created_at", ""),
                "model": meta.get("model", ""),
                "events": meta.get("events", 0),
                "files": meta.get("files", 0),
                "status": meta.get("status", "pending"),
                "severity": meta.get("severity", "INFO"),
                "error": meta.get("error", ""),
            }
        )
    return items


def save_meta(analysis_id: str, meta: dict[str, Any]) -> None:
    path = workspace_path(analysis_id) / "analysis.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")


def load_meta(analysis_id: str) -> dict[str, Any]:
    path = workspace_path(analysis_id) / "analysis.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Analisis no encontrado")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Metadatos corruptos") from None


# ---------------------------------------------------------------------------
# Ciclo de vida: gestionado por el contexto `lifespan` definido arriba.
# ---------------------------------------------------------------------------
# Paginas
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "request": request,
            "analyses": list_analyses(),
            "presets": settings.load_presets(),
            "default_model": settings.model,
            "provider": settings.provider,
        },
    )


@app.get("/analysis/{analysis_id}", response_class=HTMLResponse)
async def analysis_page(request: Request, analysis_id: str) -> HTMLResponse:
    meta = load_meta(analysis_id)
    return templates.TemplateResponse(
        request,
        "analysis.html",
        {
            "request": request,
            "meta": meta,
            "analysis_id": analysis_id,
            "presets": settings.load_presets(),
            "default_model": settings.model,
        },
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "request": request,
            "presets": settings.load_presets(),
            "default_model": settings.model,
            "fallback_models": settings.fallback_models,
            "provider": settings.provider,
            "env_file_exists": (BASE_DIR / ".env").exists(),
        },
    )


# ---------------------------------------------------------------------------
# API - estado
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def api_health() -> dict[str, Any]:
    opencode_ok = False
    version = ""
    detail = ""
    try:
        async with OpencodeClient(settings.opencode_base_url, timeout=4.0) as client:
            health = await client.health()
        opencode_ok = bool(health.get("healthy"))
        version = str(health.get("version", ""))
    except OpencodeError as exc:
        detail = str(exc)
    return {
        "app": "ok",
        "opencode": {
            "healthy": opencode_ok,
            "version": version,
            "detail": detail,
            "managed": manager.running,
            "url": settings.opencode_base_url,
        },
        "provider": settings.provider,
        "default_model": settings.model,
    }


@app.get("/api/models")
async def api_models() -> dict[str, Any]:
    try:
        async with OpencodeClient(settings.opencode_base_url, timeout=15.0) as client:
            payload = await client.provider_payload()
    except OpencodeError as exc:
        raise HTTPException(status_code=503, detail=f"No se pudo leer el catalogo: {exc}") from exc
    return build_catalog(payload)


@app.post("/api/presets")
async def api_save_presets(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("presets") or []
    presets: list[Preset] = []
    for item in raw:
        label = str(item.get("label", "")).strip()
        model = str(item.get("model", "")).strip()
        if not label or not model:
            continue
        presets.append(Preset(label, model, str(item.get("description", "")).strip()))
    if not presets:
        raise HTTPException(status_code=400, detail="Se requiere al menos un preset valido")
    settings.save_presets(presets)
    return {"ok": True, "presets": [p.to_dict() for p in presets]}


# ---------------------------------------------------------------------------
# API - ingesta
# ---------------------------------------------------------------------------
@app.post("/api/upload")
async def api_upload(files: list[UploadFile] = File(...), name: str = Form("")) -> dict[str, Any]:
    if not files:
        raise HTTPException(status_code=400, detail="No se han enviado ficheros")

    analysis_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    root = workspace_path(analysis_id)
    raw_dir = root / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    saved: list[Path] = []
    for uploaded in files:
        filename = Path(uploaded.filename or "upload.csv").name
        target = raw_dir / filename
        content = await uploaded.read()
        if len(content) > settings.max_upload_mb * 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail=f"{filename} supera el limite de {settings.max_upload_mb} MB",
            )
        target.write_bytes(content)
        saved.append(target)

    result = ingest_paths(saved, root)
    if not result.events:
        shutil.rmtree(root, ignore_errors=True)
        raise HTTPException(
            status_code=400,
            detail="No se pudo interpretar ningun fichero: " + ("; ".join(result.errors) or "formato no reconocido"),
        )

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

    meta = {
        "id": analysis_id,
        "name": name.strip() or analysis_id,
        "created_at": _now(),
        "events": result.count,
        "files": len(result.files),
        "model": "",
        "status": "pending",
        "severity": "INFO",
        "sources": metrics.get("by_source", {}),
    }
    save_meta(analysis_id, meta)

    return {
        "ok": True,
        "analysis_id": analysis_id,
        "events": result.count,
        "files": result.files,
        "errors": result.errors,
    }


# ---------------------------------------------------------------------------
# API - consulta
# ---------------------------------------------------------------------------
@app.get("/api/analysis/{analysis_id}")
async def api_analysis(analysis_id: str) -> dict[str, Any]:
    root = workspace_path(analysis_id)
    if not root.exists():
        raise HTTPException(status_code=404, detail="Analisis no encontrado")

    def _read_json(relative: str) -> Any:
        path = root / relative
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    return {
        "meta": load_meta(analysis_id),
        "metrics": _read_json("analysis/metrics.json"),
        "integrity": _read_json("analysis/integrity.json"),
        "ingest": _read_json("analysis/ingest.json"),
        "report": _read_json("report/report.json"),
        "run": {
            "status": RUNS[analysis_id].status if analysis_id in RUNS else "idle",
            "model": RUNS[analysis_id].model if analysis_id in RUNS else "",
            "error": RUNS[analysis_id].error if analysis_id in RUNS else "",
            "notes": RUNS[analysis_id].notes if analysis_id in RUNS else [],
        },
    }


@app.get("/api/analysis/{analysis_id}/events")
async def api_events(
    analysis_id: str,
    source: str = "",
    severity: str = "",
    query: str = "",
    off_hours: bool = False,
    limit: int = 500,
    offset: int = 0,
) -> dict[str, Any]:
    from ingest import read_events

    events = read_events(workspace_path(analysis_id) / "normalized" / "events.jsonl")
    if source:
        events = [e for e in events if e["source_type"] == source]
    if severity:
        wanted = {s.strip().upper() for s in severity.split(",") if s.strip()}
        events = [e for e in events if e["severity"] in wanted]
    if off_hours:
        events = [e for e in events if 0 <= e["hour"] < 7]
    if query:
        needle = query.lower()
        events = [
            e
            for e in events
            if needle in json.dumps(e, ensure_ascii=False).lower()
        ]
    total = len(events)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "events": events[offset : offset + limit],
    }


@app.get("/api/analysis/{analysis_id}/timeline")
async def api_timeline(analysis_id: str) -> dict[str, Any]:
    from ingest import read_events

    events = read_events(workspace_path(analysis_id) / "normalized" / "events.jsonl")
    return {
        "timeline": timeline_histogram(events),
        "hours": hour_histogram(events),
    }


# ---------------------------------------------------------------------------
# API - ejecucion del analisis
# ---------------------------------------------------------------------------
def _digest(metrics: dict[str, Any], integrity: dict[str, Any]) -> str:
    detection = metrics.get("detection", {})
    dwell = metrics.get("dwell", {})
    baseline = metrics.get("volume_baseline", {})
    correlation = integrity.get("siem_correlation", {})
    tactic = integrity.get("tactic_technique", {})
    lines = [
        f"- Ventana analizada: {metrics.get('window', {}).get('start')} -> {metrics.get('window', {}).get('end')} "
        f"({metrics.get('window', {}).get('span_human')})",
        f"- Eventos totales: {metrics.get('events')}. Por fuente: {metrics.get('by_source')}",
        f"- Severidad: {metrics.get('by_severity')}",
        f"- Actividad fuera de horario (00:00-06:59): {metrics.get('off_hours', {}).get('total')} eventos "
        f"(ratio {metrics.get('off_hours', {}).get('ratio')})",
        f"- Baseline de volumen: p50={baseline.get('p50')} p95={baseline.get('p95')} "
        f"umbral de anomalia (mediana+MAD)={baseline.get('threshold')} max={baseline.get('max')} "
        f"muestra={baseline.get('samples')}",
        f"- Outliers de volumen (>{3}x p95): {len(metrics.get('volume_outliers', []))}",
        f"- Deteccion: {detection.get('alerts')} alertas, {detection.get('alerts_with_correlated_signal')} con senal "
        f"correlacionada, MTTD mediano {detection.get('mttd_median_human')}, max {detection.get('mttd_max_human')}",
        f"- Contencion: {metrics.get('containment', {}).get('iso', 'sin evento de contencion')} "
        f"({metrics.get('containment', {}).get('event_id', '-')})",
        f"- Tiempo de permanencia (dwell): {dwell.get('human', 'n/d')} desde {dwell.get('first_signal', 'n/d')}",
        "",
        "Integridad de la telemetria:",
        f"- Referencias de alerta sin resolver (placeholders): {correlation.get('unresolved_count')}",
        f"- Referencias a eventos inexistentes: {correlation.get('missing_count')}",
        f"- Referencias a eventos benignos: {correlation.get('benign_citation_count')}",
        f"- Incoherencias tactica/tecnica: {tactic.get('mismatch_count')}",
        f"- Flujos imposibles (src == dst): {len(integrity.get('self_flows', []))}",
        f"- IPs internas sin activo en inventario: {integrity.get('asset_inventory', {}).get('orphan_internal_ips')}",
        f"- Detecciones sin atribucion de usuario: "
        f"{[u['event_id'] for u in integrity.get('unattributed_detections', [])]}",
    ]
    return "\n".join(lines)


def _build_prompt(analysis_id: str, root: Path, metrics: dict[str, Any], integrity: dict[str, Any]) -> str:
    ingest = {}
    ingest_path = root / "analysis" / "ingest.json"
    if ingest_path.exists():
        ingest = json.loads(ingest_path.read_text(encoding="utf-8"))

    inventory = "\n".join(
        f"  - {f['file']} -> perfil '{f['profile']}' ({f['rows']} filas, deteccion: {f['matched_by']})"
        for f in ingest.get("files", [])
    )
    return f"""Analiza el workspace de logs `{analysis_id}` y produce el informe forense completo.

## Ficheros de entrada

- CSV originales: `{root}/raw/`
- Eventos normalizados: `{root}/normalized/events.jsonl`
- Metricas deterministas: `{root}/analysis/metrics.json`
- Auditoria de integridad: `{root}/analysis/integrity.json`

Ficheros detectados:
{inventory or "  (sin inventario)"}

## Valores ya calculados (no los recalcules, verificalos y citarlos)

{_digest(metrics, integrity)}

## Que debes hacer

1. Lee `analysis/metrics.json` y `analysis/integrity.json`.
2. Verifica con `grep`/`awk`/`python3` sobre `raw/` y `normalized/events.jsonl`
   cada afirmacion que vayas a escribir. Cita IDs de evento reales.
3. Reconstruye la cadena de ataque por fases y separa lo que la evidencia
   sostiene de lo que se supone.
4. Audita las reglas de deteccion del SIEM usando `analysis/integrity.json` y
   verificando en los CSV originales.
5. Evalua deteccion, respuesta y prevencion.
6. Documenta los huecos de telemetria y los problemas de calidad de datos.
7. Escribe `{root}/report/report.json` y `{root}/report/report.md`.

Aplica la skill `log-forensics` (normativa: esquema exacto, severidad,
redaccion). Tu respuesta final debe ser un resumen ejecutivo breve.
"""


async def _emit(state: RunState, kind: str, payload: dict[str, Any]) -> None:
    message = {"kind": kind, **payload}
    state.stream.append(message)
    await state.queue.put(message)


async def _consume_events(client: OpencodeClient, directory: str, state: RunState, session_id: str) -> None:
    """Traduce el SSE de opencode a eventos de progreso para el navegador.

    Solo se reenvian las partes de texto de los mensajes del asistente: el
    stream tambien incluye el prompt del usuario y los mensajes de otras
    sesiones del mismo directorio.
    """
    assistant_messages: set[str] = set()
    try:
        async for event in client.stream_events(directory):
            etype = event.get("type", "")
            props = event.get("properties", {}) or {}
            if props.get("sessionID") and props["sessionID"] != session_id:
                continue
            if etype == "message.updated":
                info = props.get("info", {}) or {}
                if info.get("role") == "assistant" and info.get("id"):
                    assistant_messages.add(info["id"])
                    await _emit(
                        state,
                        "status",
                        {
                            "text": f"opencode: {info.get('modelID', '')} "
                            f"tokens={info.get('tokens', {}).get('total', 0)}",
                        },
                    )
            elif etype == "message.part.updated":
                part = props.get("part", {}) or {}
                if part.get("type") != "text" or not part.get("text"):
                    continue
                if part.get("messageID") and part["messageID"] not in assistant_messages:
                    continue
                await _emit(state, "assistant", {"text": part["text"], "part": part.get("id", "")})
            elif etype == "session.status":
                await _emit(state, "status", {"text": f"estado: {props.get('status', '')}"})
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        await _emit(state, "warning", {"text": f"stream cerrado: {exc}"})


async def _run_analysis(analysis_id: str, requested_model: str, agent: str) -> None:
    state = RUNS[analysis_id]
    state.status = "running"
    state.error = ""
    state.notes = []
    state.stream = []
    root = workspace_path(analysis_id)

    metrics = json.loads((root / "analysis" / "metrics.json").read_text(encoding="utf-8"))
    integrity = json.loads((root / "analysis" / "integrity.json").read_text(encoding="utf-8"))

    catalog: dict[str, Any] = {}
    chain = [requested_model] + [m for m in settings.fallback_models if m != requested_model]

    try:
        async with OpencodeClient(settings.opencode_base_url, timeout=60.0) as client:
            await manager.ensure_running()
            catalog = build_catalog(await client.provider_payload())

            available = {m["full_id"] for m in catalog.get("models", [])}
            chosen = next((m for m in chain if m in available), None)
            if chosen is None:
                chosen = requested_model
                await _emit(
                    state,
                    "warning",
                    {"text": f"El modelo {requested_model} no figura en el catalogo de {settings.provider}."},
                )
            if chosen != requested_model:
                await _emit(
                    state,
                    "warning",
                    {"text": f"Modelo inicial no disponible; se usa {chosen}."},
                )

            state.model = chosen
            await _emit(state, "status", {"text": f"Abriendo sesion de opencode en {root}..."})
            session_id = await client.create_session(str(root), f"LogScope {analysis_id}")
            state.session_id = session_id
            await _emit(state, "status", {"text": f"Sesion {session_id} | modelo {chosen}"})

            consumer = asyncio.create_task(_consume_events(client, str(root), state, session_id))
            try:
                prompt = _build_prompt(analysis_id, root, metrics, integrity)
                await _emit(state, "status", {"text": "Enviando peticion de analisis..."})
                await client.send_message(session_id, prompt, model=chosen, agent=agent)
            finally:
                consumer.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await consumer

            # --- validacion del informe -------------------------------------
            report_path = root / "report" / "report.json"
            for attempt in range(2):
                if not report_path.exists():
                    if attempt == 0:
                        await _emit(state, "warning", {"text": "El agente no genero report.json; se le repregunta."})
                        await client.send_message(
                            session_id,
                            "No se encontro report.json en el workspace. Escribelo ahora respetando el "
                            "esquema exacto de la skill log-forensics.",
                            model=chosen,
                            agent=agent,
                        )
                        continue
                    raise OpencodeError("El agente no genero report.json")

                raw = json.loads(report_path.read_text(encoding="utf-8"))
                try:
                    report = Report.model_validate(raw)
                except ValidationError as exc:
                    if attempt == 0:
                        problems = "; ".join(
                            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()[:12]
                        )
                        await _emit(state, "warning", {"text": f"report.json no valida: {problems[:600]}"})
                        await client.send_message(
                            session_id,
                            f"report.json no valida contra el esquema. Corrige estos errores y reescribe el "
                            f"fichero: {problems}",
                            model=chosen,
                            agent=agent,
                        )
                        continue
                    raise OpencodeError(f"report.json sigue sin validar: {problems}") from exc

                (root / "report" / "report.json").write_text(
                    json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
                )
                state.status = "done"
                await _emit(
                    state,
                    "done",
                    {
                        "text": f"Informe validado: {len(report.findings)} hallazgos, "
                        f"{len(report.attack_chain)} fases, {len(report.iocs)} IOCs",
                        "severity": report.severity_overall,
                    },
                )
                break

            meta = load_meta(analysis_id)
            meta.update(
                {
                    "status": "done",
                    "model": chosen,
                    "session_id": session_id,
                    "severity": report.severity_overall,
                    "findings": len(report.findings),
                    "phases": len(report.attack_chain),
                }
            )
            save_meta(analysis_id, meta)

    except ModelUnavailable as exc:
        state.status = "error"
        state.error = str(exc)
        await _emit(state, "error", {"text": str(exc)})
    except OpencodeError as exc:
        state.status = "error"
        state.error = str(exc)
        await _emit(state, "error", {"text": str(exc)})
    except Exception as exc:  # noqa: BLE001
        state.status = "error"
        state.error = f"{type(exc).__name__}: {exc}"
        await _emit(state, "error", {"text": state.error})
    finally:
        await state.queue.put(None)


@app.post("/api/analysis/{analysis_id}/analyze")
async def api_analyze(analysis_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    root = workspace_path(analysis_id)
    if not root.exists():
        raise HTTPException(status_code=404, detail="Analisis no encontrado")

    requested = settings.resolve_model(payload.get("model"))
    agent = str(payload.get("agent") or settings.agent)

    state = RUNS.get(analysis_id)
    if state is None:
        state = RunState(analysis_id=analysis_id)
        RUNS[analysis_id] = state
    if state.task and not state.task.done():
        return {"ok": False, "message": "Ya hay un analisis en curso", "status": state.status}

    state.queue = asyncio.Queue()
    state.task = asyncio.create_task(_run_analysis(analysis_id, requested, agent))
    return {"ok": True, "analysis_id": analysis_id, "model": requested, "agent": agent}


@app.get("/api/analysis/{analysis_id}/stream")
async def api_stream(analysis_id: str) -> StreamingResponse:
    state = RUNS.get(analysis_id)
    if state is None:
        state = RunState(analysis_id=analysis_id)
        RUNS[analysis_id] = state

    async def generator():
        while True:
            try:
                message = await asyncio.wait_for(state.queue.get(), timeout=20.0)
            except TimeoutError:
                yield ": keepalive\n\n"
                continue
            if message is None:
                yield f"event: done\ndata: {json.dumps({'status': state.status})}\n\n"
                break
            yield f"event: {message.get('kind', 'message')}\ndata: {json.dumps(message, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


# ---------------------------------------------------------------------------
# API - chat contextual
# ---------------------------------------------------------------------------
@app.post("/api/analysis/{analysis_id}/chat")
async def api_chat(analysis_id: str, payload: dict[str, Any]) -> StreamingResponse:
    root = workspace_path(analysis_id)
    if not root.exists():
        raise HTTPException(status_code=404, detail="Analisis no encontrado")

    message = str(payload.get("message", "")).strip()
    if not message:
        raise HTTPException(status_code=400, detail="Mensaje vacio")
    requested = settings.resolve_model(payload.get("model"))

    async def generator():
        try:
            async with OpencodeClient(settings.opencode_base_url, timeout=60.0) as client:
                await manager.ensure_running()
                session_id = payload.get("session_id") or await client.create_session(
                    str(root), f"LogScope chat {analysis_id}"
                )
                context = (
                    f"Contexto del analisis en {root}. "
                    f"El informe esta en {root}/report/report.json y las metricas en "
                    f"{root}/analysis/metrics.json. Responde en espanol, citando IDs de evento. "
                    f"Pregunta: {message}"
                )
                queue: asyncio.Queue = asyncio.Queue()
                assistant_messages: set[str] = set()
                parts: dict[str, str] = {}

                async def pump() -> None:
                    async for event in client.stream_events(str(root)):
                        props = event.get("properties", {}) or {}
                        if props.get("sessionID") and props["sessionID"] != session_id:
                            continue
                        etype = event.get("type", "")
                        if etype == "message.updated":
                            info = props.get("info", {}) or {}
                            if info.get("role") == "assistant" and info.get("id"):
                                assistant_messages.add(info["id"])
                        elif etype == "message.part.updated":
                            part = props.get("part", {}) or {}
                            if part.get("type") != "text" or not part.get("text"):
                                continue
                            if part.get("messageID") and part["messageID"] not in assistant_messages:
                                continue
                            parts[part.get("id", str(len(parts)))] = part["text"]
                            await queue.put({"kind": "assistant", "text": "\n\n".join(parts.values())})

                pump_task = asyncio.create_task(pump())

                async def run() -> None:
                    await client.send_message(session_id, context, model=requested, agent=settings.agent)

                message_task = asyncio.create_task(run())
                try:
                    while True:
                        getter = asyncio.create_task(queue.get())
                        finished, _ = await asyncio.wait(
                            {getter, message_task}, return_when=asyncio.FIRST_COMPLETED
                        )
                        if getter in finished:
                            payload_event = getter.result()
                            yield (
                                f"event: {payload_event.get('kind', 'message')}\n"
                                f"data: {json.dumps(payload_event, ensure_ascii=False)}\n\n"
                            )
                            continue
                        getter.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await getter
                        # Vuelca lo que quedara en la cola antes de cerrar.
                        while not queue.empty():
                            payload_event = queue.get_nowait()
                            yield (
                                f"event: {payload_event.get('kind', 'message')}\n"
                                f"data: {json.dumps(payload_event, ensure_ascii=False)}\n\n"
                            )
                        break
                finally:
                    pump_task.cancel()
                    message_task.cancel()
                    for task in (pump_task, message_task):
                        with contextlib.suppress(asyncio.CancelledError, Exception):
                            await task
                yield f"event: done\ndata: {json.dumps({'session_id': session_id})}\n\n"
        except (OpencodeError, ModelUnavailable) as exc:
            yield f"event: error\ndata: {json.dumps({'error': str(exc)})}\n\n"

    return StreamingResponse(generator(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


# ---------------------------------------------------------------------------
# Exportacion
# ---------------------------------------------------------------------------
@app.get("/api/analysis/{analysis_id}/export/{fmt}")
async def api_export(analysis_id: str, fmt: str):
    root = workspace_path(analysis_id)
    report_path = root / "report" / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Todavia no hay informe")
    report = json.loads(report_path.read_text(encoding="utf-8"))

    if fmt == "md":
        content = export_report_markdown(report, root)
        return PlainTextResponse(
            content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{analysis_id}-informe.md"'},
        )
    if fmt == "pdf":
        pdf_bytes = export_pdf(report, root)
        return Response(
            pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{analysis_id}-informe.pdf"'},
        )
    if fmt == "findings.csv":
        content = export_findings_csv(report)
        return PlainTextResponse(
            content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{analysis_id}-hallazgos.csv"'},
        )
    if fmt == "events.csv":
        from ingest import read_events

        events = read_events(root / "normalized" / "events.jsonl")
        buffer = io.StringIO()
        if events:
            writer = csv.DictWriter(buffer, fieldnames=list(events[0].keys()))
            writer.writeheader()
            for event in events:
                writer.writerow({k: v for k, v in event.items() if k != "raw"})
        return PlainTextResponse(
            buffer.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{analysis_id}-eventos.csv"'},
        )
    raise HTTPException(status_code=404, detail=f"Formato desconocido: {fmt}")


@app.get("/analysis/{analysis_id}/report")
async def analysis_report_page(request: Request, analysis_id: str) -> HTMLResponse:
    root = workspace_path(analysis_id)
    report_path = root / "report" / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else None
    md_path = root / "report" / "report.md"
    markdown_text = md_path.read_text(encoding="utf-8") if md_path.exists() else ""
    return templates.TemplateResponse(
        request,
        "report.html",
        {"request": request, "report": report, "markdown_text": markdown_text, "analysis_id": analysis_id},
    )


def run() -> None:  # pragma: no cover - punto de entrada del script
    import uvicorn

    uvicorn.run("server.main:app", host=settings.host, port=settings.port, log_level=settings.log_level.lower())


if __name__ == "__main__":  # pragma: no cover
    run()
