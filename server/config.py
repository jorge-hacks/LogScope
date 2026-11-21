"""Configuracion central de LogScope.

Lee el .env (opcional) y expone los parametros que usa el resto de la
aplicacion. Todos los valores tienen un default sensato para que el
proyecto arranque sin .env.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env")


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _env_int(key: str, default: int) -> int:
    try:
        return int(_env(key) or default)
    except ValueError:
        return default


def _env_list(key: str, default: list[str] | None = None) -> list[str]:
    raw = _env(key)
    if not raw:
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class Preset:
    """Alias estable que apunta a un modelo concreto del proveedor."""

    label: str
    model: str
    description: str = ""

    def to_dict(self) -> dict:
        return {"label": self.label, "model": self.model, "description": self.description}


# Presets por defecto. Sobreviven a la rotacion mensual de opencode-go:
# si un modelo desaparece, se reasigna el alias y nada mas hay que tocar.
DEFAULT_PRESETS: list[Preset] = [
    Preset("gratis", "opencode-go/hy4-flash-free", "Sin coste, ideal para iterar y tareas de relleno"),
    Preset("estandar", "opencode-go/gpt-6-luna", "Equilibrio calidad/coste, contexto de 1.05M tokens"),
    Preset("forense", "opencode-go/kimi-k3.1-pro", "Analisis profundo de atribucion y tecnicas"),
]


@dataclass
class Settings:
    host: str = field(default_factory=lambda: _env("LOGSCOPE_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("LOGSCOPE_PORT", 8000))

    opencode_bin: str = field(default_factory=lambda: _env("LOGSCOPE_OPENCODE_BIN", "opencode"))
    opencode_port: int = field(default_factory=lambda: _env_int("LOGSCOPE_OPENCODE_PORT", 4099))

    provider: str = field(default_factory=lambda: _env("LOGSCOPE_PROVIDER", "opencode-go"))
    model: str = field(default_factory=lambda: _env("LOGSCOPE_MODEL", "opencode-go/gpt-6-luna"))
    small_model: str = field(default_factory=lambda: _env("LOGSCOPE_SMALL_MODEL", "opencode-go/hy4-flash-free"))
    agent: str = field(default_factory=lambda: _env("LOGSCOPE_AGENT", "log-analyst"))
    fallback_models: list[str] = field(
        default_factory=lambda: _env_list(
            "LOGSCOPE_FALLBACK_MODELS",
            ["opencode-go/deepseek-v4.1-flash", "opencode-go/beam-free"],
        )
    )

    workspaces_dir: Path = field(
        default_factory=lambda: (PROJECT_ROOT / _env("LOGSCOPE_WORKSPACES", "workspaces")).resolve()
    )
    max_upload_mb: int = field(default_factory=lambda: _env_int("LOGSCOPE_MAX_UPLOAD_MB", 64))
    analysis_timeout: int = field(default_factory=lambda: _env_int("LOGSCOPE_ANALYSIS_TIMEOUT", 900))
    log_level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO"))

    presets_file: Path = field(default_factory=lambda: PROJECT_ROOT / "config" / "presets.json")
    project_root: Path = field(default_factory=lambda: PROJECT_ROOT)

    @property
    def opencode_base_url(self) -> str:
        return f"http://127.0.0.1:{self.opencode_port}"

    # -- presets -------------------------------------------------------------
    def load_presets(self) -> list[Preset]:
        """Presets desde disco; si no existen o estan corruptos, usa los de serie."""
        if self.presets_file.exists():
            try:
                raw = json.loads(self.presets_file.read_text(encoding="utf-8"))
                presets = [Preset(**item) for item in raw]
                if presets:
                    return presets
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        return list(DEFAULT_PRESETS)

    def save_presets(self, presets: list[Preset]) -> None:
        self.presets_file.parent.mkdir(parents=True, exist_ok=True)
        self.presets_file.write_text(
            json.dumps([p.to_dict() for p in presets], indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def resolve_model(self, requested: str | None) -> str:
        """Resuelve el modelo pedido: si es un alias de preset, lo traduce."""
        if not requested:
            return self.model
        for preset in self.load_presets():
            if requested == preset.label:
                return preset.model
        if "/" in requested:
            return requested
        return self.model


settings = Settings()
