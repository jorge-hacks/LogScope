"""Catalogo de modelos de opencode para LogScope.

El proveedor puede rotar mensualmente sus modelos, asi que nada se codifica
a mano: el catalogo se lee del propio servidor de opencode (`GET /provider`)
y se filtra al unico proveedor permitido por la configuracion.

Filtros obligatorios:
  - el modelo debe pertenecer al proveedor configurado (por defecto opencode-go)
  - el modelo debe soportar tool calling (capabilities.toolcall); el servidor
    de opencode NO lo valida y aceptaria un modelo sin tools, que romperia
    al agente en cuanto intentara usar bash o read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from server.config import settings

TIER_FREE = "free"
TIER_LOW = "low"
TIER_MEDIUM = "medium"
TIER_HIGH = "high"

TIER_LABELS = {
    TIER_FREE: "Gratis",
    TIER_LOW: "Economico",
    TIER_MEDIUM: "Medio",
    TIER_HIGH: "Alto",
}


def tier_for(cost_in: float, cost_out: float) -> str:
    total = float(cost_in or 0) + float(cost_out or 0)
    if total <= 0:
        return TIER_FREE
    if total < 1.0:
        return TIER_LOW
    if total < 6.0:
        return TIER_MEDIUM
    return TIER_HIGH


@dataclass
class CatalogEntry:
    model_id: str
    provider: str
    name: str
    cost_in: float
    cost_out: float
    context: int | None
    output_limit: int | None
    reasoning: bool
    toolcall: bool
    tier: str

    @property
    def full_id(self) -> str:
        return f"{self.provider}/{self.model_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "provider": self.provider,
            "full_id": self.full_id,
            "name": self.name,
            "cost_in": self.cost_in,
            "cost_out": self.cost_out,
            "context": self.context,
            "output_limit": self.output_limit,
            "reasoning": self.reasoning,
            "toolcall": self.toolcall,
            "tier": self.tier,
            "tier_label": TIER_LABELS[self.tier],
        }


def parse_provider_payload(payload: dict[str, Any]) -> tuple[list[CatalogEntry], dict[str, Any]]:
    """Convierte la respuesta de /provider en entradas de catalogo."""
    providers = {p.get("id"): p for p in payload.get("all", []) if isinstance(p, dict)}
    connected = [p for p in payload.get("connected", []) if p]

    provider_id = settings.provider
    provider = providers.get(provider_id)
    if provider is None:
        return [], {
            "provider": provider_id,
            "connected": connected,
            "status": "not_found",
            "message": (
                f"El proveedor '{provider_id}' no aparece en el catalogo de opencode. "
                "Disponibles: " + (", ".join(sorted(connected)) or "ninguno")
            ),
        }

    entries: list[CatalogEntry] = []
    for model_id, model in (provider.get("models") or {}).items():
        if not isinstance(model, dict):
            continue
        capabilities = model.get("capabilities") or {}
        if not capabilities.get("toolcall"):
            # Sin tool calling el agente no puede leer ni ejecutar nada util.
            continue
        cost = model.get("cost") or {}
        limits = model.get("limit") or {}
        cost_in = float(cost.get("input") or 0)
        cost_out = float(cost.get("output") or 0)
        entries.append(
            CatalogEntry(
                model_id=model_id,
                provider=provider_id,
                name=model.get("name") or model_id,
                cost_in=cost_in,
                cost_out=cost_out,
                context=limits.get("context"),
                output_limit=limits.get("output"),
                reasoning=bool(capabilities.get("reasoning")),
                toolcall=True,
                tier=tier_for(cost_in, cost_out),
            )
        )

    entries.sort(key=lambda e: (e.cost_in, e.cost_out, e.model_id))
    status = "ok" if provider_id in connected else "disconnected"
    message = ""
    if status != "ok":
        message = (
            f"El proveedor '{provider_id}' no tiene credenciales conectadas. "
            "Ejecuta 'opencode providers login' para activarlo."
        )
    return entries, {
        "provider": provider_id,
        "provider_name": provider.get("name"),
        "connected": connected,
        "status": status,
        "message": message,
        "total": len(entries),
        "by_tier": {
            tier: sum(1 for e in entries if e.tier == tier) for tier in TIER_LABELS
        },
    }


def build_catalog(payload: dict[str, Any]) -> dict[str, Any]:
    entries, meta = parse_provider_payload(payload)
    presets = []
    for preset in settings.load_presets():
        known = next((e for e in entries if e.full_id == preset.model), None)
        presets.append(
            {
                **preset.to_dict(),
                "available": known is not None,
                "tier": known.tier if known else "unknown",
                "tier_label": TIER_LABELS.get(known.tier, "Desconocido") if known else "No disponible",
                "cost_in": known.cost_in if known else None,
                "cost_out": known.cost_out if known else None,
            }
        )
    return {
        "models": [e.to_dict() for e in entries],
        "meta": meta,
        "presets": presets,
        "default_model": settings.model,
        "fallback_models": settings.fallback_models,
    }


def is_available(catalog: dict[str, Any], full_id: str) -> bool:
    return any(m["full_id"] == full_id for m in catalog.get("models", []))
