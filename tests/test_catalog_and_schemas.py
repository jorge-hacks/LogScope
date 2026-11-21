"""Tests del catalogo de modelos, los esquemas y el cliente de opencode."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models.catalog import build_catalog, parse_provider_payload, tier_for
from server.schemas import Report

# Respuesta recortada de GET /provider con la forma real observada.
PROVIDER_PAYLOAD = {
    "all": [
        {
            "id": "opencode-go",
            "name": "OpenCode Go",
            "models": {
                "gpt-6-luna": {
                    "id": "gpt-6-luna",
                    "providerID": "opencode-go",
                    "name": "GPT-6 Luna",
                    "capabilities": {"toolcall": True, "reasoning": True},
                    "cost": {"input": 0.1, "output": 0.5},
                    "limit": {"context": 1050000, "output": 128000},
                },
                "beam-free": {
                    "id": "beam-free",
                    "providerID": "opencode-go",
                    "capabilities": {"toolcall": True, "reasoning": True},
                    "cost": {"input": 0, "output": 0},
                    "limit": {"context": 1048576},
                },
                "sin-tools": {
                    "id": "sin-tools",
                    "providerID": "opencode-go",
                    "capabilities": {"toolcall": False, "reasoning": True},
                    "cost": {"input": 1, "output": 1},
                    "limit": {"context": 1000},
                },
            },
        },
        {
            "id": "opencode",
            "name": "OpenCode",
            "models": {
                "deepseek-v4.1-flash-free": {
                    "id": "deepseek-v4.1-flash-free",
                    "capabilities": {"toolcall": True},
                    "cost": {"input": 0, "output": 0},
                    "limit": {"context": 200000},
                }
            },
        },
    ],
    "connected": ["opencode-go", "opencode"],
    "default": {"opencode-go": "gpt-6-luna"},
}


def test_only_configured_provider_is_listed():
    entries, meta = parse_provider_payload(PROVIDER_PAYLOAD)
    assert meta["status"] == "ok"
    assert {e.provider for e in entries} == {"opencode-go"}
    assert "deepseek-v4.1-flash-free" not in {e.model_id for e in entries}


def test_models_without_toolcall_are_filtered():
    entries, _ = parse_provider_payload(PROVIDER_PAYLOAD)
    assert "sin-tools" not in {e.model_id for e in entries}
    assert all(e.toolcall for e in entries)


def test_models_sorted_by_cost_and_tiered():
    entries, meta = parse_provider_payload(PROVIDER_PAYLOAD)
    assert [e.model_id for e in entries] == ["beam-free", "gpt-6-luna"]
    assert entries[0].tier == "free"
    assert entries[1].tier == "low"
    assert meta["by_tier"]["free"] == 1


def test_tier_thresholds():
    assert tier_for(0, 0) == "free"
    assert tier_for(0.1, 0.5) == "low"
    assert tier_for(0.5, 1.0) == "medium"
    assert tier_for(2, 10) == "high"


def test_catalog_marks_preset_availability():
    catalog = build_catalog(PROVIDER_PAYLOAD)
    by_label = {p["label"]: p for p in catalog["presets"]}
    assert by_label["estandar"]["available"] is True
    assert by_label["forense"]["available"] is False


def test_catalog_reports_missing_provider():
    catalog = build_catalog({"all": [], "connected": [], "default": {}})
    assert catalog["meta"]["status"] == "not_found"
    assert catalog["models"] == []


def test_report_schema_accepts_valid_document():
    payload = {
        "schema_version": 1,
        "summary": "resumen",
        "severity_overall": "HIGH",
        "attack_chain": [
            {
                "phase": "Exfiltration",
                "title": "Salida de datos",
                "evidence": ["FW-00095"],
                "techniques": ["T1041"],
                "confidence": "ALTA",
            }
        ],
        "findings": [
            {
                "id": "H-01",
                "title": "Web shell activa",
                "severity": "CRITICAL",
                "evidence": ["AV-00005"],
            }
        ],
        "iocs": [{"type": "ip", "value": "203.0.113.201"}],
    }
    report = Report.model_validate(payload)
    assert report.severity_overall == "HIGH"
    assert report.findings[0].id == "H-01"
    assert report.to_dict()["attack_chain"][0]["phase"] == "Exfiltration"


def test_report_schema_rejects_bad_severity():
    with pytest.raises(ValidationError):
        Report.model_validate({"severity_overall": "SUPER_CRITICAL"})


def test_report_schema_rejects_unknown_phase():
    with pytest.raises(ValidationError):
        Report.model_validate(
            {"attack_chain": [{"phase": "Fase Inventada", "title": "x"}]}
        )


def test_report_schema_rejects_empty_finding_title():
    with pytest.raises(ValidationError):
        Report.model_validate({"findings": [{"id": "H-1", "title": "", "severity": "LOW"}]})


def test_model_split_requires_provider_prefix():
    from server.oc_client import OpencodeClient, OpencodeError

    with pytest.raises(OpencodeError):
        OpencodeClient._split_model("modelo-sin-proveedor")
    assert OpencodeClient._split_model("opencode-go/gpt-6-luna") == ("opencode-go", "gpt-6-luna")
