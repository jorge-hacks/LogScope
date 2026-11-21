"""Tests del versionado de assets, las cabeceras y el render del informe.

Estos casos cubren fallos que solo se ven en el navegador: un script
cacheado por el navegador, un JSON embebido mal serializado o una pagina de
informe que no llega a pintarse.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server.main import app

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_static_assets_are_versioned(client: TestClient):
    """Los estaticos llevan version para invalidar la cache del navegador."""
    html = client.get("/").text
    refs = re.findall(r'(?:href|src)="(/static/[^"]+)"', html)
    assert refs, "la pagina no referencia estaticos"
    for ref in refs:
        assert "?v=" in ref, f"{ref} no lleva version; el navegador puede servirlo obsoleto"


def test_static_files_ask_for_revalidation(client: TestClient):
    response = client.get("/static/js/app.js")
    assert response.status_code == 200
    assert "no-cache" in response.headers.get("cache-control", "")


def test_asset_version_changes_when_static_changes(monkeypatch):
    from server import main as main_module

    before = main_module._asset_version()
    css = ROOT / "static" / "css" / "theme.css"
    original = css.read_text(encoding="utf-8")
    try:
        css.write_text(original + "\n/* cambio */\n", encoding="utf-8")
        after = main_module._asset_version()
    finally:
        css.write_text(original, encoding="utf-8")
    assert before != after


def test_report_page_embeds_valid_json(client: TestClient, tmp_path: Path):
    """El informe embebido debe ser JSON parseable, no la repr de un dict."""
    sample = tmp_path / "auth.csv"
    sample.write_text(
        "event_id,timestamp,username,source_ip,destination_host,event_type,result\n"
        "AUTH-1,2025-05-07T01:02:00-03:00,u,1.2.3.4,H,vpn_login,FAILURE\n",
        encoding="utf-8",
    )
    analysis_id = client.post(
        "/api/upload",
        files={"files": ("auth.csv", sample.read_bytes(), "text/csv")},
        data={"name": "Informe"},
    ).json()["analysis_id"]

    from server.main import workspace_path

    workspace = workspace_path(analysis_id)
    (workspace / "report").mkdir(parents=True, exist_ok=True)
    report = {
        "summary": "Resumen con <b>etiquetas</b> & \"comillas\"",
        "severity_overall": "CRITICAL",
        "findings": [
            {"id": "H-01", "title": "Web shell", "severity": "CRITICAL", "evidence": ["AV-00003"]}
        ],
    }
    (workspace / "report" / "report.json").write_text(json.dumps(report), encoding="utf-8")
    (workspace / "report" / "report.md").write_text("# Informe\n\n## Resumen\n", encoding="utf-8")

    html = client.get(f"/analysis/{analysis_id}/report").text
    match = re.search(r'<div id="report-json" hidden>(.*?)</div>', html, re.S)
    assert match, "la pagina del informe no embebe el JSON"
    raw = match.group(1)
    # El HTML escapa los caracteres especiales: se reconstituye el texto.
    import html as html_module

    parsed = json.loads(html_module.unescape(raw))
    assert parsed["severity_overall"] == "CRITICAL"
    assert parsed["findings"][0]["id"] == "H-01"


def test_report_page_does_not_load_external_scripts(client: TestClient, tmp_path: Path):
    """Sin CDN: la herramienta debe funcionar sin salida a internet."""
    sample = tmp_path / "auth.csv"
    sample.write_text(
        "event_id,timestamp,username,source_ip,destination_host,event_type,result\n"
        "AUTH-1,2025-05-07T01:02:00-03:00,u,1.2.3.4,H,vpn_login,FAILURE\n",
        encoding="utf-8",
    )
    analysis_id = client.post(
        "/api/upload",
        files={"files": ("auth.csv", sample.read_bytes(), "text/csv")},
    ).json()["analysis_id"]

    html = client.get(f"/analysis/{analysis_id}/report").text
    external = re.findall(r'<script[^>]+src="(https?://[^"]+)"', html)
    assert not external, f"la pagina carga scripts externos: {external}"


def test_report_renderer_escapes_untrusted_content(client: TestClient, tmp_path: Path):
    """El texto que viene de los logs no debe poder inyectar HTML."""
    from server.main import workspace_path

    sample = tmp_path / "auth.csv"
    sample.write_text(
        "event_id,timestamp,username,source_ip,destination_host,event_type,result\n"
        "AUTH-1,2025-05-07T01:02:00-03:00,u,1.2.3.4,H,vpn_login,FAILURE\n",
        encoding="utf-8",
    )
    analysis_id = client.post(
        "/api/upload",
        files={"files": ("auth.csv", sample.read_bytes(), "text/csv")},
    ).json()["analysis_id"]

    payload = "<img src=x onerror=alert(1)>"
    workspace = workspace_path(analysis_id)
    (workspace / "report").mkdir(parents=True, exist_ok=True)
    (workspace / "report" / "report.json").write_text(
        json.dumps({"summary": payload, "severity_overall": "LOW"}), encoding="utf-8"
    )

    html = client.get(f"/analysis/{analysis_id}/report").text
    # El JSON embebido va escapado, y el renderer del navegador tambien escapa.
    assert "<img src=x onerror=alert(1)>" not in html
