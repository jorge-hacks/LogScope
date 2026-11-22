"""Tests de la API con un cliente de opencode simulado.

No requieren el servidor real: se comprueba la ingesta via HTTP, el contrato
de las rutas y la exportacion del informe.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server.main import app

SAMPLE = """event_id,timestamp,username,source_ip,destination_host,event_type,result,details
AUTH-1,2025-05-07T01:02:00-03:00,a.torres,198.51.100.10,VPN01,vpn_login,FAILURE,mal
AUTH-2,2025-05-07T09:00:00-03:00,d.perez,10.60.20.27,SRV-APP01,interactive_logon,SUCCESS,normal
"""


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_route(client: TestClient):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["app"] == "ok"


def test_index_page_renders(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert "LOGSCOPE" in response.text


def test_settings_page_renders(client: TestClient):
    response = client.get("/settings")
    assert response.status_code == 200
    assert "Presets" in response.text


def test_upload_creates_analysis(client: TestClient, tmp_path: Path):
    csv = tmp_path / "auth.csv"
    csv.write_text(SAMPLE, encoding="utf-8")

    response = client.post(
        "/api/upload",
        files={"files": ("auth.csv", csv.read_bytes(), "text/csv")},
        data={"name": "Test"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["events"] == 2

    analysis_id = payload["analysis_id"]
    detail = client.get(f"/api/analysis/{analysis_id}")
    assert detail.status_code == 200
    assert detail.json()["metrics"]["events"] == 2

    events = client.get(f"/api/analysis/{analysis_id}/events")
    assert events.json()["total"] == 2

    timeline = client.get(f"/api/analysis/{analysis_id}/timeline")
    assert timeline.status_code == 200
    assert len(timeline.json()["hours"]) == 24


def test_upload_rejects_empty_upload(client: TestClient):
    response = client.post("/api/upload", files=[])
    assert response.status_code == 422


def test_analysis_page_renders(client: TestClient, tmp_path: Path):
    csv = tmp_path / "auth.csv"
    csv.write_text(SAMPLE, encoding="utf-8")
    analysis_id = client.post(
        "/api/upload",
        files={"files": ("auth.csv", csv.read_bytes(), "text/csv")},
        data={"name": "Test"},
    ).json()["analysis_id"]

    response = client.get(f"/analysis/{analysis_id}")
    assert response.status_code == 200
    assert "Ejecutar analisis" in response.text


def test_unknown_analysis_returns_404(client: TestClient):
    assert client.get("/api/analysis/no-existe").status_code == 404


def test_export_requires_report(client: TestClient, tmp_path: Path):
    csv = tmp_path / "auth.csv"
    csv.write_text(SAMPLE, encoding="utf-8")
    analysis_id = client.post(
        "/api/upload",
        files={"files": ("auth.csv", csv.read_bytes(), "text/csv")},
    ).json()["analysis_id"]
    assert client.get(f"/api/analysis/{analysis_id}/export/md").status_code == 404


def test_export_markdown_and_csv(client: TestClient, tmp_path: Path, monkeypatch):
    from server import main as main_module

    csv = tmp_path / "auth.csv"
    csv.write_text(SAMPLE, encoding="utf-8")
    analysis_id = client.post(
        "/api/upload",
        files={"files": ("auth.csv", csv.read_bytes(), "text/csv")},
    ).json()["analysis_id"]

    workspace = main_module.workspace_path(analysis_id)
    report = {
        "summary": "Resumen de prueba",
        "severity_overall": "HIGH",
        "attack_chain": [
            {"phase": "Initial Access", "title": "Acceso", "ts": "2025-05-07T01:02:00-03:00", "evidence": ["AUTH-1"]}
        ],
        "findings": [
            {"id": "H-01", "title": "Hallazgo", "severity": "HIGH", "evidence": ["AUTH-1"]}
        ],
    }
    (workspace / "report").mkdir(parents=True, exist_ok=True)
    (workspace / "report" / "report.json").write_text(json.dumps(report), encoding="utf-8")

    md = client.get(f"/api/analysis/{analysis_id}/export/md")
    assert md.status_code == 200
    assert "Resumen de prueba" in md.text

    csv_out = client.get(f"/api/analysis/{analysis_id}/export/findings.csv")
    assert csv_out.status_code == 200
    assert "H-01" in csv_out.text

    pdf = client.get(f"/api/analysis/{analysis_id}/export/pdf")
    assert pdf.status_code == 200
    assert pdf.content[:4] == b"%PDF"


def test_presets_saved_and_reloaded(client: TestClient, tmp_path: Path, monkeypatch):
    from server.config import settings

    target = tmp_path / "presets.json"
    monkeypatch.setattr(settings, "presets_file", target)

    response = client.post(
        "/api/presets",
        json={"presets": [{"label": "prueba", "model": "opencode-go/beam-free", "description": "x"}]},
    )
    assert response.status_code == 200
    assert settings.load_presets()[0].label == "prueba"


def test_presets_reject_empty(client: TestClient):
    assert client.post("/api/presets", json={"presets": []}).status_code == 400


def test_concordance_endpoint_rejects_unknown_format(client: TestClient, tmp_path: Path):
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

    assert client.get(f"/api/analysis/{analysis_id}/concordance").json()["ok"] is False

    response = client.post(
        f"/api/analysis/{analysis_id}/concordance",
        files={"file": ("basura.txt", b"no es un log de alertas\n", "text/plain")},
    )
    assert response.status_code == 400
    assert "No se reconoce el formato" in response.json()["detail"]


def test_concordance_endpoint_reconciles_snort_log(client: TestClient, tmp_path: Path):
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

    log = (
        "05/07-01:02:00.000000 [**] [1:1000003:1] \"JKS-EXFILITRACION Transferencia\" [**] "
        "[Priority: 0] {TCP} 1.2.3.4:5555 -> 9.9.9.9:443\n"
    )
    response = client.post(
        f"/api/analysis/{analysis_id}/concordance",
        files={"file": ("alert_fast.txt", log.encode(), "text/plain")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["formato"] == "alert_log"
    assert payload["resumen"]["combinaciones_ids"] == 1

    # El resultado queda persistido y se puede recuperar.
    guardado = client.get(f"/api/analysis/{analysis_id}/concordance").json()
    assert guardado["ok"] is True
