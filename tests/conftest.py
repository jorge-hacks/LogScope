"""Configuracion comun de los tests.

Los tests de la API crean analisis reales. Sin este aislamiento, cada
ejecucion deja basura en el directorio `workspaces/` del proyecto (y en el
listado de la UI). Aqui se redirigen a un directorio temporal.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from server.config import settings


@pytest.fixture(autouse=True)
def isolated_workspaces(tmp_path, monkeypatch) -> Iterator[None]:
    """Cada test trabaja en su propio directorio de workspaces."""
    workspaces = tmp_path / "workspaces"
    workspaces.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "workspaces_dir", workspaces)
    yield
