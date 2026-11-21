"""Tests de las plantillas y del JavaScript del dashboard.

Estos tests cubren fallos que solo se manifiestan en el navegador: scripts
que no se cargan, identificadores globales duplicados (que rompen el script
entero con un SyntaxError) o paginas que no montan su logica.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
SCRIPTS = ROOT / "static" / "js"

# Plantilla -> script que debe cargar.
EXPECTED_SCRIPTS = {
    "index.html": "index.js",
    "analysis.html": "analysis.js",
    "settings.html": "settings.js",
}

# Scripts que se cargan en todas las paginas.
SHARED_SCRIPTS = ["app.js"]


def read_template(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def read_script(name: str) -> str:
    return (SCRIPTS / name).read_text(encoding="utf-8")


@pytest.mark.parametrize(("template", "script"), sorted(EXPECTED_SCRIPTS.items()))
def test_each_page_loads_its_script(template: str, script: str):
    """Cada pagina debe cargar su script: si no, la UI queda inerte."""
    content = read_template(template)
    assert f"/static/js/{script}" in content, f"{template} no carga {script}"


@pytest.mark.parametrize("script", SHARED_SCRIPTS)
def test_shared_scripts_are_loaded_in_base(script: str):
    assert f"/static/js/{script}" in read_template("base.html")


def test_templates_extend_logscope_instead_of_replacing_it():
    """Reemplazar window.LOGSCOPE se llevaria por delante los helpers."""
    for template in EXPECTED_SCRIPTS:
        content = read_template(template)
        assert "Object.assign(window.LOGSCOPE || {}" in content, (
            f"{template} debe extender window.LOGSCOPE, no sustituirlo"
        )


def test_no_duplicate_top_level_const_between_scripts():
    """Dos `const` iguales en scripts clasicos son un SyntaxError global.

    Con `const LS` en app.js y en index.js, el segundo script no se ejecuta
    en absoluto: la pagina se queda con los valores del HTML inicial.
    """
    declarations: dict[str, list[str]] = {}
    pattern = re.compile(r"^const\s+([A-Za-z_$][\w$]*)\s*=", re.MULTILINE)
    for path in sorted(SCRIPTS.glob("*.js")):
        for name in pattern.findall(path.read_text(encoding="utf-8")):
            declarations.setdefault(name, []).append(path.name)

    duplicates = {name: files for name, files in declarations.items() if len(files) > 1}
    assert not duplicates, f"identificadores const declarados en varios scripts: {duplicates}"


def test_scripts_do_not_use_top_level_let_or_const_for_shared_helpers():
    """Los helpers compartidos deben usarse con `var` (redeclarable)."""
    for path in sorted(SCRIPTS.glob("*.js")):
        content = path.read_text(encoding="utf-8")
        assert not re.search(r"^(const|let)\s+LS\s*=", content, re.MULTILINE), (
            f"{path.name} declara LS con const/let; provocaria SyntaxError al "
            "cargarse junto a app.js"
        )


def test_index_page_has_the_expected_controls():
    content = read_template("index.html")
    for element_id in ("dropzone", "file-input", "model-select", "preset-select", "upload-btn"):
        assert f'id="{element_id}"' in content, f"falta #{element_id} en index.html"


def test_analysis_page_has_the_expected_panels():
    content = read_template("analysis.html")
    for tab in ("timeline", "events", "findings", "attack", "siem", "iocs", "gaps", "chat"):
        assert f'id="panel-{tab}"' in content, f"falta el panel {tab}"


def test_theme_defines_the_palette():
    css = (ROOT / "static" / "css" / "theme.css").read_text(encoding="utf-8")
    for variable in (
        "--bg-base",
        "--bg-surface",
        "--accent",
        "--accent-alt",
        "--critical",
        "--high",
        "--medium",
        "--low",
        "--info",
        "--success",
    ):
        assert f"{variable}:" in css, f"falta la variable {variable} en el tema"
