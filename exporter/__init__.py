"""Exportacion del informe a Markdown, PDF y CSV."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from pathlib import Path
from typing import Any

SEVERITY_LABELS_ES = {
    "CRITICAL": "Critica",
    "HIGH": "Alta",
    "MEDIUM": "Media",
    "LOW": "Baja",
    "INFO": "Informativa",
}

PHASE_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Command and Control",
    "Impact",
    "Containment",
]


def _fmt_bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(value) < 1024 or unit == "GB":
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def build_markdown(report: dict[str, Any], workspace: Path | None = None) -> str:
    lines: list[str] = []
    add = lines.append

    add(f"# Informe de analisis de logs - {report.get('incident_type') or 'Incidente'}")
    add("")
    add(f"**Severidad global:** {SEVERITY_LABELS_ES.get(report.get('severity_overall', ''), 'Informativa')}")
    add(f"**Generado:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    if workspace:
        add(f"**Workspace:** `{workspace}`")
    add("")
    add("## Resumen")
    add("")
    add(report.get("summary", ""))
    add("")
    if report.get("executive_summary"):
        add("## Resumen ejecutivo")
        add("")
        add(report["executive_summary"])
        add("")

    chain = report.get("attack_chain", [])
    if chain:
        add("## Cronologia del incidente")
        add("")
        add("| Fase | Momento | Actor | Descripcion | Evidencia | Tecnicas |")
        add("|---|---|---|---|---|---|")
        for step in chain:
            add(
                "| {phase} | {ts} | {actor} | {desc} | {ev} | {tech} |".format(
                    phase=step.get("phase", ""),
                    ts=step.get("ts", ""),
                    actor=step.get("actor") or "-",
                    desc=(step.get("description", "").replace("|", "/")[:300]),
                    ev=", ".join(f"`{e}`" for e in step.get("evidence", [])) or "-",
                    tech=", ".join(step.get("techniques", [])) or "-",
                )
            )
        add("")

    findings = report.get("findings", [])
    if findings:
        add("## Hallazgos")
        add("")
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for finding in sorted(findings, key=lambda f: order.get(f.get("severity", "INFO"), 5)):
            add(f"### {finding.get('id', '')} - {finding.get('title', '')}")
            add("")
            add(f"- **Severidad:** {SEVERITY_LABELS_ES.get(finding.get('severity', ''), finding.get('severity', ''))}")
            if finding.get("category"):
                add(f"- **Categoria:** {finding['category']}")
            if finding.get("control_domain"):
                add(f"- **Control:** {finding['control_domain']}")
            if finding.get("techniques"):
                add(f"- **ATT&CK:** {', '.join(finding['techniques'])}")
            if finding.get("evidence"):
                add(f"- **Evidencia:** {', '.join(f'`{e}`' for e in finding['evidence'])}")
            add("")
            add(finding.get("description", ""))
            if finding.get("impact"):
                add("")
                add(f"**Impacto:** {finding['impact']}")
            if finding.get("recommendation"):
                add("")
                add(f"**Recomendacion:** {finding['recommendation']}")
            add("")

    mitre = report.get("mitre_attack", [])
    if mitre:
        add("## Mapeo MITRE ATT&CK")
        add("")
        add("| Tecnica | Tactica | Evidencia | Confianza |")
        add("|---|---|---|---|")
        for entry in mitre:
            add(
                f"| {entry.get('technique_id', '')} {entry.get('technique_name', '')} "
                f"| {', '.join(entry.get('tactics', []))} "
                f"| {', '.join(f'`{e}`' for e in entry.get('evidence', [])) or '-'} "
                f"| {entry.get('confidence', '')} |"
            )
        add("")

    review = report.get("siem_rule_review", [])
    if review:
        add("## Revision de las reglas de deteccion")
        add("")
        add("| Alerta | Problema | Severidad | Tecnica sugerida | Evidencia |")
        add("|---|---|---|---|---|")
        for issue in review:
            add(
                f"| {issue.get('alert_id', '')} | {issue.get('issue', '').replace('|', '/')} "
                f"| {issue.get('severity', '')} | {issue.get('suggested_technique', '')} "
                f"{issue.get('suggested_tactic', '')} "
                f"| {', '.join(f'`{e}`' for e in issue.get('evidence', [])) or '-'} |"
            )
        add("")

    iocs = report.get("iocs", [])
    if iocs:
        add("## Indicadores de compromiso")
        add("")
        add("| Tipo | Valor | Contexto | Confianza |")
        add("|---|---|---|---|")
        for ioc in iocs:
            add(
                f"| {ioc.get('type', '')} | `{ioc.get('value', '')}` "
                f"| {ioc.get('context', '').replace('|', '/')[:180]} | {ioc.get('confidence', '')} |"
            )
        add("")

    if report.get("telemetry_gaps"):
        add("## Huecos de telemetria")
        add("")
        for gap in report["telemetry_gaps"]:
            add(f"- {gap}")
        add("")

    if report.get("data_quality_issues"):
        add("## Calidad de los datos")
        add("")
        for issue in report["data_quality_issues"]:
            add(f"- {issue}")
        add("")

    recommendations = report.get("recommendations", [])
    if recommendations:
        add("## Recomendaciones")
        add("")
        for rec in sorted(recommendations, key=lambda r: r.get("priority", 99)):
            refs = ", ".join(rec.get("references", []))
            add(
                f"{rec.get('priority', '')}. **{rec.get('action', '')}** "
                f"_(esfuerzo: {rec.get('effort', 'medio')})_"
            )
            if rec.get("rationale"):
                add(f"   {rec['rationale']}")
            if refs:
                add(f"   Ref: {refs}")
            add("")

    review_metrics = report.get("metrics_review") or {}
    if review_metrics.get("comment") or review_metrics.get("discrepancies"):
        add("## Revision de metricas")
        add("")
        if review_metrics.get("comment"):
            add(review_metrics["comment"])
            add("")
        for discrepancy in review_metrics.get("discrepancies", []):
            add(f"- {discrepancy}")
        add("")

    return "\n".join(lines)


def export_report_markdown(report: dict[str, Any], workspace: Path | None = None) -> str:
    return build_markdown(report, workspace)


def export_findings_csv(report: dict[str, Any]) -> str:
    buffer = io.StringIO()
    fields = [
        "id",
        "title",
        "severity",
        "category",
        "control_domain",
        "techniques",
        "evidence",
        "description",
        "impact",
        "recommendation",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    for finding in report.get("findings", []):
        writer.writerow(
            {
                "id": finding.get("id", ""),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", ""),
                "category": finding.get("category", ""),
                "control_domain": finding.get("control_domain", ""),
                "techniques": "; ".join(finding.get("techniques", [])),
                "evidence": "; ".join(finding.get("evidence", [])),
                "description": finding.get("description", ""),
                "impact": finding.get("impact", ""),
                "recommendation": finding.get("recommendation", ""),
            }
        )
    return buffer.getvalue()


def export_pdf(report: dict[str, Any], workspace: Path | None = None) -> bytes:
    """Genera un PDF del informe con reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    styles = getSampleStyleSheet()
    ink = colors.HexColor("#0B1020")
    accent = colors.HexColor("#2DD4BF")
    muted = colors.HexColor("#8FA0BF")
    body = ParagraphStyle(
        "body", parent=styles["BodyText"], fontSize=9, leading=13, textColor=ink, alignment=TA_LEFT
    )
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=17, textColor=ink, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12.5, textColor=ink, spaceBefore=12, spaceAfter=5)
    h3 = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=10.5, textColor=ink, spaceBefore=8, spaceAfter=3)
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=muted)

    severity_colors = {
        "CRITICAL": colors.HexColor("#FF4D6D"),
        "HIGH": colors.HexColor("#FF9F45"),
        "MEDIUM": colors.HexColor("#FFD166"),
        "LOW": colors.HexColor("#4CC9F0"),
        "INFO": colors.HexColor("#7D8AA5"),
    }

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="LogScope - Informe de analisis de logs",
        author="LogScope",
    )

    story: list[Any] = []
    story.append(Paragraph("Informe de analisis de logs", h1))
    story.append(
        Paragraph(
            f"{report.get('incident_type', 'Incidente')} &nbsp;|&nbsp; Severidad: "
            f"<b>{SEVERITY_LABELS_ES.get(report.get('severity_overall', ''), 'Informativa')}</b> &nbsp;|&nbsp; "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')}",
            small,
        )
    )
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", color=accent, thickness=1.2))
    story.append(Spacer(1, 8))

    if report.get("summary"):
        story.append(Paragraph("Resumen", h2))
        story.append(Paragraph(report["summary"].replace("\n", "<br/>"), body))
        story.append(Spacer(1, 4))

    if report.get("executive_summary"):
        story.append(Paragraph("Resumen ejecutivo", h2))
        story.append(Paragraph(report["executive_summary"].replace("\n", "<br/>"), body))

    chain = report.get("attack_chain", [])
    if chain:
        story.append(Paragraph("Cronologia del incidente", h2))
        rows = [["Fase", "Momento", "Actor", "Descripcion", "Evidencia"]]
        for step in chain:
            rows.append(
                [
                    Paragraph(str(step.get("phase", "")), small),
                    Paragraph(str(step.get("ts", "")), small),
                    Paragraph(str(step.get("actor") or "-"), small),
                    Paragraph(str(step.get("description", ""))[:280], small),
                    Paragraph(", ".join(step.get("evidence", [])) or "-", small),
                ]
            )
        table = Table(rows, colWidths=[26 * mm, 30 * mm, 22 * mm, 66 * mm, 28 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), ink),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F5FA")]),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D8DEE9")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(table)

    findings = report.get("findings", [])
    if findings:
        story.append(PageBreak())
        story.append(Paragraph("Hallazgos", h2))
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for finding in sorted(findings, key=lambda f: order.get(f.get("severity", "INFO"), 5)):
            severity = finding.get("severity", "INFO")
            story.append(
                Paragraph(
                    f"<font color='{severity_colors.get(severity, ink).hexval()}'>&#9679;</font> "
                    f"<b>{finding.get('id', '')} - {finding.get('title', '')}</b> "
                    f"<font size='8' color='{muted.hexval()}'>[{severity}]</font>",
                    h3,
                )
            )
            meta_bits = []
            if finding.get("category"):
                meta_bits.append(f"Categoria: {finding['category']}")
            if finding.get("techniques"):
                meta_bits.append(f"ATT&CK: {', '.join(finding['techniques'])}")
            if finding.get("evidence"):
                meta_bits.append(f"Evidencia: {', '.join(finding['evidence'])}")
            if meta_bits:
                story.append(Paragraph(" | ".join(meta_bits), small))
            story.append(Paragraph(finding.get("description", "").replace("\n", "<br/>"), body))
            if finding.get("impact"):
                story.append(Paragraph(f"<b>Impacto:</b> {finding['impact']}", body))
            if finding.get("recommendation"):
                story.append(Paragraph(f"<b>Recomendacion:</b> {finding['recommendation']}", body))
            story.append(Spacer(1, 5))

    mitre = report.get("mitre_attack", [])
    if mitre:
        story.append(Paragraph("Mapeo MITRE ATT&CK", h2))
        rows = [["Tecnica", "Tactica", "Evidencia", "Confianza"]]
        for entry in mitre:
            rows.append(
                [
                    Paragraph(f"{entry.get('technique_id', '')} {entry.get('technique_name', '')}", small),
                    Paragraph(", ".join(entry.get("tactics", [])), small),
                    Paragraph(", ".join(entry.get("evidence", [])) or "-", small),
                    Paragraph(str(entry.get("confidence", "")), small),
                ]
            )
        table = Table(rows, colWidths=[52 * mm, 42 * mm, 50 * mm, 28 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), ink),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F5FA")]),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D8DEE9")),
                ]
            )
        )
        story.append(table)

    review = report.get("siem_rule_review", [])
    if review:
        story.append(Paragraph("Revision de reglas de deteccion", h2))
        for issue in review:
            story.append(
                Paragraph(
                    f"<b>{issue.get('alert_id', '')}</b> - {issue.get('issue', '')} "
                    f"<font size='8' color='{muted.hexval()}'>"
                    f"[{issue.get('severity', '')}"
                    f"{' -> ' + issue.get('suggested_technique', '') if issue.get('suggested_technique') else ''}]"
                    f"</font>",
                    body,
                )
            )
            story.append(Spacer(1, 3))

    iocs = report.get("iocs", [])
    if iocs:
        story.append(Paragraph("Indicadores de compromiso", h2))
        rows = [["Tipo", "Valor", "Contexto"]]
        for ioc in iocs:
            rows.append(
                [
                    Paragraph(str(ioc.get("type", "")), small),
                    Paragraph(str(ioc.get("value", "")), small),
                    Paragraph(str(ioc.get("context", ""))[:200], small),
                ]
            )
        table = Table(rows, colWidths=[24 * mm, 56 * mm, 92 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), ink),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F5FA")]),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D8DEE9")),
                ]
            )
        )
        story.append(table)

    for title, key in (("Huecos de telemetria", "telemetry_gaps"), ("Calidad de los datos", "data_quality_issues")):
        items = report.get(key) or []
        if items:
            story.append(Paragraph(title, h2))
            for item in items:
                story.append(Paragraph(f"- {item}", body))

    recommendations = report.get("recommendations", [])
    if recommendations:
        story.append(Paragraph("Recomendaciones", h2))
        for rec in sorted(recommendations, key=lambda r: r.get("priority", 99)):
            refs = ", ".join(rec.get("references", []))
            story.append(
                Paragraph(
                    f"<b>{rec.get('priority', '')}.</b> {rec.get('action', '')} "
                    f"<font size='8' color='{muted.hexval()}'>(esfuerzo: {rec.get('effort', 'medio')})</font>",
                    body,
                )
            )
            if rec.get("rationale"):
                story.append(Paragraph(rec["rationale"], small))
            if refs:
                story.append(Paragraph(f"Ref: {refs}", small))
            story.append(Spacer(1, 3))

    def _decorate(canvas, doc_ref):
        canvas.saveState()
        canvas.setFillColor(ink)
        canvas.rect(0, A4[1] - 12 * mm, A4[0], 12 * mm, fill=1, stroke=0)
        canvas.setFillColor(accent)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(18 * mm, A4[1] - 8 * mm, "LOGSCOPE")
        canvas.setFillColor(muted)
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"pagina {doc_ref.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_decorate, onLaterPages=_decorate)
    return buffer.getvalue()
