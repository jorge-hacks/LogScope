"""Esquemas del informe.

El agente de opencode produce `report.json`; estos modelos validan que la
estructura sea la esperada. Si la validacion falla, el backend reenvia el
mensaje al agente con los errores de validacion para que lo corrija.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Confidence = Literal["ALTA", "MEDIA", "BAJA"]
Phase = Literal[
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Containment",
    "Discovery",
    "Defense Evasion",
    "Command and Control",
    "Impact",
]


class AttackStep(BaseModel):
    phase: Phase
    title: str = Field(min_length=1)
    ts: str = ""
    actor: str = ""
    host: str = ""
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    confidence: Confidence = "MEDIA"


class Finding(BaseModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Severity
    category: str = ""
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    impact: str = ""
    recommendation: str = ""
    control_domain: str = ""


class IOC(BaseModel):
    type: str = ""
    value: str = Field(min_length=1)
    context: str = ""
    first_seen: str = ""
    last_seen: str = ""
    confidence: Confidence = "MEDIA"


class MitreTechnique(BaseModel):
    technique_id: str = Field(min_length=1)
    technique_name: str = ""
    tactics: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: Confidence = "MEDIA"


class SiemRuleIssue(BaseModel):
    alert_id: str = ""
    issue: str = Field(min_length=1)
    severity: Severity = "MEDIUM"
    suggested_technique: str = ""
    suggested_tactic: str = ""
    evidence: list[str] = Field(default_factory=list)


class Recommendation(BaseModel):
    priority: int = Field(ge=1, le=99)
    action: str = Field(min_length=1)
    rationale: str = ""
    effort: Literal["bajo", "medio", "alto"] = "medio"
    references: list[str] = Field(default_factory=list)


class MetricsReview(BaseModel):
    comment: str = ""
    discrepancies: list[str] = Field(default_factory=list)


class Report(BaseModel):
    schema_version: int = 1
    summary: str = ""
    executive_summary: str = ""
    incident_type: str = ""
    severity_overall: Severity = "INFO"
    attack_chain: list[AttackStep] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    mitre_attack: list[MitreTechnique] = Field(default_factory=list)
    siem_rule_review: list[SiemRuleIssue] = Field(default_factory=list)
    telemetry_gaps: list[str] = Field(default_factory=list)
    data_quality_issues: list[str] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    metrics_review: MetricsReview = Field(default_factory=MetricsReview)

    @field_validator("attack_chain")
    @classmethod
    def _chain_not_empty(cls, value: list[AttackStep]) -> list[AttackStep]:
        return value

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class AnalysisSummary(BaseModel):
    """Resumen ligero para listados."""

    id: str
    name: str
    created_at: str
    model: str = ""
    events: int = 0
    severity: str = "INFO"
    status: str = "pending"
    files: int = 0
