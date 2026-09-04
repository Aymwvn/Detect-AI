"""
Strict AI output schema (architecture doc section 16). The LLM MUST return
JSON matching this schema — anything else is rejected outright, never
partially trusted (app/services/ai/analysis.py:parse_llm_response).

Evidence references use a `"field:<name>"` or `"event:<id>"` format rather
than free text specifically so they can be mechanically checked against
what the alert actually contains (app/services/ai/analysis.py:
reconcile_evidence) — a reference that doesn't resolve to a real,
populated field or a real event on this alert gets stripped before the
analysis is ever shown to an analyst or stored as fact.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    reference: str  # "field:<alert_field_name>" or "event:<event_id>"
    description: str


class MitreTechniqueClaim(BaseModel):
    technique_id: str
    technique_name: str | None = None
    evidence: list[str] = Field(default_factory=list)  # references, same format as EvidenceItem.reference


class AIAnalysisOutput(BaseModel):
    classification: str
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    summary: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    mitre_techniques: list[MitreTechniqueClaim] = Field(default_factory=list)
    false_positive_hypotheses: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    investigation_priority: str
