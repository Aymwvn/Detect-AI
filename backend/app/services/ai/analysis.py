"""
AI analysis orchestrator (architecture doc sections 5, 6, 16).

This is where the two independent safety layers described in prompts.py
actually get enforced in code:

1. parse_llm_response(): the LLM's raw text MUST parse as JSON and MUST
   validate against the strict AIAnalysisOutput schema. Anything else is
   rejected — stored as an audit record with validation_status="rejected",
   never silently patched up or partially trusted.

2. reconcile_evidence(): even a schema-valid response can claim things
   the alert doesn't support (whether from model error, or a successful
   prompt injection that got the model to assert something ungrounded).
   Every evidence/technique reference is checked against the alert's
   actual populated fields and real event IDs; anything that doesn't
   resolve is stripped and logged into missing_information instead of
   reaching the analyst as a stated fact.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AIAnalysis, Alert, Event
from app.services.ai.base import LLMProvider
from app.services.ai.exceptions import AIAnalysisValidationError, LLMProviderError
from app.services.ai.prompts import SYSTEM_PROMPT, _PROMPT_FIELDS, build_user_prompt
from app.services.ai.schema import AIAnalysisOutput

logger = logging.getLogger(__name__)

# Confidence blend weights (architecture doc section 6: combine multiple
# signals, don't rely purely on the LLM's own self-report).
_SEVERITY_CONFIDENCE_COMPONENT = {
    "informational": 0.1,
    "low": 0.3,
    "medium": 0.5,
    "high": 0.7,
    "critical": 0.9,
    "unknown": 0.3,
}
_CORRELATION_CONFIDENCE_PER_ALERT = 0.05
_CORRELATION_CONFIDENCE_CAP = 0.2
_SEVERITY_WEIGHT = 0.3
_AI_WEIGHT = 0.5
# Remaining 0.2 of the blend comes from the (capped) correlation component.


def parse_llm_response(raw_text: str) -> AIAnalysisOutput:
    """Parses and strictly validates the LLM's raw text response. Strips
    markdown code fences if present (many models wrap JSON in ```json
    blocks despite being told not to) but does NOT attempt any other
    repair — a response that isn't valid JSON, or doesn't match the
    schema, is rejected outright."""
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AIAnalysisValidationError(f"LLM response is not valid JSON: {exc}") from exc

    try:
        return AIAnalysisOutput.model_validate(data)
    except Exception as exc:  # pydantic.ValidationError
        raise AIAnalysisValidationError(f"LLM response failed schema validation: {exc}") from exc


def valid_references(alert: Alert, events: list[Event]) -> set[str]:
    """The complete set of evidence references this alert can legitimately
    support: one per populated field, plus one per real event."""
    refs = {f"field:{field}" for field in _PROMPT_FIELDS if getattr(alert, field, None)}
    refs.update(f"event:{event.id}" for event in events)
    return refs


def reconcile_evidence(output: AIAnalysisOutput, valid_refs: set[str]) -> AIAnalysisOutput:
    """Drops any evidence item or MITRE technique whose reference doesn't
    resolve to something the alert actually contains. A technique that
    loses ALL its evidence is dropped entirely — never assign a technique
    without supporting evidence (architecture doc section 10)."""
    kept_evidence = [item for item in output.evidence if item.reference in valid_refs]
    dropped_refs = [item.reference for item in output.evidence if item.reference not in valid_refs]

    kept_techniques = []
    for technique in output.mitre_techniques:
        supporting = [ref for ref in technique.evidence if ref in valid_refs]
        if supporting:
            kept_techniques.append(technique.model_copy(update={"evidence": supporting}))
        else:
            dropped_refs.append(f"{technique.technique_id} (no valid supporting evidence)")

    missing = list(output.missing_information)
    if dropped_refs:
        missing.append(
            f"{len(dropped_refs)} claim(s) were dropped for lacking a valid evidence reference: "
            + ", ".join(dropped_refs)
        )

    return output.model_copy(
        update={"evidence": kept_evidence, "mitre_techniques": kept_techniques, "missing_information": missing}
    )


def combine_confidence(alert_severity: str, correlated_count: int, ai_confidence: float) -> tuple[float, dict]:
    """Blends rule-based severity, correlation strength, and the model's
    own self-reported confidence into one number — never the raw AI
    confidence alone (architecture doc section 6)."""
    severity_component = _SEVERITY_CONFIDENCE_COMPONENT.get(alert_severity, 0.3)
    correlation_component = min(correlated_count * _CORRELATION_CONFIDENCE_PER_ALERT, _CORRELATION_CONFIDENCE_CAP)
    combined = round(
        min(_SEVERITY_WEIGHT * severity_component + _AI_WEIGHT * ai_confidence + correlation_component, 1.0), 2
    )
    breakdown = {
        "severity_component": severity_component,
        "correlation_component": correlation_component,
        "ai_self_reported_confidence": ai_confidence,
        "combined": combined,
    }
    return combined, breakdown


async def _count_correlated(db: AsyncSession, alert: Alert) -> int:
    if not alert.incident_id:
        return 0
    from sqlalchemy import func

    result = await db.execute(
        select(func.count()).select_from(Alert).where(Alert.incident_id == alert.incident_id)
    )
    return max(result.scalar_one() - 1, 0)


async def analyze_alert(db: AsyncSession, alert: Alert, llm_provider: LLMProvider) -> AIAnalysis:
    """Runs one full AI analysis pass on an alert: builds the prompts,
    calls the provider, validates the response, reconciles evidence
    against what the alert can actually support, blends confidence, and
    persists the result. Always returns an AIAnalysis row — even a
    rejected/malformed response is stored (validation_status="rejected")
    for audit purposes, it's just not treated as usable analysis."""
    result = await db.execute(select(Event).where(Event.alert_id == alert.alert_id))
    events = list(result.scalars().all())

    user_prompt = build_user_prompt(alert)

    start = time.monotonic()
    try:
        raw_text = await llm_provider.complete(SYSTEM_PROMPT, user_prompt)
    except LLMProviderError:
        raise  # let the caller (API layer) decide how to surface this
    latency_ms = int((time.monotonic() - start) * 1000)

    try:
        output = parse_llm_response(raw_text)
    except AIAnalysisValidationError as exc:
        rejected = AIAnalysis(
            alert_id=alert.alert_id,
            provider=llm_provider.provider_type,
            model=llm_provider.model,
            classification="unknown",
            risk_score=0,
            confidence=0.0,
            investigation_priority="low",
            summary=f"AI response rejected: {exc}",
            raw_output={"raw_text": raw_text},
            validation_status="rejected",
            latency_ms=latency_ms,
        )
        db.add(rejected)
        await db.commit()
        await db.refresh(rejected)
        logger.warning("AI analysis rejected for alert %s: %s", alert.alert_id, exc)
        return rejected

    valid_refs = valid_references(alert, events)
    reconciled = reconcile_evidence(output, valid_refs)

    correlated_count = await _count_correlated(db, alert)
    combined_confidence, confidence_breakdown = combine_confidence(
        alert.severity, correlated_count, reconciled.confidence
    )

    analysis = AIAnalysis(
        alert_id=alert.alert_id,
        provider=llm_provider.provider_type,
        model=llm_provider.model,
        classification=reconciled.classification,
        risk_score=reconciled.risk_score,
        confidence=combined_confidence,
        investigation_priority=reconciled.investigation_priority,
        summary=reconciled.summary,
        evidence=[e.model_dump() for e in reconciled.evidence],
        mitre_techniques=[m.model_dump() for m in reconciled.mitre_techniques],
        false_positive_hypotheses=reconciled.false_positive_hypotheses,
        recommended_actions=reconciled.recommended_actions,
        missing_information=reconciled.missing_information,
        raw_output={"raw_text": raw_text, "confidence_breakdown": confidence_breakdown},
        validation_status="valid",
        latency_ms=latency_ms,
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)
    return analysis
