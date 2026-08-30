"""Stores one row per AI analysis run on an alert. This is the persisted
form of the strict JSON schema from architecture doc section 16 — schema
validation happens in the AI service layer (Phase 14) before a row ever
gets written here, so anything in this table has already passed the
evidence-reconciliation check."""

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AIAnalysis(Base):
    __tablename__ = "ai_analysis"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.alert_id"), index=True)

    provider: Mapped[str] = mapped_column(String(32))  # openai | anthropic | ollama | none
    model: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    classification: Mapped[str] = mapped_column(String(64))  # e.g. "likely_malicious"
    risk_score: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)
    investigation_priority: Mapped[str] = mapped_column(String(16))  # low/medium/high/critical

    summary: Mapped[str] = mapped_column(String(4000))

    # Each item must cite real event_id/field references — enforced by the
    # validator in the AI service layer, not by the DB itself.
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    false_positive_hypotheses: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommended_actions: Mapped[list[str]] = mapped_column(JSON, default=list)
    missing_information: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Full raw provider response, kept for audit/debugging even after parsing.
    raw_output: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    validation_status: Mapped[str] = mapped_column(String(16), default="valid")  # valid/rejected/repaired

    latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    alert: Mapped["Alert"] = relationship(back_populates="ai_analyses")
