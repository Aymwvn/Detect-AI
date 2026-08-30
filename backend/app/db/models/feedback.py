"""Analyst feedback on alerts (architecture doc section 12). Stored, never
used to auto-retrain a model — this table is designed to support a future
evaluation/fine-tuning pipeline that a human explicitly triggers, not an
automatic loop."""

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.alert_id"), index=True)
    analyst_id: Mapped[str] = mapped_column(String(255))  # references a user in the auth system (Phase 18)

    label: Mapped[str] = mapped_column(String(32))  # true_positive/false_positive/benign/needs_investigation/confirmed_incident
    comment: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    alert: Mapped["Alert"] = relationship(back_populates="feedback")
