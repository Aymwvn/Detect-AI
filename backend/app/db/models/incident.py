"""An Incident is a correlated group of alerts that the correlation engine
(Phase 11) believes represent one underlying attack chain, e.g.
Initial Access -> Execution -> Persistence. See architecture doc section 9."""

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[Optional[str]] = mapped_column(String(4000), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open/investigating/resolved/closed

    # Aggregated MITRE technique IDs across all alerts in this incident,
    # in attack-chain order where determinable. Populated by the MITRE
    # mapper (Phase 15), not hand-entered.
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)

    overall_risk_score: Mapped[Optional[int]] = mapped_column(nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )

    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")
