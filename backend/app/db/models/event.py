"""Raw/normalized events underlying an alert. An alert can reference
multiple events — this is what powers the investigation timeline
(architecture doc section 11)."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.alert_id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_type: Mapped[str] = mapped_column(String(64))  # e.g. "process_start", "network_connection"
    description: Mapped[str] = mapped_column(String(1000))
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    alert: Mapped["Alert"] = relationship(back_populates="events")
