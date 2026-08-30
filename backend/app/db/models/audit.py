"""Append-only audit trail (architecture doc section 14). Application code
should only ever INSERT into this table — no update/delete path is exposed
anywhere in the API by design."""

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    actor: Mapped[str] = mapped_column(String(255))  # user id or "system"/connector name
    action: Mapped[str] = mapped_column(String(64))  # e.g. "feedback_submitted", "alert_status_changed"
    object_type: Mapped[str] = mapped_column(String(64))  # e.g. "alert", "incident", "connector"
    object_id: Mapped[str] = mapped_column(String(36))
    details: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
