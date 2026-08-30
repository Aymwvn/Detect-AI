"""Configured SIEM/data sources. Credentials are referenced, never stored
in plaintext here — `credential_ref` points at wherever the real secret
manager keeps the actual key (env var name, vault path, etc.)."""

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Connector(Base):
    __tablename__ = "connectors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), unique=True)
    source_product: Mapped[str] = mapped_column(String(64))  # matches SourceProduct enum values
    status: Mapped[str] = mapped_column(String(32), default="inactive")  # active/inactive/error
    credential_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # non-secret config only
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
