"""Entities seen across alerts (hosts, users, IPs, hashes, domains).

This is what makes correlation and context-aware risk scoring possible:
asset criticality and user privilege lookups both live here, keyed by
entity, rather than being re-guessed per alert.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (UniqueConstraint("entity_type", "value", name="uq_entity_type_value"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    entity_type: Mapped[str] = mapped_column(String(32))  # host | user | ip | hash | domain | cloud_account
    value: Mapped[str] = mapped_column(String(512))

    # Context used by the risk engine (Phase 12). Populated manually or via
    # an asset-inventory import — never guessed by the AI.
    criticality: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # low/medium/high/critical
    privilege_level: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)  # e.g. "domain_admin"
    notes: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
