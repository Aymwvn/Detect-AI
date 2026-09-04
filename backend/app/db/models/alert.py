"""The persisted form of CommonAlertSchema (app/schemas/common_alert_schema.py).

Field-for-field mirror of the Pydantic schema, plus DetectAI-internal
foreign keys (incident_id, connector_id) that don't exist on the wire
format. Conversion between the two happens in the ingestion service
(Phase 10) — this file has zero business logic, it's persistence only.
"""

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    # --- identity & provenance ---------------------------------------------
    alert_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    external_alert_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    source: Mapped[str] = mapped_column(String(255))
    source_product: Mapped[str] = mapped_column(String(64))

    # --- classification -------------------------------------------------------
    severity: Mapped[str] = mapped_column(String(32), default="unknown")
    rule_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String(4000), nullable=True)

    # --- host / identity ----------------------------------------------------
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)

    # --- network -------------------------------------------------------------
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    # --- process -------------------------------------------------------------
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    parent_process: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    command_line: Mapped[Optional[str]] = mapped_column(String(4000), nullable=True)

    # --- file / artifact -------------------------------------------------------
    file_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    file_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # --- web / dns -------------------------------------------------------------
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)

    # --- cloud / identity context -----------------------------------------------
    cloud_account: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    authentication_context: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # --- correlation & context -------------------------------------------------
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    existing_mitre_attack_mapping: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    # --- DetectAI-internal state -------------------------------------------------
    status: Mapped[str] = mapped_column(String(32), default="new")
    dedup_group_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    # Exact-match signature computed from entity keys + rule_id (Phase 11).
    # Two alerts sharing a signature within the correlation window are
    # treated as duplicates of the same underlying event.
    dedup_signature: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    # Rule-based risk score (Phase 12) — computed independent of any LLM,
    # so the pipeline is fully functional with AI_PROVIDER=none. breakdown
    # is the transparent "why this score" explanation shown to analysts.
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    risk_score_breakdown: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    investigation_priority: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    incident_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("incidents.id"), nullable=True, index=True
    )
    incident: Mapped[Optional["Incident"]] = relationship(back_populates="alerts")

    connector_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("connectors.id"), nullable=True, index=True
    )

    events: Mapped[list["Event"]] = relationship(back_populates="alert", cascade="all, delete-orphan")
    ai_analyses: Mapped[list["AIAnalysis"]] = relationship(back_populates="alert", cascade="all, delete-orphan")
    feedback: Mapped[list["AnalystFeedback"]] = relationship(back_populates="alert", cascade="all, delete-orphan")
