"""MITRE ATT&CK technique reference data, synced from the public STIX/JSON
bundle (see docs/ARCHITECTURE.md section 10 — synced periodically, not a
live external dependency at request time)."""

from typing import Optional

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # e.g. "T1059.001"
    name: Mapped[str] = mapped_column(String(255))
    tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String(4000), nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
