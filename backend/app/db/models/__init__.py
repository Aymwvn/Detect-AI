"""Importing this module registers every ORM model against Base.metadata —
required so Alembic's autogenerate (and metadata.create_all in tests) sees
the full schema, not just whichever models happened to be imported directly.
"""

from app.db.base import Base
from app.db.models.ai_analysis import AIAnalysis
from app.db.models.alert import Alert
from app.db.models.audit import AuditLog
from app.db.models.connector import Connector
from app.db.models.entity import Entity
from app.db.models.event import Event
from app.db.models.feedback import AnalystFeedback
from app.db.models.incident import Incident
from app.db.models.mitre import MitreTechnique

__all__ = [
    "Base",
    "Alert",
    "Event",
    "Incident",
    "Entity",
    "MitreTechnique",
    "AIAnalysis",
    "AnalystFeedback",
    "AuditLog",
    "Connector",
]
