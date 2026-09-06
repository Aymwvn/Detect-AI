"""User accounts for authentication and RBAC (architecture doc section 14:
RBAC roles viewer/analyst/admin). Passwords are never stored in plaintext
— only the bcrypt hash (see app/core/security.py)."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

VALID_ROLES = ("viewer", "analyst", "admin")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    # Public registration always assigns "viewer" (see app/api/auth.py) —
    # analyst/admin roles are granted by an existing admin, never
    # self-selected at signup, to prevent privilege escalation via
    # registration.
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
