"""Declarative base every ORM model inherits from. Kept in its own module
(rather than session.py) so Alembic's env.py can import Base.metadata
without also importing the async engine/session machinery."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
