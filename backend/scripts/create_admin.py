"""
Creates or promotes a user to admin. Since public registration
(POST /auth/register) always assigns "viewer" by design (see
app/api/auth.py), this script is the only way to create the first admin
account — run it directly against the database, not through the API.

Usage:
    python scripts/create_admin.py <username> <password>

If the username already exists, it's promoted to admin (password
unchanged). Otherwise a new admin user is created with the given password.
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import select

sys.path.insert(0, ".")  # allow running as `python scripts/create_admin.py` from backend/

from app.core.security import hash_password  # noqa: E402
from app.db.models import User  # noqa: E402
from app.db.session import AsyncSessionLocal  # noqa: E402


async def create_or_promote_admin(username: str, password: str) -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()

        if user is not None:
            user.role = "admin"
            print(f"Promoted existing user '{username}' to admin.")
        else:
            user = User(username=username, hashed_password=hash_password(password), role="admin")
            db.add(user)
            print(f"Created new admin user '{username}'.")

        await db.commit()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scripts/create_admin.py <username> <password>")
        sys.exit(1)
    asyncio.run(create_or_promote_admin(sys.argv[1], sys.argv[2]))
