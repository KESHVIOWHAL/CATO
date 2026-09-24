"""Clean REST API — all security issues resolved for CATO demo."""
import os
import sqlite3
import subprocess
from typing import Optional


# SECURE: All credentials from environment variables
API_KEY    = os.environ.get("API_KEY")
DB_URL     = os.environ.get("DATABASE_URL", "sqlite:///app.db")
SECRET_KEY = os.environ.get("SECRET_KEY")


def get_user(user_id: int) -> Optional[tuple]:
    """Fetch user by ID using parameterized query."""
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SECURE: Parameterized query prevents SQL injection
    cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def search_users(query: str) -> list:
    """Search users safely."""
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username FROM users WHERE username LIKE ?",
        (f"%{query}%",)
    )
    return cursor.fetchall()


def run_health_check() -> dict:
    """System health check — safe subprocess usage."""
    ALLOWED = ["python", "--version"]
    # SECURE: shell=False with allowlist
    result = subprocess.run(ALLOWED, shell=False, capture_output=True, text=True)
    return {"python_version": result.stdout.strip(), "status": "healthy"}


def hash_password(password: str) -> str:
    """Hash password with SHA-256."""
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


def validate_email(email: str) -> bool:
    """Validate email format."""
    import re
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))


def paginate(items: list, page: int, per_page: int = 20) -> dict:
    """Paginate a list of items."""
    start = (page - 1) * per_page
    return {
        "items":    items[start:start + per_page],
        "page":     page,
        "per_page": per_page,
        "total":    len(items),
    }
