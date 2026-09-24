"""Medium-risk application — some issues present but no critical secrets."""
import os
import hashlib
import sqlite3


DB_PATH = os.environ.get("DB_PATH", "app.db")


def get_record(table: str, record_id: int):
    """Fetch record — table name not parameterizable in SQLite."""
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # MEDIUM: table name interpolation (limited injection surface)
    cursor.execute(f"SELECT * FROM {table} WHERE id = ?", (record_id,))
    return cursor.fetchone()


def hash_token(token: str) -> str:
    """Hash a token — uses MD5 which is cryptographically weak."""
    # MEDIUM: MD5 is broken for security use cases
    return hashlib.md5(token.encode()).hexdigest()


def check_permission(user_role: str, required_role: str) -> bool:
    """Check user permission."""
    roles = ["viewer", "editor", "admin"]
    # MEDIUM: assert used for security check (disabled in -O mode)
    assert user_role in roles, f"Invalid role: {user_role}"
    return roles.index(user_role) >= roles.index(required_role)


def load_config(path: str) -> dict:
    """Load YAML config."""
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


def calculate_tax(amount: float, rate: float = 0.18) -> float:
    """Calculate GST."""
    return round(amount * rate, 2)


def format_report(data: list) -> str:
    """Format data as CSV."""
    lines = ["id,value,status"]
    for row in data:
        lines.append(",".join(str(x) for x in row))
    return "\n".join(lines)
