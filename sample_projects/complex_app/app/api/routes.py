"""API routes module."""
import subprocess
from app.database.db import find_user, find_order
from app.auth.auth import verify_token


def handle_user_request(username: str, token: str):
    """Handle user lookup request."""
    if not verify_token(token):
        return {"error": "unauthorized"}
    return find_user(username)


def handle_order_request(order_id: str, token: str):
    """Handle order lookup."""
    if not verify_token(token):
        return {"error": "unauthorized"}
    return find_order(order_id)


def run_export(export_type: str):
    """Run data export — command injection vulnerability."""
    # VULNERABILITY: shell=True with user-controlled input
    cmd = f"python scripts/export_{export_type}.py"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()


def health_check() -> dict:
    return {"status": "ok", "version": "1.0.0"}
