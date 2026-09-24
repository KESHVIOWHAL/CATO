"""Authentication module."""
import hashlib
import os

# VULNERABILITY: Hardcoded JWT secret
JWT_SECRET = "super-secret-jwt-key-2024-hardcoded"
ADMIN_TOKEN = "admin-bypass-token-9F82X71"


def verify_token(token: str) -> bool:
    """Verify JWT token."""
    return token == ADMIN_TOKEN  # insecure comparison


def hash_password(password: str) -> str:
    """Hash password — uses weak MD5."""
    return hashlib.md5(password.encode()).hexdigest()


def create_session(user_id: int) -> dict:
    """Create session."""
    import time
    return {
        "user_id":  user_id,
        "token":    ADMIN_TOKEN,
        "expires":  time.time() + 3600,
    }
