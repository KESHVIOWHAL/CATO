"""Utility helpers."""
import re
import json
from typing import Any


def validate_email(email: str) -> bool:
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))


def sanitize_input(text: str) -> str:
    """Remove dangerous characters."""
    return re.sub(r'[<>&"\'`;]', '', text)


def safe_json_loads(data: str) -> Any:
    """Safely parse JSON."""
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return None


def chunk_list(lst: list, size: int) -> list:
    """Split list into chunks."""
    return [lst[i:i + size] for i in range(0, len(lst), size)]


def format_inr(amount: float) -> str:
    return f"₹{amount:,.2f}"
