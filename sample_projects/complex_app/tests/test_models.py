import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app.models.user import User, Order
from app.utils.helpers import validate_email, sanitize_input, chunk_list, format_inr
from app.services.payment import calculate_total


def test_user_is_admin():
    u = User(1, "alice", "alice@example.com", role="admin")
    assert u.is_admin() is True


def test_user_viewer_not_admin():
    u = User(2, "bob", "bob@example.com", role="viewer")
    assert u.is_admin() is False


def test_order_paid():
    o = Order("ORD-001", 1, 500.0, status="paid")
    assert o.is_paid() is True


def test_validate_email_valid():
    assert validate_email("test@example.com") is True


def test_validate_email_invalid():
    assert validate_email("bad-email") is False


def test_sanitize_removes_angle():
    result = sanitize_input("<script>alert(1)</script>")
    assert "<" not in result


def test_chunk_list():
    assert chunk_list([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]


def test_format_inr():
    assert format_inr(1000.0) == "₹1,000.00"


def test_calculate_total():
    items = [{"price": 100, "qty": 2}, {"price": 50, "qty": 1}]
    assert calculate_total(items) == 250.0
