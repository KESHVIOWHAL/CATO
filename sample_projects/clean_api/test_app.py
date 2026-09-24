import pytest
from app import validate_email, paginate, hash_password

def test_valid_email():
    assert validate_email("user@example.com") is True

def test_invalid_email():
    assert validate_email("notanemail") is False

def test_paginate_first_page():
    items = list(range(50))
    result = paginate(items, 1, 10)
    assert result["items"] == list(range(10))
    assert result["total"] == 50

def test_paginate_second_page():
    items = list(range(50))
    result = paginate(items, 2, 10)
    assert result["items"] == list(range(10, 20))

def test_hash_password_consistency():
    h1 = hash_password("secret")
    h2 = hash_password("secret")
    assert h1 == h2

def test_hash_password_different():
    assert hash_password("abc") != hash_password("xyz")
