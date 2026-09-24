import pytest
from app import calculate_discount, format_currency

def test_discount_ten_percent():
    assert calculate_discount(1000, 10) == 900.0

def test_discount_zero():
    assert calculate_discount(500, 0) == 500.0

def test_format_currency():
    assert format_currency(999.5) == "₹999.50"

def test_format_zero():
    assert format_currency(0) == "₹0.00"
