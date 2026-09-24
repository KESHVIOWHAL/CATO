# Functional tests - these PASS even though the app has security issues
# This demonstrates: "Passing tests ≠ Trustworthy software"

import pytest
from app import calculate, process_data

def test_calculate_addition():
    assert calculate(2, 3) == 5

def test_calculate_zero():
    assert calculate(0, 0) == 0

def test_process_data_strips_whitespace():
    result = process_data(["  hello  ", "  world  "])
    assert result == ["hello", "world"]

def test_process_data_filters_empty():
    result = process_data(["item1", "", "item2"])
    assert result == ["item1", "item2"]
