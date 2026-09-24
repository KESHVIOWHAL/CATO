import pytest
from app import calculate_tax, format_report, check_permission

def test_tax_standard():
    result = calculate_tax(1000)
    assert result == 180.0

def test_tax_zero():
    result = calculate_tax(0)
    assert result == 0.0

def test_format_report_header():
    result = format_report([])
    assert result.startswith("id,value,status")

def test_format_report_data():
    result = format_report([(1, "test", "ok")])
    assert "1,test,ok" in result

def test_permission_admin_has_access():
    has_access = check_permission("admin", "viewer")
    assert has_access is True

def test_permission_viewer_restricted():
    has_access = check_permission("viewer", "admin")
    assert has_access is False
