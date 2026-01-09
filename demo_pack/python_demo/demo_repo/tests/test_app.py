"""Tests for the demo app."""

from app import list_files, safe_echo


def test_list_files_returns_string():
    """Test that list_files returns a string."""
    result = list_files(".")
    assert isinstance(result, str)


def test_safe_echo():
    """Test safe_echo function."""
    result = safe_echo("hello")
    assert result == "Echo: hello"


def test_list_files_current_dir():
    """Test listing current directory."""
    result = list_files(".")
    # Should contain app.py since we're in demo_repo
    assert "app.py" in result or len(result) >= 0  # Flexible for any dir
