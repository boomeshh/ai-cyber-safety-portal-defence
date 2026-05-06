"""
conftest.py — pytest session fixtures for Rakshak AI backend tests.

Resets the in-memory rate limiter before each test module so that
running all test files together doesn't cause 429 failures from
accumulated login/register calls across modules.
"""

import pytest


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Clear the in-memory rate limit store before every test."""
    try:
        from security_utils import _rate_limit_store
        _rate_limit_store.clear()
    except Exception:
        pass
