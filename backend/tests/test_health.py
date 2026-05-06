"""
Tests for GET /health endpoint.

Validates:
- Returns HTTP 200
- Response body contains status=ok
- No Authorization header required
"""

import sys
import os

import pytest
from fastapi.testclient import TestClient

# Allow importing from backend/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app  # noqa: E402

client = TestClient(app)


def test_health_returns_200():
    """GET /health must return HTTP 200 with no auth header."""
    response = client.get("/health")
    assert response.status_code == 200, (
        f"Expected 200, got {response.status_code}"
    )


def test_health_status_ok():
    """Response body must contain status=ok."""
    response = client.get("/health")
    data = response.json()
    assert data.get("status") == "ok", (
        f"Expected status='ok', got {data.get('status')!r}"
    )


def test_health_service_name():
    """Response body must contain the correct service name."""
    response = client.get("/health")
    data = response.json()
    assert data.get("service") == "rakshak-ai-backend", (
        f"Expected service='rakshak-ai-backend', got {data.get('service')!r}"
    )


def test_health_no_auth_required():
    """Endpoint must work without any Authorization header."""
    response = client.get("/health", headers={})
    assert response.status_code == 200, (
        "Health check should not require Authorization header"
    )


def test_health_head_returns_200():
    """HEAD /health must return HTTP 200 with empty body."""
    response = client.head("/health")
    assert response.status_code == 200, (
        f"HEAD /health expected 200, got {response.status_code}"
    )


def test_health_head_no_auth_required():
    """HEAD /health must work without Authorization header."""
    response = client.head("/health", headers={})
    assert response.status_code == 200, (
        "HEAD /health should not require Authorization header"
    )
