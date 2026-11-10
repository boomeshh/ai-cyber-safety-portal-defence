"""
test_firebase_auth.py — Isolated unit tests for the Firebase ID Token
verification dependency (firebase_auth.verify_firebase_token).

Strategy
--------
- Set RAKSHAK_TESTING=1 so firebase_auth skips Firebase App initialisation.
- Patch `firebase_admin.auth.verify_id_token` with unittest.mock — zero live
  Google network calls.
- Simulate the FastAPI request/response cycle by constructing
  HTTPAuthorizationCredentials objects directly (no TestClient needed).
- Each test is fully independent; no shared state.

Coverage
--------
  a) Valid token  → returns correct uid / email claims dict
  b) Expired token → raises HTTP 401 with detail "Token has expired"
  c) Invalid / corrupted token → raises HTTP 401 with detail "Invalid authentication token"
  d) Missing Authorization header → raises HTTP 401 with
     detail "Missing or invalid authentication credentials"
  e) Empty bearer value → same 401 as (d)
  f) Revoked token → raises HTTP 401 with detail "Invalid authentication token"
  g) Extra custom claims are forwarded to caller
"""

import os
import pytest
from unittest.mock import MagicMock, patch

# Tell firebase_auth to skip Firebase App initialisation
os.environ.setdefault("RAKSHAK_TESTING", "1")

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

# Module under test
import firebase_auth as fa


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _creds(token: str) -> HTTPAuthorizationCredentials:
    """Build an HTTPAuthorizationCredentials object as FastAPI would."""
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


# ---------------------------------------------------------------------------
# a) Valid token — returns correct uid / email
# ---------------------------------------------------------------------------

class TestValidToken:
    def test_returns_uid_and_email(self):
        mock_decoded = {
            "uid": "firebase-uid-abc123",
            "email": "user@example.com",
            "iss": "https://securetoken.google.com/project",
        }
        with patch("firebase_admin.auth.verify_id_token", return_value=mock_decoded):
            result = fa.verify_firebase_token(credentials=_creds("valid.token.here"))

        assert result["uid"] == "firebase-uid-abc123"
        assert result["email"] == "user@example.com"

    def test_does_not_raise(self):
        mock_decoded = {"uid": "uid-xyz", "email": "admin@test.com"}
        with patch("firebase_admin.auth.verify_id_token", return_value=mock_decoded):
            # Should not raise
            fa.verify_firebase_token(credentials=_creds("any.valid.token"))

    def test_uid_via_user_id_field(self):
        """Firebase sometimes uses 'user_id' instead of 'uid'."""
        mock_decoded = {"user_id": "uid-from-user-id-field", "email": "x@y.com"}
        with patch("firebase_admin.auth.verify_id_token", return_value=mock_decoded):
            result = fa.verify_firebase_token(credentials=_creds("token"))
        assert result["uid"] == "uid-from-user-id-field"


# ---------------------------------------------------------------------------
# b) Expired token — 401 "Token has expired"
# ---------------------------------------------------------------------------

class TestExpiredToken:
    def test_raises_401(self):
        import firebase_admin.auth as fb_auth
        # ExpiredIdTokenError(message, cause) — cause is positional, not keyword
        with patch(
            "firebase_admin.auth.verify_id_token",
            side_effect=fb_auth.ExpiredIdTokenError("token expired", None),
        ):
            with pytest.raises(HTTPException) as exc_info:
                fa.verify_firebase_token(credentials=_creds("expired.token"))

        assert exc_info.value.status_code == 401

    def test_detail_message(self):
        import firebase_admin.auth as fb_auth
        with patch(
            "firebase_admin.auth.verify_id_token",
            side_effect=fb_auth.ExpiredIdTokenError("token expired", None),
        ):
            with pytest.raises(HTTPException) as exc_info:
                fa.verify_firebase_token(credentials=_creds("expired.token"))

        assert exc_info.value.detail == "Token has expired"


# ---------------------------------------------------------------------------
# c) Invalid / corrupted token — 401 "Invalid authentication token"
# ---------------------------------------------------------------------------

class TestInvalidToken:
    def test_invalid_raises_401(self):
        import firebase_admin.auth as fb_auth
        with patch(
            "firebase_admin.auth.verify_id_token",
            side_effect=fb_auth.InvalidIdTokenError("bad token"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                fa.verify_firebase_token(credentials=_creds("corrupted.garbage"))

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid authentication token"

    def test_revoked_raises_401(self):
        """Revoked tokens must also be rejected with the same message."""
        import firebase_admin.auth as fb_auth
        # RevokedIdTokenError(message) — single positional arg
        with patch(
            "firebase_admin.auth.verify_id_token",
            side_effect=fb_auth.RevokedIdTokenError("revoked"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                fa.verify_firebase_token(credentials=_creds("revoked.token"))

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid authentication token"

    def test_wrong_signature_raises_401(self):
        """Any unexpected exception during verification → 401."""
        with patch(
            "firebase_admin.auth.verify_id_token",
            side_effect=ValueError("unexpected error"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                fa.verify_firebase_token(credentials=_creds("bad.sig.token"))

        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# d) Missing Authorization header — 401 "Missing or invalid …"
# ---------------------------------------------------------------------------

class TestMissingHeader:
    def test_none_credentials_raises_401(self):
        with pytest.raises(HTTPException) as exc_info:
            fa.verify_firebase_token(credentials=None)

        assert exc_info.value.status_code == 401
        assert "Missing or invalid" in exc_info.value.detail

    def test_empty_bearer_value_raises_401(self):
        """An Authorization: Bearer <empty> header should also be rejected."""
        with pytest.raises(HTTPException) as exc_info:
            fa.verify_firebase_token(credentials=_creds("   "))

        assert exc_info.value.status_code == 401
        assert "Missing or invalid" in exc_info.value.detail


# ---------------------------------------------------------------------------
# g) Extra custom claims are forwarded
# ---------------------------------------------------------------------------

class TestExtraClaimsForwarded:
    def test_custom_claims_in_result(self):
        mock_decoded = {
            "uid": "uid-claims-test",
            "email": "claims@test.com",
            "role": "admin",
            "plan": "enterprise",
        }
        with patch("firebase_admin.auth.verify_id_token", return_value=mock_decoded):
            result = fa.verify_firebase_token(credentials=_creds("claims.token"))

        assert result["role"] == "admin"
        assert result["plan"] == "enterprise"
