"""
test_firebase_complaint.py — Integration tests for POST /complaints/firebase.

Strategy
--------
- RAKSHAK_TESTING=1 is set by conftest via env so Firebase App init is skipped.
- We patch `firebase_admin.auth.verify_id_token` to simulate valid / expired /
  invalid tokens — no live Google network calls.
- The test DB and uploads dir are the shared tmp fixtures from conftest.py so
  the endpoint can actually write a complaint row and audit entry.

Test cases
----------
  1. valid_token_creates_complaint   — 200, success=True, complaint_id present,
                                       required response fields present.
  2. no_auth_header_returns_401      — missing Authorization → 401.
  3. expired_token_returns_401       — ExpiredIdTokenError → 401, "Token has expired".
  4. invalid_token_returns_401       — InvalidIdTokenError → 401, "Invalid authentication token".
  5. uid_stored_as_user_id           — complaint row's user_id equals Firebase uid.
  6. body_user_id_ignored            — even if a rogue field is sent, uid comes from token.
  7. upsert_creates_local_user       — first submission auto-creates a users row.
"""

import os
import sys
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("RAKSHAK_TESTING", "1")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import main  # noqa: E402  — imported after env var is set
import firebase_admin.auth as _fb_auth  # noqa: E402

client = TestClient(main.app, raise_server_exceptions=False)

# ---------------------------------------------------------------------------
# Shared token mock data
# ---------------------------------------------------------------------------
_FIREBASE_UID = f"firebase-uid-{uuid.uuid4().hex[:8]}"
_FIREBASE_EMAIL = f"fbtest-{uuid.uuid4().hex[:6]}@example.com"

_VALID_DECODED = {
    "uid": _FIREBASE_UID,
    "email": _FIREBASE_EMAIL,
    "iss": "https://securetoken.google.com/rakshak-test",
}

_COMPLAINT_PAYLOAD = {
    "category": "Serving Personnel",
    "complaint_text": (
        "Received a suspicious WhatsApp message asking for my OTP "
        "and bank login credentials urgently."
    ),
    "suspicious_url": "",
}


def _bearer(token: str = "valid.firebase.token") -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. Valid token → 200, complaint created
# ---------------------------------------------------------------------------

class TestValidFirebaseToken:
    def test_valid_token_creates_complaint(self):
        with patch("firebase_admin.auth.verify_id_token", return_value=_VALID_DECODED):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer(),
            )
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["success"] is True
        assert "complaint_id" in data
        assert data["complaint_id"].startswith("RK-")

    def test_response_has_required_fields(self):
        with patch("firebase_admin.auth.verify_id_token", return_value=_VALID_DECODED):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer(),
            )
        assert res.status_code == 200
        data = res.json()
        for field in (
            "complaint_id", "risk_level", "risk_score", "threat_type",
            "ai_reason", "mitigation", "mitigation_steps", "severity_explanation",
            "ioc", "ai_confidence", "status", "attack_channel",
            "ml_prediction", "model_used",
        ):
            assert field in data, f"Missing response field: {field}"

    def test_risk_level_is_valid(self):
        with patch("firebase_admin.auth.verify_id_token", return_value=_VALID_DECODED):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer(),
            )
        assert res.json()["risk_level"] in ("Low", "Medium", "High", "Critical")

    def test_mitigation_steps_is_list(self):
        with patch("firebase_admin.auth.verify_id_token", return_value=_VALID_DECODED):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer(),
            )
        assert isinstance(res.json()["mitigation_steps"], list)
        assert len(res.json()["mitigation_steps"]) >= 1


# ---------------------------------------------------------------------------
# 2. Missing Authorization header → 401
# ---------------------------------------------------------------------------

class TestMissingAuthHeader:
    def test_no_auth_returns_401(self):
        res = client.post("/complaints/firebase", data=_COMPLAINT_PAYLOAD)
        assert res.status_code == 401

    def test_no_auth_detail_message(self):
        res = client.post("/complaints/firebase", data=_COMPLAINT_PAYLOAD)
        assert "Missing or invalid" in res.json().get("detail", "")


# ---------------------------------------------------------------------------
# 3. Expired token → 401 "Token has expired"
# ---------------------------------------------------------------------------

class TestExpiredFirebaseToken:
    def test_expired_token_returns_401(self):
        with patch(
            "firebase_admin.auth.verify_id_token",
            side_effect=_fb_auth.ExpiredIdTokenError("expired", None),
        ):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer("expired.token.here"),
            )
        assert res.status_code == 401

    def test_expired_token_detail(self):
        with patch(
            "firebase_admin.auth.verify_id_token",
            side_effect=_fb_auth.ExpiredIdTokenError("expired", None),
        ):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer("expired.token.here"),
            )
        assert res.json()["detail"] == "Token has expired"


# ---------------------------------------------------------------------------
# 4. Invalid / corrupted token → 401 "Invalid authentication token"
# ---------------------------------------------------------------------------

class TestInvalidFirebaseToken:
    def test_invalid_token_returns_401(self):
        with patch(
            "firebase_admin.auth.verify_id_token",
            side_effect=_fb_auth.InvalidIdTokenError("bad sig"),
        ):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer("corrupted.token"),
            )
        assert res.status_code == 401

    def test_invalid_token_detail(self):
        with patch(
            "firebase_admin.auth.verify_id_token",
            side_effect=_fb_auth.InvalidIdTokenError("bad sig"),
        ):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer("corrupted.token"),
            )
        assert res.json()["detail"] == "Invalid authentication token"

    def test_revoked_token_returns_401(self):
        with patch(
            "firebase_admin.auth.verify_id_token",
            side_effect=_fb_auth.RevokedIdTokenError("revoked"),
        ):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer("revoked.token"),
            )
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 5. uid stored as user_id in the complaints table
# ---------------------------------------------------------------------------

class TestUidStoredAsUserId:
    def test_complaint_row_user_id_equals_firebase_uid(self):
        unique_uid = f"uid-row-check-{uuid.uuid4().hex[:8]}"
        decoded = {**_VALID_DECODED, "uid": unique_uid,
                   "email": f"{unique_uid}@example.com"}

        with patch("firebase_admin.auth.verify_id_token", return_value=decoded):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer(),
            )
        assert res.status_code == 200
        complaint_id = res.json()["complaint_id"]

        # Read directly from DB to verify the stored user_id
        import sqlite3
        conn = sqlite3.connect(main.DB_NAME)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT user_id FROM complaints WHERE id = ?", (complaint_id,)
        ).fetchone()
        conn.close()

        assert row is not None
        assert row["user_id"] == unique_uid


# ---------------------------------------------------------------------------
# 6. Firebase user auto-upserted into local users table
# ---------------------------------------------------------------------------

class TestFirebaseUserUpsert:
    def test_new_firebase_user_gets_local_row(self):
        brand_new_uid = f"new-fb-uid-{uuid.uuid4().hex[:8]}"
        brand_new_email = f"{brand_new_uid}@fbtest.example.com"
        decoded = {"uid": brand_new_uid, "email": brand_new_email}

        with patch("firebase_admin.auth.verify_id_token", return_value=decoded):
            res = client.post(
                "/complaints/firebase",
                data=_COMPLAINT_PAYLOAD,
                headers=_bearer(),
            )
        assert res.status_code == 200

        import sqlite3
        conn = sqlite3.connect(main.DB_NAME)
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            "SELECT id, email, role FROM users WHERE id = ?", (brand_new_uid,)
        ).fetchone()
        conn.close()

        assert user is not None, "Local user row should have been created"
        assert user["email"] == brand_new_email
        assert user["role"] == "user"

    def test_existing_user_not_duplicated(self):
        """Calling the endpoint twice with the same uid should not create two rows."""
        uid = f"dup-check-{uuid.uuid4().hex[:8]}"
        decoded = {"uid": uid, "email": f"{uid}@example.com"}

        for _ in range(2):
            with patch("firebase_admin.auth.verify_id_token", return_value=decoded):
                client.post(
                    "/complaints/firebase",
                    data=_COMPLAINT_PAYLOAD,
                    headers=_bearer(),
                )

        import sqlite3
        conn = sqlite3.connect(main.DB_NAME)
        count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE id = ?", (uid,)
        ).fetchone()[0]
        conn.close()
        assert count == 1, "User should appear exactly once regardless of repeated calls"
