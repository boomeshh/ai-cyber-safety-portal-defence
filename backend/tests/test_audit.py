"""
Production readiness audit tests for Rakshak AI backend.

Covers:
- Public endpoints (health, root, docs)
- Auth flow (register, login, logout, /me)
- User flow (submit complaint, my-complaints)
- Admin flow (overview, status update, complaints list)
- CERT flow (intel, live-alerts, escalated, summary)
- Security (unauthenticated requests rejected, role enforcement)
- Evidence endpoints (auth required)
- AI/ML endpoints (model-info, metrics, retrain-status)
- Email alert endpoint (test-email-alert admin-only)
- Duplicate registration prevention
"""

import sys
import os
import uuid

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from main import app  # noqa: E402

client = TestClient(app, raise_server_exceptions=False)

# ---------------------------------------------------------------------------
# Module-level token cache — each role logs in ONCE to avoid rate limit
# ---------------------------------------------------------------------------
_TOKEN_CACHE: dict = {}


def _get_token(email: str, password: str, cache_key: str) -> str:
    if cache_key not in _TOKEN_CACHE:
        res = client.post("/login", json={"email": email, "password": password})
        if res.status_code != 200:
            pytest.fail(f"Login failed for {email}: {res.text}")
        _TOKEN_CACHE[cache_key] = res.json()["token"]
    return _TOKEN_CACHE[cache_key]


def _admin_token() -> str:
    return _get_token("admin@rakshak.ai", "admin123", "admin")


def _cert_token() -> str:
    return _get_token("cert@rakshak.ai", "cert123", "cert")


def _user_token() -> str:
    """Register once and cache the user token."""
    if "user" not in _TOKEN_CACHE:
        email = f"audit_user_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/register", json={
            "full_name": "Audit Test User",
            "email": email,
            "password": "TestPass123",
            "role": "user",
        })
        res = client.post("/login", json={"email": email, "password": "TestPass123"})
        if res.status_code != 200:
            pytest.fail(f"User login failed: {res.text}")
        _TOKEN_CACHE["user"] = res.json()["token"]
        _TOKEN_CACHE["user_id"] = res.json()["user"]["id"]
    return _TOKEN_CACHE["user"]


def _user_id() -> str:
    _user_token()  # ensure registered
    return _TOKEN_CACHE["user_id"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. Public endpoints
# ---------------------------------------------------------------------------

class TestPublicEndpoints:
    def test_root_returns_200(self):
        res = client.get("/")
        assert res.status_code == 200

    def test_health_get_returns_200(self):
        res = client.get("/health")
        assert res.status_code == 200

    def test_health_body(self):
        res = client.get("/health")
        data = res.json()
        assert data["status"] == "ok"
        assert data["service"] == "rakshak-ai-backend"

    def test_health_head_returns_200(self):
        res = client.head("/health")
        assert res.status_code == 200

    def test_docs_accessible(self):
        res = client.get("/docs")
        assert res.status_code == 200


# ---------------------------------------------------------------------------
# 2. Auth flow
# ---------------------------------------------------------------------------

class TestAuthFlow:
    def test_register_new_user(self):
        email = f"audit_{uuid.uuid4().hex[:8]}@test.com"
        res = client.post("/register", json={
            "full_name": "Audit User",
            "email": email,
            "password": "SecurePass123",
            "role": "user",
        })
        assert res.status_code == 200
        assert res.json().get("success") is True

    def test_duplicate_registration_rejected(self):
        # Use the cached user email — already registered
        email = f"dup_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/register", json={"full_name": "A", "email": email, "password": "pass123", "role": "user"})
        res = client.post("/register", json={"full_name": "A", "email": email, "password": "pass123", "role": "user"})
        assert res.status_code == 200
        assert res.json().get("success") is False

    def test_login_valid_credentials(self):
        token = _admin_token()
        assert token

    def test_login_wrong_password_rejected(self):
        res = client.post("/login", json={"email": "admin@rakshak.ai", "password": "wrongpassword"})
        assert res.status_code == 200
        assert res.json().get("success") is False

    def test_admin_login_role(self):
        token = _admin_token()
        me = client.get("/me", headers=_auth(token)).json()
        assert me["user"]["role"] == "admin"

    def test_cert_login_role(self):
        token = _cert_token()
        me = client.get("/me", headers=_auth(token)).json()
        assert me["user"]["role"] == "cert"

    def test_me_with_valid_token(self):
        token = _admin_token()
        res = client.get("/me", headers=_auth(token))
        assert res.status_code == 200
        assert res.json()["success"] is True

    def test_me_without_token_rejected(self):
        res = client.get("/me")
        assert res.status_code == 401

    def test_invalid_token_rejected(self):
        res = client.get("/me", headers={"Authorization": "Bearer totally_fake_token"})
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 3. User flow — complaint submission
# ---------------------------------------------------------------------------

class TestUserFlow:
    def test_submit_complaint_authenticated(self):
        token = _user_token()
        uid = _user_id()
        res = client.post("/complaints", data={
            "user_id": uid,
            "user_name": "Audit Test User",
            "category": "Serving Personnel",
            "complaint_text": "Received a phishing email asking for my OTP and bank login credentials urgently.",
            "suspicious_url": "",
        }, headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert data.get("success") is True
        assert "complaint_id" in data
        assert data["risk_level"] in ("Low", "Medium", "High", "Critical")

    def test_submit_complaint_unauthenticated_rejected(self):
        res = client.post("/complaints", data={
            "user_id": "fake",
            "user_name": "fake",
            "category": "Serving Personnel",
            "complaint_text": "test",
        })
        assert res.status_code == 401

    def test_my_complaints_authenticated(self):
        token = _user_token()
        uid = _user_id()
        res = client.get(f"/my-complaints/{uid}", headers=_auth(token))
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_my_complaints_wrong_user_rejected(self):
        token = _user_token()
        res = client.get("/my-complaints/DIFFERENT-USER-ID", headers=_auth(token))
        assert res.status_code == 403

    def test_my_complaints_unauthenticated_rejected(self):
        res = client.get("/my-complaints/some-id")
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 4. Admin flow
# ---------------------------------------------------------------------------

class TestAdminFlow:
    def test_admin_overview_returns_200(self):
        token = _admin_token()
        res = client.get("/admin/overview", headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "analytics" in data
        assert "complaints" in data
        assert "users" in data

    def test_admin_overview_analytics_fields(self):
        token = _admin_token()
        data = client.get("/admin/overview", headers=_auth(token)).json()
        analytics = data["analytics"]
        for field in ("total", "critical", "high", "medium", "low", "open_cases", "escalated"):
            assert field in analytics, f"Missing analytics field: {field}"

    def test_admin_overview_unauthenticated_rejected(self):
        res = client.get("/admin/overview")
        assert res.status_code == 401

    def test_admin_overview_cert_role_rejected(self):
        token = _cert_token()
        res = client.get("/admin/overview", headers=_auth(token))
        assert res.status_code == 403

    def test_complaints_list_admin(self):
        token = _admin_token()
        res = client.get("/complaints", headers=_auth(token))
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_complaints_list_unauthenticated_rejected(self):
        res = client.get("/complaints")
        assert res.status_code == 401

    def test_status_update_admin(self):
        token = _admin_token()
        complaints = client.get("/complaints", headers=_auth(token)).json()
        if not complaints:
            pytest.skip("No complaints in DB to update")
        cid = complaints[0]["id"]
        current_status = complaints[0]["status"]
        new_status = "Under Review" if current_status != "Under Review" else "Open"
        res = client.put(f"/update-status/{cid}?status={new_status}", headers=_auth(token))
        assert res.status_code == 200
        assert res.json().get("success") is True

    def test_status_update_unauthenticated_rejected(self):
        res = client.put("/update-status/FAKE-ID?status=Open")
        assert res.status_code == 401

    def test_audit_logs_admin(self):
        token = _admin_token()
        res = client.get("/audit-logs", headers=_auth(token))
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_audit_logs_unauthenticated_rejected(self):
        res = client.get("/audit-logs")
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 5. CERT flow
# ---------------------------------------------------------------------------

class TestCertFlow:
    def test_cert_intel_returns_200(self):
        token = _cert_token()
        res = client.get("/cert/intel", headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "analytics" in data
        assert "summary" in data
        assert "feed" in data
        assert "heatmaps" in data

    def test_cert_intel_unauthenticated_rejected(self):
        res = client.get("/cert/intel")
        assert res.status_code == 401

    def test_cert_intel_user_role_rejected(self):
        token = _user_token()
        res = client.get("/cert/intel", headers=_auth(token))
        assert res.status_code == 403

    def test_cert_live_alerts(self):
        token = _cert_token()
        res = client.get("/cert/live-alerts", headers=_auth(token))
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_cert_escalated(self):
        token = _cert_token()
        res = client.get("/cert/escalated", headers=_auth(token))
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_cert_summary(self):
        token = _cert_token()
        res = client.get("/cert/summary", headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "total_cases" in data
        assert "critical_alerts" in data

    def test_analytics_endpoint(self):
        token = _cert_token()
        res = client.get("/analytics", headers=_auth(token))
        assert res.status_code == 200

    def test_excel_export_admin(self):
        token = _admin_token()
        res = client.get("/download/excel", headers=_auth(token))
        assert res.status_code == 200

    def test_excel_export_unauthenticated_rejected(self):
        res = client.get("/download/excel")
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 6. Evidence endpoints
# ---------------------------------------------------------------------------

class TestEvidenceEndpoints:
    def test_evidence_requires_auth(self):
        res = client.get("/complaints/FAKE-ID/evidence")
        assert res.status_code == 401

    def test_evidence_meta_requires_auth(self):
        res = client.get("/complaints/FAKE-ID/evidence-meta")
        assert res.status_code == 401

    def test_evidence_meta_authenticated_nonexistent(self):
        token = _admin_token()
        res = client.get("/complaints/NONEXISTENT-ID/evidence-meta", headers=_auth(token))
        assert res.status_code in (200, 404)

    def test_evidence_file_authenticated_nonexistent(self):
        token = _admin_token()
        res = client.get("/complaints/NONEXISTENT-ID/evidence", headers=_auth(token))
        assert res.status_code in (404, 400)


# ---------------------------------------------------------------------------
# 7. AI / ML endpoints
# ---------------------------------------------------------------------------

class TestAIEndpoints:
    def test_model_info_admin(self):
        token = _admin_token()
        res = client.get("/ai/model-info", headers=_auth(token))
        assert res.status_code == 200

    def test_model_info_unauthenticated_rejected(self):
        res = client.get("/ai/model-info")
        assert res.status_code == 401

    def test_ai_metrics_admin(self):
        token = _admin_token()
        res = client.get("/ai/metrics", headers=_auth(token))
        assert res.status_code == 200

    def test_ai_metrics_unauthenticated_rejected(self):
        res = client.get("/ai/metrics")
        assert res.status_code == 401

    def test_retrain_status_admin(self):
        token = _admin_token()
        res = client.get("/ai/retrain-status", headers=_auth(token))
        assert res.status_code == 200

    def test_synthetic_summary_admin(self):
        token = _admin_token()
        res = client.get("/ai/synthetic-summary", headers=_auth(token))
        assert res.status_code == 200


# ---------------------------------------------------------------------------
# 8. Email alert test endpoint
# ---------------------------------------------------------------------------

class TestEmailAlertEndpoint:
    def test_test_email_alert_admin_only(self):
        token = _admin_token()
        res = client.post("/test-email-alert", headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "success" in data
        assert "channel_used" in data
        assert "resend_enabled" in data
        assert "smtp_enabled" in data

    def test_test_email_alert_unauthenticated_rejected(self):
        res = client.post("/test-email-alert")
        assert res.status_code == 401

    def test_test_email_alert_cert_role_rejected(self):
        token = _cert_token()
        res = client.post("/test-email-alert", headers=_auth(token))
        assert res.status_code == 403

    def test_test_email_alert_user_role_rejected(self):
        token = _user_token()
        res = client.post("/test-email-alert", headers=_auth(token))
        assert res.status_code == 403


# ---------------------------------------------------------------------------
# 9. Role enforcement — cross-role access denied
# ---------------------------------------------------------------------------

class TestRoleEnforcement:
    def test_user_cannot_access_admin_overview(self):
        token = _user_token()
        res = client.get("/admin/overview", headers=_auth(token))
        assert res.status_code == 403

    def test_user_cannot_access_cert_intel(self):
        token = _user_token()
        res = client.get("/cert/intel", headers=_auth(token))
        assert res.status_code == 403

    def test_user_cannot_list_all_complaints(self):
        token = _user_token()
        res = client.get("/complaints", headers=_auth(token))
        assert res.status_code == 403

    def test_invalid_token_rejected(self):
        res = client.get("/me", headers={"Authorization": "Bearer totally_fake_token"})
        assert res.status_code == 401



# ---------------------------------------------------------------------------
# 1. Public endpoints
# ---------------------------------------------------------------------------

class TestPublicEndpoints:
    def test_root_returns_200(self):
        res = client.get("/")
        assert res.status_code == 200

    def test_health_get_returns_200(self):
        res = client.get("/health")
        assert res.status_code == 200

    def test_health_body(self):
        res = client.get("/health")
        data = res.json()
        assert data["status"] == "ok"
        assert data["service"] == "rakshak-ai-backend"

    def test_health_head_returns_200(self):
        res = client.head("/health")
        assert res.status_code == 200

    def test_docs_accessible(self):
        res = client.get("/docs")
        assert res.status_code == 200


# ---------------------------------------------------------------------------
# 2. Auth flow
# ---------------------------------------------------------------------------

class TestAuthFlow:
    def test_register_new_user(self):
        email = f"audit_{uuid.uuid4().hex[:8]}@test.com"
        res = client.post("/register", json={
            "full_name": "Audit User",
            "email": email,
            "password": "SecurePass123",
            "role": "user",
        })
        assert res.status_code == 200
        assert res.json().get("success") is True

    def test_duplicate_registration_rejected(self):
        email = f"dup_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/register", json={"full_name": "A", "email": email, "password": "pass123", "role": "user"})
        res = client.post("/register", json={"full_name": "A", "email": email, "password": "pass123", "role": "user"})
        assert res.status_code == 200
        assert res.json().get("success") is False

    def test_login_valid_credentials(self):
        email = f"login_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/register", json={"full_name": "L", "email": email, "password": "pass123", "role": "user"})
        res = client.post("/login", json={"email": email, "password": "pass123"})
        assert res.status_code == 200
        data = res.json()
        assert data.get("success") is True
        assert "token" in data
        assert data["token"]

    def test_login_wrong_password_rejected(self):
        email = f"wp_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/register", json={"full_name": "W", "email": email, "password": "correct", "role": "user"})
        res = client.post("/login", json={"email": email, "password": "wrong"})
        assert res.status_code == 200
        assert res.json().get("success") is False

    def test_admin_login(self):
        res = client.post("/login", json={"email": "admin@rakshak.ai", "password": "admin123"})
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["user"]["role"] == "admin"

    def test_cert_login(self):
        res = client.post("/login", json={"email": "cert@rakshak.ai", "password": "cert123"})
        assert res.status_code == 200
        assert res.json()["user"]["role"] == "cert"

    def test_me_with_valid_token(self):
        token = _admin_token()
        res = client.get("/me", headers=_auth(token))
        assert res.status_code == 200
        assert res.json()["success"] is True

    def test_me_without_token_rejected(self):
        res = client.get("/me")
        assert res.status_code == 401

    def test_logout(self):
        # Use a fresh one-off login so we don't invalidate the cached admin token
        res = client.post("/login", json={"email": "admin@rakshak.ai", "password": "admin123"})
        if res.status_code != 200:
            pytest.skip("Rate limited — skipping logout test")
        token = res.json()["token"]
        res2 = client.post("/logout", headers=_auth(token))
        assert res2.status_code == 200
        # Token should now be invalid
        res3 = client.get("/me", headers=_auth(token))
        assert res3.status_code == 401


# ---------------------------------------------------------------------------
# 3. User flow — complaint submission
# ---------------------------------------------------------------------------

class TestUserFlow:
    def test_submit_complaint_authenticated(self):
        token = _user_token()
        uid = _user_id()
        res = client.post("/complaints", data={
            "user_id": uid,
            "user_name": "Audit Test User",
            "category": "Serving Personnel",
            "complaint_text": "Received a phishing email asking for my OTP and bank login credentials urgently.",
            "suspicious_url": "",
        }, headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert data.get("success") is True
        assert "complaint_id" in data
        assert data["risk_level"] in ("Low", "Medium", "High", "Critical")

    def test_submit_complaint_unauthenticated_rejected(self):
        res = client.post("/complaints", data={
            "user_id": "fake",
            "user_name": "fake",
            "category": "Serving Personnel",
            "complaint_text": "test",
        })
        assert res.status_code == 401

    def test_my_complaints_authenticated(self):
        token = _user_token()
        uid = _user_id()
        res = client.get(f"/my-complaints/{uid}", headers=_auth(token))
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_my_complaints_wrong_user_rejected(self):
        token = _user_token()
        res = client.get("/my-complaints/DIFFERENT-USER-ID", headers=_auth(token))
        assert res.status_code == 403

    def test_my_complaints_unauthenticated_rejected(self):
        res = client.get("/my-complaints/some-id")
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 4. Admin flow
# ---------------------------------------------------------------------------

class TestAdminFlow:
    def test_admin_overview_returns_200(self):
        token = _admin_token()
        res = client.get("/admin/overview", headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "analytics" in data
        assert "complaints" in data
        assert "users" in data

    def test_admin_overview_analytics_fields(self):
        token = _admin_token()
        data = client.get("/admin/overview", headers=_auth(token)).json()
        analytics = data["analytics"]
        for field in ("total", "critical", "high", "medium", "low", "open_cases", "escalated"):
            assert field in analytics, f"Missing analytics field: {field}"

    def test_admin_overview_unauthenticated_rejected(self):
        res = client.get("/admin/overview")
        assert res.status_code == 401

    def test_admin_overview_cert_role_rejected(self):
        token = _cert_token()
        res = client.get("/admin/overview", headers=_auth(token))
        assert res.status_code == 403

    def test_complaints_list_admin(self):
        token = _admin_token()
        res = client.get("/complaints", headers=_auth(token))
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_complaints_list_unauthenticated_rejected(self):
        res = client.get("/complaints")
        assert res.status_code == 401

    def test_status_update_admin(self):
        token = _admin_token()
        complaints = client.get("/complaints", headers=_auth(token)).json()
        if not complaints:
            pytest.skip("No complaints in DB to update")
        cid = complaints[0]["id"]
        current_status = complaints[0]["status"]
        new_status = "Under Review" if current_status != "Under Review" else "Open"
        res = client.put(f"/update-status/{cid}?status={new_status}", headers=_auth(token))
        assert res.status_code == 200
        assert res.json().get("success") is True

    def test_status_update_unauthenticated_rejected(self):
        res = client.put("/update-status/FAKE-ID?status=Open")
        assert res.status_code == 401

    def test_audit_logs_admin(self):
        token = _admin_token()
        res = client.get("/audit-logs", headers=_auth(token))
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_audit_logs_unauthenticated_rejected(self):
        res = client.get("/audit-logs")
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 5. CERT flow
# ---------------------------------------------------------------------------

class TestCertFlow:
    def test_cert_intel_returns_200(self):
        token = _cert_token()
        res = client.get("/cert/intel", headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "analytics" in data
        assert "summary" in data
        assert "feed" in data
        assert "heatmaps" in data

    def test_cert_intel_unauthenticated_rejected(self):
        res = client.get("/cert/intel")
        assert res.status_code == 401

    def test_cert_intel_user_role_rejected(self):
        token = _user_token()
        res = client.get("/cert/intel", headers=_auth(token))
        assert res.status_code == 403

    def test_cert_live_alerts(self):
        token = _cert_token()
        res = client.get("/cert/live-alerts", headers=_auth(token))
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_cert_escalated(self):
        token = _cert_token()
        res = client.get("/cert/escalated", headers=_auth(token))
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_cert_summary(self):
        token = _cert_token()
        res = client.get("/cert/summary", headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "total_cases" in data
        assert "critical_alerts" in data

    def test_analytics_endpoint(self):
        token = _cert_token()
        res = client.get("/analytics", headers=_auth(token))
        assert res.status_code == 200

    def test_excel_export_admin(self):
        token = _admin_token()
        res = client.get("/download/excel", headers=_auth(token))
        assert res.status_code == 200

    def test_excel_export_unauthenticated_rejected(self):
        res = client.get("/download/excel")
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 6. Evidence endpoints
# ---------------------------------------------------------------------------

class TestEvidenceEndpoints:
    def test_evidence_requires_auth(self):
        res = client.get("/complaints/FAKE-ID/evidence")
        assert res.status_code == 401

    def test_evidence_meta_requires_auth(self):
        res = client.get("/complaints/FAKE-ID/evidence-meta")
        assert res.status_code == 401

    def test_evidence_meta_authenticated_nonexistent(self):
        token = _admin_token()
        res = client.get("/complaints/NONEXISTENT-ID/evidence-meta", headers=_auth(token))
        # Should return 200 with available=False, or 404 — either is acceptable
        assert res.status_code in (200, 404)

    def test_evidence_file_authenticated_nonexistent(self):
        token = _admin_token()
        res = client.get("/complaints/NONEXISTENT-ID/evidence", headers=_auth(token))
        assert res.status_code in (404, 400)


# ---------------------------------------------------------------------------
# 7. AI / ML endpoints
# ---------------------------------------------------------------------------

class TestAIEndpoints:
    def test_model_info_admin(self):
        token = _admin_token()
        res = client.get("/ai/model-info", headers=_auth(token))
        assert res.status_code == 200

    def test_model_info_unauthenticated_rejected(self):
        res = client.get("/ai/model-info")
        assert res.status_code == 401

    def test_ai_metrics_admin(self):
        token = _admin_token()
        res = client.get("/ai/metrics", headers=_auth(token))
        assert res.status_code == 200

    def test_ai_metrics_unauthenticated_rejected(self):
        res = client.get("/ai/metrics")
        assert res.status_code == 401

    def test_retrain_status_admin(self):
        token = _admin_token()
        res = client.get("/ai/retrain-status", headers=_auth(token))
        assert res.status_code == 200

    def test_synthetic_summary_admin(self):
        token = _admin_token()
        res = client.get("/ai/synthetic-summary", headers=_auth(token))
        assert res.status_code == 200


# ---------------------------------------------------------------------------
# 8. Email alert test endpoint
# ---------------------------------------------------------------------------

class TestEmailAlertEndpoint:
    def test_test_email_alert_admin_only(self):
        token = _admin_token()
        res = client.post("/test-email-alert", headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        # Must return success field and channel_used (even if no email configured)
        assert "success" in data
        assert "channel_used" in data
        assert "resend_enabled" in data
        assert "smtp_enabled" in data

    def test_test_email_alert_unauthenticated_rejected(self):
        res = client.post("/test-email-alert")
        assert res.status_code == 401

    def test_test_email_alert_cert_role_rejected(self):
        token = _cert_token()
        res = client.post("/test-email-alert", headers=_auth(token))
        assert res.status_code == 403

    def test_test_email_alert_user_role_rejected(self):
        token = _user_token()
        res = client.post("/test-email-alert", headers=_auth(token))
        assert res.status_code == 403


# ---------------------------------------------------------------------------
# 9. Role enforcement — cross-role access denied
# ---------------------------------------------------------------------------

class TestRoleEnforcement:
    def test_user_cannot_access_admin_overview(self):
        token = _user_token()
        res = client.get("/admin/overview", headers=_auth(token))
        assert res.status_code == 403

    def test_user_cannot_access_cert_intel(self):
        token = _user_token()
        res = client.get("/cert/intel", headers=_auth(token))
        assert res.status_code == 403

    def test_user_cannot_list_all_complaints(self):
        token = _user_token()
        res = client.get("/complaints", headers=_auth(token))
        assert res.status_code == 403

    def test_invalid_token_rejected(self):
        res = client.get("/me", headers={"Authorization": "Bearer totally_fake_token"})
        assert res.status_code == 401
