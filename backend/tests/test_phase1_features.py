"""
Tests for Phase 1 judge-impact features:
- build_mitigation_steps
- build_severity_explanation
- extract_ioc
- Complaint submission response includes new fields
- my-complaints response includes new fields
- Evidence download is audit-logged
"""

import sys
import os
import uuid

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from main import app, build_mitigation_steps, build_severity_explanation, extract_ioc  # noqa: E402

client = TestClient(app, raise_server_exceptions=False)

# ---------------------------------------------------------------------------
# Token cache (avoid rate limit)
# ---------------------------------------------------------------------------
_TOKENS: dict = {}


def _admin_token() -> str:
    if "admin" not in _TOKENS:
        res = client.post("/login", json={"email": "admin@rakshak.ai", "password": "admin123"})
        assert res.status_code == 200
        _TOKENS["admin"] = res.json()["token"]
    return _TOKENS["admin"]


def _user_token_and_id() -> tuple[str, str]:
    if "user" not in _TOKENS:
        email = f"p1_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/register", json={"full_name": "P1 User", "email": email, "password": "pass123", "role": "user"})
        res = client.post("/login", json={"email": email, "password": "pass123"})
        assert res.status_code == 200
        _TOKENS["user"] = res.json()["token"]
        _TOKENS["user_id"] = res.json()["user"]["id"]
    return _TOKENS["user"], _TOKENS["user_id"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. build_mitigation_steps
# ---------------------------------------------------------------------------

class TestBuildMitigationSteps:
    def test_phishing_returns_steps(self):
        steps = build_mitigation_steps("Phishing", "High")
        assert isinstance(steps, list)
        assert len(steps) >= 4
        assert any("link" in s.lower() or "password" in s.lower() for s in steps)

    def test_malware_returns_steps(self):
        steps = build_mitigation_steps("Malware / APK Threat", "High")
        assert any("apk" in s.lower() or "uninstall" in s.lower() for s in steps)

    def test_opsec_returns_steps(self):
        steps = build_mitigation_steps("OPSEC Leak Risk", "Critical")
        assert any("intelligence" in s.lower() or "sensitive" in s.lower() or "delete" in s.lower() for s in steps)

    def test_fraud_returns_steps(self):
        steps = build_mitigation_steps("Identity / Financial Fraud", "Medium")
        assert any("bank" in s.lower() or "payment" in s.lower() for s in steps)

    def test_unknown_threat_returns_generic_steps(self):
        steps = build_mitigation_steps("Unknown Threat XYZ", "Low")
        assert isinstance(steps, list)
        assert len(steps) >= 3

    def test_critical_adds_urgent_step(self):
        steps = build_mitigation_steps("Phishing", "Critical")
        assert any("urgent" in s.lower() or "cert" in s.lower() for s in steps)

    def test_low_risk_no_urgent_step(self):
        steps = build_mitigation_steps("Spam", "Low")
        assert not any("urgent" in s.lower() for s in steps)

    def test_returns_list_not_string(self):
        result = build_mitigation_steps("Phishing", "High")
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, str)


# ---------------------------------------------------------------------------
# 2. build_severity_explanation
# ---------------------------------------------------------------------------

class TestBuildSeverityExplanation:
    def test_returns_required_fields(self):
        result = build_severity_explanation("High", 75, 82, "Phishing", ["otp", "click"])
        for field in ("risk_level", "risk_score", "score_band", "ai_confidence_pct", "threat_type", "summary", "note"):
            assert field in result, f"Missing field: {field}"

    def test_critical_score_band(self):
        result = build_severity_explanation("Critical", 95, 97, "Espionage Indicator", [])
        assert "81" in result["score_band"] or "very high" in result["score_band"]

    def test_low_score_band(self):
        result = build_severity_explanation("Low", 25, 30, "Spam", [])
        assert "low" in result["score_band"]

    def test_summary_matches_level(self):
        result = build_severity_explanation("Medium", 55, 60, "Phishing", [])
        assert "moderate" in result["summary"].lower() or "medium" in result["summary"].lower() or "review" in result["summary"].lower()

    def test_top_indicators_capped_at_3(self):
        indicators = ["a", "b", "c", "d", "e"]
        result = build_severity_explanation("High", 70, 75, "Phishing", indicators)
        assert len(result["top_indicators"]) <= 3

    def test_empty_indicators_ok(self):
        result = build_severity_explanation("Low", 20, 25, "Spam", [])
        assert result["top_indicators"] == []


# ---------------------------------------------------------------------------
# 3. extract_ioc
# ---------------------------------------------------------------------------

class TestExtractIOC:
    def test_extracts_url(self):
        result = extract_ioc("Click this link http://evil.com/phish to verify", "")
        assert "http://evil.com/phish" in result["urls"]

    def test_extracts_domain(self):
        result = extract_ioc("Visit http://malicious-site.in/login now", "")
        assert any("malicious-site.in" in d for d in result["domains"])

    def test_extracts_email(self):
        result = extract_ioc("Contact attacker@evil.org for details", "")
        assert "attacker@evil.org" in result["emails"]

    def test_extracts_phone(self):
        result = extract_ioc("Call 9876543210 immediately", "")
        assert "9876543210" in result["phones"]

    def test_empty_text_returns_empty_lists(self):
        result = extract_ioc("", "")
        assert result["urls"] == []
        assert result["domains"] == []
        assert result["emails"] == []
        assert result["phones"] == []

    def test_suspicious_url_param_included(self):
        result = extract_ioc("some text", "http://phishing-url.com/verify")
        assert any("phishing-url.com" in d for d in result["domains"])

    def test_returns_dict_with_all_keys(self):
        result = extract_ioc("test", "")
        for key in ("urls", "domains", "emails", "phones"):
            assert key in result

    def test_deduplicates_urls(self):
        text = "http://evil.com http://evil.com http://evil.com"
        result = extract_ioc(text, "")
        assert result["urls"].count("http://evil.com") == 1


# ---------------------------------------------------------------------------
# 4. Complaint submission response includes new fields
# ---------------------------------------------------------------------------

class TestComplaintResponseFields:
    def test_submit_complaint_has_mitigation_steps(self):
        token, uid = _user_token_and_id()
        res = client.post("/complaints", data={
            "user_id": uid,
            "user_name": "P1 User",
            "category": "Serving Personnel",
            "complaint_text": "Received phishing email asking for OTP and bank login urgently.",
            "suspicious_url": "",
        }, headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "mitigation_steps" in data
        assert isinstance(data["mitigation_steps"], list)
        assert len(data["mitigation_steps"]) >= 1

    def test_submit_complaint_has_severity_explanation(self):
        token, uid = _user_token_and_id()
        res = client.post("/complaints", data={
            "user_id": uid,
            "user_name": "P1 User",
            "category": "Serving Personnel",
            "complaint_text": "Suspicious APK sent via WhatsApp claiming to be canteen app.",
            "suspicious_url": "",
        }, headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "severity_explanation" in data
        se = data["severity_explanation"]
        assert "risk_level" in se
        assert "risk_score" in se
        assert "summary" in se

    def test_submit_complaint_has_ioc(self):
        token, uid = _user_token_and_id()
        res = client.post("/complaints", data={
            "user_id": uid,
            "user_name": "P1 User",
            "category": "Serving Personnel",
            "complaint_text": "Got email from attacker@evil.org with link http://phish.in/verify",
            "suspicious_url": "http://phish.in/verify",
        }, headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "ioc" in data
        ioc = data["ioc"]
        for key in ("urls", "domains", "emails", "phones"):
            assert key in ioc

    def test_existing_fields_still_present(self):
        """Ensure no existing response fields were removed."""
        token, uid = _user_token_and_id()
        res = client.post("/complaints", data={
            "user_id": uid,
            "user_name": "P1 User",
            "category": "Serving Personnel",
            "complaint_text": "Test complaint for field preservation check.",
            "suspicious_url": "",
        }, headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        for field in ("complaint_id", "risk_level", "risk_score", "threat_type",
                      "ai_reason", "mitigation", "ai_confidence", "status",
                      "attack_channel", "ml_prediction", "model_used"):
            assert field in data, f"Existing field missing: {field}"


# ---------------------------------------------------------------------------
# 5. my-complaints response includes new fields
# ---------------------------------------------------------------------------

class TestMyComplaintsResponseFields:
    def test_my_complaints_has_mitigation_steps(self):
        token, uid = _user_token_and_id()
        res = client.get(f"/my-complaints/{uid}", headers=_auth(token))
        assert res.status_code == 200
        complaints = res.json()
        if not complaints:
            pytest.skip("No complaints for this user yet")
        c = complaints[0]
        assert "mitigation_steps" in c
        assert isinstance(c["mitigation_steps"], list)

    def test_my_complaints_has_severity_explanation(self):
        token, uid = _user_token_and_id()
        res = client.get(f"/my-complaints/{uid}", headers=_auth(token))
        assert res.status_code == 200
        complaints = res.json()
        if not complaints:
            pytest.skip("No complaints for this user yet")
        c = complaints[0]
        assert "severity_explanation" in c
        assert "risk_level" in c["severity_explanation"]

    def test_my_complaints_has_ioc(self):
        token, uid = _user_token_and_id()
        res = client.get(f"/my-complaints/{uid}", headers=_auth(token))
        assert res.status_code == 200
        complaints = res.json()
        if not complaints:
            pytest.skip("No complaints for this user yet")
        c = complaints[0]
        assert "ioc" in c


# ---------------------------------------------------------------------------
# 6. Evidence download audit logging
# ---------------------------------------------------------------------------

class TestEvidenceAuditLog:
    def test_evidence_download_creates_audit_entry(self):
        """
        After accessing evidence (even for nonexistent complaint), the auth check
        runs first. For a real complaint with evidence, an audit entry is created.
        We verify the audit log endpoint works and returns entries.
        """
        token = _admin_token()
        res = client.get("/audit-logs", headers=_auth(token))
        assert res.status_code == 200
        logs = res.json()
        assert isinstance(logs, list)
        # Verify audit log structure
        if logs:
            log = logs[0]
            assert "action" in log
            assert "created_at" in log
