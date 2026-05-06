"""
Tests for Phase 2 judge-impact features:
- Case notes (add/view, role enforcement)
- Complaint timeline (default events, auth)
- AI feedback (add/view, verdict validation, ML unchanged)
- Audit log entries for NOTE_ADDED, FEEDBACK_ADDED, TIMELINE_VIEWED
"""

import sys
import os
import uuid

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from main import app, build_complaint_timeline  # noqa: E402

client = TestClient(app, raise_server_exceptions=False)

# ---------------------------------------------------------------------------
# Token cache — one login per role per session
# ---------------------------------------------------------------------------
_TOKENS: dict = {}


def _admin_token() -> str:
    if "admin" not in _TOKENS:
        res = client.post("/login", json={"email": "admin@rakshak.ai", "password": "admin123"})
        assert res.status_code == 200, f"Admin login failed: {res.text}"
        _TOKENS["admin"] = res.json()["token"]
    return _TOKENS["admin"]


def _cert_token() -> str:
    if "cert" not in _TOKENS:
        res = client.post("/login", json={"email": "cert@rakshak.ai", "password": "cert123"})
        assert res.status_code == 200, f"CERT login failed: {res.text}"
        _TOKENS["cert"] = res.json()["token"]
    return _TOKENS["cert"]


def _user_token_and_id() -> tuple[str, str]:
    if "user" not in _TOKENS:
        email = f"p2_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/register", json={"full_name": "P2 User", "email": email, "password": "pass123", "role": "user"})
        res = client.post("/login", json={"email": email, "password": "pass123"})
        assert res.status_code == 200
        _TOKENS["user"] = res.json()["token"]
        _TOKENS["user_id"] = res.json()["user"]["id"]
    return _TOKENS["user"], _TOKENS["user_id"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _get_any_complaint_id() -> str:
    """Return the ID of any existing complaint, or create one."""
    token = _admin_token()
    res = client.get("/complaints", headers=_auth(token))
    complaints = res.json()
    if complaints:
        return complaints[0]["id"]
    # Create one
    user_token, uid = _user_token_and_id()
    res = client.post("/complaints", data={
        "user_id": uid,
        "user_name": "P2 User",
        "category": "Serving Personnel",
        "complaint_text": "Phase 2 test complaint for notes and timeline.",
        "suspicious_url": "",
    }, headers=_auth(user_token))
    assert res.status_code == 200
    return res.json()["complaint_id"]


# ---------------------------------------------------------------------------
# 1. Case Notes — POST /admin/complaints/{id}/notes
# ---------------------------------------------------------------------------

class TestCaseNotes:
    def test_admin_can_add_note(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        res = client.post(
            f"/admin/complaints/{cid}/notes",
            json={"note": "Admin internal note for testing."},
            headers=_auth(token),
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["complaint_id"] == cid
        assert "note_id" in data
        assert data["note"] == "Admin internal note for testing."

    def test_cert_can_add_note(self):
        cid = _get_any_complaint_id()
        token = _cert_token()
        res = client.post(
            f"/admin/complaints/{cid}/notes",
            json={"note": "CERT internal note for testing."},
            headers=_auth(token),
        )
        assert res.status_code == 200
        assert res.json()["success"] is True

    def test_user_cannot_add_note(self):
        cid = _get_any_complaint_id()
        user_token, _ = _user_token_and_id()
        res = client.post(
            f"/admin/complaints/{cid}/notes",
            json={"note": "User trying to add note."},
            headers=_auth(user_token),
        )
        assert res.status_code == 403

    def test_unauthenticated_cannot_add_note(self):
        cid = _get_any_complaint_id()
        res = client.post(f"/admin/complaints/{cid}/notes", json={"note": "No auth."})
        assert res.status_code == 401

    def test_empty_note_rejected(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        res = client.post(
            f"/admin/complaints/{cid}/notes",
            json={"note": "   "},
            headers=_auth(token),
        )
        assert res.status_code == 400

    def test_nonexistent_complaint_returns_404(self):
        token = _admin_token()
        res = client.post(
            "/admin/complaints/NONEXISTENT-ID/notes",
            json={"note": "Test note."},
            headers=_auth(token),
        )
        assert res.status_code == 404

    def test_admin_can_view_notes(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        # Add a note first
        client.post(
            f"/admin/complaints/{cid}/notes",
            json={"note": "Viewable note."},
            headers=_auth(token),
        )
        res = client.get(f"/admin/complaints/{cid}/notes", headers=_auth(token))
        assert res.status_code == 200
        notes = res.json()
        assert isinstance(notes, list)
        assert len(notes) >= 1
        note = notes[-1]
        for field in ("id", "complaint_id", "actor_name", "actor_role", "note", "created_at"):
            assert field in note, f"Missing field: {field}"

    def test_cert_can_view_notes(self):
        cid = _get_any_complaint_id()
        token = _cert_token()
        res = client.get(f"/admin/complaints/{cid}/notes", headers=_auth(token))
        assert res.status_code == 200

    def test_user_cannot_view_notes(self):
        cid = _get_any_complaint_id()
        user_token, _ = _user_token_and_id()
        res = client.get(f"/admin/complaints/{cid}/notes", headers=_auth(user_token))
        assert res.status_code == 403

    def test_unauthenticated_cannot_view_notes(self):
        cid = _get_any_complaint_id()
        res = client.get(f"/admin/complaints/{cid}/notes")
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 2. Timeline — GET /admin/complaints/{id}/timeline
# ---------------------------------------------------------------------------

class TestComplaintTimeline:
    def test_admin_can_view_timeline(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        res = client.get(f"/admin/complaints/{cid}/timeline", headers=_auth(token))
        assert res.status_code == 200
        data = res.json()
        assert "complaint_id" in data
        assert "timeline" in data
        assert isinstance(data["timeline"], list)

    def test_cert_can_view_timeline(self):
        cid = _get_any_complaint_id()
        token = _cert_token()
        res = client.get(f"/admin/complaints/{cid}/timeline", headers=_auth(token))
        assert res.status_code == 200

    def test_user_cannot_view_timeline(self):
        cid = _get_any_complaint_id()
        user_token, _ = _user_token_and_id()
        res = client.get(f"/admin/complaints/{cid}/timeline", headers=_auth(user_token))
        assert res.status_code == 403

    def test_unauthenticated_cannot_view_timeline(self):
        cid = _get_any_complaint_id()
        res = client.get(f"/admin/complaints/{cid}/timeline")
        assert res.status_code == 401

    def test_timeline_has_reported_event(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        res = client.get(f"/admin/complaints/{cid}/timeline", headers=_auth(token))
        events = res.json()["timeline"]
        event_names = [e["event"] for e in events]
        assert "Reported" in event_names

    def test_timeline_has_ai_analyzed_event(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        res = client.get(f"/admin/complaints/{cid}/timeline", headers=_auth(token))
        events = res.json()["timeline"]
        event_names = [e["event"] for e in events]
        assert "AI Analyzed" in event_names

    def test_timeline_events_have_required_fields(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        res = client.get(f"/admin/complaints/{cid}/timeline", headers=_auth(token))
        events = res.json()["timeline"]
        for event in events:
            for field in ("event", "description", "actor", "role", "created_at"):
                assert field in event, f"Timeline event missing field: {field}"

    def test_nonexistent_complaint_returns_404(self):
        token = _admin_token()
        res = client.get("/admin/complaints/NONEXISTENT-ID/timeline", headers=_auth(token))
        assert res.status_code == 404

    def test_timeline_creates_audit_entry(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        client.get(f"/admin/complaints/{cid}/timeline", headers=_auth(token))
        # Verify audit log has TIMELINE_VIEWED entry
        logs = client.get("/audit-logs", headers=_auth(token)).json()
        actions = [log["action"] for log in logs]
        assert "TIMELINE_VIEWED" in actions

    def test_build_complaint_timeline_helper_nonexistent(self):
        """Helper returns empty list for nonexistent complaint."""
        result = build_complaint_timeline("NONEXISTENT-ID")
        assert result == []


# ---------------------------------------------------------------------------
# 3. AI Feedback — POST/GET /admin/complaints/{id}/feedback
# ---------------------------------------------------------------------------

class TestAIFeedback:
    def test_admin_can_add_feedback_correct(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        res = client.post(
            f"/admin/complaints/{cid}/feedback",
            json={"verdict": "correct", "comment": "Classification looks right."},
            headers=_auth(token),
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["verdict"] == "correct"
        assert "feedback_id" in data
        assert data["note"] == "Feedback recorded. ML prediction is unchanged."

    def test_admin_can_add_feedback_wrong(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        res = client.post(
            f"/admin/complaints/{cid}/feedback",
            json={"verdict": "wrong_classification"},
            headers=_auth(token),
        )
        assert res.status_code == 200
        assert res.json()["verdict"] == "wrong_classification"

    def test_admin_can_add_feedback_needs_review(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        res = client.post(
            f"/admin/complaints/{cid}/feedback",
            json={"verdict": "needs_review", "comment": "Borderline case."},
            headers=_auth(token),
        )
        assert res.status_code == 200
        assert res.json()["verdict"] == "needs_review"

    def test_cert_can_add_feedback(self):
        cid = _get_any_complaint_id()
        token = _cert_token()
        res = client.post(
            f"/admin/complaints/{cid}/feedback",
            json={"verdict": "correct"},
            headers=_auth(token),
        )
        assert res.status_code == 200

    def test_user_cannot_add_feedback(self):
        cid = _get_any_complaint_id()
        user_token, _ = _user_token_and_id()
        res = client.post(
            f"/admin/complaints/{cid}/feedback",
            json={"verdict": "correct"},
            headers=_auth(user_token),
        )
        assert res.status_code == 403

    def test_unauthenticated_cannot_add_feedback(self):
        cid = _get_any_complaint_id()
        res = client.post(f"/admin/complaints/{cid}/feedback", json={"verdict": "correct"})
        assert res.status_code == 401

    def test_invalid_verdict_rejected(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        res = client.post(
            f"/admin/complaints/{cid}/feedback",
            json={"verdict": "totally_wrong_value"},
            headers=_auth(token),
        )
        assert res.status_code == 400

    def test_nonexistent_complaint_returns_404(self):
        token = _admin_token()
        res = client.post(
            "/admin/complaints/NONEXISTENT-ID/feedback",
            json={"verdict": "correct"},
            headers=_auth(token),
        )
        assert res.status_code == 404

    def test_feedback_does_not_change_ml_prediction(self):
        """Adding feedback must not alter the stored ml_prediction on the complaint."""
        cid = _get_any_complaint_id()
        token = _admin_token()

        # Get original ML prediction
        complaints = client.get("/complaints", headers=_auth(token)).json()
        original = next((c for c in complaints if c["id"] == cid), None)
        if not original:
            pytest.skip("Complaint not found in list")
        original_ml = original.get("ml_prediction")

        # Add feedback
        client.post(
            f"/admin/complaints/{cid}/feedback",
            json={"verdict": "wrong_classification", "comment": "Test"},
            headers=_auth(token),
        )

        # Re-fetch and verify ML prediction unchanged
        complaints_after = client.get("/complaints", headers=_auth(token)).json()
        after = next((c for c in complaints_after if c["id"] == cid), None)
        if not after:
            pytest.skip("Complaint not found after feedback")
        assert after.get("ml_prediction") == original_ml

    def test_admin_can_view_feedback(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        # Add feedback first
        client.post(
            f"/admin/complaints/{cid}/feedback",
            json={"verdict": "correct"},
            headers=_auth(token),
        )
        res = client.get(f"/admin/complaints/{cid}/feedback", headers=_auth(token))
        assert res.status_code == 200
        feedbacks = res.json()
        assert isinstance(feedbacks, list)
        assert len(feedbacks) >= 1
        fb = feedbacks[-1]
        for field in ("id", "complaint_id", "actor_name", "actor_role", "verdict", "created_at"):
            assert field in fb, f"Missing field: {field}"

    def test_cert_can_view_feedback(self):
        cid = _get_any_complaint_id()
        token = _cert_token()
        res = client.get(f"/admin/complaints/{cid}/feedback", headers=_auth(token))
        assert res.status_code == 200

    def test_user_cannot_view_feedback(self):
        cid = _get_any_complaint_id()
        user_token, _ = _user_token_and_id()
        res = client.get(f"/admin/complaints/{cid}/feedback", headers=_auth(user_token))
        assert res.status_code == 403

    def test_unauthenticated_cannot_view_feedback(self):
        cid = _get_any_complaint_id()
        res = client.get(f"/admin/complaints/{cid}/feedback")
        assert res.status_code == 401

    def test_feedback_creates_audit_entry(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        client.post(
            f"/admin/complaints/{cid}/feedback",
            json={"verdict": "correct"},
            headers=_auth(token),
        )
        logs = client.get("/audit-logs", headers=_auth(token)).json()
        actions = [log["action"] for log in logs]
        assert "FEEDBACK_ADDED" in actions

    def test_note_creates_audit_entry(self):
        cid = _get_any_complaint_id()
        token = _admin_token()
        client.post(
            f"/admin/complaints/{cid}/notes",
            json={"note": "Audit check note."},
            headers=_auth(token),
        )
        logs = client.get("/audit-logs", headers=_auth(token)).json()
        actions = [log["action"] for log in logs]
        assert "NOTE_ADDED" in actions
