"""
security_utils.py — Defence-grade security utilities for Rakshak AI.
Covers: input sanitization, rate limiting, security headers middleware,
and file upload validation.

All helpers are additive — they do not replace existing auth logic.
"""

import re
import os
import time
import html
import logging
import hashlib
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("security_utils")

# ---------------------------------------------------------------------------
# Strict allowlist: only the file types a complaint portal legitimately needs.
# Everything not on this list is rejected — deny-by-default.
# ---------------------------------------------------------------------------
SAFE_EXTENSIONS: frozenset[str] = frozenset({
    # Images — evidence screenshots
    ".png", ".jpg", ".jpeg", ".webp",
    # Documents
    ".pdf", ".txt",
})

SAFE_MIME_TYPES: frozenset[str] = frozenset({
    "image/png", "image/jpeg", "image/webp",
    "application/pdf",
    "text/plain",
})

# Hard-block list — executables and script files that must never be stored.
# Kept as a secondary safety net; primary gate is the SAFE_EXTENSIONS allowlist.
BLOCKED_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".bat", ".sh", ".ps1", ".vbs",
    ".js",  ".ts",  ".jsx", ".tsx",
    ".py",  ".rb",  ".php", ".pl",  ".go",
    ".jar", ".war", ".ear",
    ".html", ".htm", ".svg",
    ".apk", ".ipa",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".dll", ".so",  ".dylib",
    ".cmd", ".com", ".scr", ".hta",
})

# 5 MB hard cap for evidence uploads (down from the previous 15 MB)
MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB


# ---------------------------------------------------------------------------
# Input sanitization
# ---------------------------------------------------------------------------
def sanitize_text(text: str, max_length: int = 5000) -> str:
    """
    Sanitize free-text input for safe database storage.

    Steps (in order):
    1. Remove null bytes — prevent NUL-injection attacks.
    2. HTML-escape the entire string — converts <, >, &, ", ' to their safe
       entity equivalents so the raw value stored in the DB is harmless when
       later rendered in any HTML context (stored XSS prevention).
    3. Strip any residual bare script/tag patterns that survived escaping
       (belt-and-braces, handles edge cases like double-encoded input).
    4. Truncate to max_length.

    Note: html.escape is non-destructive for plain text — ampersands in URLs
    and normal punctuation round-trip correctly.
    """
    if not text:
        return ""
    # 1. Remove null bytes
    text = text.replace("\x00", "")
    # 2. HTML-escape — primary XSS defence
    text = html.escape(text, quote=True)
    # 3. Belt-and-braces: strip any residual tag-like patterns
    text = re.sub(r"&lt;script[^&]*&gt;.*?&lt;/script&gt;", "", text,
                  flags=re.IGNORECASE | re.DOTALL)
    # 4. Truncate
    return text.strip()[:max_length]


def sanitize_url(url: str) -> str:
    """Basic URL sanitization — strip whitespace and null bytes."""
    if not url:
        return ""
    url = url.replace("\x00", "").strip()
    # Only allow http/https URLs
    if url and not re.match(r"^https?://", url, re.IGNORECASE):
        if url.startswith("www."):
            url = "https://" + url
        elif url and "." in url:
            url = "https://" + url
    return url[:2000]


def validate_file_upload(
    filename: str,
    content_type: str,
    file_size: int,
    content: bytes | None = None,
) -> tuple[bool, str]:
    """
    Validate an uploaded evidence file against strict security criteria.

    Policy (deny-by-default):
      1. Filename must be present.
      2. Every filename suffix must be free of blocked extensions.
      3. Final extension must be on the SAFE_EXTENSIONS allowlist.
      4. File size must not exceed MAX_FILE_SIZE_BYTES.
      5. MIME type, if provided, must match the SAFE_MIME_TYPES allowlist.
      6. Provided content must match the allowed binary file signature.

    Returns (is_valid: bool, reason: str).
    The reason string is safe to return to the client (no internal path info).
    """
    if not filename:
        return False, "No filename provided."

    lower_filename = filename.lower()
    suffixes = [suffix.lower() for suffix in Path(lower_filename).suffixes]
    ext = suffixes[-1] if suffixes else ""

    blocked_suffix = next(
        (suffix for suffix in suffixes if suffix in BLOCKED_EXTENSIONS),
        None,
    )
    if blocked_suffix:
        return False, f"File type '{blocked_suffix}' is blocked for security reasons."

    # Primary gate: extension must be explicitly allowed
    if ext not in SAFE_EXTENSIONS:
        return False, f"File type '{ext or '(none)'}' is not permitted. Allowed: images (png, jpg, jpeg, webp) and documents (pdf, txt)."

    if file_size > MAX_FILE_SIZE_BYTES:
        size_mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
        return False, f"File too large. Maximum allowed size is {size_mb} MB."

    # MIME type check — enforce, don't just warn
    if content_type and content_type not in SAFE_MIME_TYPES:
        return False, f"MIME type '{content_type}' is not permitted for evidence uploads."

    if content is not None:
        signatures = {
            ".png": b"\x89PNG\r\n\x1a\n",
            ".jpg": b"\xff\xd8\xff",
            ".jpeg": b"\xff\xd8\xff",
            ".webp": b"RIFF",
            ".pdf": b"%PDF-",
        }
        signature = signatures.get(ext)
        if signature and not (
            content.startswith(signature)
            and (ext != ".webp" or content[8:12] == b"WEBP")
        ):
            return False, f"File content does not match the '{ext}' file signature."

        if ext == ".txt":
            normalized = content.lstrip().lower()
            if b"\x00" in content or normalized.startswith(
                (b"mz", b"<?php", b"<script")
            ):
                return False, "Text evidence contains binary or executable content."

    return True, "OK"


def generate_safe_filename(original_name: str, prefix: str = "") -> str:
    """
    Generate a fully server-controlled filename that prevents directory
    traversal, path injection, and information leakage.

    The original client filename is NOT preserved in the stored name.
    Format: {prefix}_{timestamp}_{sha256[:16]}_{safe_ext}

    The original extension is retained (already validated by the caller)
    so the OS can serve the file with the correct Content-Type.
    """
    _, ext = os.path.splitext(original_name.lower())
    # Sanitize extension — only keep alphanumeric chars
    safe_ext = re.sub(r"[^\w]", "", ext)[:6]
    name_hash = hashlib.sha256(original_name.encode()).hexdigest()[:16]
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    parts = [p for p in [prefix, timestamp, name_hash] if p]
    base = "_".join(parts)
    return f"{base}.{safe_ext}" if safe_ext else base


# ---------------------------------------------------------------------------
# Rate limiting (in-memory, per IP)
# ---------------------------------------------------------------------------
_rate_limit_store: dict = defaultdict(list)

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS   = 30  # per window per IP


def check_rate_limit(client_ip: str) -> tuple[bool, str]:
    """
    Check if a client IP has exceeded the rate limit.
    Returns (allowed: bool, message: str).
    Uses a sliding window approach.
    """
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS

    # Clean old entries
    _rate_limit_store[client_ip] = [
        t for t in _rate_limit_store[client_ip] if t > window_start
    ]

    count = len(_rate_limit_store[client_ip])
    if count >= RATE_LIMIT_MAX_REQUESTS:
        return False, f"Rate limit exceeded. Max {RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_WINDOW_SECONDS}s."

    _rate_limit_store[client_ip].append(now)
    return True, "OK"


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds defence-grade security headers to every response.
    Does not affect CORS — that is handled by FastAPI's CORSMiddleware.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]            = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]         = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"]   = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' http://127.0.0.1:8000;"
        )
        return response


# ---------------------------------------------------------------------------
# Rate limit middleware
# ---------------------------------------------------------------------------
class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP rate limiting middleware.
    Applies to complaint submission and login endpoints only.
    """
    PROTECTED_PATHS = {"/complaints", "/login", "/register"}

    async def dispatch(self, request: Request, call_next):
        if request.method == "POST" and request.url.path in self.PROTECTED_PATHS:
            client_ip = request.client.host if request.client else "unknown"
            allowed, message = check_rate_limit(client_ip)
            if not allowed:
                logger.warning(f"[security] Rate limit hit for IP {client_ip} on {request.url.path}")
                return JSONResponse(
                    status_code=429,
                    content={"detail": message, "error": "rate_limit_exceeded"},
                )
        return await call_next(request)
