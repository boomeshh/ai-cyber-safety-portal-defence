"""
security_utils.py — Defence-grade security utilities for Rakshak AI.
Covers: input sanitization, rate limiting, security headers middleware,
and file upload validation.

All helpers are additive — they do not replace existing auth logic.
"""

import re
import os
import time
import logging
import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Optional
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("security_utils")

# ---------------------------------------------------------------------------
# Allowed file extensions and MIME types for evidence upload
# ---------------------------------------------------------------------------
SAFE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif",
    ".pdf", ".txt", ".csv",
    ".mp3", ".wav",
    ".mp4", ".mov",
}

SAFE_MIME_TYPES = {
    "image/png", "image/jpeg", "image/webp", "image/gif",
    "application/pdf",
    "text/plain", "text/csv",
    "audio/mpeg", "audio/wav",
    "video/mp4", "video/quicktime",
}

# Dangerous extensions that should always be blocked
BLOCKED_EXTENSIONS = {".exe", ".bat", ".sh", ".ps1", ".vbs", ".js", ".jar"}

MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024  # 15 MB


# ---------------------------------------------------------------------------
# Input sanitization
# ---------------------------------------------------------------------------
def sanitize_text(text: str, max_length: int = 5000) -> str:
    """
    Sanitize free-text input.
    - Strip leading/trailing whitespace
    - Remove null bytes
    - Truncate to max_length
    - Remove common XSS patterns
    """
    if not text:
        return ""
    # Remove null bytes
    text = text.replace("\x00", "")
    # Strip dangerous HTML/script tags
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", "", text)
    # Remove SQL injection patterns (basic)
    text = re.sub(r"(--|;|/\*|\*/|xp_|UNION\s+SELECT|DROP\s+TABLE)", "", text, flags=re.IGNORECASE)
    # Truncate
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


def validate_file_upload(filename: str, content_type: str, file_size: int) -> tuple[bool, str]:
    """
    Validate an uploaded file.
    Returns (is_valid: bool, reason: str).
    """
    if not filename:
        return False, "No filename provided."

    _, ext = os.path.splitext(filename.lower())

    if ext in BLOCKED_EXTENSIONS:
        return False, f"File type '{ext}' is not allowed for security reasons."

    if file_size > MAX_FILE_SIZE_BYTES:
        return False, f"File too large. Maximum size is {MAX_FILE_SIZE_BYTES // (1024*1024)} MB."

    # Warn but don't block on MIME type mismatch (browsers can be inconsistent)
    if content_type and content_type not in SAFE_MIME_TYPES:
        logger.warning(f"[security] Unusual MIME type uploaded: {content_type} for {filename}")

    return True, "OK"


def generate_safe_filename(original_name: str, prefix: str = "") -> str:
    """
    Generate a safe, hashed filename to prevent path traversal.
    Format: {prefix}_{sha256_of_original[:12]}_{sanitized_basename}
    """
    basename = os.path.basename(original_name)
    # Remove dangerous characters
    safe_base = re.sub(r"[^\w.\-]", "_", basename)
    name_hash = hashlib.sha256(original_name.encode()).hexdigest()[:12]
    timestamp  = datetime.now().strftime("%Y%m%d%H%M%S%f")
    parts = [p for p in [prefix, timestamp, name_hash, safe_base] if p]
    return "_".join(parts)


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
