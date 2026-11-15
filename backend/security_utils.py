"""
security_utils.py — Defence-grade security utilities for Rakshak AI.
Covers: input sanitization, rate limiting, security headers middleware,
and file upload validation.

All helpers are additive — they do not replace existing auth logic.
"""

import re
import os
import sys
import time
import html
import logging
import hashlib
import secrets
import base64
import binascii
from collections import defaultdict
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Optional
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
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
# .jsp added: Java Server Pages are executable server-side scripts.
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
    ".jsp",   # Java Server Pages — executable server-side script
})

# 5 MB hard cap for evidence uploads
MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB
_UPLOAD_CHUNK_SIZE: int = 65536  # 64 KB read chunks for streaming size check


# ---------------------------------------------------------------------------
# Strict truthy helper — mirrors firebase_auth._is_truthy_env
# ---------------------------------------------------------------------------

def _is_truthy_env(name: str) -> bool:
    """Return True only for "1", "true", "yes", "on" (case-insensitive)."""
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# AES-256-GCM authenticated encryption
# ---------------------------------------------------------------------------
AES_KEY_ENV = "RAKSHAK_AES_KEY"
AES_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
_TESTING_AES_KEY = hashlib.sha256(
    b"rakshak-ai-testing-aes-256-gcm-key-v1"
).digest()
_HKDF_SALT = b"rakshak-ai-aes-256-gcm-v1"


def _decode_aes_key(raw_key: str) -> bytes:
    value = raw_key.strip()
    if len(value) == AES_KEY_BYTES * 2:
        try:
            key = bytes.fromhex(value)
        except ValueError:
            key = b""
        if len(key) == AES_KEY_BYTES:
            return key

    try:
        key = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(
            f"{AES_KEY_ENV} must be a 64-character hex or base64-encoded 32-byte key."
        ) from error
    if len(key) != AES_KEY_BYTES:
        raise ValueError(
            f"{AES_KEY_ENV} must decode to exactly {AES_KEY_BYTES} bytes."
        )
    return key


@lru_cache(maxsize=1)
def _get_aes_key() -> bytes:
    """
    Resolve the AES-256 key with fail-closed production behaviour.

    Resolution order:
      1. RAKSHAK_AES_KEY env var (hex or base64-encoded 32-byte key).
      2. Testing mode (RAKSHAK_TESTING strictly truthy) → deterministic test key.
      3. Development mode (RAKSHAK_ENV in {dev, development, local}) → ephemeral key.
      4. SECRET_KEY / RAKSHAK_SECRET_KEY → HKDF-derived key (logged as warning).
      5. PRODUCTION FAIL-CLOSED: if neither RAKSHAK_AES_KEY nor SECRET_KEY is
         set outside testing/dev, raise RuntimeError rather than use a hardcoded
         fallback secret — the legacy fallback is REMOVED.

    The hardcoded "rakshak-ai-legacy-secret-fallback-v1" string that was
    previously used as a production fallback has been intentionally deleted.
    Any deployment that relied on it must now set RAKSHAK_AES_KEY or SECRET_KEY.
    """
    configured_key = os.getenv(AES_KEY_ENV)
    if configured_key:
        return _decode_aes_key(configured_key)

    if _is_truthy_env("RAKSHAK_TESTING"):
        return _TESTING_AES_KEY

    environment = os.getenv("RAKSHAK_ENV", "").strip().lower()
    if environment in {"dev", "development", "local"}:
        logger.warning(
            "[security] %s is unset; using an ephemeral AES key for development.",
            AES_KEY_ENV,
        )
        return os.urandom(AES_KEY_BYTES)

    secret = os.getenv("SECRET_KEY") or os.getenv("RAKSHAK_SECRET_KEY")
    if secret:
        logger.warning(
            "[security] %s is unset in production; deriving AES key from SECRET_KEY via HKDF. "
            "Configure %s for a stable encryption key.",
            AES_KEY_ENV,
            AES_KEY_ENV,
        )
        return HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_BYTES,
            salt=_HKDF_SALT,
            info=b"payload-encryption",
        ).derive(secret.encode("utf-8"))

    # FAIL CLOSED — no key available in production
    raise RuntimeError(
        f"[security] PRODUCTION STARTUP ABORTED: Neither {AES_KEY_ENV} nor SECRET_KEY "
        "is configured. Set RAKSHAK_AES_KEY to a 64-character hex string (32 random bytes) "
        "or SECRET_KEY as a fallback. The legacy hardcoded secret has been removed for "
        "security compliance."
    )


def validate_crypto_config() -> None:
    """Validate encryption configuration during application startup."""
    _get_aes_key()


def encrypt_payload(plaintext: str | bytes) -> str:
    """Encrypt a UTF-8 string or bytes with AES-256-GCM.

    The returned token is base64(nonce || ciphertext || authentication tag).
    A fresh 96-bit nonce is generated for every call.
    """
    if isinstance(plaintext, str):
        payload = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytes):
        payload = plaintext
    else:
        raise TypeError("plaintext must be str or bytes")

    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    ciphertext = AESGCM(_get_aes_key()).encrypt(nonce, payload, None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_payload(token: str) -> str:
    """Decrypt and authenticate a token produced by :func:`encrypt_payload`."""
    try:
        encoded = base64.b64decode(token, validate=True)
        if len(encoded) < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES:
            raise ValueError("Encrypted payload is too short.")
        nonce = encoded[:AES_GCM_NONCE_BYTES]
        ciphertext = encoded[AES_GCM_NONCE_BYTES:]
        plaintext = AESGCM(_get_aes_key()).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except (binascii.Error, InvalidTag, UnicodeDecodeError, TypeError, ValueError) as error:
        raise ValueError("Invalid encrypted payload.") from error


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


async def read_upload_chunked(uploaded_file) -> bytes:
    """
    Read an UploadFile in 64 KB chunks, aborting with HTTP 413 as soon as
    cumulative bytes exceed MAX_FILE_SIZE_BYTES.

    This prevents loading a multi-gigabyte file into RAM before the size check.
    Raises fastapi.HTTPException(413) on oversized uploads.
    Returns the complete content bytes for valid-sized files.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await uploaded_file.read(_UPLOAD_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_FILE_SIZE_BYTES:
            size_mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum allowed size is {size_mb} MB.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def generate_safe_filename(
    original_name: str,
    prefix: str = "",
    content: bytes | None = None,
) -> str:
    """
    Generate a fully server-controlled, content-addressed filename that
    prevents directory traversal, path injection, and information leakage.

    The original client filename is NOT preserved in the stored name.

    Format: {prefix}_{timestamp}_{sha256_of_content[:16]}_{nonce}.{safe_ext}

    When *content* is provided the hash is computed from the actual file bytes,
    making the name content-addressed.  When *content* is None the hash falls
    back to hashing the original filename string (preserving backward compat
    for callers that don't pass content).

    The 128-bit random hex nonce (secrets.token_hex(16)) appended after the
    hash ensures that two identical uploads by different users never collide
    on the filesystem and that filenames are not guessable even if the content
    hash is known.
    """
    _, ext = os.path.splitext(original_name.lower())
    # Sanitize extension — only keep alphanumeric chars
    safe_ext = re.sub(r"[^\w]", "", ext)[:6]

    # Content-addressed hash: use actual bytes when available, else filename
    if content is not None:
        name_hash = hashlib.sha256(content).hexdigest()[:16]
    else:
        name_hash = hashlib.sha256(original_name.encode()).hexdigest()[:16]

    # 128-bit cryptographically random nonce (32 hex chars)
    nonce = secrets.token_hex(16)

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    parts = [p for p in [prefix, timestamp, name_hash, nonce] if p]
    base = "_".join(parts)
    return f"{base}.{safe_ext}" if safe_ext else base


def check_upload_path(base_dir: str, target_path: str) -> bool:
    """
    Return True if *target_path* is contained within *base_dir*.

    Uses os.path.commonpath() rather than startswith() to prevent path
    traversal bypasses on case-insensitive filesystems and paths that share
    a common prefix string but differ in directory structure.

    Example of the startswith() bypass this prevents:
        base_dir   = "/app/uploads"
        target     = "/app/uploads-evil/../../etc/passwd"
        startswith → True (wrong!)
        commonpath → "/app" != "/app/uploads" → False (correct)
    """
    try:
        common = os.path.commonpath(
            [os.path.realpath(base_dir), os.path.realpath(target_path)]
        )
        return common == os.path.realpath(base_dir)
    except (ValueError, OSError):
        return False


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
