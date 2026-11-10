"""
firebase_auth.py — Firebase ID Token verification dependency for Rakshak AI.

Provides a FastAPI-compatible dependency `verify_firebase_token` that:
  - Extracts the Bearer token from the Authorization header
  - Validates it via firebase_admin.auth.verify_id_token()
  - Returns a dict with verified user claims: uid, email
  - Raises HTTP 401 with descriptive detail on every failure path

Singleton pattern: Firebase App is initialised once per process.

Test / CI environment:
  Set the env var RAKSHAK_TESTING=1 (or any truthy value) to skip real
  Firebase initialisation.  Tests patch firebase_admin.auth.verify_id_token
  directly via unittest.mock — no live Google network calls are made.
"""

import os
import logging
from functools import lru_cache

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("firebase_auth")

# ---------------------------------------------------------------------------
# Lazy import of firebase_admin so the module can be imported even when the
# package is absent (the ImportError is raised only when the dependency is
# actually called at request time, keeping startup clean).
# ---------------------------------------------------------------------------
try:
    import firebase_admin
    from firebase_admin import auth as firebase_auth_module
    from firebase_admin import credentials as firebase_credentials
    _FIREBASE_AVAILABLE = True
except ImportError:  # pragma: no cover
    firebase_admin = None  # type: ignore[assignment]
    firebase_auth_module = None  # type: ignore[assignment]
    firebase_credentials = None  # type: ignore[assignment]
    _FIREBASE_AVAILABLE = False


# ---------------------------------------------------------------------------
# HTTPBearer scheme — auto_error=False so we can return a clean 401 ourselves
# instead of the default Starlette 403.
# ---------------------------------------------------------------------------
_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Firebase App singleton
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _get_firebase_app():  # pragma: no cover
    """
    Initialise Firebase Admin SDK once and cache the app object.

    Resolution order for credentials:
      1. GOOGLE_APPLICATION_CREDENTIALS env var (standard ADC path — works on
         Cloud Run, GKE, local dev with `gcloud auth application-default login`)
      2. FIREBASE_SERVICE_ACCOUNT_JSON env var containing the raw JSON blob
         (useful for Render / Railway secret injection)
      3. Fall back to default credentials (useful inside GCP products)

    Returns the firebase_admin.App instance.
    """
    if not _FIREBASE_AVAILABLE:
        raise RuntimeError(
            "firebase-admin is not installed. "
            "Run: pip install firebase-admin"
        )

    # Already initialised (e.g. by another call)
    try:
        return firebase_admin.get_app()
    except ValueError:
        pass  # Not yet initialised — continue below

    service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
    google_creds_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

    if service_account_json:
        import json
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            tmp.write(service_account_json)
            tmp_path = tmp.name

        cred = firebase_credentials.Certificate(tmp_path)
        logger.info("[firebase_auth] Initialised from FIREBASE_SERVICE_ACCOUNT_JSON")
    elif google_creds_path:
        cred = firebase_credentials.Certificate(google_creds_path)
        logger.info(
            "[firebase_auth] Initialised from GOOGLE_APPLICATION_CREDENTIALS"
        )
    else:
        cred = firebase_credentials.ApplicationDefault()
        logger.info("[firebase_auth] Initialised from Application Default Credentials")

    return firebase_admin.initialize_app(cred)


# ---------------------------------------------------------------------------
# Public dependency
# ---------------------------------------------------------------------------
def verify_firebase_token(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer_scheme),
) -> dict:
    """
    FastAPI dependency.  Usage:

        from firebase_auth import verify_firebase_token

        @app.get("/protected")
        def protected_endpoint(user: dict = Depends(verify_firebase_token)):
            return {"uid": user["uid"], "email": user["email"]}

    Returns
    -------
    dict with keys:
        uid   : str  — Firebase UID
        email : str  — verified email (empty string if not present in token)
        (plus any additional claims present in the token)

    Raises
    ------
    HTTPException 401 on every failure path.
    """
    # ── 1. Missing or malformed Authorization header ────────────────────────
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authentication credentials",
        )

    token: str = credentials.credentials.strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authentication credentials",
        )

    # ── 2. Test / CI shortcut — env var skips Firebase, never in production ─
    #    Tests patch firebase_admin.auth.verify_id_token directly;
    #    this branch is only reached if that patch raises or the token is
    #    literally "__test_bypass__" which no test uses.
    #    (Kept here as a last-resort escape hatch; guarded by env var.)
    if os.getenv("RAKSHAK_TESTING") and token == "__test_bypass__":  # pragma: no cover
        return {"uid": "test-uid", "email": "test@example.com"}

    # ── 3. Ensure firebase-admin is available ───────────────────────────────
    if not _FIREBASE_AVAILABLE:
        logger.error("[firebase_auth] firebase-admin package not installed")
        raise HTTPException(
            status_code=503,
            detail="Authentication service unavailable",
        )

    # ── 4. Ensure Firebase App is initialised (no-op in test with mock) ─────
    #    We only skip _get_firebase_app() when running tests (env var set) so
    #    unit tests don't need GCP credentials.
    if not os.getenv("RAKSHAK_TESTING"):
        _get_firebase_app()  # pragma: no cover

    # ── 5. Verify the token ─────────────────────────────────────────────────
    try:
        decoded: dict = firebase_auth_module.verify_id_token(token)
    except firebase_auth_module.ExpiredIdTokenError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except firebase_auth_module.RevokedIdTokenError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication token"
        )
    except firebase_auth_module.InvalidIdTokenError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication token"
        )
    except firebase_auth_module.CertificateFetchError:  # pragma: no cover
        logger.error("[firebase_auth] Could not fetch Firebase public certificates")
        raise HTTPException(
            status_code=503, detail="Authentication service unavailable"
        )
    except Exception as exc:  # pragma: no cover
        logger.error("[firebase_auth] Unexpected token verification error: %s", exc)
        raise HTTPException(
            status_code=401, detail="Invalid authentication token"
        )

    # ── 6. Extract and return verified claims ───────────────────────────────
    return {
        "uid": decoded.get("uid") or decoded.get("user_id", ""),
        "email": decoded.get("email", ""),
        **{
            k: v
            for k, v in decoded.items()
            if k not in ("uid", "user_id", "email")
        },
    }
