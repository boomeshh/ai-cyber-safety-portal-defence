"""
Bug Condition Exploration Tests — localhost-config-restore

These tests assert that the BUG EXISTS on the current (unfixed) state of the repo.
They PASS when the bug is present and FAIL after the fix is applied.

Validates: Requirements 1.4, 1.5
"""

import os
import re

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Test 1: backend/.env contains live SMTP credentials
# ---------------------------------------------------------------------------

def test_backend_env_has_real_smtp_user():
    """
    Bug sub-condition 1a: SMTP_USER in backend/.env is a real email address,
    not the placeholder 'your-email@gmail.com'.

    PASSES on unfixed code (bug exists).
    FAILS after fix (placeholder restored).
    """
    env_path = os.path.join(REPO_ROOT, "backend", ".env")
    content = _read(env_path)

    smtp_user = None
    for line in content.splitlines():
        if line.startswith("SMTP_USER="):
            smtp_user = line.split("=", 1)[1].strip()
            break

    assert smtp_user is not None, "SMTP_USER key not found in backend/.env"

    # The bug condition: SMTP_USER is NOT the placeholder
    placeholder = "your-email@gmail.com"
    assert smtp_user != placeholder, (
        f"SMTP_USER is already a placeholder ({placeholder}); bug condition does not hold"
    )

    # Confirm it looks like a real email (contains @)
    assert "@" in smtp_user, f"SMTP_USER '{smtp_user}' does not look like an email address"

    # Counterexample documentation
    print(f"\nCounterexample: SMTP_USER={smtp_user!r} (real email committed to repo)")


def test_backend_env_email_enabled_true():
    """
    Bug sub-condition 1b: EMAIL_ENABLED is 'true' in backend/.env,
    meaning live SMTP credentials are active.

    PASSES on unfixed code (bug exists).
    FAILS after fix (EMAIL_ENABLED=false).
    """
    env_path = os.path.join(REPO_ROOT, "backend", ".env")
    content = _read(env_path)

    email_enabled = None
    for line in content.splitlines():
        if line.startswith("EMAIL_ENABLED="):
            email_enabled = line.split("=", 1)[1].strip()
            break

    assert email_enabled is not None, "EMAIL_ENABLED key not found in backend/.env"

    # The bug condition: EMAIL_ENABLED is 'true'
    assert email_enabled == "true", (
        f"EMAIL_ENABLED is '{email_enabled}', not 'true'; bug condition does not hold"
    )

    print(f"\nCounterexample: EMAIL_ENABLED={email_enabled!r} (live SMTP active)")


# ---------------------------------------------------------------------------
# Test 2: Root .gitignore does NOT exclude .env files
# ---------------------------------------------------------------------------

def test_root_gitignore_missing_env_exclusion():
    """
    Bug sub-condition 2: Root .gitignore does not contain '**/.env' or 'backend/.env',
    leaving .env files unprotected from accidental commits.

    PASSES on unfixed code (bug exists).
    FAILS after fix (exclusion rules added).
    """
    gitignore_path = os.path.join(REPO_ROOT, ".gitignore")
    content = _read(gitignore_path)

    lines = [line.strip() for line in content.splitlines()]

    has_glob_pattern = "**/.env" in lines
    has_backend_pattern = "backend/.env" in lines

    # The bug condition: neither pattern is present
    assert not has_glob_pattern and not has_backend_pattern, (
        "Root .gitignore already excludes .env files; bug condition does not hold. "
        f"Found '**/.env': {has_glob_pattern}, found 'backend/.env': {has_backend_pattern}"
    )

    print(
        f"\nCounterexample: Root .gitignore has no '**/.env' or 'backend/.env' entry "
        f"(content snippet: {content[:200]!r})"
    )


# ---------------------------------------------------------------------------
# Test 3: admin-frontend/.gitignore does NOT contain a bare .env entry
# ---------------------------------------------------------------------------

def test_admin_frontend_gitignore_missing_env_exclusion():
    """
    Bug sub-condition 3: admin-frontend/.gitignore does not contain a bare '.env' entry,
    leaving admin-frontend/.env unprotected.

    PASSES on unfixed code (bug exists).
    FAILS after fix (.env entry added).
    """
    gitignore_path = os.path.join(REPO_ROOT, "admin-frontend", ".gitignore")
    content = _read(gitignore_path)

    lines = [line.strip() for line in content.splitlines()]

    # A bare '.env' entry (not '.env.local' etc.)
    has_bare_env = ".env" in lines

    assert not has_bare_env, (
        "admin-frontend/.gitignore already contains a bare '.env' entry; "
        "bug condition does not hold"
    )

    print(
        f"\nCounterexample: admin-frontend/.gitignore has no bare '.env' entry "
        f"(has .env.local variants only)"
    )


# ---------------------------------------------------------------------------
# Test 4: cert-frontend/.gitignore does NOT contain a bare .env entry
# ---------------------------------------------------------------------------

def test_cert_frontend_gitignore_missing_env_exclusion():
    """
    Bug sub-condition 4: cert-frontend/.gitignore does not contain a bare '.env' entry,
    leaving cert-frontend/.env unprotected.

    PASSES on unfixed code (bug exists).
    FAILS after fix (.env entry added).
    """
    gitignore_path = os.path.join(REPO_ROOT, "cert-frontend", ".gitignore")
    content = _read(gitignore_path)

    lines = [line.strip() for line in content.splitlines()]

    has_bare_env = ".env" in lines

    assert not has_bare_env, (
        "cert-frontend/.gitignore already contains a bare '.env' entry; "
        "bug condition does not hold"
    )

    print(
        f"\nCounterexample: cert-frontend/.gitignore has no bare '.env' entry "
        f"(has .env.local variants only)"
    )


# ---------------------------------------------------------------------------
# Test 5: LOCALHOST_SETUP.md does NOT exist at repo root
# ---------------------------------------------------------------------------

def test_localhost_setup_md_absent():
    """
    Bug sub-condition 5: LOCALHOST_SETUP.md does not exist at the repo root,
    leaving developers without setup instructions.

    PASSES on unfixed code (bug exists).
    FAILS after fix (file created).
    """
    setup_doc_path = os.path.join(REPO_ROOT, "LOCALHOST_SETUP.md")

    assert not os.path.exists(setup_doc_path), (
        f"LOCALHOST_SETUP.md already exists at {setup_doc_path}; "
        "bug condition does not hold"
    )

    print(f"\nCounterexample: LOCALHOST_SETUP.md is absent from repo root ({REPO_ROOT})")
