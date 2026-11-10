"""
conftest.py — pytest session fixtures for Rakshak AI backend tests.

Resets the in-memory rate limiter before each test module so that
running all test files together doesn't cause 429 failures from
accumulated login/register calls across modules.
"""

import pytest

TEST_ADMIN_EMAIL = "test-admin@invalid.example"
TEST_ADMIN_PASSWORD = "test-admin-password-only"
TEST_CERT_EMAIL = "test-cert@invalid.example"
TEST_CERT_PASSWORD = "test-cert-password-only"


@pytest.fixture(scope="session", autouse=True)
def provision_test_privileged_accounts(tmp_path_factory):
    import main
    import ml_engine

    test_dir = tmp_path_factory.mktemp("rakshak-tests")
    test_db = test_dir / "complaints.db"
    test_uploads = test_dir / "uploads"
    test_uploads.mkdir()

    original_db_name = main.DB_NAME
    original_ml_db_name = ml_engine.DB_NAME
    original_upload_dir = main.UPLOAD_DIR
    main.DB_NAME = str(test_db)
    ml_engine.DB_NAME = str(test_db)
    main.UPLOAD_DIR = str(test_uploads)
    main.init_db()

    conn = main.get_connection()
    accounts = [
        ("TEST-ADMIN", "Test Admin", TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD, "admin"),
        ("TEST-CERT", "Test CERT", TEST_CERT_EMAIL, TEST_CERT_PASSWORD, "cert"),
    ]
    for user_id, full_name, email, password, role in accounts:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if not existing:
            conn.execute(
                """
                INSERT INTO users (id, full_name, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
                """,
                (user_id, full_name, email, main.hash_password(password), role),
            )
    conn.commit()
    conn.close()
    yield
    main.DB_NAME = original_db_name
    ml_engine.DB_NAME = original_ml_db_name
    main.UPLOAD_DIR = original_upload_dir


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Clear the in-memory rate limit store before every test."""
    try:
        from security_utils import _rate_limit_store
        _rate_limit_store.clear()
    except Exception:
        pass
