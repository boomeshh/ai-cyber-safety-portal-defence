import sqlite3

from main import init_db


def test_startup_initialization_does_not_create_privileged_demo_accounts(tmp_path, monkeypatch):
    test_db = tmp_path / "startup.db"
    monkeypatch.setattr("main.DB_NAME", str(test_db))

    init_db()

    conn = sqlite3.connect(test_db)
    privileged = conn.execute(
        "SELECT role FROM users WHERE role IN ('admin', 'cert')"
    ).fetchall()
    conn.close()

    assert privileged == []
