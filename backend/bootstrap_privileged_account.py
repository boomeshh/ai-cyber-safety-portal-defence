"""Create one privileged account explicitly, without storing or logging passwords."""

import argparse
import getpass
import os
from datetime import datetime

from main import get_connection, hash_password


def create_account(role: str, email: str, full_name: str, password: str) -> bool:
    if not email.strip() or not full_name.strip() or not password:
        raise ValueError("Email, full name, and password are required.")

    conn = get_connection()
    existing = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (email.strip().lower(),),
    ).fetchone()
    if existing:
        conn.close()
        print(f"{role} account already exists; no changes made.")
        return False

    user_id = f"BOOTSTRAP-{role.upper()}-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    conn.execute(
        """
        INSERT INTO users (id, full_name, email, password_hash, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            full_name.strip(),
            email.strip().lower(),
            hash_password(password),
            role,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()
    print(f"{role} account created for {email.strip().lower()}.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Create an Admin or CERT account once.")
    parser.add_argument("--role", choices=("admin", "cert"), required=True)
    parser.add_argument("--email", default=os.getenv("RAKSHAK_BOOTSTRAP_EMAIL"))
    parser.add_argument("--name", default=os.getenv("RAKSHAK_BOOTSTRAP_NAME"))
    args = parser.parse_args()

    email = args.email or input("Account email: ")
    full_name = args.name or input("Account full name: ")
    password = os.getenv("RAKSHAK_BOOTSTRAP_PASSWORD") or getpass.getpass("Account password: ")
    create_account(args.role, email, full_name, password)


if __name__ == "__main__":
    main()
