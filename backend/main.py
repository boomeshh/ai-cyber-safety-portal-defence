from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional
import pandas as pd
import sqlite3
import os
import shutil
import hashlib
import secrets
import mimetypes

app = FastAPI(title="Rakshak AI Phase 1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "complaints.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif",
    ".pdf", ".doc", ".docx", ".txt", ".csv",
    ".mp3", ".wav", ".m4a",
    ".mp4", ".mov", ".avi", ".mkv",
    ".apk", ".zip"
}
MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024

os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_column(cursor, table_name: str, column_name: str, definition: str):
    columns = [row[1] for row in cursor.execute(f"PRAGMA table_info({table_name})").fetchall()]
    if column_name not in columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            password_hash TEXT,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            user_name TEXT NOT NULL,
            category TEXT NOT NULL,
            complaint_text TEXT NOT NULL,
            suspicious_url TEXT,
            screenshot_path TEXT,
            threat_type TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            ai_reason TEXT NOT NULL,
            mitigation TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    ensure_column(cursor, "complaints", "evidence_path", "TEXT")
    ensure_column(cursor, "complaints", "evidence_name", "TEXT")
    ensure_column(cursor, "complaints", "evidence_type", "TEXT")
    ensure_column(cursor, "complaints", "evidence_hash", "TEXT")
    ensure_column(cursor, "complaints", "attack_channel", "TEXT")
    ensure_column(cursor, "complaints", "ai_confidence", "INTEGER DEFAULT 0")
    ensure_column(cursor, "complaints", "linked_case_count", "INTEGER DEFAULT 0")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            actor_user_id TEXT,
            actor_name TEXT,
            actor_role TEXT,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT,
            old_value TEXT,
            new_value TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()

    # Migrate older plain-text passwords to secure hash on startup.
    rows = cursor.execute("SELECT id, password, password_hash FROM users").fetchall()
    for row in rows:
        if row["password"] and not row["password_hash"]:
            cursor.execute(
                "UPDATE users SET password_hash = ?, password = NULL WHERE id = ?",
                (hash_password(row["password"]), row["id"]),
            )

    conn.commit()
    conn.close()


# ---------- Security helpers ----------
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash or "$" not in stored_hash:
        return False
    salt, digest_hex = stored_hash.split("$", 1)
    test_digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000).hex()
    return secrets.compare_digest(test_digest, digest_hex)


def create_session(user_id: str, role: str) -> str:
    token = secrets.token_urlsafe(40)
    created_at = datetime.now()
    expires_at = created_at + timedelta(hours=12)

    conn = get_connection()
    conn.execute(
        "INSERT INTO sessions (token, user_id, role, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
        (token, user_id, role, expires_at.isoformat(), created_at.isoformat()),
    )
    conn.commit()
    conn.close()
    return token


def extract_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    prefix = "Bearer "
    if authorization.startswith(prefix):
        return authorization[len(prefix):].strip()
    return authorization.strip()


def get_current_user(authorization: Optional[str]) -> dict:
    token = extract_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Missing access token")

    conn = get_connection()
    session = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
    if not session:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid session")

    if datetime.fromisoformat(session["expires_at"]) < datetime.now():
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="Session expired")

    user = conn.execute(
        "SELECT id, full_name, email, role, created_at FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(user)


def write_audit(actor_user_id, actor_name, actor_role, action, target_type, target_id=None, old_value=None, new_value=None, details=None):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO audit_logs (
            id, actor_user_id, actor_name, actor_role, action, target_type,
            target_id, old_value, new_value, details, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"AUD-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
            actor_user_id,
            actor_name,
            actor_role,
            action,
            target_type,
            target_id,
            old_value,
            new_value,
            details,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()


# ---------- AI / risk helpers ----------
def detect_channel(text: str, url: str, evidence_name: str) -> str:
    base = f"{text} {url} {evidence_name}".lower()
    if any(word in base for word in ["whatsapp", "telegram", "sms", "message"]):
        return "Messaging"
    if any(word in base for word in ["mail", "email", ".eml"]):
        return "Email"
    if any(word in base for word in ["call", "voice", "audio"]):
        return "Voice Call"
    if any(word in base for word in ["instagram", "facebook", "social", "profile"]):
        return "Social Media"
    return "Unknown"


def calculate_risk(complaint_text: str, suspicious_url: str, evidence_name: str = ""):
    text = (complaint_text or "").lower()
    url = (suspicious_url or "").lower()
    file_name = (evidence_name or "").lower()

    score = 0
    reasons = []
    tags = set()

    keyword_weights = {
        "otp": 25,
        "password": 25,
        "bank": 20,
        "login": 18,
        "verify": 16,
        "urgent": 12,
        "immediately": 10,
        "suspended": 15,
        "click": 10,
        "army": 20,
        "defence": 20,
        "official": 12,
        "support": 8,
        "kyc": 10,
        "update": 8,
        "reward": 10,
        "blocked": 12,
        "account": 10,
        "confidential": 16,
        "classified": 28,
        "posting": 14,
        "deployment": 18,
        "location": 12,
        "salary": 8,
        "investment": 8,
        "apk": 22,
        "attachment": 14,
        "resume": 8,
        "friend request": 14,
        "romance": 18,
        "video call": 18,
    }

    for word, weight in keyword_weights.items():
        if word in text:
            score += weight
            reasons.append(f"Keyword indicator: {word}")

    if url:
        score += 10
        reasons.append("URL submitted for analysis")
        tags.add("Phishing")

    if any(shortener in url for shortener in ["bit.ly", "tinyurl", "shorturl", "goo.gl"]):
        score += 25
        reasons.append("Shortened URL detected")
        tags.add("Phishing")

    if "http://" in url:
        score += 10
        reasons.append("Non-secure HTTP link detected")

    if any(pattern in url for pattern in ["verify", "login", "update", "secure", "account", "gift", "bonus"]):
        score += 12
        reasons.append("Suspicious URL pattern detected")
        tags.add("Phishing")

    if file_name:
        reasons.append(f"Evidence file detected: {file_name}")

    if file_name.endswith((".apk", ".zip", ".exe")):
        score += 28
        reasons.append("Potential malware-bearing attachment detected")
        tags.add("Malware")

    if any(word in text for word in ["honeytrap", "romance", "friend request", "video call", "girl", "relationship"]):
        score += 24
        reasons.append("Possible honeytrap / social engineering indicators")
        tags.add("Honeytrap / Social Engineering")

    if any(word in text for word in ["army", "defence", "regiment", "unit", "officer"]) and any(word in text for word in ["verify", "official", "login", "payment", "kyc"]):
        score += 26
        reasons.append("Possible defence impersonation pattern detected")
        tags.add("Defence Impersonation")

    if any(word in text for word in ["classified", "deployment", "location", "movement", "unit strength"]):
        score += 30
        reasons.append("Potential OPSEC / sensitive operational data exposure")
        tags.add("OPSEC Leak Risk")

    if any(word in text for word in ["spy", "espionage", "confidential", "internal document"]):
        score += 28
        reasons.append("Potential espionage indicator identified")
        tags.add("Espionage Indicator")

    if "otp" in text and "click" in text:
        score += 15
        reasons.append("Credential theft pattern detected")
        tags.add("Phishing")

    if "bank" in text and "urgent" in text:
        score += 15
        reasons.append("High-pressure financial scam pattern detected")
        tags.add("Financial Fraud")

    if "password" in text and "login" in text:
        score += 12
        reasons.append("Account compromise pattern detected")
        tags.add("Phishing")

    if not tags:
        tags.add("Suspicious Communication")

    score = min(score, 100)
    confidence = min(55 + score // 2, 98)

    if score >= 81:
        level = "Critical"
        mitigation = "Do not interact further. Disconnect affected device if needed, preserve evidence, reset credentials, and escalate to CERT immediately."
        status = "Escalated"
    elif score >= 61:
        level = "High"
        mitigation = "Avoid clicking links or opening files. Verify through trusted official channels and change credentials if already exposed."
        status = "Under Review"
    elif score >= 31:
        level = "Medium"
        mitigation = "Proceed cautiously. Preserve screenshots/files and verify the sender before taking action."
        status = "Open"
    else:
        level = "Low"
        mitigation = "Monitor the issue and verify authenticity through official channels."
        status = "Open"

    return {
        "score": score,
        "level": level,
        "reason": "; ".join(reasons) if reasons else "General suspicious activity indicators detected",
        "mitigation": mitigation,
        "threat_type": " | ".join(sorted(tags)),
        "confidence": confidence,
        "status": status,
    }


def compute_file_hash(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as file_obj:
        while chunk := file_obj.read(8192):
            digest.update(chunk)
    return digest.hexdigest()


def get_linked_case_count(suspicious_url: str, evidence_hash: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    count = cursor.execute(
        """
        SELECT COUNT(*) AS total FROM complaints
        WHERE (suspicious_url != '' AND suspicious_url = ?)
           OR (evidence_hash != '' AND evidence_hash = ?)
        """,
        (suspicious_url or "", evidence_hash or ""),
    ).fetchone()["total"]
    conn.close()
    return int(count or 0)


init_db()


class RegisterRequest(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role: str = "user"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class StatusUpdate(BaseModel):
    status: str


@app.get("/")
def root():
    return {"message": "Rakshak AI Phase 1 Backend Running"}


@app.post("/register")
def register_user(payload: RegisterRequest):
    conn = get_connection()
    existing = conn.execute("SELECT * FROM users WHERE email = ?", (payload.email.lower(),)).fetchone()
    if existing:
        conn.close()
        return {"success": False, "message": "Email already registered"}

    user_id = f"USR-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute(
        "INSERT INTO users (id, full_name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, payload.full_name.strip(), payload.email.lower(), hash_password(payload.password), payload.role, created_at),
    )
    conn.commit()
    conn.close()

    write_audit(user_id, payload.full_name.strip(), payload.role, "USER_REGISTERED", "user", user_id, details=payload.email.lower())
    return {"success": True, "message": "User registered successfully", "user_id": user_id}


@app.post("/login")
def login_user(payload: LoginRequest):
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (payload.email.lower(),)).fetchone()
    conn.close()

    if not user or not verify_password(payload.password, user["password_hash"]):
        return {"success": False, "message": "Invalid email or password"}

    token = create_session(user["id"], user["role"])
    safe_user = {
        "id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "role": user["role"],
        "created_at": user["created_at"],
    }
    write_audit(user["id"], user["full_name"], user["role"], "USER_LOGIN", "session", details="Session created")
    return {"success": True, "message": "Login successful", "user": safe_user, "token": token}


@app.get("/me")
def get_me(authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)
    return {"success": True, "user": user}


@app.post("/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    token = extract_token(authorization)
    if not token:
        return {"success": False, "message": "Missing token"}

    conn = get_connection()
    deleted = conn.execute("DELETE FROM sessions WHERE token = ?", (token,)).rowcount
    conn.commit()
    conn.close()
    return {"success": bool(deleted), "message": "Logged out" if deleted else "Session not found"}


@app.post("/complaints")
async def create_complaint(
    user_id: str = Form(...),
    user_name: str = Form(...),
    category: str = Form(...),
    complaint_text: str = Form(...),
    suspicious_url: str = Form(""),
    evidence: UploadFile | None = File(None),
    screenshot: UploadFile | None = File(None),
    authorization: Optional[str] = Header(default=None),
):
    current_user = get_current_user(authorization)
    if current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="User mismatch")

    uploaded_file = evidence or screenshot
    evidence_path = ""
    evidence_name = ""
    evidence_type = ""
    evidence_hash = ""

    if uploaded_file and uploaded_file.filename:
        _, ext = os.path.splitext(uploaded_file.filename.lower())
        if ext and ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}")

        content = await uploaded_file.read()
        if len(content) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(status_code=400, detail="File too large. Maximum size is 15 MB")

        complaint_id = f"RK-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        evidence_name = uploaded_file.filename
        safe_name = f"{complaint_id}_{os.path.basename(uploaded_file.filename)}"
        evidence_path = os.path.join(UPLOAD_DIR, safe_name)
        with open(evidence_path, "wb") as out_file:
            out_file.write(content)
        evidence_type = uploaded_file.content_type or mimetypes.guess_type(uploaded_file.filename)[0] or "application/octet-stream"
        evidence_hash = compute_file_hash(evidence_path)
    else:
        complaint_id = f"RK-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"

    ai_result = calculate_risk(complaint_text, suspicious_url, evidence_name)
    linked_case_count = get_linked_case_count(suspicious_url, evidence_hash)
    if linked_case_count >= 1:
        ai_result["score"] = min(ai_result["score"] + 10, 100)
        ai_result["confidence"] = min(ai_result["confidence"] + 5, 99)
        ai_result["reason"] += f"; Linked indicator found in {linked_case_count} earlier case(s)"
        if ai_result["score"] >= 81:
            ai_result["level"] = "Critical"
            ai_result["status"] = "Escalated"

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attack_channel = detect_channel(complaint_text, suspicious_url, evidence_name)

    conn = get_connection()
    conn.execute(
        """
        INSERT INTO complaints (
            id, user_id, user_name, category, complaint_text, suspicious_url,
            screenshot_path, threat_type, risk_score, risk_level, ai_reason, mitigation,
            status, created_at, evidence_path, evidence_name, evidence_type,
            evidence_hash, attack_channel, ai_confidence, linked_case_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            complaint_id,
            user_id,
            user_name,
            category,
            complaint_text,
            suspicious_url,
            evidence_path,
            ai_result["threat_type"],
            ai_result["score"],
            ai_result["level"],
            ai_result["reason"],
            ai_result["mitigation"],
            ai_result["status"],
            created_at,
            evidence_path,
            evidence_name,
            evidence_type,
            evidence_hash,
            attack_channel,
            ai_result["confidence"],
            linked_case_count,
        ),
    )
    conn.commit()
    conn.close()

    write_audit(user_id, user_name, current_user["role"], "COMPLAINT_CREATED", "complaint", complaint_id, details=f"Risk {ai_result['level']} / {ai_result['threat_type']}")
    if ai_result["status"] == "Escalated":
        write_audit(user_id, user_name, current_user["role"], "AUTO_ESCALATED", "complaint", complaint_id, new_value="Escalated", details="Critical risk threshold met")

    return {
        "success": True,
        "message": "Complaint submitted successfully",
        "complaint_id": complaint_id,
        "risk_score": ai_result["score"],
        "risk_level": ai_result["level"],
        "threat_type": ai_result["threat_type"],
        "ai_reason": ai_result["reason"],
        "mitigation": ai_result["mitigation"],
        "ai_confidence": ai_result["confidence"],
        "status": ai_result["status"],
        "linked_case_count": linked_case_count,
        "attack_channel": attack_channel,
    }


@app.get("/complaints")
def get_all_complaints():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM complaints ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/my-complaints/{user_id}")
def get_my_complaints(user_id: str, authorization: Optional[str] = Header(default=None)):
    current_user = get_current_user(authorization)
    if current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM complaints WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.patch("/complaints/{complaint_id}/status")
def update_status(complaint_id: str, payload: StatusUpdate):
    conn = get_connection()
    old_row = conn.execute("SELECT status FROM complaints WHERE id = ?", (complaint_id,)).fetchone()
    conn.execute("UPDATE complaints SET status = ? WHERE id = ?", (payload.status, complaint_id))
    conn.commit()
    conn.close()
    write_audit(None, "system", "system", "STATUS_UPDATED", "complaint", complaint_id, old_value=old_row["status"] if old_row else None, new_value=payload.status)
    return {"success": True, "message": "Status updated successfully"}


@app.get("/audit-logs")
def get_audit_logs(limit: int = 50):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/analytics")
def get_analytics():
    conn = get_connection()
    rows = [dict(row) for row in conn.execute("SELECT * FROM complaints").fetchall()]
    conn.close()

    total = len(rows)
    critical = sum(1 for r in rows if r["risk_level"] == "Critical")
    high = sum(1 for r in rows if r["risk_level"] == "High")
    medium = sum(1 for r in rows if r["risk_level"] == "Medium")
    low = sum(1 for r in rows if r["risk_level"] == "Low")
    open_cases = sum(1 for r in rows if r["status"] == "Open")
    under_review = sum(1 for r in rows if r["status"] == "Under Review")
    escalated = sum(1 for r in rows if r["status"] == "Escalated")
    resolved = sum(1 for r in rows if r["status"] == "Resolved")

    threat_distribution = {}
    channel_distribution = {}
    for row in rows:
        for threat in row["threat_type"].split(" | "):
            threat_distribution[threat] = threat_distribution.get(threat, 0) + 1
        channel = row.get("attack_channel") or "Unknown"
        channel_distribution[channel] = channel_distribution.get(channel, 0) + 1

    daily_trend = {}
    for row in rows:
        date_only = row["created_at"].split(" ")[0]
        daily_trend[date_only] = daily_trend.get(date_only, 0) + 1

    risk_distribution = {"Low": low, "Medium": medium, "High": high, "Critical": critical}

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "open_cases": open_cases,
        "under_review": under_review,
        "escalated": escalated,
        "resolved": resolved,
        "threat_distribution": threat_distribution,
        "channel_distribution": channel_distribution,
        "daily_trend": daily_trend,
        "risk_distribution": risk_distribution,
    }


@app.get("/cert/live-alerts")
def get_live_alerts():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM complaints WHERE risk_level = 'Critical' ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/cert/escalated")
def get_escalated_cases():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM complaints WHERE status = 'Escalated' ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/cert/summary")
def get_cert_summary():
    conn = get_connection()
    rows = [dict(row) for row in conn.execute("SELECT * FROM complaints").fetchall()]
    conn.close()

    return {
        "total_cases": len(rows),
        "critical_alerts": sum(1 for r in rows if r["risk_level"] == "Critical"),
        "escalated_cases": sum(1 for r in rows if r["status"] == "Escalated"),
        "open_cases": sum(1 for r in rows if r["status"] == "Open"),
    }


@app.get("/download/excel")
def download_excel():
    conn = get_connection()
    df = pd.read_sql_query("SELECT * FROM complaints ORDER BY created_at DESC", conn)
    conn.close()
    file_name = os.path.join(BASE_DIR, "complaints_export.xlsx")
    df.to_excel(file_name, index=False)
    return FileResponse(
        path=file_name,
        filename="complaints_export.xlsx",
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.put("/update-status/{case_id}")
def update_status_simple(case_id: str, status: str):
    conn = get_connection()
    old_row = conn.execute("SELECT status FROM complaints WHERE id = ?", (case_id,)).fetchone()
    conn.execute("UPDATE complaints SET status = ? WHERE id = ?", (status, case_id))
    conn.commit()
    conn.close()
    write_audit(None, "system", "system", "STATUS_UPDATED", "complaint", case_id, old_value=old_row["status"] if old_row else None, new_value=status)
    return {"success": True, "message": "Status updated successfully"}


@app.get("/cert/full-feed")
def get_cert_full_feed():
    conn = get_connection()
    live_alerts = [dict(row) for row in conn.execute("SELECT * FROM complaints WHERE risk_level = 'Critical' ORDER BY created_at DESC").fetchall()]
    escalated_cases = [dict(row) for row in conn.execute("SELECT * FROM complaints WHERE status = 'Escalated' ORDER BY created_at DESC").fetchall()]
    recent_cases = [dict(row) for row in conn.execute("SELECT * FROM complaints ORDER BY created_at DESC LIMIT 10").fetchall()]
    conn.close()
    return {
        "live_alerts": live_alerts,
        "escalated_cases": escalated_cases,
        "recent_cases": recent_cases,
    }
