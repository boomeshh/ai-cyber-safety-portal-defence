from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from datetime import datetime
import pandas as pd
import sqlite3
import os
import shutil

app = FastAPI()

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

DB_NAME = "complaints.db"
UPLOAD_DIR = "uploads"

os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
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

    conn.commit()
    conn.close()


init_db()


def calculate_risk(complaint_text: str, suspicious_url: str):
    text = (complaint_text or "").lower()
    url = (suspicious_url or "").lower()

    score = 0
    reasons = []

    keyword_weights = {
        "otp": 25,
        "password": 25,
        "bank": 20,
        "login": 15,
        "verify": 15,
        "urgent": 10,
        "immediately": 10,
        "suspended": 15,
        "click": 10,
        "army": 20,
        "defence": 20,
        "official": 10,
        "support": 10,
        "kyc": 10,
        "update": 8,
        "reward": 10,
        "blocked": 12,
        "account": 10,
    }

    for word, weight in keyword_weights.items():
        if word in text:
            score += weight
            reasons.append(f"Detected keyword: {word}")

    if url:
        score += 10
        reasons.append("URL submitted for analysis")

    if "bit.ly" in url or "tinyurl" in url or "shorturl" in url:
        score += 25
        reasons.append("Shortened URL detected")

    if "http://" in url:
        score += 10
        reasons.append("Non-secure HTTP link detected")

    if any(pattern in url for pattern in ["verify", "login", "update", "secure", "account"]):
        score += 12
        reasons.append("Suspicious URL pattern detected")

    # Combination pattern scoring
    if "otp" in text and "click" in text:
        score += 15
        reasons.append("Credential theft pattern detected")

    if "bank" in text and "urgent" in text:
        score += 15
        reasons.append("High-pressure financial scam pattern detected")

    if ("army" in text or "defence" in text) and "verify" in text:
        score += 20
        reasons.append("Possible defence impersonation detected")

    if "password" in text and "login" in text:
        score += 12
        reasons.append("Account compromise pattern detected")

    # Final risk buckets
    if score >= 81:
        level = "Critical"
        mitigation = "Do not interact with the sender or link. Escalate immediately and reset affected credentials."
        threat_type = "Phishing / Impersonation"
    elif score >= 61:
        level = "High"
        mitigation = "Avoid clicking links or sharing credentials. Verify through official channels immediately."
        threat_type = "High-Risk Social Engineering"
    elif score >= 31:
        level = "Medium"
        mitigation = "Proceed cautiously. Verify the message and sender before taking any action."
        threat_type = "Suspicious Communication"
    else:
        level = "Low"
        mitigation = "Monitor the case and verify authenticity before proceeding."
        threat_type = "Low-Risk Report"

    if not reasons:
        reasons.append("General suspicious activity indicators detected")

    return score, level, "; ".join(reasons), mitigation, threat_type

class RegisterRequest(BaseModel):
    full_name: str
    email: str
    password: str
    role: str = "user"


class LoginRequest(BaseModel):
    email: str
    password: str


class StatusUpdate(BaseModel):
    status: str


@app.get("/")
def root():
    return {"message": "Rakshak AI Backend Running"}


@app.post("/register")
def register_user(payload: RegisterRequest):
    conn = get_connection()
    cursor = conn.cursor()

    existing = cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (payload.email,)
    ).fetchone()

    if existing:
        conn.close()
        return {"success": False, "message": "Email already registered"}

    user_id = f"USR-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO users (id, full_name, email, password, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        payload.full_name,
        payload.email,
        payload.password,
        payload.role,
        created_at
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "User registered successfully",
        "user_id": user_id
    }


@app.post("/login")
def login_user(payload: LoginRequest):
    conn = get_connection()
    cursor = conn.cursor()

    user = cursor.execute("""
        SELECT * FROM users
        WHERE email = ? AND password = ?
    """, (payload.email, payload.password)).fetchone()

    conn.close()

    if not user:
        return {"success": False, "message": "Invalid email or password"}

    return {
        "success": True,
        "message": "Login successful",
        "user": dict(user)
    }


@app.post("/complaints")
async def create_complaint(
    user_id: str = Form(...),
    user_name: str = Form(...),
    category: str = Form(...),
    complaint_text: str = Form(...),
    suspicious_url: str = Form(""),
    screenshot: UploadFile | None = File(None),
):
    score, level, ai_reason, mitigation, threat_type = calculate_risk(
        complaint_text, suspicious_url
    )

    complaint_id = f"RK-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    screenshot_path = ""
    if screenshot:
        file_path = os.path.join(UPLOAD_DIR, f"{complaint_id}_{screenshot.filename}")
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(screenshot.file, buffer)
        screenshot_path = file_path

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO complaints (
            id, user_id, user_name, category, complaint_text, suspicious_url,
            screenshot_path, threat_type, risk_score, risk_level,
            ai_reason, mitigation, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        complaint_id,
        user_id,
        user_name,
        category,
        complaint_text,
        suspicious_url,
        screenshot_path,
        threat_type,
        score,
        level,
        ai_reason,
        mitigation,
        "Open",
        created_at
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Complaint submitted successfully",
        "complaint_id": complaint_id,
        "risk_score": score,
        "risk_level": level,
        "threat_type": threat_type,
        "ai_reason": ai_reason,
        "mitigation": mitigation
    }


@app.get("/complaints")
def get_all_complaints():
    conn = get_connection()
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT * FROM complaints
        ORDER BY created_at DESC
    """).fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.get("/complaints/{complaint_id}")
def get_complaint_by_id(complaint_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    row = cursor.execute("""
        SELECT * FROM complaints WHERE id = ?
    """, (complaint_id,)).fetchone()
    conn.close()

    if not row:
        return {"success": False, "message": "Complaint not found"}

    return {"success": True, "complaint": dict(row)}


@app.get("/my-complaints/{user_id}")
def get_my_complaints(user_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT * FROM complaints
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,)).fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.patch("/complaints/{complaint_id}/status")
def update_status(complaint_id: str, payload: StatusUpdate):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE complaints
        SET status = ?
        WHERE id = ?
    """, (payload.status, complaint_id))

    conn.commit()
    conn.close()

    return {"success": True, "message": "Status updated successfully"}


@app.get("/analytics")
def get_analytics():
    conn = get_connection()
    cursor = conn.cursor()
    rows = [dict(row) for row in cursor.execute("SELECT * FROM complaints").fetchall()]
    conn.close()

    total = len(rows)
    critical = sum(1 for r in rows if r["risk_level"] == "Critical")
    high = sum(1 for r in rows if r["risk_level"] == "High")
    medium = sum(1 for r in rows if r["risk_level"] == "Medium")
    low = sum(1 for r in rows if r["risk_level"] == "Low")
    open_cases = sum(1 for r in rows if r["status"] == "Open")
    escalated = sum(1 for r in rows if r["status"] == "Escalated")
    resolved = sum(1 for r in rows if r["status"] == "Resolved")

    threat_distribution = {}
    for row in rows:
        threat = row["threat_type"]
        threat_distribution[threat] = threat_distribution.get(threat, 0) + 1

    daily_trend = {}
    for row in rows:
        date_only = row["created_at"].split(" ")[0]
        daily_trend[date_only] = daily_trend.get(date_only, 0) + 1

    risk_distribution = {
        "Low": low,
        "Medium": medium,
        "High": high,
        "Critical": critical
    }

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "open_cases": open_cases,
        "escalated": escalated,
        "resolved": resolved,
        "threat_distribution": threat_distribution,
        "daily_trend": daily_trend,
        "risk_distribution": risk_distribution
    }

@app.get("/cert/live-alerts")
def get_live_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT * FROM complaints
        WHERE risk_level = 'Critical'
        ORDER BY created_at DESC
    """).fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.get("/cert/escalated")
def get_escalated_cases():
    conn = get_connection()
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT * FROM complaints
        WHERE status = 'Escalated'
        ORDER BY created_at DESC
    """).fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.get("/cert/summary")
def get_cert_summary():
    conn = get_connection()
    cursor = conn.cursor()
    rows = [dict(row) for row in cursor.execute("SELECT * FROM complaints").fetchall()]
    conn.close()

    total = len(rows)
    critical = sum(1 for r in rows if r["risk_level"] == "Critical")
    escalated = sum(1 for r in rows if r["status"] == "Escalated")
    open_cases = sum(1 for r in rows if r["status"] == "Open")

    return {
        "total_cases": total,
        "critical_alerts": critical,
        "escalated_cases": escalated,
        "open_cases": open_cases
    }


@app.get("/download/excel")
def download_excel():
    conn = get_connection()
    df = pd.read_sql_query("SELECT * FROM complaints ORDER BY created_at DESC", conn)
    conn.close()

    file_name = "complaints_export.xlsx"
    df.to_excel(file_name, index=False)

    return FileResponse(
        path=file_name,
        filename=file_name,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
@app.put("/update-status/{case_id}")
def update_status_simple(case_id: str, status: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE complaints
        SET status = ?
        WHERE id = ?
    """, (status, case_id))

    conn.commit()
    conn.close()

    return {"success": True, "message": "Status updated successfully"}
@app.get("/cert/full-feed")
def get_cert_full_feed():
    conn = get_connection()
    cursor = conn.cursor()

    live_alerts = [
        dict(row) for row in cursor.execute("""
            SELECT * FROM complaints
            WHERE risk_level = 'Critical'
            ORDER BY created_at DESC
        """).fetchall()
    ]

    escalated_cases = [
        dict(row) for row in cursor.execute("""
            SELECT * FROM complaints
            WHERE status = 'Escalated'
            ORDER BY created_at DESC
        """).fetchall()
    ]

    recent_cases = [
        dict(row) for row in cursor.execute("""
            SELECT * FROM complaints
            ORDER BY created_at DESC
            LIMIT 6
        """).fetchall()
    ]

    conn.close()

    return {
        "live_alerts": live_alerts,
        "escalated_cases": escalated_cases,
        "recent_cases": recent_cases
    }