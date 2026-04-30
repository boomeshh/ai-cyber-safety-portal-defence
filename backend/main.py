from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional
import pandas as pd
import sqlite3
import os
import hashlib
import secrets
import mimetypes

# Load .env file if present (optional — does not crash if missing)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

from ml_engine import (
    hybrid_analyze_complaint,
    train_threat_model,
    load_model_info,
    normalize_threat_label,
    maybe_auto_retrain,
    get_retrain_status,
    AUTO_RETRAIN_ENABLED,
    MAX_SYNTHETIC_RATIO,
)
from integrations import send_high_risk_alert, check_url_threat_intel, dispatch_cert_alert
from security_utils import (
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
    sanitize_text,
    sanitize_url,
)
from seed_data import seed_complaints

app = FastAPI(title="Rakshak AI - Hybrid ML Backend")

# Security middleware — order matters: rate limit first, then headers
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # Production
        "https://rakshakai.online",
        "https://www.rakshakai.online",
        "https://admin.rakshakai.online",
        "https://cert.rakshakai.online",
        # Local development
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002",
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
    ".apk", ".zip", ".exe"
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


# ---------------- Security Helpers ----------------
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


def require_roles(authorization: Optional[str], allowed_roles: list[str]) -> dict:
    user = get_current_user(authorization)
    if user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return user


def write_audit(
    actor_user_id,
    actor_name,
    actor_role,
    action,
    target_type,
    target_id=None,
    old_value=None,
    new_value=None,
    details=None,
):
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


# ---------------- Database Init ----------------
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
    ensure_column(cursor, "complaints", "ml_prediction", "TEXT")
    ensure_column(cursor, "complaints", "model_used", "TEXT")
    ensure_column(cursor, "complaints", "ml_predicted_type", "TEXT")
    ensure_column(cursor, "complaints", "rule_based_type", "TEXT")
    ensure_column(cursor, "complaints", "campaign_signature", "TEXT")
    ensure_column(cursor, "complaints", "incident_hour", "INTEGER")
    ensure_column(cursor, "complaints", "incident_day", "TEXT")
    ensure_column(cursor, "complaints", "geo_bucket", "TEXT")
    ensure_column(cursor, "complaints", "decision_path", "TEXT")
    ensure_column(cursor, "complaints", "corrected_label", "TEXT")
    ensure_column(cursor, "complaints", "correction_reason", "TEXT")
    ensure_column(cursor, "complaints", "corrected_by", "TEXT")
    ensure_column(cursor, "complaints", "corrected_at", "TEXT")
    ensure_column(cursor, "complaints", "evidence_size", "INTEGER")
    ensure_column(cursor, "complaints", "evidence_indicators", "TEXT")

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

    demo_accounts = [
        ("ADM-DEMO-001", "Rakshak Admin", "admin@rakshak.ai", "admin", "admin123"),
        ("CERT-DEMO-001", "Rakshak CERT Officer", "cert@rakshak.ai", "cert", "cert123"),
    ]

    for user_id, full_name, email, role, raw_password in demo_accounts:
        existing = cursor.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if not existing:
            cursor.execute(
                "INSERT INTO users (id, full_name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    user_id,
                    full_name,
                    email,
                    hash_password(raw_password),
                    role,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )

    conn.commit()

    rows = cursor.execute("SELECT id, password, password_hash FROM users").fetchall()
    for row in rows:
        if row["password"] and not row["password_hash"]:
            cursor.execute(
                "UPDATE users SET password_hash = ?, password = NULL WHERE id = ?",
                (hash_password(row["password"]), row["id"]),
            )

    conn.commit()
    conn.close()


# ---------------- AI / ML Helpers ----------------
def detect_channel(text: str, url: str, evidence_name: str) -> str:
    base = f"{text} {url} {evidence_name}".lower()

    if any(word in base for word in ["whatsapp", "wa.me"]):
        return "WhatsApp"
    if any(word in base for word in ["telegram", "t.me"]):
        return "Telegram"
    if any(word in base for word in ["sms", "otp", "text message"]):
        return "SMS"
    if any(word in base for word in ["email", "mail", ".eml"]):
        return "Email"
    if any(word in base for word in ["call", "voice", "audio"]):
        return "Voice Call"
    if any(word in base for word in ["instagram", "facebook", "x.com", "twitter", "social"]):
        return "Social Media"
    if "http" in base or "www." in base:
        return "Web"

    return "Unknown"


# ---------------------------------------------------------------------------
# ML helpers — thin wrappers around ml_engine
# ---------------------------------------------------------------------------
def get_ml_result(complaint_text: str) -> dict:
    """Legacy compatibility shim — kept so nothing else breaks."""
    from ml_engine import predict_threat_ml
    ml = predict_threat_ml(complaint_text)
    return {
        "prediction": ml["label"].lower().split("/")[0].strip(),
        "confidence": ml["confidence"],
        "all_scores": ml.get("all_scores", {}),
        "model_used": "TF-IDF + LogisticRegression" if ml["available"] else "Rule-Based Fallback",
    }


def extract_evidence_indicators(text: str, url: str) -> dict:
    """Extract URLs, phone numbers, and email addresses from complaint text + URL."""
    import re
    combined = f"{text or ''} {url or ''}"
    urls = re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', combined)
    phones = re.findall(r'\b(?:\+91[\-\s]?)?[6-9]\d{9}\b|\b\d{10,12}\b', combined)
    emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', combined)
    return {
        "urls": list(set(urls))[:10],
        "phones": list(set(phones))[:10],
        "emails": list(set(emails))[:10],
    }


def calculate_rule_risk(complaint_text: str, suspicious_url: str, evidence_name: str = ""):
    text = (complaint_text or "").lower()
    url = (suspicious_url or "").lower()
    file_name = (evidence_name or "").lower()

    score = 0
    indicators = []
    risk_notes = []
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
        "refund": 14,
        "cvv": 20,
        "card": 12,
        "transfer": 12,
    }

    for word, weight in keyword_weights.items():
        if word in text:
            score += weight
            indicators.append(f"Suspicious keyword: {word}")

    if url:
        score += 10
        indicators.append("URL submitted for analysis")
        tags.add("Phishing")

    if any(shortener in url for shortener in ["bit.ly", "tinyurl", "shorturl", "goo.gl"]):
        score += 25
        indicators.append("Shortened URL detected")
        tags.add("Phishing")

    if "http://" in url:
        score += 10
        indicators.append("Non-secure HTTP link detected")

    if any(pattern in url for pattern in ["verify", "login", "update", "secure", "account", "gift", "bonus"]):
        score += 12
        indicators.append("Suspicious URL pattern detected")
        tags.add("Phishing")

    if file_name:
        indicators.append(f"Evidence file attached: {file_name}")

    if file_name.endswith((".apk", ".zip", ".exe")):
        score += 28
        indicators.append("Potential malware-bearing attachment detected")
        tags.add("Malware")
        risk_notes.append("Attachment may deliver malware or a trojanized application.")

    if any(word in text for word in ["honeytrap", "romance", "friend request", "video call", "girl", "relationship"]):
        score += 24
        indicators.append("Possible honeytrap / social engineering indicators")
        tags.add("Honeytrap / Social Engineering")
        risk_notes.append("Conversation pattern may be trying to build trust before exploitation.")

    if any(word in text for word in ["army", "defence", "regiment", "unit", "officer"]) and any(
        word in text for word in ["verify", "official", "login", "payment", "kyc"]
    ):
        score += 26
        indicators.append("Possible defence impersonation pattern detected")
        tags.add("Defence Impersonation")
        risk_notes.append("Message appears to misuse defence identity or authority cues.")

    if any(word in text for word in ["classified", "deployment", "location", "movement", "unit strength"]):
        score += 30
        indicators.append("Potential OPSEC / sensitive operational data exposure")
        tags.add("OPSEC Leak Risk")
        risk_notes.append("Shared content may expose operational or location-sensitive information.")

    if any(word in text for word in ["spy", "espionage", "confidential", "internal document"]):
        score += 28
        indicators.append("Potential espionage indicator identified")
        tags.add("Espionage Indicator")
        risk_notes.append("The complaint contains possible collection or exfiltration cues.")

    if "otp" in text and "click" in text:
        score += 15
        indicators.append("Credential theft pattern detected")
        tags.add("Phishing")
        risk_notes.append("The message may redirect the victim to capture OTP or login credentials.")

    if "bank" in text and "urgent" in text:
        score += 15
        indicators.append("High-pressure financial scam pattern detected")
        tags.add("Financial Fraud")
        risk_notes.append("Urgency and banking language suggest possible fraud or social engineering.")

    if "password" in text and "login" in text:
        score += 12
        indicators.append("Account compromise pattern detected")
        tags.add("Phishing")
        risk_notes.append("Account credential compromise is likely if the message is acted upon.")

    if not risk_notes:
        risk_notes.append("The submitted content shows enough suspicious indicators to require verification through official channels.")

    if not tags:
        tags.add("Suspicious Communication")

    score = min(score, 100)

    return {
        "rule_score": score,
        "indicators": indicators,
        "risk_notes": risk_notes,
        "tags": tags,
    }


def build_hybrid_result(complaint_text: str, suspicious_url: str, evidence_name: str = ""):
    """Full hybrid analysis using rule engine + ML engine."""
    rule_result = calculate_rule_risk(complaint_text, suspicious_url, evidence_name)
    return hybrid_analyze_complaint(
        complaint_text=complaint_text,
        suspicious_url=suspicious_url,
        evidence_name=evidence_name,
        rule_result=rule_result,
    )


def compute_file_hash(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as file_obj:
        while chunk := file_obj.read(8192):
            digest.update(chunk)
    return digest.hexdigest()


def get_linked_case_count(suspicious_url: str, evidence_hash: str) -> int:
    conn = get_connection()
    count = conn.execute(
        """
        SELECT COUNT(*) AS total FROM complaints
        WHERE (suspicious_url != '' AND suspicious_url = ?)
           OR (evidence_hash != '' AND evidence_hash = ?)
        """,
        (suspicious_url or "", evidence_hash or ""),
    ).fetchone()["total"]
    conn.close()
    return int(count or 0)


def get_all_complaints_data():
    conn = get_connection()
    rows = [dict(row) for row in conn.execute("SELECT * FROM complaints ORDER BY created_at DESC").fetchall()]
    conn.close()
    return rows


def build_analytics(rows: list[dict]):
    total = len(rows)
    critical = sum(1 for r in rows if r["risk_level"] == "Critical")
    high = sum(1 for r in rows if r["risk_level"] == "High")
    medium = sum(1 for r in rows if r["risk_level"] == "Medium")
    low = sum(1 for r in rows if r["risk_level"] == "Low")
    open_cases = sum(1 for r in rows if r["status"] == "Open")
    under_review = sum(1 for r in rows if r["status"] == "Under Review")
    escalated = sum(1 for r in rows if r["status"] == "Escalated")
    resolved = sum(1 for r in rows if r["status"] == "Resolved")
    action_initiated = sum(1 for r in rows if r["status"] == "Action Initiated")
    archived = sum(1 for r in rows if r["status"] == "Archived")

    threat_distribution = {}
    channel_distribution = {}
    category_distribution = {}
    model_distribution = {}

    linked_indicator_cases = 0
    auto_escalated_cases = 0

    for row in rows:
        for threat in (row.get("threat_type") or "Unknown").split(" | "):
            threat = threat.strip() or "Unknown"
            threat_distribution[threat] = threat_distribution.get(threat, 0) + 1

        channel = row.get("attack_channel") or "Unknown"
        channel_distribution[channel] = channel_distribution.get(channel, 0) + 1

        category = row.get("category") or "Unknown"
        category_distribution[category] = category_distribution.get(category, 0) + 1

        model_name = row.get("model_used") or "Rule-Based"
        model_distribution[model_name] = model_distribution.get(model_name, 0) + 1

        try:
            if int(row.get("linked_case_count") or 0) > 0:
                linked_indicator_cases += 1
        except (ValueError, TypeError):
            pass

        if row.get("status") == "Escalated" and row.get("risk_level") == "Critical":
            auto_escalated_cases += 1

    daily_trend = {}
    for row in rows:
        created = row.get("created_at") or ""
        date_only = created.split(" ")[0] if created else "unknown"
        if date_only:
            daily_trend[date_only] = daily_trend.get(date_only, 0) + 1

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
        "action_initiated": action_initiated,
        "archived": archived,
        "threat_distribution": threat_distribution,
        "channel_distribution": channel_distribution,
        "category_distribution": category_distribution,
        "daily_trend": daily_trend,
        "risk_distribution": {"Low": low, "Medium": medium, "High": high, "Critical": critical},
        "linked_indicator_cases": linked_indicator_cases,
        "auto_escalated_cases": auto_escalated_cases,
        "model_distribution": model_distribution,
    }


def build_campaign_graph(rows: list[dict]):
    nodes = []
    edges = []
    seen_nodes = set()
    seen_edges = set()

    def add_node(node_id, label, kind, severity="normal"):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({"id": node_id, "label": label, "kind": kind, "severity": severity})

    def add_edge(source, target, label):
        key = (source, target, label)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({"source": source, "target": target, "label": label})

    repeated_rows = [r for r in rows if int(r.get("linked_case_count") or 0) > 0][:12]

    for row in repeated_rows:
        complaint_id = row["id"]
        risk = row.get("risk_level", "Low")
        add_node(complaint_id, complaint_id[-8:], "complaint", risk.lower())

        if row.get("suspicious_url"):
            url_value = row["suspicious_url"]
            url_key = f"url:{url_value[:60]}"
            label = (url_value[:28] + "...") if len(url_value) > 28 else url_value
            add_node(url_key, label, "url", "alert")
            add_edge(complaint_id, url_key, "targets")

        if row.get("evidence_name"):
            ev_key = f"file:{row.get('evidence_hash') or row.get('evidence_name')}"
            add_node(ev_key, row["evidence_name"][:24], "evidence", "normal")
            add_edge(complaint_id, ev_key, "evidence")

        if row.get("attack_channel"):
            ch_key = f"channel:{row['attack_channel']}"
            add_node(ch_key, row["attack_channel"], "channel", "normal")
            add_edge(complaint_id, ch_key, "via")

    return {"nodes": nodes[:30], "edges": edges[:40]}


def build_cert_intel(rows: list[dict]):
    if not rows:
        return {
            "total_cases": 0, "critical_alerts": 0, "escalated_cases": 0,
            "open_cases": 0, "linked_campaigns": 0, "opsec_priority": 0,
            "highest_risk_score": 0, "recent_critical_ids": [], "avg_ai_confidence": 0.0,
        }

    live_alerts = [r for r in rows if r.get("risk_level") == "Critical"]
    escalated_cases = [r for r in rows if r.get("status") == "Escalated"]
    repeated_cases = [r for r in rows if int(r.get("linked_case_count") or 0) > 0]
    opsec_cases = [
        r for r in rows
        if "OPSEC" in (r.get("threat_type") or "") or "Espionage" in (r.get("threat_type") or "")
    ]

    conf_vals = [
        float(r["ai_confidence"])
        for r in rows
        if r.get("ai_confidence") is not None and str(r["ai_confidence"]).strip() != ""
    ]
    avg_confidence = round(sum(conf_vals) / len(conf_vals), 1) if conf_vals else 0.0

    risk_scores = [int(r.get("risk_score") or 0) for r in rows]
    highest = max(risk_scores) if risk_scores else 0

    return {
        "total_cases": len(rows),
        "critical_alerts": len(live_alerts),
        "escalated_cases": len(escalated_cases),
        "open_cases": sum(1 for r in rows if r.get("status") == "Open"),
        "linked_campaigns": len(repeated_cases),
        "opsec_priority": len(opsec_cases),
        "highest_risk_score": highest,
        "recent_critical_ids": [r["id"] for r in live_alerts[:5]],
        "avg_ai_confidence": avg_confidence,
    }


def build_heatmaps(rows: list[dict]) -> dict:
    """Build three heatmap structures. Safe against empty data and missing fields."""
    HOURS = [str(h) for h in range(0, 24)]
    DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    CHANNELS = ["Email", "WhatsApp", "Telegram", "SMS", "Web", "Social Media", "Voice Call", "Unknown"]
    RISK_LEVELS = ["Low", "Medium", "High", "Critical"]
    CATEGORIES = [
        "Phishing", "Suspicious Communication", "Malware / APK Threat",
        "Honeytrap / Romance Manipulation", "Espionage / OPSEC Risk",
        "Identity / Financial Fraud", "Unknown / Needs Review",
    ]

    def _empty_grid(y_len, x_len):
        return [[0] * x_len for _ in range(y_len)]

    if not rows:
        return {
            "hourly_risk_heatmap": {
                "title": "Hour vs Day Threat Heatmap",
                "x_labels": HOURS, "y_labels": DAYS,
                "values": _empty_grid(len(DAYS), len(HOURS)),
            },
            "channel_risk_heatmap": {
                "title": "Channel vs Risk Heatmap",
                "x_labels": RISK_LEVELS, "y_labels": CHANNELS,
                "values": _empty_grid(len(CHANNELS), len(RISK_LEVELS)),
            },
            "category_channel_heatmap": {
                "title": "Category vs Channel Heatmap",
                "x_labels": CHANNELS, "y_labels": CATEGORIES,
                "values": _empty_grid(len(CATEGORIES), len(CHANNELS)),
            },
        }

    # 1. Hour vs Day
    hour_day: dict = {}
    for r in rows:
        try:
            hour = str(int(r.get("incident_hour") or 0))
        except (ValueError, TypeError):
            hour = "0"
        day = r.get("incident_day") or "Monday"
        if day not in DAYS:
            day = "Monday"
        if hour not in HOURS:
            hour = "0"
        hour_day[(hour, day)] = hour_day.get((hour, day), 0) + 1

    hourly_values = [
        [hour_day.get((h, day), 0) for h in HOURS]
        for day in DAYS
    ]

    # 2. Channel vs Risk
    ch_risk: dict = {}
    for r in rows:
        ch = r.get("attack_channel") or "Unknown"
        ch = ch if ch in CHANNELS else "Unknown"
        rl = r.get("risk_level") or "Low"
        rl = rl if rl in RISK_LEVELS else "Low"
        ch_risk[(ch, rl)] = ch_risk.get((ch, rl), 0) + 1

    channel_values = [
        [ch_risk.get((ch, rl), 0) for rl in RISK_LEVELS]
        for ch in CHANNELS
    ]

    # 3. Category vs Channel
    cat_ch: dict = {}
    for r in rows:
        threat = r.get("threat_type") or "Unknown / Needs Review"
        cat = normalize_threat_label(threat)
        if cat not in CATEGORIES:
            cat = "Unknown / Needs Review"
        ch = r.get("attack_channel") or "Unknown"
        ch = ch if ch in CHANNELS else "Unknown"
        cat_ch[(cat, ch)] = cat_ch.get((cat, ch), 0) + 1

    cat_values = [
        [cat_ch.get((cat, ch), 0) for ch in CHANNELS]
        for cat in CATEGORIES
    ]

    return {
        "hourly_risk_heatmap": {
            "title": "Hour vs Day Threat Heatmap",
            "x_labels": HOURS, "y_labels": DAYS,
            "values": hourly_values,
        },
        "channel_risk_heatmap": {
            "title": "Channel vs Risk Heatmap",
            "x_labels": RISK_LEVELS, "y_labels": CHANNELS,
            "values": channel_values,
        },
        "category_channel_heatmap": {
            "title": "Category vs Channel Heatmap",
            "x_labels": CHANNELS, "y_labels": CATEGORIES,
            "values": cat_values,
        },
    }


def build_campaign_clusters(rows: list[dict]) -> list[dict]:
    """
    Group complaints by campaign_signature into cluster summaries.
    Includes: count, dominant risk, avg confidence, dominant category/channel.
    """
    clusters: dict = {}
    for r in rows:
        sig = (r.get("campaign_signature") or "").strip()
        if not sig:
            continue
        if sig not in clusters:
            clusters[sig] = {
                "signature": sig,
                "count": 0,
                "categories": {},
                "channels": {},
                "risk_levels": {},
                "risk_scores": [],
                "confidence_vals": [],
            }
        c = clusters[sig]
        c["count"] += 1

        cat = normalize_threat_label(r.get("threat_type") or "Unknown")
        c["categories"][cat] = c["categories"].get(cat, 0) + 1

        ch = r.get("attack_channel") or "Unknown"
        c["channels"][ch] = c["channels"].get(ch, 0) + 1

        rl = r.get("risk_level") or "Low"
        c["risk_levels"][rl] = c["risk_levels"].get(rl, 0) + 1

        try:
            c["risk_scores"].append(int(r.get("risk_score") or 0))
        except (ValueError, TypeError):
            pass

        try:
            conf = r.get("ai_confidence")
            if conf is not None and str(conf).strip() != "":
                c["confidence_vals"].append(float(conf))
        except (ValueError, TypeError):
            pass

    result = []
    for sig, c in sorted(clusters.items(), key=lambda x: x[1]["count"], reverse=True)[:15]:
        dominant_cat = max(c["categories"], key=c["categories"].get) if c["categories"] else "Unknown"
        dominant_ch = max(c["channels"], key=c["channels"].get) if c["channels"] else "Unknown"
        dominant_risk = max(c["risk_levels"], key=c["risk_levels"].get) if c["risk_levels"] else "Low"
        avg_risk = round(sum(c["risk_scores"]) / len(c["risk_scores"]), 1) if c["risk_scores"] else 0
        avg_conf = round(sum(c["confidence_vals"]) / len(c["confidence_vals"]), 1) if c["confidence_vals"] else 0

        result.append({
            "signature": sig,
            "count": c["count"],
            "dominant_category": dominant_cat,
            "dominant_channel": dominant_ch,
            "dominant_risk_level": dominant_risk,
            "avg_risk_score": avg_risk,
            "avg_confidence": avg_conf,
        })
    return result


init_db()
seed_complaints(DB_NAME)


# ---------------- Request Models ----------------
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


# ---------------- Routes ----------------
@app.get("/")
def root():
    return {"message": "Rakshak AI Hybrid Backend Running"}


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
        (
            user_id,
            payload.full_name.strip(),
            payload.email.lower(),
            hash_password(payload.password),
            payload.role,
            created_at,
        ),
    )
    conn.commit()
    conn.close()

    write_audit(
        user_id,
        payload.full_name.strip(),
        payload.role,
        "USER_REGISTERED",
        "user",
        user_id,
        details=payload.email.lower(),
    )
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
    return {"success": True, "user": get_current_user(authorization)}


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
    complaint_id = f"RK-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"

    if uploaded_file and uploaded_file.filename:
        _, ext = os.path.splitext(uploaded_file.filename.lower())
        if ext and ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}")

        content = await uploaded_file.read()
        if len(content) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(status_code=400, detail="File too large. Maximum size is 15 MB")

        evidence_name = uploaded_file.filename
        safe_name = f"{complaint_id}_{os.path.basename(uploaded_file.filename)}"
        evidence_path = os.path.join(UPLOAD_DIR, safe_name)

        with open(evidence_path, "wb") as out_file:
            out_file.write(content)

        evidence_type = uploaded_file.content_type or mimetypes.guess_type(uploaded_file.filename)[0] or "application/octet-stream"
        evidence_hash = compute_file_hash(evidence_path)

    # Sanitize inputs before analysis
    complaint_text = sanitize_text(complaint_text)
    suspicious_url = sanitize_url(suspicious_url)

    # URL threat intelligence check (non-blocking, enriches indicators)
    url_intel = {}
    if suspicious_url:
        try:
            url_intel = check_url_threat_intel(suspicious_url)
        except Exception:
            url_intel = {}

    ai_result = build_hybrid_result(complaint_text, suspicious_url, evidence_name)

    # Boost score if URL flagged as malicious by threat intel
    if url_intel.get("is_malicious"):
        ai_result["score"] = min(ai_result["score"] + 15, 100)
        ai_result["reason"] += f"\n\nThreat Intel:\n• URL flagged: {url_intel.get('details', '')}"
        if ai_result["score"] >= 81:
            ai_result["level"] = "Critical"
            ai_result["status"] = "Escalated"
    linked_case_count = get_linked_case_count(suspicious_url, evidence_hash)

    if linked_case_count >= 1:
        ai_result["score"] = min(ai_result["score"] + 10, 100)
        ai_result["confidence"] = min(ai_result["confidence"] + 5, 99)
        ai_result["reason"] += f"\n\nCampaign Alert:\n• Linked indicator found in {linked_case_count} earlier case(s)."

        if ai_result["score"] >= 81:
            ai_result["level"] = "Critical"
            ai_result["status"] = "Escalated"

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attack_channel = detect_channel(complaint_text, suspicious_url, evidence_name)
    incident_hour = datetime.now().hour
    incident_day = datetime.now().strftime("%A")
    decision_path = ai_result.get("decision_path", "")

    # Extract evidence indicators from text + URL
    import json as _json
    ev_indicators = extract_evidence_indicators(complaint_text, suspicious_url)
    evidence_indicators_json = _json.dumps(ev_indicators)

    # Evidence file size
    evidence_size = 0
    if evidence_path and os.path.exists(evidence_path):
        try:
            evidence_size = os.path.getsize(evidence_path)
        except Exception:
            pass

    # Derive campaign_signature: domain + threat type for consistent grouping
    campaign_signature = ""
    threat_slug = (ai_result.get("rule_based_type") or ai_result["threat_type"] or "unknown")[:20].lower().replace(" ", "-").replace("/", "-")
    if suspicious_url:
        try:
            from urllib.parse import urlparse
            domain = urlparse(suspicious_url).netloc or suspicious_url[:40]
            campaign_signature = f"url:{domain}:{threat_slug}"
        except Exception:
            campaign_signature = f"url:{suspicious_url[:30]}:{threat_slug}"
    elif evidence_hash:
        campaign_signature = f"file:{evidence_hash[:12]}:{threat_slug}"
    elif attack_channel and attack_channel != "Unknown":
        campaign_signature = f"ch:{attack_channel.lower()}:{threat_slug}"

    conn = get_connection()
    conn.execute(
        """
        INSERT INTO complaints (
            id, user_id, user_name, category, complaint_text, suspicious_url,
            screenshot_path, threat_type, risk_score, risk_level, ai_reason, mitigation,
            status, created_at, evidence_path, evidence_name, evidence_type,
            evidence_hash, attack_channel, ai_confidence, linked_case_count,
            ml_prediction, model_used, ml_predicted_type, rule_based_type,
            campaign_signature, incident_hour, incident_day, decision_path,
            evidence_size, evidence_indicators
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            complaint_id, user_id, user_name, category, complaint_text, suspicious_url,
            evidence_path, ai_result["threat_type"], ai_result["score"], ai_result["level"],
            ai_result["reason"], ai_result["mitigation"], ai_result["status"], created_at,
            evidence_path, evidence_name, evidence_type, evidence_hash, attack_channel,
            ai_result["confidence"], linked_case_count, ai_result["ml_prediction"],
            ai_result["model_used"], ai_result.get("ml_predicted_type", ai_result["ml_prediction"]),
            ai_result.get("rule_based_type", ""), campaign_signature, incident_hour, incident_day,
            decision_path, evidence_size, evidence_indicators_json,
        ),
    )
    conn.commit()
    conn.close()

    write_audit(
        user_id,
        user_name,
        current_user["role"],
        "COMPLAINT_CREATED",
        "complaint",
        complaint_id,
        details=f"Risk {ai_result['level']} / {ai_result['threat_type']} / ML {ai_result['ml_prediction']}",
    )

    if ai_result["status"] == "Escalated":
        write_audit(
            user_id,
            user_name,
            current_user["role"],
            "AUTO_ESCALATED",
            "complaint",
            complaint_id,
            new_value="Escalated",
            details="Critical risk threshold met",
        )

    response = {
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
        "ml_prediction": ai_result["ml_prediction"],
        "model_used": ai_result["model_used"],
    }

    # Safe auto-retrain — never blocks the response
    try:
        import threading
        threading.Thread(target=maybe_auto_retrain, daemon=True).start()
    except Exception:
        pass

    # Send email alert for High/Critical cases (non-blocking background thread)
    if ai_result["level"] in ("High", "Critical"):
        try:
            import threading
            threading.Thread(
                target=send_high_risk_alert,
                args=(complaint_id, ai_result["level"], ai_result["threat_type"],
                      user_name, int(ai_result["confidence"])),
                daemon=True,
            ).start()
        except Exception:
            pass

    return response


@app.get("/complaints")
def get_all_complaints(authorization: Optional[str] = Header(default=None)):
    require_roles(authorization, ["admin", "cert"])
    return get_all_complaints_data()


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


@app.get("/complaints/{complaint_id}/evidence")
def get_evidence_file(complaint_id: str, authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)

    conn = get_connection()
    row = conn.execute("SELECT * FROM complaints WHERE id = ?", (complaint_id,)).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Complaint not found")

    row = dict(row)

    if user["role"] == "user" and row["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    if not row.get("evidence_path") or not os.path.exists(row["evidence_path"]):
        raise HTTPException(status_code=404, detail="Evidence file not found")

    return FileResponse(
        path=row["evidence_path"],
        filename=row.get("evidence_name") or os.path.basename(row["evidence_path"]),
    )


@app.patch("/complaints/{complaint_id}/status")
def update_status(complaint_id: str, payload: StatusUpdate, authorization: Optional[str] = Header(default=None)):
    actor = require_roles(authorization, ["admin", "cert"])

    conn = get_connection()
    old_row = conn.execute("SELECT status FROM complaints WHERE id = ?", (complaint_id,)).fetchone()

    if not old_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Complaint not found")

    conn.execute("UPDATE complaints SET status = ? WHERE id = ?", (payload.status, complaint_id))
    conn.commit()
    conn.close()

    write_audit(
        actor["id"],
        actor["full_name"],
        actor["role"],
        "STATUS_UPDATED",
        "complaint",
        complaint_id,
        old_value=old_row["status"],
        new_value=payload.status,
    )
    return {"success": True, "message": "Status updated successfully"}


@app.get("/audit-logs")
def get_audit_logs(limit: int = 50, authorization: Optional[str] = Header(default=None)):
    require_roles(authorization, ["admin", "cert"])

    conn = get_connection()
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.get("/analytics")
def get_analytics(authorization: Optional[str] = Header(default=None)):
    require_roles(authorization, ["admin", "cert"])
    return build_analytics(get_all_complaints_data())


@app.get("/admin/overview")
def get_admin_overview(authorization: Optional[str] = Header(default=None)):
    actor = require_roles(authorization, ["admin"])

    complaints = get_all_complaints_data()
    analytics = build_analytics(complaints)

    conn = get_connection()
    audit_rows = [dict(row) for row in conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 20").fetchall()]
    users = [dict(row) for row in conn.execute("SELECT id, full_name, email, role, created_at FROM users ORDER BY created_at DESC").fetchall()]
    conn.close()

    write_audit(actor["id"], actor["full_name"], actor["role"], "ADMIN_OVERVIEW_VIEWED", "dashboard", details="Admin dashboard loaded")

    return {
        "analytics": analytics,
        "complaints": complaints,
        "audit_logs": audit_rows,
        "users": users,
        "campaign_graph": build_campaign_graph(complaints),
    }


@app.get("/cert/live-alerts")
def get_live_alerts(authorization: Optional[str] = Header(default=None)):
    require_roles(authorization, ["cert", "admin"])
    return [r for r in get_all_complaints_data() if r["risk_level"] == "Critical"]


@app.get("/cert/escalated")
def get_escalated_cases(authorization: Optional[str] = Header(default=None)):
    require_roles(authorization, ["cert", "admin"])
    return [r for r in get_all_complaints_data() if r["status"] == "Escalated"]


@app.get("/cert/summary")
def get_cert_summary(authorization: Optional[str] = Header(default=None)):
    require_roles(authorization, ["cert", "admin"])
    return build_cert_intel(get_all_complaints_data())


@app.get("/cert/intel")
def get_cert_intel(authorization: Optional[str] = Header(default=None)):
    actor = require_roles(authorization, ["cert", "admin"])

    complaints = get_all_complaints_data()
    analytics = build_analytics(complaints)
    summary = build_cert_intel(complaints)
    heatmaps = build_heatmaps(complaints)
    campaign_clusters = build_campaign_clusters(complaints)
    model_info = load_model_info()

    repeated_cases = sorted(
        [r for r in complaints if int(r.get("linked_case_count") or 0) > 0],
        key=lambda x: int(x.get("linked_case_count") or 0),
        reverse=True,
    )[:10]

    opsec_cases = [
        r for r in complaints
        if "OPSEC" in (r.get("threat_type") or "") or "Espionage" in (r.get("threat_type") or "")
    ][:10]

    write_audit(actor["id"], actor["full_name"], actor["role"], "CERT_INTEL_VIEWED", "dashboard", details="CERT intel dashboard loaded")

    return {
        "analytics": analytics,
        "summary": summary,
        "campaign_graph": build_campaign_graph(complaints),
        "campaign_clusters": campaign_clusters,
        "heatmaps": heatmaps,
        "model_info": model_info,
        "trend_data": analytics.get("daily_trend", {}),
        "feed": {
            "live_alerts": [r for r in complaints if r["risk_level"] == "Critical"][:10],
            "escalated_cases": [r for r in complaints if r["status"] == "Escalated"][:10],
            "recent_cases": complaints[:10],
            "repeated_cases": repeated_cases,
            "opsec_cases": opsec_cases,
        },
    }


@app.put("/update-status/{case_id}")
def update_status_simple(case_id: str, status: str, authorization: Optional[str] = Header(default=None)):
    actor = require_roles(authorization, ["admin", "cert"])

    conn = get_connection()
    old_row = conn.execute("SELECT status FROM complaints WHERE id = ?", (case_id,)).fetchone()

    if not old_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Complaint not found")

    conn.execute("UPDATE complaints SET status = ? WHERE id = ?", (status, case_id))
    conn.commit()
    conn.close()

    write_audit(
        actor["id"],
        actor["full_name"],
        actor["role"],
        "STATUS_UPDATED",
        "complaint",
        case_id,
        old_value=old_row["status"],
        new_value=status,
    )

    return {"success": True, "message": "Status updated successfully"}


# ---------------------------------------------------------------------------
# AI / ML endpoints
# ---------------------------------------------------------------------------

class TrainRequest(BaseModel):
    use_synthetic: bool = True
    synthetic_ratio_override: Optional[float] = None
    force_retrain: bool = False
    trigger_reason: str = "manual"


@app.post("/ai/train")
def train_model_endpoint(
    payload: TrainRequest = TrainRequest(),
    authorization: Optional[str] = Header(default=None),
):
    """Admin-only: retrain the LogisticRegression model."""
    actor = require_roles(authorization, ["admin"])

    # Validate synthetic ratio
    if payload.synthetic_ratio_override is not None:
        if not (0.0 <= payload.synthetic_ratio_override <= MAX_SYNTHETIC_RATIO):
            raise HTTPException(
                status_code=400,
                detail=f"synthetic_ratio_override must be between 0.0 and {MAX_SYNTHETIC_RATIO}.",
            )

    result = train_threat_model(
        use_synthetic=payload.use_synthetic,
        synthetic_ratio_override=payload.synthetic_ratio_override,
        trigger_reason=payload.trigger_reason,
    )
    write_audit(
        actor["id"], actor["full_name"], actor["role"],
        "AI_MODEL_TRAINED", "model",
        details=(
            f"samples={result.get('sample_count')} "
            f"real={result.get('real_sample_count')} "
            f"syn={result.get('synthetic_sample_count')} "
            f"acc={result.get('training_accuracy')} "
            f"f1={result.get('macro_f1')} "
            f"trigger={payload.trigger_reason}"
        ),
    )
    return result


@app.get("/ai/model-info")
def get_model_info(authorization: Optional[str] = Header(default=None)):
    """Admin or CERT: return complete model metadata."""
    require_roles(authorization, ["admin", "cert"])
    return load_model_info()


@app.get("/ai/retrain-status")
def retrain_status(authorization: Optional[str] = Header(default=None)):
    """Admin or CERT: return auto-retrain status."""
    require_roles(authorization, ["admin", "cert"])
    return get_retrain_status()


class SyntheticGenRequest(BaseModel):
    per_class_count: int = 60
    clear_existing_before_insert: bool = False


@app.post("/ai/generate-synthetic-data")
def generate_synthetic_data_endpoint(
    payload: SyntheticGenRequest = SyntheticGenRequest(),
    authorization: Optional[str] = Header(default=None),
):
    """Admin-only: generate and store synthetic training samples."""
    actor = require_roles(authorization, ["admin"])

    from synthetic_data import generate_synthetic_samples, insert_synthetic_samples

    if payload.per_class_count < 1 or payload.per_class_count > 500:
        raise HTTPException(status_code=400, detail="per_class_count must be between 1 and 500.")

    samples = generate_synthetic_samples(per_class_count=payload.per_class_count)
    result  = insert_synthetic_samples(
        samples,
        clear_existing=payload.clear_existing_before_insert,
    )

    write_audit(
        actor["id"], actor["full_name"], actor["role"],
        "SYNTHETIC_DATA_GENERATED", "model",
        details=(
            f"inserted={result['total_inserted']} "
            f"skipped={result['duplicate_skipped_count']} "
            f"per_class={payload.per_class_count}"
        ),
    )
    return result


@app.get("/ai/synthetic-summary")
def synthetic_summary(authorization: Optional[str] = Header(default=None)):
    """Admin or CERT: return synthetic sample statistics."""
    require_roles(authorization, ["admin", "cert"])
    from synthetic_data import get_synthetic_summary
    return get_synthetic_summary()


# ---------------------------------------------------------------------------
# Admin action endpoints
# ---------------------------------------------------------------------------

class AdminActionRequest(BaseModel):
    action: str   # mark_safe | escalate_cert | flag_campaign | close | reopen
    reason: Optional[str] = None


@app.post("/admin/action/{complaint_id}")
def admin_action(
    complaint_id: str,
    payload: AdminActionRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Admin-only: perform quick actions on a complaint."""
    actor = require_roles(authorization, ["admin"])

    action_status_map = {
        "mark_safe":      "Resolved",
        "escalate_cert":  "Escalated",
        "flag_campaign":  "Under Review",
        "close":          "Archived",
        "reopen":         "Open",
    }
    if payload.action not in action_status_map:
        raise HTTPException(status_code=400, detail=f"Unknown action: {payload.action}")

    new_status = action_status_map[payload.action]
    conn = get_connection()
    row = conn.execute("SELECT status FROM complaints WHERE id = ?", (complaint_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Complaint not found")

    old_status = row["status"]
    conn.execute("UPDATE complaints SET status = ? WHERE id = ?", (new_status, complaint_id))
    conn.commit()
    conn.close()

    write_audit(
        actor["id"], actor["full_name"], actor["role"],
        f"ADMIN_ACTION_{payload.action.upper()}", "complaint", complaint_id,
        old_value=old_status, new_value=new_status,
        details=payload.reason or f"Admin action: {payload.action}",
    )
    return {"success": True, "action": payload.action, "new_status": new_status}


# ---------------------------------------------------------------------------
# ML feedback / label correction
# ---------------------------------------------------------------------------

class FeedbackRequest(BaseModel):
    corrected_label: str
    correction_reason: Optional[str] = None


@app.post("/admin/feedback/{complaint_id}")
def save_feedback(
    complaint_id: str,
    payload: FeedbackRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Admin-only: correct the AI threat label for a complaint."""
    actor = require_roles(authorization, ["admin"])

    from ml_engine import THREAT_LABELS, normalize_threat_label
    normalized = normalize_threat_label(payload.corrected_label)

    conn = get_connection()
    row = conn.execute("SELECT id, threat_type FROM complaints WHERE id = ?", (complaint_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Complaint not found")

    conn.execute(
        """UPDATE complaints SET corrected_label=?, correction_reason=?, corrected_by=?, corrected_at=?
           WHERE id=?""",
        (normalized, payload.correction_reason, actor["id"],
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"), complaint_id),
    )
    conn.commit()
    conn.close()

    write_audit(
        actor["id"], actor["full_name"], actor["role"],
        "AI_LABEL_CORRECTED", "complaint", complaint_id,
        old_value=dict(row)["threat_type"], new_value=normalized,
        details=payload.correction_reason or "Manual correction",
    )
    return {"success": True, "corrected_label": normalized, "message": "Feedback saved for next retrain"}


@app.get("/admin/feedback-count")
def get_feedback_count(authorization: Optional[str] = Header(default=None)):
    require_roles(authorization, ["admin", "cert"])
    conn = get_connection()
    count = conn.execute(
        "SELECT COUNT(*) FROM complaints WHERE corrected_label IS NOT NULL AND corrected_label != ''"
    ).fetchone()[0]
    conn.close()
    return {"feedback_count": int(count or 0)}


# ---------------------------------------------------------------------------
# Enhanced evidence meta
# ---------------------------------------------------------------------------

@app.get("/complaints/{complaint_id}/evidence-meta")
def get_evidence_meta(complaint_id: str, authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)

    conn = get_connection()
    row = conn.execute("SELECT * FROM complaints WHERE id = ?", (complaint_id,)).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Complaint not found")

    row = dict(row)

    if user["role"] == "user" and row["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    if not row.get("evidence_path"):
        return {"available": False}

    import json as _json
    ev_indicators = {}
    try:
        raw = row.get("evidence_indicators") or "{}"
        ev_indicators = _json.loads(raw) if raw else {}
    except Exception:
        pass

    return {
        "available": True,
        "complaint_id": complaint_id,
        "file_name": row.get("evidence_name"),
        "file_type": row.get("evidence_type") or mimetypes.guess_type(row.get("evidence_name") or "")[0] or "application/octet-stream",
        "file_size": row.get("evidence_size"),
        "uploaded_at": row.get("created_at"),
        "download_url": f"http://127.0.0.1:8000/complaints/{complaint_id}/evidence",
        "extracted_urls": ev_indicators.get("urls", []),
        "extracted_phones": ev_indicators.get("phones", []),
        "extracted_emails": ev_indicators.get("emails", []),
    }


# ---------------------------------------------------------------------------
# Enhanced Excel export
# ---------------------------------------------------------------------------

@app.get("/download/excel")
def download_excel(authorization: Optional[str] = Header(default=None)):
    require_roles(authorization, ["admin", "cert"])

    conn = get_connection()
    df = pd.read_sql_query(
        """SELECT id, threat_type, rule_based_type, ml_predicted_type, decision_path,
                  risk_score, risk_level, ai_confidence, campaign_signature,
                  linked_case_count, status, attack_channel, category,
                  user_name, created_at, corrected_label
           FROM complaints ORDER BY created_at DESC""",
        conn,
    )
    conn.close()

    file_name = os.path.join(BASE_DIR, "complaints_export.xlsx")
    df.to_excel(file_name, index=False)

    return FileResponse(
        path=file_name,
        filename="complaints_export.xlsx",
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


# ---------------------------------------------------------------------------
# GET /ai/metrics — model performance metrics (admin/cert)
# ---------------------------------------------------------------------------

@app.get("/ai/metrics")
def get_ai_metrics(authorization: Optional[str] = Header(default=None)):
    """
    Return current model performance metrics.
    Includes accuracy, precision, recall, F1, class distribution,
    feedback count, synthetic ratio, and auto-retrain status.
    """
    require_roles(authorization, ["admin", "cert"])

    info = load_model_info()
    retrain = get_retrain_status()

    return {
        "model_exists":           info.get("model_exists", False),
        "algorithm":              info.get("algorithm", "LogisticRegression"),
        "trained_at":             info.get("trained_at"),
        "sample_count":           info.get("sample_count"),
        "real_sample_count":      info.get("real_sample_count"),
        "synthetic_sample_count": info.get("synthetic_sample_count"),
        "synthetic_ratio":        info.get("synthetic_ratio"),
        "feature_count":          info.get("feature_count"),
        "classes":                info.get("classes", []),
        # Core metrics
        "accuracy":               info.get("training_accuracy"),
        "macro_precision":        info.get("macro_precision"),
        "macro_recall":           info.get("macro_recall"),
        "macro_f1":               info.get("macro_f1"),
        # Comparison
        "previous_accuracy":      info.get("previous_accuracy"),
        "previous_macro_f1":      info.get("previous_macro_f1"),
        "accuracy_delta":         info.get("accuracy_delta"),
        "macro_f1_delta":         info.get("macro_f1_delta"),
        # Distribution
        "class_distribution":     info.get("class_distribution", {}),
        "feedback_count":         info.get("feedback_count", 0),
        # Status
        "fallback_active":        info.get("fallback_active", True),
        "auto_retrain_enabled":   retrain.get("auto_retrain_enabled"),
        "model_age_hours":        retrain.get("model_age_hours"),
        "complaints_since_last_train": retrain.get("complaints_since_last_train"),
        "should_retrain_now":     retrain.get("should_retrain_now"),
        "warning":                info.get("warning"),
    }


# ---------------------------------------------------------------------------
# POST /cert/alert — dispatch a CERT alert for a complaint (cert/admin)
# ---------------------------------------------------------------------------

@app.post("/cert/alert")
def trigger_cert_alert(complaint_id: str, authorization: Optional[str] = Header(default=None)):
    """
    Manually dispatch a CERT alert for a specific complaint.
    Sends email alert and returns structured alert record.
    """
    actor = require_roles(authorization, ["cert", "admin"])

    conn = get_connection()
    row = conn.execute("SELECT * FROM complaints WHERE id = ?", (complaint_id,)).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Complaint not found")

    row = dict(row)
    alert = dispatch_cert_alert(
        complaint_id=complaint_id,
        risk_level=row.get("risk_level", "Unknown"),
        threat_type=row.get("threat_type", "Unknown"),
        user_name=row.get("user_name", "Unknown"),
        details=f"Manually triggered by {actor['full_name']} ({actor['role']})",
    )

    write_audit(
        actor["id"], actor["full_name"], actor["role"],
        "CERT_ALERT_DISPATCHED", "complaint", complaint_id,
        details=f"Alert ID: {alert.get('alert_id')}",
    )

    return {"success": True, "alert": alert}


# ---------------------------------------------------------------------------
# GET /complaints/{complaint_id}/url-intel — URL threat intel for a complaint
# ---------------------------------------------------------------------------

@app.get("/complaints/{complaint_id}/url-intel")
def get_url_intel(complaint_id: str, authorization: Optional[str] = Header(default=None)):
    """
    Run threat intelligence check on the URL attached to a complaint.
    Returns heuristic + optional VirusTotal result.
    """
    require_roles(authorization, ["admin", "cert"])

    conn = get_connection()
    row = conn.execute(
        "SELECT suspicious_url FROM complaints WHERE id = ?", (complaint_id,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Complaint not found")

    url = (row["suspicious_url"] or "").strip()
    if not url:
        return {"complaint_id": complaint_id, "url": None, "result": {"is_malicious": False, "details": "No URL attached."}}

    result = check_url_threat_intel(url)
    return {"complaint_id": complaint_id, "url": url, "result": result}
