"""
synthetic_data.py — Template-based synthetic complaint generator for Rakshak AI.
Generates realistic, varied training samples for the 7-class threat taxonomy.
All records are clearly flagged as synthetic (is_synthetic=1).
"""

import random
import sqlite3
import os
from datetime import datetime
from typing import Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME  = os.path.join(BASE_DIR, "complaints.db")

# ---------------------------------------------------------------------------
# Template slots
# ---------------------------------------------------------------------------
_CHANNELS = ["WhatsApp", "Telegram", "SMS", "Email", "Voice Call", "Web"]

_TARGETS = [
    "a serving personnel",
    "a family member of a defence officer",
    "a veteran",
    "an army officer",
    "a defence employee",
    "a soldier",
    "a retired officer",
]

_URGENCY = [
    "immediately", "urgently", "right now", "without delay",
    "as soon as possible", "within 24 hours", "before it is too late",
]

_PLATFORMS = {
    "WhatsApp": ["via WhatsApp", "on WhatsApp", "through a WhatsApp message"],
    "Telegram": ["via Telegram", "on Telegram", "through a Telegram channel"],
    "SMS":      ["via SMS", "through a text message", "in an SMS"],
    "Email":    ["via email", "through an official-looking email", "in an email"],
    "Voice Call": ["over a phone call", "via a voice call", "during a call"],
    "Web":      ["on a website", "through a web link", "via a browser pop-up"],
}

# ---------------------------------------------------------------------------
# Templates per class
# ---------------------------------------------------------------------------
_TEMPLATES = {
    "Phishing": [
        "Received a message {platform} asking to verify OTP {urgency} or account will be blocked.",
        "Got a link {platform} claiming to be from the defence salary portal asking for login credentials.",
        "A message {platform} told {target} to click a link and update KYC {urgency}.",
        "Received an alert {platform} saying the bank account is suspended and to verify details {urgency}.",
        "A fake welfare portal link was shared {platform} asking {target} to enter password and OTP.",
        "Message {platform} claimed army welfare payment is pending and asked to verify account {urgency}.",
        "Received a phishing link {platform} disguised as official defence login page.",
        "Got an email {platform} with a link to reset password that redirected to a fake site.",
        "A message {platform} asked {target} to verify identity by entering OTP on a suspicious link.",
        "Received a message {platform} claiming account will be deactivated unless login is verified {urgency}.",
    ],
    "Suspicious Communication": [
        "Received an unsolicited message {platform} from an unknown number asking for personal details.",
        "A stranger contacted {target} {platform} asking unusual questions about their work.",
        "Got a suspicious call claiming to be from a government department asking for information.",
        "Received a strange link {platform} from an unknown contact with no explanation.",
        "An unknown person {platform} kept asking {target} about their daily schedule.",
        "Received repeated messages {platform} from an unknown number asking to connect privately.",
        "A suspicious account {platform} sent a friend request and started asking personal questions.",
        "Got a message {platform} from an unknown sender asking to share contact details {urgency}.",
        "Received an unusual message {platform} asking {target} to confirm their identity.",
        "An unknown caller asked {target} about their posting location and unit details.",
    ],
    "Malware / APK Threat": [
        "Received a message {platform} asking to download an APK file to access welfare benefits.",
        "Got a link {platform} to download a zip file claiming to contain salary update documents.",
        "A message {platform} asked {target} to install an app for secure military communication.",
        "Received an email {platform} with an attachment claiming to be a classified update.",
        "Got a message {platform} with a link to download an executable file to unlock a report.",
        "A suspicious APK was shared {platform} claiming to be an official defence application.",
        "Received a message {platform} asking to install an app to view a secure message {urgency}.",
        "Got a link {platform} to download a file that turned out to be malware.",
        "A message {platform} asked {target} to open an attached zip file to view important documents.",
        "Received a suspicious file {platform} disguised as a government welfare document.",
    ],
    "Honeytrap / Romance Manipulation": [
        "An unknown person contacted {target} {platform} claiming to be a friend and asking to meet privately.",
        "Received messages {platform} from someone claiming romantic interest and asking for money.",
        "A person {platform} built trust with {target} over weeks and then asked for sensitive documents.",
        "Got a message {platform} from someone claiming to be a female officer asking to connect privately.",
        "An online contact {platform} asked {target} to share their location for a private meeting.",
        "Received a video call request {platform} from an unknown person claiming to know {target}.",
        "A person {platform} sent romantic messages to {target} and later asked for financial help.",
        "Got a message {platform} from someone claiming to be a friend of a colleague asking to meet.",
        "An unknown contact {platform} asked {target} to share personal photos claiming it was safe.",
        "Received messages {platform} from someone who claimed to be in love and asked for bank details.",
    ],
    "Espionage / OPSEC Risk": [
        "Received a message {platform} asking {target} to share regiment details and posting location.",
        "Got a request {platform} asking for deployment movement details {urgency}.",
        "A message {platform} asked {target} to send confidential unit information for verification.",
        "Received a suspicious request {platform} asking for unit strength and location data.",
        "Got a message {platform} asking {target} to share classified documents for a report.",
        "An unknown contact {platform} asked for details about upcoming military exercises.",
        "Received a request {platform} asking {target} to confirm troop movement details.",
        "Got a message {platform} asking for sensitive operational information under the guise of a survey.",
        "A person {platform} asked {target} to share internal communication logs {urgency}.",
        "Received a suspicious request {platform} for details about base security arrangements.",
    ],
    "Identity / Financial Fraud": [
        "Received a message {platform} asking {target} to transfer money to secure their account {urgency}.",
        "Got a call claiming ATM card will be deactivated unless a processing fee is paid {urgency}.",
        "A message {platform} asked {target} to provide card number and CVV for a pending refund.",
        "Received a message {platform} offering a guaranteed investment return and asking for money.",
        "Got a message {platform} claiming a lottery prize and asking for bank details to transfer funds.",
        "A person {platform} asked {target} to send money for an emergency claiming to be a relative.",
        "Received a message {platform} asking to pay a fee to claim a welfare benefit {urgency}.",
        "Got a call asking {target} to share OTP to receive a pending salary credit.",
        "A message {platform} claimed a refund is pending and asked for account details {urgency}.",
        "Received a message {platform} asking {target} to invest in a scheme with guaranteed returns.",
    ],
    "Unknown / Needs Review": [
        "Received an unusual message {platform} that does not clearly indicate any threat.",
        "Got a message {platform} from an unknown contact that seems suspicious but unclear.",
        "A message {platform} was received by {target} that requires further review.",
        "Received a communication {platform} that may or may not be a threat — needs investigation.",
        "Got a message {platform} with unclear intent from an unknown sender.",
        "Received a message {platform} that {target} found confusing and potentially suspicious.",
        "An unknown contact {platform} sent a message that is difficult to classify.",
        "Got a communication {platform} that does not fit a clear threat category.",
        "Received a message {platform} that seems out of place but no clear malicious intent.",
        "A message {platform} was flagged by {target} as potentially suspicious but unconfirmed.",
    ],
}


# ---------------------------------------------------------------------------
# Core generation functions
# ---------------------------------------------------------------------------
def normalize_generated_text(text: str) -> str:
    """Clean up generated text — strip extra spaces, normalize punctuation."""
    import re
    text = re.sub(r"\s+", " ", text).strip()
    if text and not text.endswith("."):
        text += "."
    return text


def generate_class_samples(
    threat_label: str,
    count: int = 60,
    seed: Optional[int] = None,
) -> list[dict]:
    """
    Generate `count` synthetic samples for a single threat class.
    Uses slot-based randomization to avoid exact duplicates.
    """
    if seed is not None:
        random.seed(seed)

    templates = _TEMPLATES.get(threat_label, [])
    if not templates:
        return []

    results = []
    seen_texts: set = set()
    max_attempts = count * 10
    attempts = 0

    while len(results) < count and attempts < max_attempts:
        attempts += 1
        template = random.choice(templates)
        channel  = random.choice(_CHANNELS)
        platform = random.choice(_PLATFORMS[channel])
        target   = random.choice(_TARGETS)
        urgency  = random.choice(_URGENCY)

        raw_text = template.format(
            platform=platform,
            target=target,
            urgency=urgency,
        )
        text = normalize_generated_text(raw_text)

        if text in seen_texts:
            continue
        seen_texts.add(text)

        results.append({
            "complaint_text":   text,
            "threat_label":     threat_label,
            "channel":          channel,
            "is_synthetic":     1,
            "synthetic_source": "template_generator",
            "created_at":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    return results


def generate_synthetic_samples(
    per_class_count: int = 60,
    seed: Optional[int] = 42,
) -> list[dict]:
    """
    Generate synthetic samples for all 7 threat classes.
    Returns a flat list of sample dicts.
    """
    from ml_engine import THREAT_LABELS
    all_samples = []
    for label in THREAT_LABELS:
        samples = generate_class_samples(label, count=per_class_count, seed=seed)
        all_samples.extend(samples)
    return all_samples


# ---------------------------------------------------------------------------
# DB persistence
# ---------------------------------------------------------------------------
def ensure_synthetic_table(db_path: str = DB_NAME) -> None:
    """Create synthetic_training_samples table if it does not exist."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS synthetic_training_samples (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_text   TEXT NOT NULL,
            threat_label     TEXT NOT NULL,
            channel          TEXT,
            is_synthetic     INTEGER DEFAULT 1,
            synthetic_source TEXT,
            created_at       TEXT
        )
    """)
    conn.commit()
    conn.close()


def insert_synthetic_samples(
    samples: list[dict],
    db_path: str = DB_NAME,
    clear_existing: bool = False,
) -> dict:
    """
    Insert synthetic samples into the DB.
    Skips exact duplicate texts.
    Returns insertion stats.
    """
    ensure_synthetic_table(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    if clear_existing:
        conn.execute("DELETE FROM synthetic_training_samples")
        conn.commit()

    # Load existing texts to skip duplicates
    existing = set(
        row[0] for row in conn.execute(
            "SELECT complaint_text FROM synthetic_training_samples"
        ).fetchall()
    )

    inserted = 0
    skipped  = 0
    per_class: dict = {}

    for s in samples:
        text = (s.get("complaint_text") or "").strip()
        if not text or text in existing:
            skipped += 1
            continue
        existing.add(text)
        conn.execute(
            """INSERT INTO synthetic_training_samples
               (complaint_text, threat_label, channel, is_synthetic, synthetic_source, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                text,
                s.get("threat_label", "Unknown / Needs Review"),
                s.get("channel", "Unknown"),
                1,
                s.get("synthetic_source", "template_generator"),
                s.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ),
        )
        inserted += 1
        label = s.get("threat_label", "Unknown")
        per_class[label] = per_class.get(label, 0) + 1

    conn.commit()
    conn.close()
    return {
        "total_inserted":        inserted,
        "inserted_per_class":    per_class,
        "duplicate_skipped_count": skipped,
    }


def get_synthetic_summary(db_path: str = DB_NAME) -> dict:
    """Return summary stats about stored synthetic samples."""
    ensure_synthetic_table(db_path)
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        total = conn.execute(
            "SELECT COUNT(*) FROM synthetic_training_samples"
        ).fetchone()[0]

        per_class_rows = conn.execute(
            "SELECT threat_label, COUNT(*) as cnt FROM synthetic_training_samples GROUP BY threat_label"
        ).fetchall()

        per_channel_rows = conn.execute(
            "SELECT channel, COUNT(*) as cnt FROM synthetic_training_samples GROUP BY channel"
        ).fetchall()

        source_rows = conn.execute(
            "SELECT synthetic_source, COUNT(*) as cnt FROM synthetic_training_samples GROUP BY synthetic_source"
        ).fetchall()

        conn.close()

        return {
            "total_synthetic_samples": int(total),
            "per_class":   {r["threat_label"]: r["cnt"] for r in per_class_rows},
            "per_channel": {r["channel"]: r["cnt"] for r in per_channel_rows},
            "per_source":  {r["synthetic_source"]: r["cnt"] for r in source_rows},
        }
    except Exception as e:
        return {"error": str(e), "total_synthetic_samples": 0}
