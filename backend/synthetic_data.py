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
        # Extended templates for balance
        "Got a link {platform} to a fake army canteen card renewal portal asking for login and OTP.",
        "Received a message {platform} claiming ECHS card is expiring and asking to verify details {urgency}.",
        "A fake pension portal link was shared {platform} asking {target} to enter Aadhaar and bank details.",
        "Got a message {platform} with a link to a fake defence welfare scheme asking for credentials.",
        "Received an SMS claiming salary revision is pending and asking to click a link {urgency}.",
        "A message {platform} asked {target} to update their service record on a suspicious website.",
        "Got a link {platform} to a fake army welfare association page asking for login details.",
        "Received a message {platform} claiming a welfare benefit is ready and asking to verify account.",
        "A fake official-looking email {platform} asked {target} to reset their defence portal password.",
        "Got a message {platform} with a link to a fake canteen discount portal asking for OTP.",
        "Received a message {platform} claiming the defence ID card needs renewal and asking for details.",
        "A link {platform} led to a fake army records portal asking {target} to enter service number.",
        "Got a message {platform} claiming a pending salary arrear and asking to verify bank account {urgency}.",
        "Received a suspicious link {platform} disguised as an official army welfare notification.",
        "A message {platform} asked {target} to click a link to claim a defence welfare bonus {urgency}.",
        "Got an email {platform} with a fake army logo asking to verify login credentials {urgency}.",
        "Received a message {platform} claiming the account will be frozen unless OTP is shared {urgency}.",
        "A fake ECHS renewal link was shared {platform} asking for card number and CVV.",
        "Got a message {platform} with a link to a fake defence salary portal asking for password.",
        "Received a message {platform} claiming a KYC update is required {urgency} or benefits will stop.",
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
        # Extended templates for balance
        "Got a message {platform} from an unknown number asking about {target}'s work schedule.",
        "Received a suspicious message {platform} from someone claiming to be a welfare officer.",
        "An unknown contact {platform} kept asking {target} about their family members' details.",
        "Got a message {platform} from an unverified account claiming to offer defence benefits.",
        "Received a message {platform} from an unknown sender with a suspicious attachment.",
        "An unknown person {platform} asked {target} to join a private group for defence updates.",
        "Got a suspicious call asking {target} to confirm their service number and rank.",
        "Received a message {platform} from an unknown contact asking about upcoming leave plans.",
        "An unverified account {platform} sent {target} a message asking to verify their identity.",
        "Got a message {platform} from an unknown number claiming to be from the welfare department.",
        "Received a suspicious message {platform} asking {target} to call back on an unknown number.",
        "An unknown contact {platform} asked {target} to share their unit's contact directory.",
        "Got a message {platform} from an unidentified sender asking about defence welfare schemes.",
        "Received a suspicious call asking {target} to confirm their posting details.",
        "An unknown person {platform} asked {target} to share their official email address.",
        "Got a message {platform} from an unknown contact asking about {target}'s retirement plans.",
        "Received a suspicious message {platform} from someone claiming to know {target}'s superior.",
        "An unverified account {platform} asked {target} to participate in a defence survey.",
        "Got a message {platform} from an unknown number asking about {target}'s current assignment.",
        "Received a suspicious message {platform} asking {target} to confirm their Aadhaar details.",
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
        # Extended templates for balance
        "Got a message {platform} asking to download an APK for a fake canteen discount app.",
        "Received a link {platform} to download a fake army welfare app that installs malware.",
        "A message {platform} asked {target} to install an app to receive ECHS benefits {urgency}.",
        "Got a link {platform} to download a fake defence ID card renewal application.",
        "Received a message {platform} with a link to a fake army salary app asking for installation.",
        "A suspicious APK was shared {platform} claiming to be a secure defence communication tool.",
        "Got a message {platform} asking to download a file to view a confidential welfare update.",
        "Received a link {platform} to a fake army canteen app that requests device permissions.",
        "A message {platform} asked {target} to install an app to track their pension status.",
        "Got a link {platform} to download a fake ECHS card renewal app with malware.",
        "Received a message {platform} with a zip file claiming to contain promotion list documents.",
        "A suspicious file was shared {platform} disguised as an official army circular.",
        "Got a message {platform} asking to install an app to access a fake defence welfare portal.",
        "Received a link {platform} to download a fake army records update application.",
        "A message {platform} asked {target} to open an APK file to claim a welfare benefit {urgency}.",
        "Got a suspicious attachment {platform} claiming to be a salary revision document.",
        "Received a message {platform} with a link to download a fake army communication app.",
        "A suspicious APK was shared {platform} claiming to provide canteen card discounts.",
        "Got a message {platform} asking to install an app to verify defence ID card details.",
        "Received a link {platform} to a fake army welfare app that steals contact information.",
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
        # Extended templates for balance — critical for class balance
        "An unknown person {platform} befriended {target} and gradually asked for sensitive information.",
        "Got a friend request {platform} from an attractive profile that started asking personal questions.",
        "Received messages {platform} from someone claiming to be a defence officer seeking friendship.",
        "An online contact {platform} sent {target} gifts and then asked for favours in return.",
        "Got a message {platform} from someone claiming to be a welfare officer who wanted to meet.",
        "Received a video call {platform} from an unknown person who claimed to be a colleague.",
        "An unknown contact {platform} asked {target} to share their home address for a surprise gift.",
        "Got messages {platform} from someone who claimed to be in distress and needed financial help.",
        "Received a friend request {platform} from an unknown profile that sent romantic messages.",
        "An online contact {platform} asked {target} to keep their conversation private from family.",
        "Got a message {platform} from someone claiming to be a retired officer seeking companionship.",
        "Received messages {platform} from an unknown person who claimed to have feelings for {target}.",
        "An unknown contact {platform} asked {target} to share photos of their workplace.",
        "Got a message {platform} from someone who claimed to be a welfare worker and asked to meet.",
        "Received a video call request {platform} from an unknown person claiming to be a relative.",
        "An online contact {platform} built trust with {target} and then asked for money {urgency}.",
        "Got messages {platform} from someone who claimed to be a friend and asked for personal details.",
        "Received a friend request {platform} from an unknown profile that asked about {target}'s unit.",
        "An unknown person {platform} sent {target} romantic messages and later asked for bank details.",
        "Got a message {platform} from someone claiming to be a welfare officer who needed personal info.",
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
        # Extended templates for balance — critical for class balance
        "Got a message {platform} asking {target} to share photos of the base entrance.",
        "Received a request {platform} asking for details about the unit's equipment and vehicles.",
        "An unknown contact {platform} asked {target} to share the duty roster {urgency}.",
        "Got a message {platform} asking for details about the commanding officer's schedule.",
        "Received a suspicious request {platform} asking {target} to share internal memos.",
        "An unknown person {platform} asked {target} to photograph sensitive areas of the base.",
        "Got a message {platform} asking for details about the unit's communication frequencies.",
        "Received a request {platform} asking {target} to share the names of personnel in the unit.",
        "An unknown contact {platform} asked {target} to confirm the location of a military convoy.",
        "Got a message {platform} asking for details about the unit's training schedule.",
        "Received a suspicious request {platform} asking {target} to share classified operation details.",
        "An unknown person {platform} asked {target} to share photos of military equipment.",
        "Got a message {platform} asking for details about the unit's supply chain.",
        "Received a request {platform} asking {target} to share the base's emergency protocols.",
        "An unknown contact {platform} asked {target} to confirm details about a military exercise.",
        "Got a message {platform} asking for details about the unit's cybersecurity measures.",
        "Received a suspicious request {platform} asking {target} to share internal defence reports.",
        "An unknown person {platform} asked {target} to share the unit's operational plans.",
        "Got a message {platform} asking for details about the base's access control systems.",
        "Received a request {platform} asking {target} to share sensitive personnel records.",
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
        # Extended templates for balance
        "Got a message {platform} claiming ECHS card renewal requires a payment of Rs 499 {urgency}.",
        "Received a message {platform} asking {target} to pay a processing fee for a pension update.",
        "A fake army welfare scheme {platform} asked {target} to invest money for guaranteed returns.",
        "Got a call claiming the defence salary account needs verification and asking for OTP.",
        "Received a message {platform} claiming a canteen card discount requires a small fee {urgency}.",
        "A message {platform} asked {target} to share their Aadhaar number for a welfare benefit.",
        "Got a message {platform} claiming a pending army welfare payment requires bank verification.",
        "Received a call asking {target} to share their ATM PIN to receive a salary arrear.",
        "A message {platform} asked {target} to pay a fee to renew their defence ID card {urgency}.",
        "Got a message {platform} claiming a lottery win from a defence welfare association.",
        "Received a message {platform} asking {target} to transfer money to a fake welfare fund.",
        "A call claimed the defence pension account is blocked and asked for OTP to unblock it.",
        "Got a message {platform} asking {target} to pay a registration fee for a welfare scheme.",
        "Received a message {platform} claiming a salary bonus is pending and asking for bank details.",
        "A message {platform} asked {target} to share their card details for a fake ECHS renewal.",
        "Got a call claiming the army canteen card needs reactivation and asking for CVV.",
        "Received a message {platform} asking {target} to invest in a fake defence welfare fund.",
        "A message {platform} claimed a pending refund from the army canteen and asked for account details.",
        "Got a message {platform} asking {target} to pay a fee to claim a fake defence scholarship.",
        "Received a call asking {target} to share their bank account details for a welfare transfer.",
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
        # Extended templates for balance — critical for class balance
        "Got a message {platform} from an unknown number that seemed odd but had no clear threat.",
        "Received a communication {platform} that {target} could not identify as safe or dangerous.",
        "An unknown contact {platform} sent a message that was confusing and hard to interpret.",
        "Got a message {platform} that seemed suspicious but did not contain any clear indicators.",
        "Received a message {platform} from an unknown sender that {target} was unsure about.",
        "An unknown person {platform} sent a message that was unusual but not clearly malicious.",
        "Got a communication {platform} that {target} flagged as potentially suspicious.",
        "Received a message {platform} that seemed out of context and required further review.",
        "An unknown contact {platform} sent a message that was ambiguous and hard to classify.",
        "Got a message {platform} from an unknown sender that {target} found difficult to understand.",
        "Received a communication {platform} that may be suspicious but needs more information.",
        "An unknown person {platform} sent a message that was unclear and potentially concerning.",
        "Got a message {platform} that {target} could not determine was safe or a threat.",
        "Received a communication {platform} from an unknown contact that seemed unusual.",
        "An unknown sender {platform} sent a message that was confusing and potentially suspicious.",
        "Got a message {platform} that seemed odd but {target} was not sure if it was a threat.",
        "Received a communication {platform} that required further investigation to classify.",
        "An unknown contact {platform} sent a message that was ambiguous and needed review.",
        "Got a message {platform} from an unknown number that {target} could not identify.",
        "Received a communication {platform} that was flagged as potentially suspicious by {target}.",
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
