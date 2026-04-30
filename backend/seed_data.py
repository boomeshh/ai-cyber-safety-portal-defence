"""
seed_data.py — Demo complaint seeding for Rakshak AI

Inserts realistic defence cyber safety complaints when the database is empty.
Safe to call on every startup: exits immediately if any complaints already exist.
Uses only raw sqlite3 (matching the rest of the backend — no new dependencies).
"""

import sqlite3
import os
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _ts(days_ago: int = 0, hour: int = 10) -> str:
    """Return an ISO-format timestamp string offset by *days_ago* days."""
    dt = datetime.utcnow() - timedelta(days=days_ago)
    return dt.replace(hour=hour, minute=0, second=0, microsecond=0).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


# ---------------------------------------------------------------------------
# Seed records — 12 realistic defence cyber safety complaints
# ---------------------------------------------------------------------------

SEED_COMPLAINTS = [
    # 1 — Phishing / Critical
    {
        "id": "SEED-001",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Serving Personnel",
        "complaint_text": (
            "I received an email claiming to be from the Army Welfare Office asking me "
            "to click a link and verify my service number and bank account details for "
            "a salary revision. The link looked official but the domain was misspelled."
        ),
        "suspicious_url": "http://armywelfare-verify.in/login",
        "screenshot_path": None,
        "threat_type": "Phishing",
        "risk_score": 92,
        "risk_level": "Critical",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Credential phishing link targeting defence personnel\n"
            "• Misspelled official domain\n"
            "• Urgency language around salary revision\n\n"
            "Risk Explanation:\n"
            "High-confidence phishing attempt impersonating Army Welfare Office. "
            "Designed to harvest service credentials and banking details.\n\n"
            "Campaign Alert:\n"
            "Matches known campaign targeting serving personnel during pay revision cycles."
        ),
        "mitigation": (
            "Do not click the link. Report to your unit cyber cell immediately. "
            "Verify any welfare communication through official Army portals only."
        ),
        "status": "Escalated",
        "created_at": _ts(days_ago=1, hour=9),
        "attack_channel": "Email",
        "ai_confidence": 94,
        "linked_case_count": 3,
        "ml_prediction": "phishing",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Phishing",
        "rule_based_type": "Phishing",
        "campaign_signature": "ARMY-WELFARE-PHISH-2026",
        "incident_hour": 9,
        "incident_day": "Monday",
        "decision_path": "ML+Rule hybrid → Critical",
    },
    # 2 — Malware / High
    {
        "id": "SEED-002",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Serving Personnel",
        "complaint_text": (
            "A WhatsApp message from an unknown number sent me an APK file claiming "
            "it was a new canteen discount app for defence personnel. After installing "
            "it my phone started behaving strangely and contacts were being accessed."
        ),
        "suspicious_url": None,
        "screenshot_path": None,
        "threat_type": "Malware / APK Threat",
        "risk_score": 88,
        "risk_level": "High",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Unsolicited APK distributed via WhatsApp\n"
            "• Impersonation of canteen/welfare service\n"
            "• Post-install anomalous device behaviour\n\n"
            "Risk Explanation:\n"
            "Trojanized APK likely contains spyware or RAT capable of exfiltrating "
            "contacts, messages, and location data from the device."
        ),
        "mitigation": (
            "Uninstall the APK immediately. Factory reset the device if possible. "
            "Report the sender number to your unit security officer. "
            "Never install APKs from unofficial sources."
        ),
        "status": "Under Review",
        "created_at": _ts(days_ago=2, hour=14),
        "attack_channel": "WhatsApp",
        "ai_confidence": 89,
        "linked_case_count": 1,
        "ml_prediction": "malware",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Malware / APK Threat",
        "rule_based_type": "Malware",
        "campaign_signature": "CANTEEN-APK-MALWARE-2026",
        "incident_hour": 14,
        "incident_day": "Tuesday",
        "decision_path": "ML+Rule hybrid → High",
    },
    # 3 — OPSEC Risk / Critical
    {
        "id": "SEED-003",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Serving Personnel",
        "complaint_text": (
            "A civilian acquaintance on Facebook kept asking me about our unit's "
            "deployment schedule, number of personnel, and upcoming exercise locations. "
            "They claimed to be a journalist writing about defence welfare."
        ),
        "suspicious_url": None,
        "screenshot_path": None,
        "threat_type": "OPSEC Leak Risk",
        "risk_score": 95,
        "risk_level": "Critical",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Targeted questioning about deployment and unit strength\n"
            "• Civilian contact using journalist cover story\n"
            "• Social media platform used for elicitation\n\n"
            "Risk Explanation:\n"
            "Classic intelligence elicitation pattern. Disclosure of deployment "
            "schedules or unit strength constitutes a serious OPSEC breach."
        ),
        "mitigation": (
            "Cease all communication with this contact immediately. "
            "Report to your unit intelligence officer. "
            "Do not share any operational information on social media."
        ),
        "status": "Escalated",
        "created_at": _ts(days_ago=3, hour=11),
        "attack_channel": "Social Media",
        "ai_confidence": 96,
        "linked_case_count": 0,
        "ml_prediction": "opsec",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "OPSEC Leak Risk",
        "rule_based_type": "OPSEC Leak Risk",
        "campaign_signature": None,
        "incident_hour": 11,
        "incident_day": "Wednesday",
        "decision_path": "ML+Rule hybrid → Critical",
    },
    # 4 — Social Engineering / High
    {
        "id": "SEED-004",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Family Member",
        "complaint_text": (
            "Someone called my wife pretending to be from the Army Records Office "
            "and said my husband's pension would be stopped unless she provided "
            "his service number and Aadhaar details over the phone within 24 hours."
        ),
        "suspicious_url": None,
        "screenshot_path": None,
        "threat_type": "Honeytrap / Social Engineering",
        "risk_score": 80,
        "risk_level": "High",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Impersonation of Army Records Office\n"
            "• Urgency pressure tactic (24-hour deadline)\n"
            "• Targeting family member to extract service credentials\n\n"
            "Risk Explanation:\n"
            "Vishing attack using authority impersonation and urgency to extract "
            "sensitive identity information from a family member."
        ),
        "mitigation": (
            "Do not provide any information over unsolicited calls. "
            "Verify through official Army Records Office numbers only. "
            "Report the caller number to cyber cell."
        ),
        "status": "Open",
        "created_at": _ts(days_ago=4, hour=16),
        "attack_channel": "Voice Call",
        "ai_confidence": 82,
        "linked_case_count": 2,
        "ml_prediction": "social_engineering",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Honeytrap / Social Engineering",
        "rule_based_type": "Honeytrap / Social Engineering",
        "campaign_signature": "PENSION-VISHING-2026",
        "incident_hour": 16,
        "incident_day": "Thursday",
        "decision_path": "ML+Rule hybrid → High",
    },
    # 5 — Financial Fraud / High
    {
        "id": "SEED-005",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Veteran",
        "complaint_text": (
            "I received an SMS saying my ex-servicemen health scheme card was expiring "
            "and I needed to pay Rs 499 to renew it online. The link asked for my "
            "debit card number, CVV, and OTP."
        ),
        "suspicious_url": "http://echs-renewal-portal.co.in/pay",
        "screenshot_path": None,
        "threat_type": "Identity / Financial Fraud",
        "risk_score": 85,
        "risk_level": "High",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Fake ECHS renewal portal\n"
            "• Requesting card number, CVV, and OTP\n"
            "• Non-official domain mimicking government portal\n\n"
            "Risk Explanation:\n"
            "Classic card skimming fraud targeting veterans via SMS. "
            "Designed to steal payment credentials and OTP for unauthorized transactions."
        ),
        "mitigation": (
            "Do not enter payment details on this site. "
            "ECHS renewals are done only through official ECHS portals or service centres. "
            "Report to your nearest cyber crime cell."
        ),
        "status": "Action Initiated",
        "created_at": _ts(days_ago=5, hour=10),
        "attack_channel": "SMS",
        "ai_confidence": 87,
        "linked_case_count": 4,
        "ml_prediction": "fraud",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Identity / Financial Fraud",
        "rule_based_type": "Financial Fraud",
        "campaign_signature": "ECHS-FRAUD-SMS-2026",
        "incident_hour": 10,
        "incident_day": "Friday",
        "decision_path": "ML+Rule hybrid → High",
    },
    # 6 — Espionage / Critical
    {
        "id": "SEED-006",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Serving Personnel",
        "complaint_text": (
            "I was approached on LinkedIn by a foreign national claiming to be a "
            "defence researcher. They offered payment for sharing internal documents "
            "about our unit's equipment procurement and maintenance schedules."
        ),
        "suspicious_url": None,
        "screenshot_path": None,
        "threat_type": "Espionage Indicator",
        "risk_score": 98,
        "risk_level": "Critical",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Foreign national contact offering payment for classified information\n"
            "• Targeting procurement and maintenance schedules\n"
            "• LinkedIn used as initial contact vector\n\n"
            "Risk Explanation:\n"
            "High-confidence espionage attempt. Solicitation of internal defence "
            "documents by a foreign contact constitutes a serious national security threat."
        ),
        "mitigation": (
            "Do not respond or share any documents. "
            "Report immediately to your unit intelligence officer and CERT. "
            "Preserve all communication records as evidence."
        ),
        "status": "Escalated",
        "created_at": _ts(days_ago=6, hour=13),
        "attack_channel": "Social Media",
        "ai_confidence": 98,
        "linked_case_count": 0,
        "ml_prediction": "espionage",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Espionage Indicator",
        "rule_based_type": "Espionage Indicator",
        "campaign_signature": None,
        "incident_hour": 13,
        "incident_day": "Saturday",
        "decision_path": "ML+Rule hybrid → Critical",
    },
    # 7 — Phishing / Medium
    {
        "id": "SEED-007",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Family Member",
        "complaint_text": (
            "My daughter received a Telegram message claiming she had won a prize "
            "from an Army Family Welfare Association lottery. She was asked to pay "
            "Rs 200 processing fee to claim the prize."
        ),
        "suspicious_url": "https://t.me/armyfamilylottery2026",
        "screenshot_path": None,
        "threat_type": "Phishing",
        "risk_score": 65,
        "risk_level": "Medium",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Advance fee fraud pattern (pay to claim prize)\n"
            "• Impersonation of Army Family Welfare Association\n"
            "• Telegram used as delivery channel\n\n"
            "Risk Explanation:\n"
            "Advance fee scam targeting defence families. "
            "No legitimate lottery requires upfront payment to claim winnings."
        ),
        "mitigation": (
            "Ignore and block the contact. "
            "Inform family members that official welfare associations never run paid lotteries. "
            "Report the Telegram handle to cyber cell."
        ),
        "status": "Resolved",
        "created_at": _ts(days_ago=7, hour=18),
        "attack_channel": "Telegram",
        "ai_confidence": 71,
        "linked_case_count": 1,
        "ml_prediction": "phishing",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Phishing",
        "rule_based_type": "Phishing",
        "campaign_signature": "LOTTERY-SCAM-TG-2026",
        "incident_hour": 18,
        "incident_day": "Sunday",
        "decision_path": "ML+Rule hybrid → Medium",
    },
    # 8 — Malware / Medium
    {
        "id": "SEED-008",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Serving Personnel",
        "complaint_text": (
            "I downloaded a PDF from an unofficial website that claimed to contain "
            "the latest promotion list. After opening it, my antivirus flagged a "
            "macro-based threat embedded in the document."
        ),
        "suspicious_url": "http://defencepromotionlist.net/list2026.pdf",
        "screenshot_path": None,
        "threat_type": "Malware / APK Threat",
        "risk_score": 72,
        "risk_level": "Medium",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Macro-embedded malware in PDF lure\n"
            "• Unofficial domain mimicking official promotion list source\n"
            "• Antivirus detection triggered\n\n"
            "Risk Explanation:\n"
            "Document-based malware delivery using promotion list as lure. "
            "Macros may establish persistence or exfiltrate data."
        ),
        "mitigation": (
            "Do not open the file again. Run a full system scan. "
            "Download promotion lists only from official Army portals. "
            "Report the URL to your unit cyber cell."
        ),
        "status": "Resolved",
        "created_at": _ts(days_ago=8, hour=12),
        "attack_channel": "Web",
        "ai_confidence": 74,
        "linked_case_count": 0,
        "ml_prediction": "malware",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Malware / APK Threat",
        "rule_based_type": "Malware",
        "campaign_signature": None,
        "incident_hour": 12,
        "incident_day": "Monday",
        "decision_path": "ML+Rule hybrid → Medium",
    },
    # 9 — Social Engineering / Medium
    {
        "id": "SEED-009",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Veteran",
        "complaint_text": (
            "A person claiming to be from a veterans support NGO called me and "
            "offered free legal help for my pension case. They asked for my "
            "discharge certificate number and personal address to proceed."
        ),
        "suspicious_url": None,
        "screenshot_path": None,
        "threat_type": "Honeytrap / Social Engineering",
        "risk_score": 60,
        "risk_level": "Medium",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Unsolicited call offering legal services\n"
            "• Requesting discharge certificate number and home address\n"
            "• NGO impersonation pattern\n\n"
            "Risk Explanation:\n"
            "Social engineering attempt targeting veterans. "
            "Discharge certificate numbers can be used for identity fraud."
        ),
        "mitigation": (
            "Do not share personal documents or certificate numbers over phone. "
            "Verify NGO credentials through official Sainik Welfare Board. "
            "Report suspicious callers to local cyber cell."
        ),
        "status": "Open",
        "created_at": _ts(days_ago=9, hour=15),
        "attack_channel": "Voice Call",
        "ai_confidence": 63,
        "linked_case_count": 0,
        "ml_prediction": "social_engineering",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Honeytrap / Social Engineering",
        "rule_based_type": "Honeytrap / Social Engineering",
        "campaign_signature": None,
        "incident_hour": 15,
        "incident_day": "Tuesday",
        "decision_path": "ML+Rule hybrid → Medium",
    },
    # 10 — Spam / Low
    {
        "id": "SEED-010",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Family Member",
        "complaint_text": (
            "My spouse keeps receiving bulk SMS messages advertising investment "
            "schemes with guaranteed returns, claiming to be endorsed by retired "
            "defence officers. The messages come from different numbers daily."
        ),
        "suspicious_url": None,
        "screenshot_path": None,
        "threat_type": "Suspicious Communication",
        "risk_score": 30,
        "risk_level": "Low",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Bulk unsolicited SMS from rotating numbers\n"
            "• Guaranteed return investment claims\n"
            "• False endorsement by retired defence officers\n\n"
            "Risk Explanation:\n"
            "Low-risk spam campaign. Could escalate to fraud if victim engages. "
            "No immediate credential or data theft risk detected."
        ),
        "mitigation": (
            "Block the numbers and mark as spam. "
            "Do not engage with investment offers from unknown sources. "
            "Register on DND (Do Not Disturb) service with your telecom provider."
        ),
        "status": "Resolved",
        "created_at": _ts(days_ago=10, hour=8),
        "attack_channel": "SMS",
        "ai_confidence": 35,
        "linked_case_count": 0,
        "ml_prediction": "spam",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Suspicious Communication",
        "rule_based_type": "Suspicious Communication",
        "campaign_signature": None,
        "incident_hour": 8,
        "incident_day": "Wednesday",
        "decision_path": "Rule-Based → Low",
    },
    # 11 — Fraud / High
    {
        "id": "SEED-011",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Serving Personnel",
        "complaint_text": (
            "I received a WhatsApp message from someone claiming to be my Commanding "
            "Officer asking me to urgently purchase Google Play gift cards worth "
            "Rs 5000 and share the codes. The number was not my CO's actual number."
        ),
        "suspicious_url": None,
        "screenshot_path": None,
        "threat_type": "Identity / Financial Fraud",
        "risk_score": 78,
        "risk_level": "High",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Commanding Officer impersonation via WhatsApp\n"
            "• Gift card fraud pattern\n"
            "• Urgency pressure from fake authority figure\n\n"
            "Risk Explanation:\n"
            "Gift card scam using CO impersonation. "
            "A common fraud vector targeting military personnel who may comply "
            "with perceived orders from superiors."
        ),
        "mitigation": (
            "Never purchase gift cards on instruction from unverified contacts. "
            "Verify directly with your CO through official channels. "
            "Report the number to your unit security officer."
        ),
        "status": "Under Review",
        "created_at": _ts(days_ago=11, hour=17),
        "attack_channel": "WhatsApp",
        "ai_confidence": 81,
        "linked_case_count": 2,
        "ml_prediction": "fraud",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Identity / Financial Fraud",
        "rule_based_type": "Financial Fraud",
        "campaign_signature": "CO-IMPERSONATION-GIFTCARD-2026",
        "incident_hour": 17,
        "incident_day": "Thursday",
        "decision_path": "ML+Rule hybrid → High",
    },
    # 12 — Espionage / Critical
    {
        "id": "SEED-012",
        "user_id": "ADM-DEMO-001",
        "user_name": "Demo User",
        "category": "Serving Personnel",
        "complaint_text": (
            "I noticed that a colleague was photographing internal notice boards "
            "and movement orders using a personal phone and sending images via "
            "an encrypted messaging app to an unknown contact."
        ),
        "suspicious_url": None,
        "screenshot_path": None,
        "threat_type": "Espionage Indicator",
        "risk_score": 97,
        "risk_level": "Critical",
        "ai_reason": (
            "Detected Indicators:\n"
            "• Photographing classified movement orders\n"
            "• Transmission via encrypted channel to unknown contact\n"
            "• Insider threat pattern\n\n"
            "Risk Explanation:\n"
            "Insider threat with active exfiltration of operational documents. "
            "Immediate escalation required. This constitutes a potential espionage incident."
        ),
        "mitigation": (
            "Report immediately to unit intelligence officer and commanding officer. "
            "Do not confront the individual directly. "
            "Preserve evidence and restrict access to sensitive areas pending investigation."
        ),
        "status": "Escalated",
        "created_at": _ts(days_ago=12, hour=7),
        "attack_channel": "Unknown",
        "ai_confidence": 97,
        "linked_case_count": 0,
        "ml_prediction": "espionage",
        "model_used": "TF-IDF + LogisticRegression",
        "ml_predicted_type": "Espionage Indicator",
        "rule_based_type": "Espionage Indicator",
        "campaign_signature": None,
        "incident_hour": 7,
        "incident_day": "Friday",
        "decision_path": "ML+Rule hybrid → Critical",
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def seed_complaints(db_path: str) -> None:
    """
    Insert demo complaints into the database if it is empty.

    Args:
        db_path: Absolute path to the SQLite database file.

    Safe to call on every startup — exits immediately if complaints exist.
    Never raises; prints a warning on unexpected errors so startup is not blocked.
    """
    try:
        conn = _get_connection(db_path)
        try:
            cursor = conn.cursor()

            # Guard: do nothing if complaints already exist
            count = cursor.execute("SELECT COUNT(*) FROM complaints").fetchone()[0]
            if count > 0:
                print(f"[seed] Database already has {count} complaint(s). Skipping seed.")
                return

            # Insert all seed records
            for record in SEED_COMPLAINTS:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO complaints (
                        id, user_id, user_name, category, complaint_text,
                        suspicious_url, screenshot_path, threat_type, risk_score,
                        risk_level, ai_reason, mitigation, status, created_at,
                        attack_channel, ai_confidence, linked_case_count,
                        ml_prediction, model_used, ml_predicted_type,
                        rule_based_type, campaign_signature,
                        incident_hour, incident_day, decision_path
                    ) VALUES (
                        :id, :user_id, :user_name, :category, :complaint_text,
                        :suspicious_url, :screenshot_path, :threat_type, :risk_score,
                        :risk_level, :ai_reason, :mitigation, :status, :created_at,
                        :attack_channel, :ai_confidence, :linked_case_count,
                        :ml_prediction, :model_used, :ml_predicted_type,
                        :rule_based_type, :campaign_signature,
                        :incident_hour, :incident_day, :decision_path
                    )
                    """,
                    record,
                )

            conn.commit()
            print(f"[seed] Inserted {len(SEED_COMPLAINTS)} demo complaint(s) successfully.")

        finally:
            conn.close()

    except Exception as exc:
        # Never crash startup — just warn
        print(f"[seed] WARNING: seed_complaints failed: {exc}")
