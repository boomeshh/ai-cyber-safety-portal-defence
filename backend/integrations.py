"""
integrations.py — External integration helpers for Rakshak AI.
Covers: email alerts (SMTP + Resend), threat intelligence URL check (VirusTotal stub),
and CERT alert dispatch.

All functions are safe — failures are logged and never crash the main app.
Configure via environment variables or a .env file.
"""

import os
import re
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

logger = logging.getLogger("integrations")

# ---------------------------------------------------------------------------
# SMTP configuration
# ---------------------------------------------------------------------------
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").replace(" ", "")
ALERT_TO      = os.getenv("ALERT_TO", "")
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Resend configuration
# ---------------------------------------------------------------------------
RESEND_ENABLED   = os.getenv("RESEND_ENABLED", "false").lower() == "true"
RESEND_API_KEY   = os.getenv("RESEND_API_KEY", "")
RESEND_FROM      = os.getenv("RESEND_FROM", "Rakshak AI <alerts@rakshakai.online>")
RESEND_ALERT_TO  = os.getenv("RESEND_ALERT_TO", ALERT_TO)  # falls back to SMTP recipients

# ---------------------------------------------------------------------------
# VirusTotal configuration (optional)
# ---------------------------------------------------------------------------
VT_API_KEY    = os.getenv("VT_API_KEY", "")
VT_ENABLED    = os.getenv("VT_ENABLED", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Resend email alert
# ---------------------------------------------------------------------------
def send_resend_alert(subject: str, html: str) -> bool:
    """
    Send an HTML email via the Resend API.
    Returns True on success, False on failure.
    Silently skips if RESEND_ENABLED is False or credentials are missing.
    """
    if not RESEND_ENABLED:
        logger.debug("[integrations] Resend alerts disabled (RESEND_ENABLED=false).")
        return False

    if not RESEND_API_KEY:
        logger.warning("[integrations] RESEND_API_KEY not configured. Skipping Resend alert.")
        return False

    recipients = [a.strip() for a in RESEND_ALERT_TO.split(",") if a.strip()]
    if not recipients:
        logger.warning("[integrations] No Resend recipients configured (RESEND_ALERT_TO).")
        return False

    try:
        import resend  # installed via requirements.txt
        resend.api_key = RESEND_API_KEY

        params = {
            "from": RESEND_FROM,
            "to": recipients,
            "subject": subject,
            "html": html,
        }
        response = resend.Emails.send(params)
        logger.info(f"[integrations] Resend alert sent — id={response.get('id')} to={recipients} subject={subject!r}")
        return True

    except Exception as exc:
        logger.error(f"[integrations] Resend send failed: {exc}")
        return False


# ---------------------------------------------------------------------------
# Email alert
# ---------------------------------------------------------------------------
def send_alert_email(
    subject: str,
    body: str,
    to_addresses: Optional[list] = None,
) -> bool:
    """
    Send an email alert via SMTP.
    Returns True on success, False on failure.
    Silently skips if EMAIL_ENABLED is False or credentials are missing.
    """
    if not EMAIL_ENABLED:
        logger.debug("[integrations] Email alerts disabled (EMAIL_ENABLED=false).")
        return False

    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("[integrations] SMTP credentials not configured. Skipping email.")
        return False

    recipients = to_addresses or [a.strip() for a in ALERT_TO.split(",") if a.strip()]
    if not recipients:
        logger.warning("[integrations] No email recipients configured.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = ", ".join(recipients)

        # Plain text part
        msg.attach(MIMEText(body, "plain"))

        # HTML part — simple dark-themed card
        html_body = f"""
        <html><body style="background:#020617;color:#e2e8f0;font-family:Arial,sans-serif;padding:24px;">
          <div style="max-width:600px;margin:0 auto;background:#0f172a;border:1px solid #1e293b;
                      border-radius:16px;padding:24px;">
            <div style="color:#38bdf8;font-weight:800;font-size:0.85rem;letter-spacing:2px;
                        margin-bottom:12px;">RAKSHAK AI · ALERT</div>
            <h2 style="color:#f8fafc;margin-bottom:16px;">{subject}</h2>
            <pre style="color:#cbd5e1;white-space:pre-wrap;font-size:0.9rem;">{body}</pre>
            <div style="margin-top:20px;color:#64748b;font-size:0.8rem;">
              Sent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · Rakshak AI Defence Portal
            </div>
          </div>
        </body></html>
        """
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, recipients, msg.as_string())

        logger.info(f"[integrations] Alert email sent to {recipients}: {subject}")
        return True

    except Exception as e:
        logger.error(f"[integrations] Email send failed: {e}")
        return False


def send_high_risk_alert(complaint_id: str, risk_level: str, threat_type: str,
                          user_name: str, ai_confidence: int) -> bool:
    """
    Send a formatted high/critical risk alert.
    Tries Resend first (if enabled), falls back to SMTP.
    Called after complaint creation when risk_level is High or Critical.
    """
    subject = f"[{risk_level.upper()} ALERT] Rakshak AI — New {risk_level} Threat Detected"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Shared HTML body used by both Resend and SMTP
    html_body = f"""
    <html><body style="background:#020617;color:#e2e8f0;font-family:Arial,sans-serif;padding:24px;">
      <div style="max-width:600px;margin:0 auto;background:#0f172a;border:1px solid #1e293b;
                  border-radius:16px;padding:24px;">
        <div style="color:#38bdf8;font-weight:800;font-size:0.85rem;letter-spacing:2px;
                    margin-bottom:12px;">RAKSHAK AI · {risk_level.upper()} ALERT</div>
        <h2 style="color:#f8fafc;margin-bottom:16px;">{subject}</h2>
        <table style="width:100%;border-collapse:collapse;color:#cbd5e1;font-size:0.9rem;">
          <tr><td style="padding:6px 0;color:#64748b;">Complaint ID</td><td>{complaint_id}</td></tr>
          <tr><td style="padding:6px 0;color:#64748b;">Risk Level</td>
              <td style="color:{'#ef4444' if risk_level=='Critical' else '#f97316'};font-weight:700;">{risk_level}</td></tr>
          <tr><td style="padding:6px 0;color:#64748b;">Threat Type</td><td>{threat_type}</td></tr>
          <tr><td style="padding:6px 0;color:#64748b;">Reported By</td><td>{user_name}</td></tr>
          <tr><td style="padding:6px 0;color:#64748b;">AI Confidence</td><td>{ai_confidence}%</td></tr>
          <tr><td style="padding:6px 0;color:#64748b;">Time</td><td>{timestamp}</td></tr>
        </table>
        <div style="margin-top:20px;padding:12px 16px;background:#1e293b;border-radius:10px;
                    color:#94a3b8;font-size:0.85rem;">
          Action Required: Log in to the Admin/CERT dashboard to review this case.
        </div>
        <div style="margin-top:16px;color:#475569;font-size:0.78rem;">
          Sent at {timestamp} · Rakshak AI Defence Portal
        </div>
      </div>
    </body></html>
    """

    plain_body = (
        f"Complaint ID : {complaint_id}\n"
        f"Risk Level   : {risk_level}\n"
        f"Threat Type  : {threat_type}\n"
        f"Reported By  : {user_name}\n"
        f"AI Confidence: {ai_confidence}%\n"
        f"Time         : {timestamp}\n\n"
        f"Action Required: Log in to the Admin/CERT dashboard to review this case."
    )

    # Try Resend first
    if RESEND_ENABLED:
        result = send_resend_alert(subject, html_body)
        if result:
            return True
        logger.warning("[integrations] Resend failed — attempting SMTP fallback.")

    # Fall back to SMTP
    return send_alert_email(subject, plain_body)


# ---------------------------------------------------------------------------
# Threat intelligence — URL check
# ---------------------------------------------------------------------------
def check_url_threat_intel(url: str) -> dict:
    """
    Check a URL against VirusTotal (if configured) or run a local heuristic check.
    Returns a dict with: is_malicious, source, details.
    Never raises.
    """
    if not url or not url.strip():
        return {"is_malicious": False, "source": "none", "details": "No URL provided."}

    # Local heuristic check (always runs)
    heuristic_result = _local_url_heuristic(url)

    if VT_ENABLED and VT_API_KEY:
        vt_result = _virustotal_check(url)
        if vt_result.get("checked"):
            return vt_result

    return heuristic_result


def _local_url_heuristic(url: str) -> dict:
    """
    Fast local heuristic URL risk check.
    Checks for: shorteners, suspicious patterns, HTTP (non-HTTPS), known bad TLDs.
    """
    lower = url.lower()
    flags = []

    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "shorturl.at", "rb.gy"]
    if any(s in lower for s in shorteners):
        flags.append("Shortened URL detected")

    suspicious_patterns = [
        "verify", "login", "update", "secure", "account", "gift",
        "bonus", "free", "claim", "reward", "kyc", "otp", "password",
    ]
    for pat in suspicious_patterns:
        if pat in lower:
            flags.append(f"Suspicious URL keyword: '{pat}'")

    if lower.startswith("http://"):
        flags.append("Non-HTTPS URL (insecure)")

    bad_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".download"]
    for tld in bad_tlds:
        if lower.endswith(tld) or f"{tld}/" in lower:
            flags.append(f"High-risk TLD detected: {tld}")

    # IP-based URL
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', lower):
        flags.append("IP-based URL (no domain)")

    is_malicious = len(flags) >= 2  # flag as malicious if 2+ heuristics trigger

    return {
        "is_malicious": is_malicious,
        "source":       "local_heuristic",
        "flags":        flags,
        "details":      "; ".join(flags) if flags else "No suspicious patterns detected.",
        "checked":      True,
    }


def _virustotal_check(url: str) -> dict:
    """
    Check URL via VirusTotal API v3.
    Requires VT_API_KEY environment variable.
    Returns result dict or falls back gracefully.
    """
    try:
        import urllib.request
        import urllib.parse
        import base64
        import json as _json

        # VirusTotal URL ID = base64url(url) without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        req = urllib.request.Request(
            api_url,
            headers={"x-apikey": VT_API_KEY, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = _json.loads(resp.read().decode())

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(stats.values()) if stats else 0

        is_malicious = malicious >= 3 or suspicious >= 5

        return {
            "is_malicious": is_malicious,
            "source":       "virustotal",
            "malicious_votes": malicious,
            "suspicious_votes": suspicious,
            "total_engines": total,
            "details": f"VirusTotal: {malicious} malicious, {suspicious} suspicious out of {total} engines.",
            "checked": True,
        }
    except Exception as e:
        logger.warning(f"[integrations] VirusTotal check failed: {e}")
        return {"is_malicious": False, "source": "virustotal_error", "details": str(e), "checked": False}


# ---------------------------------------------------------------------------
# CERT alert dispatch
# ---------------------------------------------------------------------------
def dispatch_cert_alert(complaint_id: str, risk_level: str, threat_type: str,
                         user_name: str, details: str = "") -> dict:
    """
    Dispatch a CERT-level alert.
    Currently: sends email + returns structured alert dict.
    Can be extended to push to a CERT SIEM or webhook.
    """
    alert = {
        "alert_id":     f"CERT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "complaint_id": complaint_id,
        "risk_level":   risk_level,
        "threat_type":  threat_type,
        "user_name":    user_name,
        "details":      details,
        "dispatched_at": datetime.now().isoformat(),
        "channels":     [],
    }

    # Email channel
    email_sent = send_high_risk_alert(complaint_id, risk_level, threat_type, user_name, 0)
    if email_sent:
        alert["channels"].append("email")

    logger.info(f"[integrations] CERT alert dispatched: {alert['alert_id']} for {complaint_id}")
    return alert
