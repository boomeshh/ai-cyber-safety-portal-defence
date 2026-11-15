"""Pure deterministic rule-based risk scoring for complaint triage."""


def calculate_rule_risk(complaint_text: str, suspicious_url: str, evidence_name: str = ""):
    text = (complaint_text or "").lower()
    url = (suspicious_url or "").lower()
    file_name = (evidence_name or "").lower()

    score = 0
    indicators = []
    risk_notes = []
    tags = set()

    keyword_weights = {
        "otp": 25, "password": 25, "bank": 20, "login": 18, "verify": 16,
        "urgent": 12, "immediately": 10, "suspended": 15, "click": 10,
        "army": 20, "defence": 20, "official": 12, "support": 8, "kyc": 10,
        "update": 8, "reward": 10, "blocked": 12, "account": 10,
        "confidential": 16, "classified": 28, "posting": 14, "deployment": 18,
        "location": 12, "salary": 8, "investment": 8, "apk": 22,
        "attachment": 14, "resume": 8, "friend request": 14, "romance": 18,
        "video call": 18, "refund": 14, "cvv": 20, "card": 12, "transfer": 12,
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

    return {
        "rule_score": min(score, 100),
        "indicators": indicators,
        "risk_notes": risk_notes,
        "tags": tags,
    }
