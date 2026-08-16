# 🛡️ Rakshak AI
### AI-Powered Cyber Threat Reporting, Analysis & Response Platform

Rakshak AI helps everyday individuals report suspicious cyber incidents — phishing, malicious links, fraudulent messages, and suspicious files — and provides automated AI-driven analysis, risk scoring, prioritization, and actionable guidance.

**Live:** [rakshakai.online](https://www.rakshakai.online) · [admin.rakshakai.online](https://admin.rakshakai.online)

---

## 🎯 Problem

Everyday users receive phishing messages, malicious links, fake communications, fraudulent requests, and suspicious files. Existing reporting channels often require users to identify the threat themselves, and incidents can be difficult to prioritize once reported.

---

## 💡 Solution

Rakshak AI provides a single workflow to:

**Report → Analyze → Risk Score → Prioritize → Act**

1. **Report** — The user submits a suspicious message, link, file, or other evidence.
2. **Analyze** — The AI/ML engine examines the submitted content for threat indicators.
3. **Risk Score** — A risk score is generated based on the analysis.
4. **Prioritize** — Incidents are ranked so higher-risk cases surface first.
5. **Act** — The user receives guidance, and administrators can review and manage the case.

---

## 👤 Who Can Use It

- **Individual / Citizen**
- **Family Member**
- **Employee / Professional**

---

## 🚀 Key Features

### User Portal
- Email authentication with email verification
- Submit complaints with multi-format evidence (images, PDF, audio, video, APK)
- AI-powered threat analysis with risk scoring
- View complaint history with AI confidence, extracted indicators, and mitigation steps
- Mobile-first responsive design

### Admin / Management Portal
- Role-based complaint triage queue
- Status management (Open → Under Review → Escalated → Resolved)
- Internal case notes and AI feedback system
- Evidence access/download with authenticated sessions
- Campaign intelligence graph and audit trail

### AI / Threat Analysis
- Threat classification across supported categories
- Indicator of Compromise (IOC) extraction
- Campaign/cluster detection via linked indicators
- Heatmap intelligence views (Hour vs Day, Channel vs Risk, Category vs Channel)
- Model retraining with safety guardrails

### Security / Authentication
- Email/password authentication with email verification requirement
- Password hashing
- Session/token-based authentication
- Rate limiting on authentication endpoints
- Security headers middleware
- Input sanitization
- Role-based access control
- Audit logging for administrative actions

---

## 🧠 AI / ML Engine

| Component | Approach |
|-----------|----------|
| Feature Extraction | TF-IDF Vectorizer |
| Classification | Logistic Regression |
| Decision Logic | Hybrid rule-based + ML |
| Threat Categories | Phishing, Malware/APK, Fraud, Suspicious Communication, and related categories |
| IOC Extraction | Regex-based URL/domain/email/phone extraction |
| Campaign Detection | Linked indicator matching |
| Retraining | Safety-guarded (model is not replaced if accuracy drops) |

This is a traditional machine learning pipeline (TF-IDF + Logistic Regression), not a deep learning or LLM-based system.

---

## ⚠️ Risk Scoring

Each submitted report is analyzed and assigned a risk score reflecting the likelihood and severity of the threat, which is then used to prioritize review and determine the guidance shown to the user.

---

## 🏗️ System Architecture

```
User
  ↓
User Frontend
  ↓
Backend API
  ↓
AI / ML Analysis
  ↓
Risk Scoring
  ↓
Database / Storage
  ↓
Admin / Management Dashboard
```

---

## 🔄 Workflow

1. User submits suspicious content/evidence
2. Backend receives the complaint
3. AI/ML engine analyzes the submitted content
4. Threat indicators are extracted/detected
5. Risk score is generated
6. Risk level is assigned
7. User receives guidance / next action
8. Admin reviews and manages the incident

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React, React Router, Firebase Auth |
| Backend | FastAPI, Python |
| Database | SQLite |
| AI/ML | scikit-learn (TF-IDF + Logistic Regression) |
| Authentication | Firebase Email/Password + Email Verification |
| Email Alerts | Resend API (with SMTP fallback) |
| Deployment | Vercel (frontend) + Render (backend) |
| Security | Password hashing, session/JWT handling, rate limiting, security headers |

---

## 📊 API

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/health` | Health check |
| POST | `/register` | User registration |
| POST | `/login` | User login |
| POST | `/complaints` | Submit complaint with evidence |
| GET | `/my-complaints/{id}` | User's complaint history |
| GET | `/admin/overview` | Admin dashboard data |
| GET | `/public/awareness` | Public anonymized statistics |
| GET | `/admin/complaints/{id}/report` | Incident report (HTML) |

---

## 🔐 Security

- Email verification required before portal access
- Password hashing (PBKDF2-HMAC-SHA256)
- Session/JWT-based authentication
- Rate limiting on authentication endpoints
- Security headers middleware (X-Frame-Options, CSP, HSTS)
- Input sanitization (XSS + SQL injection prevention)
- Role-based access control
- Audit logging for administrative actions

---

## 🖥️ Screenshots

### User Portal
- Login
- Registration
- Email Verification

### Complaint Submission
- Submit Complaint
- Complaint Submitted Successfully

### Analysis Result
- Complaint Result / Risk Analysis

### Admin Dashboard
- Admin Dashboard

### Analytics / Intelligence
- Heatmap Intelligence
- Campaign Cluster Analysis

*(Screenshot files are located in the `/screenshots` folder of the repository.)*

---

## ⚙️ Local Development

**Quick start:**

```bash
# Backend
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000

# User Frontend
cd user-frontend && npm install && npm start

# Admin Frontend
cd admin-frontend && npm install && npm start
```

```env
API_URL=your_backend_url
```

---

## 🧪 Testing

```bash
py -m pytest backend/tests/ -q
```

---

## 🌟 Future Scope / Roadmap

- [ ] Deep learning model upgrade
- [ ] Real-time WebSocket alerts

---

## 👨‍💻 Author

**Boomesh** — Cloud Engineering | AI/ML Developer

*Rakshak AI — Helping citizens stay safe online.*
