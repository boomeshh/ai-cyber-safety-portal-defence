# 🛡️ Rakshak AI — YUDHISTHIRA
### AI-Powered Defence Cyber Incident & Safety Portal

> Inspired by **Smart India Hackathon 2025 — Problem Statement ID 25183**
> Built for defence personnel, families, and veterans of the Indian Armed Forces.

**Live:** [rakshakai.online](https://www.rakshakai.online) · [admin.rakshakai.online](https://admin.rakshakai.online) · [cert.rakshakai.online](https://cert.rakshakai.online)

---

## 🎯 Problem Statement

Defence personnel, veterans, and their families are increasingly targeted by sophisticated cyber threats — phishing, malware, honeytrap operations, OPSEC leaks, and financial fraud. Existing reporting systems are slow, manual, and lack AI-powered threat intelligence.

**Rakshak AI** solves this by providing an automated, AI-driven cyber incident reporting and threat analysis platform purpose-built for the defence ecosystem.

---

## 🚀 Live Deployment

| Service | URL |
|---------|-----|
| 👤 User Portal | https://www.rakshakai.online |
| 🔐 Admin Dashboard | https://admin.rakshakai.online |
| 🛡️ CERT Command Center | https://cert.rakshakai.online |
| ⚙️ Backend API | https://ai-cyber-safety-portal-defence.onrender.com |
| 📖 API Docs | https://ai-cyber-safety-portal-defence.onrender.com/docs |

---

## ✨ Key Features

### 👤 User Portal
- Firebase Email Authentication with email verification
- Submit cyber complaints with multi-format evidence (images, PDF, audio, video, APK)
- Real-time AI threat analysis with risk scoring
- View complaint history with AI confidence, IOC extraction, and mitigation steps
- Mobile-first responsive design

### 🔐 Admin Dashboard
- Role-based complaint triage queue
- Status management (Open → Under Review → Escalated → Resolved)
- Internal case notes and AI feedback system
- Evidence open/download with JWT authentication
- Campaign intelligence graph and audit trail

### 🛡️ CERT Command Center
- Live critical alert feed (auto-refresh every 5 seconds)
- Heatmap intelligence (Hour vs Day, Channel vs Risk, Category vs Channel)
- Campaign cluster analysis and ML model intelligence panel
- Excel export for offline analysis
- Model retraining with safety guardrails

---

## 🧠 AI/ML Engine

| Component | Technology |
|-----------|-----------|
| Feature Extraction | TF-IDF Vectorizer |
| Classification | Logistic Regression (7-class) |
| Decision Logic | Hybrid Rule + ML |
| Threat Classes | Phishing, Malware/APK, Honeytrap, Financial Fraud, OPSEC Risk, Espionage, Suspicious Communication |
| IOC Extraction | Regex-based URL/domain/email/phone extraction |
| Campaign Detection | Linked indicator matching |
| Auto-Retrain | Safety-guarded (no model replacement if accuracy drops) |

---

## 🏗️ Architecture

```
User Browser
    │
    ├── User Frontend (React + Firebase Auth) ──► Vercel
    ├── Admin Frontend (React) ──────────────────► Vercel
    └── CERT Frontend (React + Chart.js) ────────► Vercel
              │
              ▼
    FastAPI Backend (Python) ────────────────────► Render
              │
    ┌─────────┼──────────────┐
    │         │              │
  SQLite    ML Engine    Resend Email
  Database  (sklearn)    Alerts
```

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, React Router v7, Firebase Auth |
| Backend | FastAPI, Python 3.11+ |
| Database | SQLite |
| ML/AI | scikit-learn (TF-IDF + LogisticRegression) |
| Authentication | Firebase Email/Password + Email Verification |
| Email Alerts | Resend API (SMTP fallback) |
| Deployment | Vercel (frontend) + Render (backend) |
| Security | PBKDF2 hashing, JWT sessions, rate limiting, security headers |

---

## 📸 Screenshots

| User Portal | Admin Dashboard | CERT Command Center |
|-------------|-----------------|---------------------|
| ![User Login](screenshots/USER%20LOGIN.png) | ![Admin Dashboard](screenshots/ADMIN%20DASHBOARD.png) | ![CERT](screenshots/COMMAND%20CENTER%20DASHBOARD.png) |

| Register | Submit Complaint | Verify Email |
|----------|-----------------|--------------|
| ![Register](screenshots/USER%20CREATE%20ACCOUNT.png) | ![Submit](screenshots/Sumbit%20Complaint.png) | ![Verify](screenshots/VERFIY%20MAIL.png) |

| Complaint Result | Heatmap Intelligence | Campaign Clusters |
|-----------------|---------------------|-------------------|
| ![Result](screenshots/COMPLAINT%20SUMBITED%20SUCCESSFULLY.png) | ![Heatmap](screenshots/HAETMAP%20IN%20CERT.png) | ![Campaign](screenshots/CAMPAGAIN%20CLUSTER%20CERT.png) |

---

## 🔧 Local Development Setup

See [LOCALHOST_SETUP.md](LOCALHOST_SETUP.md) for complete setup instructions.

**Quick start:**

```bash
# Backend
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000

# Frontends (separate terminals)
cd user-frontend  && npm install && npm start   # http://localhost:3000
cd admin-frontend && npm install && npm start   # http://localhost:3001
cd cert-frontend  && npm install && npm start   # http://localhost:3002
```

**Demo credentials:**

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@rakshak.ai | admin123 |
| CERT Officer | cert@rakshak.ai | cert123 |

---

## 🔐 Security Features

- Firebase Email Verification (users must verify before accessing portal)
- PBKDF2-HMAC-SHA256 password hashing (120,000 iterations)
- Session tokens (40-byte cryptographically secure random)
- Rate limiting (30 req/60s per IP on auth endpoints)
- Security headers middleware (X-Frame-Options, CSP, HSTS)
- Input sanitization (XSS + SQL injection prevention)
- Role-based access control (user / admin / cert)
- Audit logging for all admin and CERT actions

---

## 🧪 Testing

```bash
py -m pytest backend/tests/ -q
# Expected: 166 passed
```

---

## 🌟 Phase Roadmap

- [x] Core complaint system + AI analysis
- [x] Admin/CERT dashboards + analytics
- [x] Campaign detection + heatmaps
- [x] Firebase auth + email verification
- [x] IOC extraction + severity explanation + mitigation steps
- [x] Case notes + timeline + AI feedback
- [x] Public awareness dashboard + HTML incident reports
- [x] Mobile-first responsive UI + cross-browser compatibility
- [ ] Deep learning model upgrade
- [ ] Real-time WebSocket alerts

---

## 👨‍💻 Author

**Boomesh** — Cloud Engineering | AI/ML Developer | Defence-Tech Enthusiast

*Rakshak AI — Protecting those who protect the nation.*ssion) |

**Boomesh**
Cloud Engineering | AI/ML Developer | Defence-Tech Enthusiast

---

*Rakshak AI — Protecting those who protect the nation.*
se 2 — Admin/CERT dashboards + analytics
- [x] Phase 3 — Campaign detection + heatmaps
- [x] Phase 4 — Firebase auth + email verification
- [x] Phase 5 — IOC extraction + severity explanation + mitigation steps
- [x] Phase 6 — Case notes + timeline + AI feedback
- [x] Phase 7 — Public awareness dashboard + HTML incident reports
- [x] Phase 8 — Mobile-first responsive UI + cross-browser compatibility
- [ ] Phase 9 — Deep learning model upgrade
- [ ] Phase 10 — Real-time WebSocket alerts

---

## 👨‍💻 Author

# Expected: 166 passed
```

Test suites:
- `test_audit.py` — Full API endpoint coverage (56 tests)
- `test_health.py` — Health check endpoints
- `test_phase1_features.py` — IOC, severity, mitigation (30 tests)
- `test_phase2_features.py` — Notes, timeline, feedback (35 tests)
- `test_phase3_features.py` — Public awareness, incident report (19 tests)
- `test_ml_balance.py` — ML dataset balance and retrain safety (20 tests)

---

## 🌟 Phase Roadmap

- [x] Phase 1 — Core complaint system + AI analysis
- [x] Phain` | User login |
| POST | `/complaints` | Submit complaint with evidence |
| GET | `/my-complaints/{id}` | User's complaint history |
| GET | `/admin/overview` | Admin dashboard data |
| GET | `/cert/intel` | CERT intelligence feed |
| GET | `/public/awareness` | Public anonymized statistics |
| GET | `/admin/complaints/{id}/report` | HTML incident report |

Full API documentation: https://ai-cyber-safety-portal-defence.onrender.com/docs

---

## 🧪 Testing

```bash
cd rakshak-ai
py -m pytest backend/tests/ -qimiting (30 req/60s per IP on auth endpoints)
- Security headers middleware (X-Frame-Options, CSP, HSTS)
- Input sanitization (XSS + SQL injection prevention)
- Evidence file hash verification (SHA-256)
- Role-based access control (user / admin / cert)
- Audit logging for all admin/CERT actions

---

## 📊 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check (UptimeRobot compatible) |
| POST | `/register` | User registration |
| POST | `/logrt  # http://localhost:3001

# CERT Frontend
cd cert-frontend && npm install && npm start   # http://localhost:3002
```

**Demo credentials:**
| Role | Email | Password |
|------|-------|----------|
| Admin | admin@rakshak.ai | admin123 |
| CERT Officer | cert@rakshak.ai | cert123 |

---

## 🔐 Security Features

- Firebase Email Verification (users must verify before accessing portal)
- PBKDF2-HMAC-SHA256 password hashing (120,000 iterations)
- Session tokens (40-byte cryptographically secure random)
- Rate lots/CERT.png) |

---

## 🔧 Local Development Setup

See [LOCALHOST_SETUP.md](LOCALHOST_SETUP.md) for complete setup instructions.

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
cd user-frontend && npm install && npm start   # http://localhost:3000

# Admin Frontend
cd admin-frontend && npm install && npm sta| Authentication | Firebase Email/Password + Email Verification |
| Email Alerts | Resend API (SMTP fallback) |
| Deployment | Vercel (frontend) + Render (backend) |
| Security | PBKDF2 password hashing, JWT sessions, rate limiting, security headers |

---

## 📸 Screenshots

| User Portal | Admin Dashboard | CERT Command Center |
|-------------|-----------------|---------------------|
| ![User](screenshots/USER.png) | ![Admin](screenshots/ADMIN.png) | ![CERT](screensh