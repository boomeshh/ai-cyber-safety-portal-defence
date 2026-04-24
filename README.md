# 🔐 Rakshak AI — Cyber Safety Portal for Defence

AI-powered cyber incident reporting and threat intelligence platform for defence personnel, families, and veterans.

---

## 💡 Overview
This system allows users to report suspicious messages, links, or activities.  
It uses a hybrid AI engine to analyze threats, assign risk scores, and detect attack patterns.

---

## 🧠 AI Engine
- Rule-based detection (keywords, URLs, patterns)
- ML model (TF-IDF + Logistic Regression)
- Hybrid decision logic (rule + ML)
- Explainable outputs (risk reason + indicators)

---

## 📊 Features
- Complaint submission with evidence
- Threat classification (Phishing, OPSEC Risk, etc.)
- Risk scoring (Low / Medium / High / Critical)
- Campaign detection (linked cases)
- Admin triage dashboard
- CERT command center with alerts

---

## 🏗️ Architecture
User → Frontend → Backend → AI Engine → Database → Dashboards (User / Admin / CERT)

---

## 🧰 Tech Stack
- React (Frontend)
- FastAPI (Backend)
- Python (ML Engine)
- Scikit-learn (TF-IDF + Logistic Regression)
- SQLite (Database)

---

## ⚙️ Run Locally

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
