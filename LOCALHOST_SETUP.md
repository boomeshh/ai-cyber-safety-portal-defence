# Rakshak AI — Localhost Setup Guide

## Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.9+ |
| Node.js | 18+ |
| Git | any recent version |

---

## Port Assignments

| Service | URL |
|---------|-----|
| FastAPI Backend | http://localhost:8000 |
| User Frontend | http://localhost:3000 |
| Admin Frontend | http://localhost:3001 |
| CERT Frontend | http://localhost:3002 |

---

## Environment Setup

Each service has a `.env.example` file. Copy it to `.env` before starting:

```bash
# Backend
copy backend\.env.example backend\.env

# User frontend
copy user-frontend\.env.example user-frontend\.env

# Admin frontend
copy admin-frontend\.env.example admin-frontend\.env

# CERT frontend
copy cert-frontend\.env.example cert-frontend\.env
```

> Mac/Linux: use `cp` instead of `copy`.

Edit `backend/.env` to add your real SMTP credentials if you want email alerts.
Leave `EMAIL_ENABLED=false` to skip email sending during development.

---

## Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate — Windows
venv\Scripts\activate

# Activate — Mac / Linux
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the backend
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Backend health check: http://localhost:8000/docs

---

## Frontend Setup

Open three separate terminals — one per frontend.

### User Frontend (port 3000)

```bash
cd user-frontend
npm install
npm start
```

### Admin Frontend (port 3001)

```bash
cd admin-frontend
npm install
npm start
```

### CERT Frontend (port 3002)

```bash
cd cert-frontend
npm install
npm start
```

> React will auto-assign ports 3000, 3001, 3002 in order. If another app is already
> using a port, React will prompt you to use the next available one.

---

## Account Provisioning

Public registration creates standard user accounts only. It never creates Admin or
CERT accounts.

Create a privileged account explicitly from the backend directory. The command
prompts for the password securely without logging it:

```bash
python bootstrap_privileged_account.py --role admin
python bootstrap_privileged_account.py --role cert
```

For non-interactive provisioning, set `RAKSHAK_BOOTSTRAP_EMAIL`,
`RAKSHAK_BOOTSTRAP_NAME`, and `RAKSHAK_BOOTSTRAP_PASSWORD` only for the
one-time command invocation. Existing accounts are preserved and never reset.

---

## Production Deployment

For production (Vercel, Render, Railway, etc.), set `REACT_APP_API_BASE_URL` to your
deployed backend URL in each frontend's environment variables panel — no code changes
needed. The backend reads all secrets from environment variables set in the hosting
platform.
