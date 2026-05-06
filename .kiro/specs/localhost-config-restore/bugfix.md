You are a senior full-stack engineer working on a production-grade AI cyber security platform (Rakshak AI).

I am facing a critical issue:
After configuring the project for Vercel/Render deployment, the project no longer works on localhost.

Stack:
- Backend: FastAPI (localhost:8000)
- Frontend:
  - User: React (localhost:3000)
  - Admin: React (localhost:3001)
  - CERT: React (localhost:3002)

Goal:
Fix ONLY localhost configuration issues without breaking any existing features.

STRICT RULES:
- DO NOT rewrite business logic
- DO NOT remove any features
- DO NOT modify ML logic
- DO NOT break authentication
- ONLY fix configuration, API URLs, CORS, env, and evidence download

-----------------------------------
TASKS TO PERFORM
-----------------------------------

1. FIX API BASE URL ISSUE
- Find all hardcoded production URLs (Vercel/Render/AWS)
- Replace them with:
  process.env.REACT_APP_API_BASE_URL

- Create .env in each frontend:
  REACT_APP_API_BASE_URL=http://localhost:8000

- Ensure axios/fetch uses this base URL everywhere

-----------------------------------

2. FIX BACKEND CORS
Update FastAPI CORS config:

allow_origins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:3002",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:3001",
  "http://127.0.0.1:3002"
]

-----------------------------------

3. FIX EVIDENCE DOWNLOAD (CRITICAL BUG)
Problem:
Evidence uses <a href> which does NOT send JWT token.

Fix:
- Replace all <a href="/complaints/{id}/evidence"> with button + fetch()

Example:
fetch(url, {
  headers: {
    Authorization: `Bearer ${token}`
  }
})
→ convert to blob
→ open using URL.createObjectURL(blob)

-----------------------------------

4. ENV SECURITY FIX
- Remove real API keys from .env
- Create .env.example with dummy values
- Add .env to .gitignore

-----------------------------------

5. CREATE LOCALHOST_SETUP.md
Include:

Backend:
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000

Frontend:
cd user-frontend && npm install && npm start
cd admin-frontend && npm install && npm start
cd cert-frontend && npm install && npm start

-----------------------------------

TEST CASES (MUST PASS)

1. Backend runs on localhost:8000
2. No CORS errors
3. Login works
4. Token stored correctly
5. Dashboard loads
6. Submit complaint works
7. My complaints loads
8. Evidence upload works
9. Evidence open/download works (with token)
10. Admin dashboard loads
11. Admin status update works
12. CERT dashboard loads analytics
13. No "Missing access token" error
14. No "Backend connection failed"
15. No production URL hardcoded

-----------------------------------

OUTPUT FORMAT

1. List all changed files
2. Show code diffs
3. Explain each fix
4. Provide final run steps
5. Confirm:
   - localhost works
   - production not broken
   - no secrets exposed