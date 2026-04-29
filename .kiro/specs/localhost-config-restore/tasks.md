# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Live Secrets and Missing Protections
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface concrete evidence of each sub-condition BEFORE applying the fix
  - **Scoped PBT Approach**: Scope the property to the three concrete failing cases (credentials, gitignore gaps, missing doc)
  - Inspect `backend/.env` and assert `SMTP_USER` contains a real email address (not `your-email@gmail.com`) and `EMAIL_ENABLED=true`
  - Inspect `.gitignore` and assert it does NOT contain `**/.env` or `backend/.env`
  - Inspect `admin-frontend/.gitignore` and assert it does NOT contain a bare `.env` entry
  - Inspect `cert-frontend/.gitignore` and assert it does NOT contain a bare `.env` entry
  - Assert `LOCALHOST_SETUP.md` does NOT exist at repo root
  - Run test on UNFIXED code
  - **EXPECTED OUTCOME**: Test FAILS (this is correct - it proves the bug exists)
  - Document counterexamples found (e.g., `SMTP_USER=boomesh.public@gmail.com`, no `.env` in root gitignore, `LOCALHOST_SETUP.md` absent)
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.4, 1.5_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Source Files and Runtime Config Unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - Observe: `backend/main.py` content on unfixed code (record checksum or key lines)
  - Observe: all `*/src/` files are unmodified on unfixed code
  - Observe: `admin-frontend/.env`, `cert-frontend/.env`, `user-frontend/.env`, and all `.env.example` files on unfixed code
  - Write property-based test: for all files NOT in the fix scope, file content is byte-for-byte identical before and after fix
  - Verify test passes on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

- [x] 3. Fix for localhost config restore (credentials, gitignore gaps, missing setup doc)

  - [x] 3.1 Sanitize `backend/.env` credentials
    - Replace `SMTP_USER` value with `your-email@gmail.com`
    - Replace `SMTP_PASSWORD` value with `your-app-password`
    - Replace `ALERT_TO` value with `admin@example.com`
    - Set `EMAIL_ENABLED=false`
    - Keep `SMTP_HOST`, `SMTP_PORT`, `VT_ENABLED`, and `VT_API_KEY` unchanged
    - _Bug_Condition: isBugCondition where backend_env.SMTP_USER != placeholder AND EMAIL_ENABLED == "true"_
    - _Expected_Behavior: backend/.env contains only placeholder values; EMAIL_ENABLED=false; backend starts without SMTP errors_
    - _Preservation: backend/main.py, all frontend source files, all frontend .env files, and backend/.env.example must not be modified_
    - _Requirements: 1.4, 2.4_

  - [x] 3.2 Fix `.gitignore` files (3 files)
    - Root `.gitignore`: add a `# Environment files` section with `**/.env` and `backend/.env`
    - `admin-frontend/.gitignore`: add `.env` after the `.DS_Store` line
    - `cert-frontend/.gitignore`: add `.env` after the `.DS_Store` line
    - Do NOT modify `user-frontend/.gitignore` (already excludes `.env`)
    - _Bug_Condition: isBugCondition where root/admin/cert gitignores do not exclude .env_
    - _Expected_Behavior: git check-ignore matches any .env file in root, admin-frontend, cert-frontend, and backend_
    - _Preservation: no source files or runtime config are affected by gitignore changes_
    - _Requirements: 1.4, 2.4_

  - [x] 3.3 Create `LOCALHOST_SETUP.md` at repo root
    - Add Prerequisites section: Python 3.9+, Node 18+, Git
    - Add Backend setup: `cd backend`, create venv, activate (Windows and Mac/Linux variants), `pip install -r requirements.txt`, `uvicorn main:app --reload --host 127.0.0.1 --port 8000`
    - Add Frontend setup for all three frontends with their ports (user: 3000, admin: 3001, cert: 3002)
    - Add port assignments table (backend: 8000, user-frontend: 3000, admin-frontend: 3001, cert-frontend: 3002)
    - Add Environment setup: copy `.env.example` to `.env` instructions for each service
    - Add Demo credentials: `admin@rakshak.ai / admin123`, `cert@rakshak.ai / cert123`
    - Add note that production deployment uses environment variables set in the hosting platform
    - _Bug_Condition: isBugCondition where LOCALHOST_SETUP.md does not exist_
    - _Expected_Behavior: LOCALHOST_SETUP.md exists with all required sections; new developer can follow it to run all services_
    - _Preservation: no source code or runtime config is modified_
    - _Requirements: 1.5, 2.5_

  - [x] 3.4 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Live Secrets and Missing Protections Resolved
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms `isBugCondition` returns false for all three sub-conditions
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.4, 2.5_

  - [x] 3.5 Verify preservation tests still pass
    - **Property 2: Preservation** - Source Files and Runtime Config Unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm `backend/main.py`, all `*/src/` files, and all frontend `.env`/`.env.example` files are byte-for-byte identical

- [x] 4. Checkpoint - Ensure all tests pass
  - Confirm `backend/.env` contains no real email addresses or passwords
  - Confirm all 4 gitignore files (root, admin-frontend, cert-frontend, user-frontend) exclude `.env`
  - Confirm `LOCALHOST_SETUP.md` exists with all required sections
  - Confirm no source code was modified
  - Ensure all tests pass; ask the user if questions arise
