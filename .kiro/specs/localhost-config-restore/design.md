# localhost-config-restore Bugfix Design

## Overview

The repository has real SMTP credentials committed in `backend/.env`, `.env` files are not
excluded from git in the root, admin-frontend, and cert-frontend gitignores, and there is no
`LOCALHOST_SETUP.md` to guide developers. This design covers the three targeted fixes:
sanitizing `backend/.env`, patching the missing `.gitignore` entries, and creating setup
documentation. All other configuration (CORS, API base URLs, evidence download, auth
utilities, frontend `.env` files) is already correct and must not be touched.

---

## Glossary

- **Bug_Condition (C)**: The set of conditions that constitute the defect — real secrets
  committed to `backend/.env`, `.env` files unprotected by gitignore in three locations,
  and no `LOCALHOST_SETUP.md` present.
- **Property (P)**: The desired state after the fix — no real credentials in version
  control, all `.env` files excluded by gitignore, and a working setup guide at the repo
  root.
- **Preservation**: All existing runtime behavior (CORS, API routing, ML pipeline, auth,
  evidence download) that must remain completely unchanged by this fix.
- **backend/.env**: The backend environment file that currently contains live SMTP
  credentials and must be sanitized to placeholder values.
- **SMTP credentials**: `SMTP_USER`, `SMTP_PASSWORD`, and `ALERT_TO` values in
  `backend/.env` that are currently real and must be replaced with safe placeholders.
- **gitignore gap**: The absence of `.env` exclusion rules in `.gitignore` (root),
  `admin-frontend/.gitignore`, and `cert-frontend/.gitignore`.

---

## Bug Details

### Bug Condition

The bug manifests across three distinct sub-conditions, all present simultaneously in the
repository:

1. `backend/.env` contains live SMTP credentials (`SMTP_USER`, `SMTP_PASSWORD`, `ALERT_TO`)
   and has `EMAIL_ENABLED=true`, meaning real secrets are committed and active.
2. The root `.gitignore`, `admin-frontend/.gitignore`, and `cert-frontend/.gitignore` do
   not exclude `.env`, so future secret commits to those locations are unprotected.
3. No `LOCALHOST_SETUP.md` exists at the repo root, leaving developers without setup
   instructions.

**Formal Specification:**
```
FUNCTION isBugCondition(repo_state)
  INPUT: repo_state — snapshot of the repository file contents and gitignore rules
  OUTPUT: boolean

  has_live_credentials :=
    repo_state.backend_env.SMTP_USER != placeholder
    AND repo_state.backend_env.SMTP_PASSWORD != placeholder
    AND repo_state.backend_env.EMAIL_ENABLED == "true"

  has_gitignore_gap :=
    NOT repo_state.root_gitignore.excludes(".env")
    OR NOT repo_state.admin_gitignore.excludes(".env")
    OR NOT repo_state.cert_gitignore.excludes(".env")

  missing_setup_doc :=
    NOT repo_state.file_exists("LOCALHOST_SETUP.md")

  RETURN has_live_credentials OR has_gitignore_gap OR missing_setup_doc
END FUNCTION
```

### Examples

- `backend/.env` with `SMTP_USER=boomesh.public@gmail.com` → bug condition holds; a git
  push would expose a real email address and app password publicly.
- Root `.gitignore` without `**/.env` → bug condition holds; a developer who creates
  `backend/.env` with new credentials could accidentally commit them.
- `admin-frontend/.gitignore` without `.env` → bug condition holds; `admin-frontend/.env`
  is not protected from accidental commits.
- `LOCALHOST_SETUP.md` absent → bug condition holds; a new developer cloning the repo has
  no documented path to run the project locally.
- After fix: `backend/.env` has `SMTP_USER=your-email@gmail.com`, `EMAIL_ENABLED=false`,
  all three gitignores exclude `.env`, and `LOCALHOST_SETUP.md` exists → bug condition
  does NOT hold.

---

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- All runtime API behavior (complaint submission, ML analysis, auth, CERT dashboard,
  admin dashboard) must continue to work exactly as before.
- `backend/main.py` CORS configuration must not be modified.
- All frontend source files must not be modified.
- All frontend `.env` and `.env.example` files must not be modified.
- `backend/.env.example` must not be modified.
- The backend application must still load and start without errors after `backend/.env`
  is sanitized (placeholder values keep the structure valid; `EMAIL_ENABLED=false`
  disables SMTP so no real send is attempted).
- Email alerting continues to work correctly when a developer supplies real credentials
  and sets `EMAIL_ENABLED=true` in their own local `.env`.

**Scope:**
All inputs that do NOT involve the three bug sub-conditions above are completely unaffected.
This includes:
- Any HTTP request to the backend API
- Any frontend page load or user interaction
- Any ML inference or threat analysis
- Any git operation on files other than the four gitignore files and `backend/.env`

---

## Hypothesized Root Cause

1. **Credentials committed directly**: `backend/.env` was created with real SMTP
   credentials during initial deployment setup and committed without being added to
   `.gitignore` first. The root `.gitignore` never included a `.env` pattern for the
   backend directory.

2. **Incomplete gitignore coverage**: The frontend gitignores were generated from the
   standard Create React App template, which excludes `.env.local`, `.env.*.local` but
   NOT the plain `.env` file. The root `.gitignore` was written manually and omitted
   `.env` entries entirely.

3. **No setup documentation**: `LOCALHOST_SETUP.md` was never created — the project went
   straight from local development to deployment without capturing the local run
   instructions.

---

## Correctness Properties

Property 1: Bug Condition — No Live Secrets in Version Control

_For any_ repository state where `isBugCondition` returns true, the fixed repository
SHALL have `backend/.env` contain only placeholder values (no real email addresses,
passwords, or API keys), `EMAIL_ENABLED` set to `false`, and all three gitignore files
SHALL exclude `.env` so that future `.env` files cannot be accidentally committed.

**Validates: Requirements 2.4**

Property 2: Preservation — Runtime Behavior Unchanged

_For any_ input where the bug condition does NOT hold (i.e., the fix has been applied),
the fixed repository SHALL produce exactly the same runtime behavior as the original
repository for all API requests, frontend interactions, ML inference, auth flows, and
evidence handling — because no source code, CORS config, or frontend environment files
are modified by this fix.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**

---

## Fix Implementation

### Changes Required

**File 1: `backend/.env`**

Replace live credentials with safe placeholders and disable email sending:

```
EMAIL_ENABLED=false
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_TO=admin@example.com
VT_ENABLED=false
VT_API_KEY=
```

Specific changes:
- `EMAIL_ENABLED`: `true` → `false`
- `SMTP_USER`: `boomesh.public@gmail.com` → `your-email@gmail.com`
- `SMTP_PASSWORD`: `ayqr uqen oyus qdal` → `your-app-password`
- `ALERT_TO`: `rakshakai.admin@gmail.com` → `admin@example.com`

---

**File 2: `.gitignore`** (root)

Add `.env` exclusion entries:

```
# Environment files
**/.env
backend/.env
```

---

**File 3: `admin-frontend/.gitignore`**

Add `.env` after the existing `.DS_Store` line:

```
.env
```

---

**File 4: `cert-frontend/.gitignore`**

Add `.env` after the existing `.DS_Store` line:

```
.env
```

---

**File 5: `LOCALHOST_SETUP.md`** (new file at repo root)

Create a setup guide covering:
- Prerequisites
- Backend setup (venv, pip install, uvicorn)
- Three frontend setups (npm install + npm start, one per frontend)
- Port assignments table
- Default demo credentials
- `.env` copy instruction

---

## Testing Strategy

### Validation Approach

Two-phase approach: first confirm the bug conditions exist on the unfixed repo, then verify
each fix resolves its sub-condition without affecting runtime behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface concrete evidence of each sub-condition BEFORE applying the fix.

**Test Plan**: Inspect file contents and gitignore rules directly to confirm the bug
conditions hold on the current (unfixed) state.

**Test Cases**:
1. **Credentials check**: Read `backend/.env` and assert `SMTP_USER` contains a real
   email address and `EMAIL_ENABLED=true` (will confirm bug on unfixed code).
2. **Root gitignore gap**: Read `.gitignore` and assert it does NOT contain `.env` or
   `**/.env` (will confirm bug on unfixed code).
3. **Admin gitignore gap**: Read `admin-frontend/.gitignore` and assert it does NOT
   contain a bare `.env` entry (will confirm bug on unfixed code).
4. **Cert gitignore gap**: Read `cert-frontend/.gitignore` and assert it does NOT
   contain a bare `.env` entry (will confirm bug on unfixed code).
5. **Missing setup doc**: Assert `LOCALHOST_SETUP.md` does not exist at repo root
   (will confirm bug on unfixed code).

**Expected Counterexamples**:
- `backend/.env` contains `boomesh.public@gmail.com` and `ayqr uqen oyus qdal`
- `.gitignore` has no `.env` pattern
- `admin-frontend/.gitignore` and `cert-frontend/.gitignore` have no bare `.env` entry
- `LOCALHOST_SETUP.md` is absent

### Fix Checking

**Goal**: Verify that after the fix, `isBugCondition` returns false for all three
sub-conditions.

**Pseudocode:**
```
FOR ALL sub_condition IN [credentials, gitignore_gap, missing_setup_doc] DO
  result := check_fixed_repo(sub_condition)
  ASSERT isBugCondition(result) == false
END FOR
```

**Specific assertions after fix:**
- `backend/.env` SMTP_USER equals `your-email@gmail.com` (placeholder)
- `backend/.env` EMAIL_ENABLED equals `false`
- `.gitignore` contains `**/.env` or `backend/.env`
- `admin-frontend/.gitignore` contains `.env`
- `cert-frontend/.gitignore` contains `.env`
- `LOCALHOST_SETUP.md` exists and contains backend + frontend setup sections

### Preservation Checking

**Goal**: Verify that no runtime behavior changes after the fix.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT original_runtime_behavior(input) == fixed_runtime_behavior(input)
END FOR
```

**Test Plan**: Since no source code is modified, preservation is verified by confirming
the unchanged files are identical before and after the fix.

**Test Cases**:
1. **CORS preservation**: `backend/main.py` is byte-for-byte identical after fix.
2. **Frontend source preservation**: No files under `*/src/` are modified.
3. **Frontend env preservation**: All `*/.env` and `*/.env.example` files (except
   `backend/.env`) are identical after fix.
4. **Backend startup**: Backend starts without errors with the sanitized `.env`
   (EMAIL_ENABLED=false means no SMTP connection is attempted at startup).

### Unit Tests

- Assert `backend/.env` contains no real email addresses or passwords after sanitization.
- Assert each of the four gitignore files contains the required `.env` exclusion pattern.
- Assert `LOCALHOST_SETUP.md` exists and contains required sections (Prerequisites,
  Backend Setup, Frontend Setup, port table, demo credentials).

### Property-Based Tests

- For any developer environment where `backend/.env` is copied from the sanitized version,
  the backend SHALL start without attempting an SMTP connection (`EMAIL_ENABLED=false`).
- For any file matching `**/.env` in the repo, the fixed gitignore rules SHALL exclude it
  from tracking (verified by `git check-ignore` returning a match).
- For any new `.env` file created in `admin-frontend/` or `cert-frontend/`, the updated
  gitignore SHALL prevent it from being staged.

### Integration Tests

- Clone the repo fresh, follow `LOCALHOST_SETUP.md` instructions, and verify all four
  services start on their designated ports (8000, 3000, 3001, 3002).
- Verify that `git status` shows no `.env` files as untracked or staged after the fix.
- Verify that a developer supplying real credentials in `backend/.env` and setting
  `EMAIL_ENABLED=true` can send a test alert without any code changes.
