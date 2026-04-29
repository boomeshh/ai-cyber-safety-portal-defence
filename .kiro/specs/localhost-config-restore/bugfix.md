# Bugfix Requirements Document

## Introduction

After configuring the project for Vercel/Render deployment, the full-stack Rakshak AI portal
(FastAPI backend + three React frontends) no longer runs correctly on localhost. The bug
manifests as frontend pages failing to reach the backend, CORS rejections, and broken
evidence open/download flows when running locally.

The fix scope covers: environment variable configuration, API base URL wiring, CORS
allowlist, authenticated evidence access, secret hygiene, and developer setup documentation.
No existing features are to be removed or rewritten.

---

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN a developer starts the project on localhost THEN the system fails to connect
    frontends to the backend because hardcoded production/Render/Vercel URLs override
    the environment-variable-based API base URL in one or more frontend files.

1.2 WHEN a frontend makes an API request to `http://localhost:8000` THEN the system
    returns a CORS error because the backend `allow_origins` list is missing one or more
    of the required localhost origins (`http://localhost:3000`, `http://localhost:3001`,
    `http://localhost:3002`, `http://127.0.0.1:3000`, `http://127.0.0.1:3001`,
    `http://127.0.0.1:3002`).

1.3 WHEN a user attempts to open or download evidence from the complaint detail view
    THEN the system fails with a missing/invalid token error because the evidence URL
    is used as a direct `<a href>` or `<img src>` link that does not carry the
    `Authorization: Bearer <token>` header.

1.4 WHEN a developer clones the repository and inspects `.env` files THEN the system
    exposes real API keys, SMTP credentials, or backend URLs because `.env` files
    containing secrets are committed to version control without a corresponding safe
    `.env.example` template.

1.5 WHEN a developer sets up the project for the first time THEN the system provides
    no documented run commands, port assignments, or environment setup steps, causing
    the developer to guess the correct startup sequence.

### Expected Behavior (Correct)

2.1 WHEN a developer starts the project on localhost THEN the system SHALL resolve all
    API calls through `process.env.REACT_APP_API_BASE_URL` (defaulting to
    `http://localhost:8000`) with no hardcoded production URLs present in any frontend
    source file.

2.2 WHEN a frontend running on any of the three localhost ports makes an API request
    THEN the system SHALL accept the request without a CORS error, because the backend
    `allow_origins` list SHALL include all six required localhost origins.

2.3 WHEN a user opens or downloads evidence THEN the system SHALL fetch the file via
    `fetch()` with an `Authorization: Bearer <token>` header and serve the result as
    a blob URL, so that protected endpoints are never accessed via a bare `href` or
    `src` attribute.

2.4 WHEN a developer inspects the repository THEN the system SHALL provide a safe
    `.env.example` file for each service (backend, user-frontend, admin-frontend,
    cert-frontend) that contains only placeholder values and comments, with no real
    secrets committed.

2.5 WHEN a developer sets up the project for the first time THEN the system SHALL
    provide a `LOCALHOST_SETUP.md` file at the repository root that documents the
    exact commands to install dependencies, configure `.env` files, and start each
    service on its designated port.

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a user submits a complaint with or without evidence THEN the system SHALL
    CONTINUE TO process the submission, run hybrid ML analysis, and return a complaint
    ID, risk level, threat type, and mitigation advice.

3.2 WHEN a user logs in with valid credentials THEN the system SHALL CONTINUE TO
    issue a session token, store it in `localStorage`, and redirect to the dashboard.

3.3 WHEN an admin logs in and views the complaint queue THEN the system SHALL CONTINUE
    TO display all complaints with filtering, status update controls, and evidence
    open functionality.

3.4 WHEN a CERT officer views the command center THEN the system SHALL CONTINUE TO
    display live analytics, heatmaps, campaign clusters, and the incident feed with
    auto-refresh every 5 seconds.

3.5 WHEN the backend receives a high or critical risk complaint THEN the system SHALL
    CONTINUE TO send an email alert via SMTP if `EMAIL_ENABLED=true` and valid
    credentials are configured.

3.6 WHEN a user views their complaint list THEN the system SHALL CONTINUE TO display
    evidence previews (image, PDF, audio, video) and a working download button using
    the authenticated blob-URL approach already implemented in `MyComplaints.js`.

3.7 WHEN the project is deployed to a production environment THEN the system SHALL
    CONTINUE TO function correctly by setting `REACT_APP_API_BASE_URL` to the
    production backend URL in each frontend's deployment environment variables.
