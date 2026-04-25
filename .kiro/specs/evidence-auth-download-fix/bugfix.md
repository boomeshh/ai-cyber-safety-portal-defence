# Bugfix Requirements Document

## Introduction

Evidence download and preview is failing in the Admin Dashboard with the error `{"detail":"Missing access token"}`. The admin frontend opens the backend evidence URL directly in a new browser tab via an `<a href="...">` anchor tag. That navigation request does not include the `Authorization: Bearer <token>` header required by the protected FastAPI endpoint, causing the 401 rejection.

The user frontend (`MyComplaints.js`) already uses an authenticated `fetch` + blob + `URL.createObjectURL()` pattern and is not affected. The backend evidence endpoints are correct and must remain protected. Only the admin frontend evidence link needs to be fixed.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN an admin clicks the "Open" evidence link in the Complaint Queue table THEN the system opens the backend URL directly in a new tab without an Authorization header, causing the backend to return `{"detail":"Missing access token"}` and the evidence fails to load.

1.2 WHEN the browser navigates directly to `http://127.0.0.1:8000/complaints/{id}/evidence` via an anchor tag THEN the system does not attach the stored Bearer token from localStorage, so the request is unauthenticated.

### Expected Behavior (Correct)

2.1 WHEN an admin clicks the evidence "Open" link THEN the system SHALL fetch the evidence file using `fetch()` with the `Authorization: Bearer <token>` header, create a blob URL via `URL.createObjectURL()`, and open it in a new tab.

2.2 WHEN the authenticated fetch completes successfully THEN the system SHALL open the blob URL in a new tab so the admin can view or download the evidence file without exposing the raw backend URL.

2.3 WHEN the authenticated fetch fails (e.g. expired session, file not found) THEN the system SHALL display a clear error message to the admin instead of silently failing or showing a JSON error page.

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a regular user views evidence in the My Complaints page THEN the system SHALL CONTINUE TO fetch evidence with the Authorization header using the existing `EvidencePreview` component and blob URL pattern.

3.2 WHEN an admin updates a complaint status via the dropdown THEN the system SHALL CONTINUE TO call `PUT /update-status/{caseId}` with the Authorization header as currently implemented.

3.3 WHEN the backend receives a request to `GET /complaints/{id}/evidence` with a valid Bearer token THEN the system SHALL CONTINUE TO return the file with correct content type and filename headers.

3.4 WHEN the backend receives a request to `GET /complaints/{id}/evidence` without a token THEN the system SHALL CONTINUE TO return `{"detail":"Missing access token"}` with HTTP 401.

3.5 WHEN an admin views the dashboard UI THEN the system SHALL CONTINUE TO preserve the existing visual theme, layout, table structure, and all other dashboard functionality.
