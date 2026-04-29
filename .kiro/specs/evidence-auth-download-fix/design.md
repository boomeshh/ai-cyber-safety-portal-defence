# Evidence Auth Download Fix - Bugfix Design

## Overview

The Admin Dashboard renders evidence links as plain `<a href="...">` anchor tags pointing directly to the protected backend endpoint `GET /complaints/{id}/evidence`. Browser navigation via anchor tags does not attach custom headers, so the `Authorization: Bearer <token>` header is never sent. The FastAPI backend correctly rejects the unauthenticated request with `{"detail":"Missing access token"}`.

The fix replaces the anchor tag with an `onClick` handler that calls `fetch()` with `getAuthHeaders()`, converts the response to a blob via `URL.createObjectURL()`, and opens it in a new tab. On failure, a clear error message is shown. No backend changes are needed. The user frontend (`MyComplaints.js`) already uses this pattern and is unaffected.

## Glossary

- **Bug_Condition (C)**: The condition that triggers the bug — an admin clicks an evidence link rendered as a plain `<a href>` anchor, causing an unauthenticated browser navigation request
- **Property (P)**: The desired behavior — evidence is fetched via `fetch()` with the `Authorization: Bearer <token>` header, and the resulting blob URL is opened in a new tab
- **Preservation**: All existing admin dashboard behavior (status updates, UI layout, table structure, audit trail, user list) and the user frontend evidence pattern that must remain unchanged by the fix
- **`openEvidence(complaintId)`**: The new async handler in `AdminDashboard.js` that replaces the anchor tag, calls `fetch()` with auth headers, and opens the blob URL
- **`getAuthHeaders()`**: Utility in `admin-frontend/src/utils/auth.js` that returns `{ Authorization: "Bearer <token>" }` from localStorage
- **`evidence_name`**: The field on a complaint object that, when truthy, indicates an evidence file is attached and the link should be rendered
- **blob URL**: A temporary `blob:` scheme URL created by `URL.createObjectURL()` that allows the browser to open file content without exposing the raw backend URL

## Bug Details

### Bug Condition

The bug manifests when an admin clicks the "Open" evidence link in the Complaint Queue table. The link is rendered as `<a href={`${API}/complaints/${item.id}/evidence`} target="_blank">`, which causes the browser to navigate directly to the backend URL. Browser-initiated navigation does not attach custom headers, so the `Authorization` header is absent and the backend returns a 401 error.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type EvidenceLinkInteraction
  OUTPUT: boolean

  RETURN input.component == 'AdminDashboard'
         AND input.complaintHasEvidence == true
         AND input.interactionType == 'click'
         AND input.requestMethod == 'browser-navigation'  // i.e. anchor tag href
         AND NOT authHeaderAttached(input.request)
END FUNCTION
```

### Examples

- Admin clicks "Open" for complaint RK-001 which has evidence → browser navigates to `http://127.0.0.1:8000/complaints/RK-001/evidence` with no `Authorization` header → backend returns `{"detail":"Missing access token"}` → admin sees a JSON error page instead of the file
- Admin clicks "Open" for complaint RK-002 with an image attachment → same unauthenticated navigation → 401 response → blank/error tab
- Admin clicks "Open" after token has expired → same anchor navigation → 401 response (expected failure, but error message should be shown clearly after fix)
- Complaint with no evidence (`evidence_name` is null/empty) → link is not rendered (`'-'` is shown) → no interaction possible → not a bug condition

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Mouse clicks on action buttons and status dropdowns in the admin dashboard must continue to work exactly as before
- The `handleStatusChange` function must continue to call `PUT /update-status/{caseId}` with `getAuthHeaders()` unchanged
- The admin dashboard UI, visual theme, table structure, stat cards, audit trail, and user registry sections must remain visually and functionally identical
- The user frontend `EvidencePreview` component in `MyComplaints.js` must continue to use its existing authenticated fetch + blob pattern without any modification
- The backend endpoints `GET /complaints/{id}/evidence` and `GET /complaints/{id}/evidence-meta` must remain protected and unchanged

**Scope:**
All interactions that do NOT involve clicking an evidence link in the admin Complaint Queue table should be completely unaffected by this fix. This includes:
- Status dropdown changes in the admin table
- All other admin dashboard data loading (`/admin/overview`)
- All user frontend complaint and evidence flows
- All backend request/response behavior

## Hypothesized Root Cause

Based on the bug description, the root cause is straightforward:

1. **Anchor Tag Navigation Bypasses Custom Headers**: The `<a href="...">` element causes the browser to issue a standard HTTP GET navigation request. The Fetch/XHR API is the only way to attach custom headers like `Authorization`; browser anchor navigation has no mechanism for this.
   - The anchor is rendered at: `<a href={`${API}/complaints/${item.id}/evidence`} target="_blank" rel="noreferrer" className="text-link">Open</a>`
   - This is the sole cause of the bug

2. **No Fallback or Error Handling**: The current implementation has no error handling for the evidence link — the admin simply sees a raw JSON error page in the new tab with no feedback in the dashboard UI.

3. **Pattern Inconsistency**: The user frontend (`MyComplaints.js`) correctly uses `fetch()` + blob + `URL.createObjectURL()` for the same backend endpoint. The admin frontend was not updated to use the same pattern when evidence links were added.

## Correctness Properties

Property 1: Bug Condition - Authenticated Evidence Fetch

_For any_ admin interaction where `isBugCondition` returns true (admin clicks an evidence link for a complaint with an attached file), the fixed `openEvidence` handler SHALL call `fetch()` with an `Authorization: Bearer <token>` header, receive the file content, create a blob URL via `URL.createObjectURL()`, and open that blob URL in a new tab — without performing any unauthenticated browser navigation.

**Validates: Requirements 2.1, 2.2**

Property 2: Preservation - Non-Evidence-Link Behavior

_For any_ admin dashboard interaction where `isBugCondition` does NOT hold (status updates, data loading, UI rendering, or any user frontend interaction), the fixed code SHALL produce exactly the same behavior as the original code, preserving all existing functionality including status update calls, dashboard layout, and the user frontend evidence pattern.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `admin-frontend/src/pages/AdminDashboard.js`

**Specific Changes**:

1. **Add `openEvidence` handler**: Define an async function inside `AdminDashboard` that accepts a `complaintId`, calls `fetch(`${API}/complaints/${complaintId}/evidence`, { headers: getAuthHeaders() })`, converts the response to a blob, creates a blob URL, and calls `window.open(url, '_blank')`.

2. **Add error state for evidence**: Add a piece of state (e.g. `evidenceError`) to hold an error message string when the fetch fails, and render it near the table or as an inline alert.

3. **Replace anchor tag with button/span**: In the Complaint Queue table's Evidence column, replace:
   ```jsx
   <a href={`${API}/complaints/${item.id}/evidence`} target="_blank" rel="noreferrer" className="text-link">Open</a>
   ```
   with:
   ```jsx
   <button onClick={() => openEvidence(item.id)} className="text-link" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>Open</button>
   ```

4. **Handle fetch errors**: In `openEvidence`, catch errors and set `evidenceError` state with a descriptive message (e.g. `"Failed to open evidence: " + err.message`).

5. **Revoke blob URL after use**: Optionally call `URL.revokeObjectURL(url)` after a short delay to avoid memory leaks, consistent with the user frontend pattern.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write tests that render the `AdminDashboard` component with a mocked complaint that has `evidence_name` set, then simulate a click on the evidence link and assert that `fetch()` is called with an `Authorization` header. Run these tests on the UNFIXED code to observe failures and understand the root cause.

**Test Cases**:
1. **Anchor Tag Test**: Render the unfixed component, find the `<a>` evidence link, assert that `fetch` is called with auth headers on click — will fail because the anchor navigates instead of calling fetch (will fail on unfixed code)
2. **Auth Header Test**: Simulate a click on the evidence link and assert `Authorization` header is present in the outgoing request — will fail because anchor navigation does not use fetch (will fail on unfixed code)
3. **New Tab Test**: Assert that `window.open` is called with a `blob:` URL — will fail because the anchor uses `target="_blank"` href navigation instead (will fail on unfixed code)
4. **Error Handling Test**: Mock fetch to return a 401 and assert an error message is displayed in the UI — may fail on unfixed code since there is no error handling

**Expected Counterexamples**:
- `fetch` is never called when the anchor tag is clicked — the browser handles navigation directly
- Possible causes: anchor tag href navigation, no fetch call, no blob URL creation

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  result := openEvidence_fixed(input.complaintId)
  ASSERT fetch called with Authorization header
  ASSERT window.open called with blob: URL
  ASSERT no unauthenticated navigation occurred
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT AdminDashboard_original(input) = AdminDashboard_fixed(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for status updates, data loading, and UI rendering, then write property-based tests capturing that behavior.

**Test Cases**:
1. **Status Update Preservation**: Observe that `handleStatusChange` calls `PUT /update-status/{id}` with auth headers on unfixed code, then write test to verify this continues after fix
2. **Dashboard Layout Preservation**: Observe that stat cards, audit trail, user table, and campaign graph render correctly on unfixed code, then write test to verify structure is unchanged after fix
3. **No-Evidence Row Preservation**: Observe that rows with no `evidence_name` render `'-'` and have no clickable link on unfixed code, then verify this continues after fix

### Unit Tests

- Test that `openEvidence` calls `fetch` with the correct URL and `Authorization` header
- Test that `openEvidence` calls `window.open` with a `blob:` URL on success
- Test that `openEvidence` sets error state with a descriptive message on fetch failure
- Test that rows with no `evidence_name` still render `'-'` and no button is shown

### Property-Based Tests

- Generate random complaint IDs and verify `openEvidence` always calls `fetch` with an `Authorization` header when `evidence_name` is truthy
- Generate random dashboard states and verify that status dropdowns, stat cards, and other UI elements render identically before and after the fix
- Generate random fetch failure scenarios (network error, 401, 404, 500) and verify an error message is always displayed

### Integration Tests

- Test full admin flow: login → load dashboard → click evidence link → verify file opens in new tab with correct content
- Test that clicking evidence after token expiry shows a clear error message rather than a JSON error page
- Test that status update dropdown continues to work correctly in the same session where evidence was opened
