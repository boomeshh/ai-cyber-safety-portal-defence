# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Anchor Tag Bypasses Authorization Header
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists
  - **Scoped PBT Approach**: Scope the property to the concrete failing case - any complaint with `evidence_name` truthy, clicked by an admin
  - Create `admin-frontend/src/pages/AdminDashboard.test.js`
  - Mock `fetch` globally and mock `getAuthHeaders` to return `{ Authorization: 'Bearer test-token' }`
  - Render `AdminDashboard` with a mocked complaint where `evidence_name` is set (e.g. `"photo.png"`)
  - Find the evidence element in the Evidence column and simulate a click
  - Assert that `fetch` was called with the evidence URL and an `Authorization` header
  - Assert that `window.open` was called with a `blob:` URL
  - Run test on UNFIXED code — `fetch` will NOT be called (anchor tag navigates directly), so assertions fail
  - **EXPECTED OUTCOME**: Test FAILS (this is correct - it proves the bug exists)
  - Document counterexample: "clicking the `<a>` evidence link does not invoke `fetch`; browser navigates directly without Authorization header"
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Non-Evidence-Link Behavior Unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - Observe on UNFIXED code: `handleStatusChange` calls `fetch` with `PUT /update-status/{id}` and auth headers
  - Observe on UNFIXED code: rows with no `evidence_name` render `'-'` with no clickable element
  - Observe on UNFIXED code: stat cards, audit trail, user table, and filter dropdowns render correctly
  - Write property-based tests in `AdminDashboard.test.js`:
    - For all status dropdown changes (any caseId, any valid status string): assert `fetch` is called with `PUT /update-status/{caseId}` and `Authorization` header
    - For all complaints where `evidence_name` is falsy: assert the Evidence cell renders `'-'` and no `<a>` or `<button>` is present
    - For any dashboard state: assert stat cards, audit trail section, and user table are present in the rendered output
  - Run tests on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.5_

- [x] 3. Fix evidence link in AdminDashboard.js

  - [x] 3.1 Implement the fix
    - Add `evidenceError` state: `const [evidenceError, setEvidenceError] = useState('');`
    - Add `openEvidence` async handler inside `AdminDashboard`:
      ```js
      const openEvidence = async (complaintId) => {
        try {
          setEvidenceError('');
          const res = await fetch(`${API}/complaints/${complaintId}/evidence`, { headers: getAuthHeaders() });
          if (!res.ok) throw new Error(`Request failed: ${res.status}`);
          const blob = await res.blob();
          const url = URL.createObjectURL(blob);
          window.open(url, '_blank');
          setTimeout(() => URL.revokeObjectURL(url), 10000);
        } catch (err) {
          setEvidenceError('Failed to open evidence: ' + err.message);
        }
      };
      ```
    - Replace the anchor tag in the Evidence column:
      - Remove: `<a href={`${API}/complaints/${item.id}/evidence`} target="_blank" rel="noreferrer" className="text-link">Open</a>`
      - Add: `<button onClick={() => openEvidence(item.id)} className="text-link" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>Open</button>`
    - Render `evidenceError` near the table when non-empty (e.g. `{evidenceError && <div style={{ color: '#fca5a5', marginTop: 8 }}>{evidenceError}</div>}`)
    - _Bug_Condition: isBugCondition(input) where input.component == 'AdminDashboard' AND input.complaintHasEvidence == true AND input.interactionType == 'click' AND input.requestMethod == 'browser-navigation'_
    - _Expected_Behavior: fetch() called with Authorization header → blob URL created → window.open(blobUrl, '_blank')_
    - _Preservation: handleStatusChange, dashboard layout, no-evidence rows, user frontend EvidencePreview all unchanged_
    - _Requirements: 2.1, 2.2, 2.3, 3.2, 3.5_

  - [x] 3.2 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Authenticated Evidence Fetch
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 asserts `fetch` is called with `Authorization` header and `window.open` is called with a `blob:` URL
    - Run `AdminDashboard.test.js` bug condition test on FIXED code
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2_

  - [x] 3.3 Verify preservation tests still pass
    - **Property 2: Preservation** - Non-Evidence-Link Behavior Unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2 on FIXED code
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm status updates, no-evidence rows, and dashboard layout all behave identically after fix

- [x] 4. Checkpoint - Ensure all tests pass
  - Run the full test suite: `cd admin-frontend && npm test -- --watchAll=false`
  - All tests in `AdminDashboard.test.js` must pass
  - No regressions in `App.test.js` or any other existing tests
  - Ask the user if any questions arise
