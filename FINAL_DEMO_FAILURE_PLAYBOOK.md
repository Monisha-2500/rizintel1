# RizIntel — Final Demo Failure Playbook & Recovery Guide

This playbook details exact recovery procedures, presenter scripts, and verified backup evidence for handling potential runtime failures during the Cognizant NPN Cybersecurity Hackathon demonstration.

> [!IMPORTANT]
> **TRUTHFUL RECOVERY PRINCIPLE**: Never fabricate runtime results or substitute unlabelled mock data during live scanning. Follow exact recovery steps and provide transparent, evaluator-safe backup narration.

---

## Failure Recovery Scenarios

### 1. Target App Unreachable (OWASP WebGoat Unavailable)
- **SYMPTOM**: Scan run fails or job log displays `target host 127.0.0.1:8085 unreachable`.
- **CAUSE**: WebGoat process `target_app.py` is not running on port 8085.
- **IMMEDIATE RECOVERY**:
  1. Open terminal in `backend/` directory.
  2. Run command: `python target_app.py`
  3. Re-run preflight check: `python -m scripts.demo_preflight`
- **WHAT PRESENTER SHOULD SAY**: *"The local target application environment on port 8085 was disconnected. I have restarted target_app.py and our preflight check verifies target reachability."*
- **BACKUP EVIDENCE TO SHOW**: Previously verified live scan run `RUN-E2E-CLOSURE-7F89` in Scan Runs history (`/scan-runs`).

---

### 2. Nuclei Binary Unavailable
- **SYMPTOM**: Scanner agent job claim returns capability error `NUCLEI = UNAVAILABLE`.
- **CAUSE**: `nuclei.exe` binary is missing from system PATH or `backend/` root directory.
- **IMMEDIATE RECOVERY**:
  1. Verify executable exists in `backend/nuclei.exe`.
  2. Run `.\nuclei.exe -version` in `backend/`.
- **WHAT PRESENTER SHOULD SAY**: *"The scanner agent requires the Nuclei executable binary. I am pointing the agent to backend/nuclei.exe v3.3.8."*
- **BACKUP EVIDENCE TO SHOW**: `PHASE4_E2E_PROOF.md` and `evidence/02_real_scanner_execution.md`.

---

### 3. Scanner Agent Offline
- **SYMPTOM**: Created scan run remains stuck in status `WAITING_FOR_INPUT` / `QUEUED`.
- **CAUSE**: Machine scanner agent process is not active.
- **IMMEDIATE RECOVERY**:
  1. Open terminal in `backend/` directory.
  2. Run command: `python -m scanner_agent.agent`
  3. Observe agent authentication and atomic job claim.
- **WHAT PRESENTER SHOULD SAY**: *"The scan job is queued waiting for an active machine agent. I am launching our authorized scanner agent daemon, which will claim the job using its salted SHA-256 machine token."*
- **BACKUP EVIDENCE TO SHOW**: `/scanner-agents` page showing active agent status.

---

### 4. Scanner Returns Zero Findings
- **SYMPTOM**: Scan run reaches status `COMPLETED` with 0 raw findings and 0 actionable findings.
- **CAUSE**: Target application endpoint returned clean responses without triggering vulnerabilities.
- **IMMEDIATE RECOVERY**:
  1. Keep current scan run as clean baseline proof.
  2. Navigate to completed scan run `RUN-E2E-CLOSURE-7F89` in Scan Runs history (`/scan-runs`).
- **WHAT PRESENTER SHOULD SAY**: *"The real scanner executed successfully against the target endpoint and verified 0 active vulnerabilities. For full visual inspection of our pipeline decision intelligence, we open completed run `RUN-E2E-CLOSURE-7F89`."*
- **BACKUP EVIDENCE TO SHOW**: Scoped Command Center for `RUN-E2E-CLOSURE-7F89`.

---

### 5. Backend Service Unavailable
- **SYMPTOM**: UI displays red top header banner `"Backend Service Reconnecting..."` and HTTP 500 / ECONNREFUSED errors in console.
- **CAUSE**: FastAPI backend process on port 8000 stopped or crashed.
- **IMMEDIATE RECOVERY**:
  1. Open terminal in `backend/` directory.
  2. Run command: `python main.py`
  3. Verify health endpoint: `GET http://127.0.0.1:8000/health`
- **WHAT PRESENTER SHOULD SAY**: *"The backend API service is restarting. RizIntel's frontend gracefully detects backend connectivity loss and displays a reconnecting state without crashing."*
- **BACKUP EVIDENCE TO SHOW**: `BackendHealthBanner.jsx` component state and `/health` JSON payload.

---

### 6. SSE Stream Disconnect
- **SYMPTOM**: Live Scan Visualizer status badge changes to `RECONNECTING` or stage events freeze.
- **CAUSE**: Browser SSE network socket dropped or stream ticket expired (60s lifetime).
- **IMMEDIATE RECOVERY**:
  1. Frontend `streamService.js` automatically requests a new stream ticket and reconnects using `Last-Event-ID`.
  2. If manual action required, click **Refresh Stream** button on Scan Runs page.
- **WHAT PRESENTER SHOULD SAY**: *"Our real-time SSE stream automatically reconnects and uses event replay via Last-Event-ID headers to guarantee zero missed pipeline stage updates."*
- **BACKUP EVIDENCE TO SHOW**: `tests/test_phase3_realtime_stream.py` SSE replay test results.

---

### 7. Scan Run Takes Too Long
- **SYMPTOM**: Nuclei scanner execution takes longer than expected (> 45s).
- **CAUSE**: Extensive target endpoint crawler phase.
- **IMMEDIATE RECOVERY**:
  1. Leave background scan run running in tab.
  2. Open second tab navigating directly to `/command-center?scan_run_id=RUN-E2E-CLOSURE-7F89&org_id=ORG-DEMO-001`.
- **WHAT PRESENTER SHOULD SAY**: *"The live scanner is executing in the background. While Nuclei completes its deep crawl, let us inspect the completed decision intelligence results for run RUN-E2E-CLOSURE-7F89."*
- **BACKUP EVIDENCE TO SHOW**: Command Center scoped view for `RUN-E2E-CLOSURE-7F89`.

---

### 8. Unexpected Frontend Refresh
- **SYMPTOM**: Browser window reloads or user accidentally hits F5.
- **CAUSE**: Page refresh.
- **IMMEDIATE RECOVERY**:
  1. React Router restores state from URL search params (`?scan_run_id=...&org_id=...`).
  2. Auth session is maintained via `localStorage` JWT token.
- **WHAT PRESENTER SHOULD SAY**: *"RizIntel's state is URL-persisted and session-restored. Refreshing the browser preserves org context and scan-run scoping seamlessly."*
- **BACKUP EVIDENCE TO SHOW**: Restored Command Center dashboard.

---

### 9. Authentication / Session Expiration
- **SYMPTOM**: API returns HTTP 401 Unauthorized or redirects to `/login`.
- **CAUSE**: JWT access token expired.
- **IMMEDIATE RECOVERY**:
  1. On `/login` page, select demo user dropdown `usr-lead-003 (Security Lead)`.
  2. Click **Login to Workspace** button.
- **WHAT PRESENTER SHOULD SAY**: *"The JWT authentication session expired. I am re-authenticating as Security Lead usr-lead-003 with HMAC-SHA256 token verification."*
- **BACKUP EVIDENCE TO SHOW**: `/workspace` page showing restored Security Lead privileges.
