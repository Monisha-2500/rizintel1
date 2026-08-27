# RizIntel Phase 7 — Failure Experience & Recovery Matrix

This matrix documents RizIntel's graceful failure handling, error states, and recovery behaviors across potential runtime failure modes.

---

| # | Failure Mode | Backend Behavior | UI / Frontend Experience | Infinite Spinner? | Mock Fallback? | Actionable Guidance |
|---|---|---|---|---|---|---|
| 1 | **Backend API Offline** | Connection refused | Renders `BackendHealthBanner` (`"Backend Service Reconnecting..."`) | `NO` | `NO` in live scan-run context | Actionable banner informing user to verify backend FastAPI service on port 8000. |
| 2 | **Scanner Agent Offline** | Job remains `QUEUED` in queue | Displays `WAITING_FOR_INPUT` badge with *"Waiting for active scanner agent..."* | `NO` | `NO` | Prompt to start agent daemon `python -m scanner_agent.agent`. |
| 3 | **Nuclei Binary Unavailable** | Agent job claim detects missing capability | Displays agent capability warning `NUCLEI = UNAVAILABLE` | `NO` | `NO` | Install Nuclei or add binary to system PATH. |
| 4 | **Target App Unreachable** | Agent execution captures connection failure | Job transitions to `FAILED` with execution log detail | `NO` | `NO` | Displays *"Target host 127.0.0.1:8085 unreachable"* error badge. |
| 5 | **Scanner Execution Timeout** | Subprocess killed after timeout (default 300s) | Job transitions to `FAILED` with timeout reason | `NO` | `NO` | Inform user of scan timeout constraint. |
| 6 | **Malformed Scanner Report** | Ingestion validation returns HTTP 422 | Submission status `REJECTED`, scan run `FAILED` | `NO` | `NO` | Renders report schema validation error message. |
| 7 | **Pipeline Processing Crash** | Processing exception caught, transaction rolled back | Scan run status `FAILED` | `NO` | `NO` | Displays error banner with sanitized error message. |
| 8 | **SSE Stream Disconnect** | Server stream closes / network drops | `streamService` enters reconnect loop (`RECONNECTING`) | `NO` | `NO` | Status indicator updates to `RECONNECTING`. |
| 9 | **SSE Ticket Expired / Used** | Stream endpoint returns HTTP 401 / 403 | Connection rejected, requests new stream ticket | `NO` | `NO` | Obtains fresh short-lived ticket automatically. |
| 10 | **Zero Findings Discovered** | Pipeline completes successfully | Scan run reaches `COMPLETED`, Command Center shows 0 findings | `NO` | `NO` | Honest display: *"0 vulnerabilities detected on target."* |

---

## Recovery & Integrity Principles
- **No Silent Mock Fallback**: Scoped live scan runs (`?scan_run_id=...`) NEVER substitute mock findings when errors occur.
- **Audit Ledger Preservation**: Failed jobs and error events are permanently persisted in `scan_run_events` audit trail.
- **RBAC Scoped Retries**: Retries must be triggered by authorized users (`SECURITY_LEAD` or `ADMIN`) creating a new ScanRun.
