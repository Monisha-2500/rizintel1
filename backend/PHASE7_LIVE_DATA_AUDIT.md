# RizIntel Phase 7 — Live Data Integrity Audit

This audit evaluates all occurrences of mock data, test fixtures, fallback handlers, and timers across the frontend and backend codebase to guarantee that `LIVE_SCAN` mode **NEVER** silently substitutes mock vulnerability findings or fake pipeline progress.

---

## Audit Findings & Classification

| File Path | Line / Component | Purpose | LIVE Impact | Acceptable? | Action Required |
|---|---|---|---|---|---|
| `frontend/src/services/findingsService.js` | `fetchWithAuth()` fallback handler | Transitions frontend runtime status to `FALLBACK` on network error | **NONE in LIVE mode**. When operating in scoped scan run mode (`?scan_run_id=...`), live requests return 404 / error banner instead of mock findings. | `YES` | Verified. `LIVE_SCAN` mode displays truthful empty/error state. |
| `frontend/src/services/workspaceService.js` | `getRegisteredAssets()` | Fetches live assets for organization | **NONE**. Returns empty array `[]` on error. | `YES` | None. |
| `frontend/src/pages/ScanRunsPage.jsx` | Pipeline stepper state | Renders scan run stage progress | **NONE**. Stepper state is derived exclusively from persisted `scan_run_events` and real-time SSE stream. Zero fake timers. | `YES` | None. |
| `frontend/src/pages/CommandCenter.jsx` | `loadDashboard()` | Fetches dashboard summary | **NONE in LIVE mode**. When `scan_run_id` is present, queries backend live API exclusively. | `YES` | None. |
| `frontend/src/pages/Finding360.jsx` | `loadFindingDetails()` | Fetches 360 finding detail | **NONE**. Returns 404 error banner on invalid finding ID. | `YES` | None. |
| `frontend/src/pages/RizTracePage.jsx` | Provenance graph renderer | Renders decision tree | **NONE**. Renders live lineage; missing steps display `NOT_AVAILABLE`. | `YES` | None. |
| `backend/evaluation/datasets/` | `webgoat_scan.json`, `juiceshop_scan.json` | Phase 5 evaluation ground-truth datasets | **NONE**. Isolated inside `backend/evaluation/` package for evaluation runner. | `YES` | None. |
| `backend/mem2/data/sample_input.json` | Sample multi-scanner payload | Testing fixture for M1–M7 pipeline tests | **NONE**. Development test fixture only. | `YES` | None. |

---

## Live Data Integrity Guarantees
1. **Zero Silent Fallback**: Live scan run queries (`?scan_run_id=...&org_id=...`) strictly hit FastAPI backend API endpoints. If the backend fails or returns 404, an explicit error banner is rendered.
2. **Zero Fake Timers**: ScanRun lifecycle state transitions are driven 100% by persisted `scan_run_events` and SSE events.
3. **Transparent Data Origin**: UI displays `Data Origin: LIVE_SCAN` tag for live scan run findings.
