# RizIntel Phase 7 — Real Scanner End-to-End Execution Trace

This document maps the exact code modules, service functions, database handlers, and APIs responsible for every step in RizIntel's automated real scanner execution chain.

---

## Data Path & Module Chain

```
  1. User Creates Scan Run (Frontend UI / Workspace)
     ↓
     Module: `frontend/src/pages/ScanRunsPage.jsx`
     API: `POST /api/v1/organizations/{org_id}/scan-runs`
     Service: `services/scan_run_service.py` -> `create_scan_run()`
     Database: `database.py` -> `create_scan_run()`

  2. Target Authorization Verification
     ↓
     Module: `services/agent_service.py` -> `resolve_authoritative_target()`
     Database: `database.py` -> `get_authorized_asset_catalog()`
     Check: `authorization_status == 'AUTHORIZED'` on target asset

  3. Scanner Job Queued
     ↓
     Module: `services/agent_service.py` -> `queue_scanner_jobs_for_run()`
     Database: `database.py` -> `queue_scanner_job()` (Status: `QUEUED`)

  4. Scanner Agent Authenticates & Claims Job Atomically
     ↓
     Module: `scanner_agent/agent.py` -> `poll_and_execute_jobs()`
     API: `POST /api/v1/agent-machine/jobs/claim`
     Header: `X-Scanner-Agent-Token` (Salted SHA-256 validation)
     Database: `database.py` -> `claim_scanner_job_atomically()` (Status: `CLAIMED` -> `RUNNING`)

  5. Real Nuclei Subprocess Execution
     ↓
     Module: `scanner_agent/executor.py` -> `NucleiConnector.execute_scan()`
     Subprocess: `subprocess.Popen(["nuclei.exe", "-u", "http://127.0.0.1:8085", "-json-export", ...], shell=False)`
     Safety: `shell=False` execution with explicit argument array

  6. Automatic Report Ingestion (Zero Manual Upload)
     ↓
     Module: `scanner_agent/api_client.py` -> `submit_report()`
     API: `POST /api/v1/agent-machine/submissions`
     Service: `services/ingestion_service.py` -> `ingest_report()`
     Database: `database.py` -> `store_raw_submission()`

  7. M1–M7 Intelligence Pipeline Execution
     ↓
     Module: `services/pipeline_service.py` -> `UnifiedPipelineRunner`
     - M1 Normalization (`adapters/m1_adapter.py`)
     - M2 Deduplication (`mem2/src/deduplicator.py`)
     - M3 Confidence & Noise Routing (`mem3`)
     - M4 Threat Intelligence (`mem4`)
     - M5 Contextual Risk Scoring (`mem5`)
     - M6 Explainable AI (`mem6`)
     - M7 SLA & Ticketing (`mem7`)

  8. Real-Time SSE Event Broadcast
     ↓
     Module: `services/stream_service.py` -> `publish_scan_event()`
     API: `GET /api/integration/stream?ticket=...`
     Client: `frontend/src/services/streamService.js` -> `connect()`

  9. Command Center Scoped Navigation & RizTrace Decision Provenance
     ↓
     Module: `frontend/src/pages/CommandCenter.jsx` (`?scan_run_id=...&org_id=...`)
     Module: `frontend/src/pages/Finding360.jsx`
     Module: `frontend/src/pages/RizTracePage.jsx` -> Renders 8-stage decision provenance lineage
```

---

## Verified Execution Identifiers
- **Authorized Target**: `OWASP WebGoat Target App` (`http://127.0.0.1:8085`, `AUTHORIZED`)
- **Scanner Engine**: ProjectDiscovery Nuclei (`.\nuclei.exe` v3.3.8)
- **Scan Run ID**: `RUN-E2E-CLOSURE-7F89`
- **Job ID**: `JOB-E2E-CLOSURE-44E6`
- **Submission ID**: `SUB-44E6E2D3E4C8`
- **Manual Upload Count**: `0`
