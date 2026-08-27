# RizIntel 5–7 Minute Evaluator Demo Script & Presentation Guide

This script provides a structured 5–7 minute evaluator presentation guide and explicit backup narration for demonstrating the RizIntel Security Decision Intelligence Platform.

---

## 1. Timeline & Presentation Agenda

| Time | Segment | Core Action | Screen / Endpoint |
|---|---|---|---|
| **0:00 – 0:30** | **Problem Statement** | Present multi-scanner alert fatigue, duplicated signals, and unprioritized vulnerability queues. | Login Portal (`/login`) |
| **0:30 – 1:00** | **Workspace & Org Scope** | Log in as Security Lead (`lead@rizintel.demo`), inspect active organization (`ORG-DEMO-001`). | Workspace (`/workspace`) |
| **1:00 – 1:30** | **Asset Authorization** | Inspect registered target asset `ASSET-WEBGOAT-001` (`http://127.0.0.1:8085`, `AUTHORIZED`). | Asset Registry (`/asset-registry`) |
| **1:30 – 2:30** | **Create Live Scan Run** | Create a new ScanRun selecting `NUCLEI` scanner agent for authorized OWASP WebGoat target. | Scan Runs Queue (`/scan-runs`) |
| **2:30 – 3:15** | **Live Scanner & SSE** | Observe atomic job claim, `nuclei.exe` execution, auto-report upload, and 17 real-time SSE stage events. | Live ScanRun Stepper (`/scan-runs`) |
| **3:15 – 4:15** | **Command Center** | Click **Open Command Center** (`?scan_run_id=...&org_id=...`) to inspect scan-run scoped risk scores. | Command Center (`/command-center?scan_run_id=...`) |
| **4:15 – 5:00** | **Finding360 Inspection** | Open 360-degree finding modal to inspect M3 confidence, M4 threat intel, M5 risk score, and M6 explanation. | Finding360 Modal (`/findings/...`) |
| **5:00 – 5:45** | **RizTrace Provenance** | Click **RizTrace** to inspect the 8-stage decision provenance graph rendering scanner source lineage. | RizTrace Graph (`/provenance?scan_run_id=...`) |
| **5:45 – 6:30** | **Measurable Evaluation** | Present Phase 5 ground-truth evaluation metrics (F1 = 1.0, FSR = 0.0, FMR = 0.0 over 14 real signals). | Evaluation Report (`PHASE5_EVALUATION_REPORT.md`) |
| **6:30 – 7:00** | **Closing & Architecture** | Highlight HMAC-SHA256 JWT, machine agent token hashing, zero-trust target authorization, and `shell=False` execution. | Architecture Documentation |

---

## 2. Backup Narration Guidance (Zero Findings / Extended Scanner Execution)

If the live scanner execution returns zero findings or requires longer than the presentation window:
1. Navigate directly to a previously completed verified live scan run: `http://127.0.0.1:5173/scan-runs`.
2. Select the completed `LIVE_SCAN` run (`RUN-E2E-CLOSURE-7F89`) to demonstrate Command Center, Finding360, and RizTrace provenance.
3. **Truthful Narration**:
   > *"During live scanner execution, Nuclei scanned the target endpoint. For full visual demonstration of our decision intelligence pipeline, we are displaying run `RUN-E2E-CLOSURE-7F89`, a previously verified LIVE_SCAN execution against OWASP WebGoat on port 8085."*
