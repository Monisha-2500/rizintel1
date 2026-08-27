# RizIntel — One-Page Architecture Cheatsheet

A concise module-by-module technical reference mapping the complete data path from Scanner Execution to RizTrace Decision Provenance.

---

## Complete End-to-End Data Path

```
  Scanner Engine (Nuclei/ZAP/Wapiti)
     ↓
  Scanner Agent Daemon (`scanner_agent/agent.py`)
     ↓
  Scan Run Lifecycle (`services/scan_run_service.py`)
     ↓
  Raw Report Submission (`services/ingestion_service.py`)
     ↓
  M1 Normalization Engine (`adapters/m1_adapter.py`)
     ↓
  M2 Intelligent Deduplication (`mem2/src/deduplicator.py`)
     ↓
  M3 Confidence & Noise Engine (`mem3`)
     ↓
  M4 Threat Intelligence (`mem4`)
     ↓
  M5 Dynamic Risk Engine (`mem5/src/risk_engine.py`)
     ↓
  M6 Explainable Advisor (`mem6`)
     ↓
  M7 SLA & Ticketing Engine (`mem7`)
     ↓
  Persisted Event & Results Ledger (`database.py`)
     ↓
  Real-Time SSE Streaming (`services/stream_service.py`)
     ↓
  M8 Command Center Dashboard (`frontend/src/pages/CommandCenter.jsx`)
     ↓
  RizTrace Decision Provenance (`frontend/src/pages/RizTracePage.jsx`)
```

---

## Module-by-Module Reference Card

| Module | Input | Process | Output | Why It Exists |
|---|---|---|---|---|
| **1. Scanner Engine** | Target URL, Templates | Runs binary (`nuclei.exe`, ZAP, Wapiti) with `shell=False` | Native JSON/XML report | Generates raw security findings from target environment. |
| **2. Scanner Agent** | Server Job Queue | Polls API with `X-Scanner-Agent-Token`, claims job, runs scanner | Raw report posted to API | Unattended machine execution without human JWT credentials. |
| **3. Scan Run** | Org ID, Asset ID, Scanner list | Creates scan run, checks `authorization_status == 'AUTHORIZED'`, queues jobs | Queued ScanRun record | Orchestrates scan lifecycle (`WAITING_FOR_INPUT` $\to$ `COMPLETED`). |
| **4. Raw Submission** | Native scanner JSON/XML report | Validates payload schema, computes SHA-256 hash, stores on disk | Submission ID | Immutable persistence of raw scanner data. |
| **5. M1 Normalizer** | Native scanner report | Maps fields into Schema v1.0 canonical format, derives CWE/fingerprint | `M1NormalizedFinding[]` | Standardizes heterogeneous scanner outputs. |
| **6. M2 Deduplicator** | `M1NormalizedFinding[]` | Groups findings by asset, matches fingerprints, correlates duplicates | `DeduplicatedFinding[]` + consensus score | Eliminates duplicate tickets across multiple scanners. |
| **7. M3 Confidence** | `DeduplicatedFinding[]` | Evaluates 5 confidence signals, classifies noise | `ConfidenceFinding[]` (`ACTIONABLE` / `NEEDS_REVIEW` / `SUPPRESSED`) | Separates signal certainty from risk impact. |
| **8. M4 Threat Intel** | `ConfidenceFinding[]` | Enriches findings with EPSS, CISA KEV, and CVSS scores | `ThreatEnrichedFinding[]` | Adds real-world threat context. |
| **9. M5 Risk Engine** | `ThreatEnrichedFinding[]` + Asset Context | Applies deterministic risk scoring formula ($0–100$) | `RiskAssessedFinding[]` | Sole mathematical authority for risk prioritization. |
| **10. M6 Explainability** | `RiskAssessedFinding[]` | Generates dual-audience rationales and top risk drivers | `ExplainedFinding[]` | Translates technical scores into actionable remediation playbooks. |
| **11. M7 SLA Engine** | `ExplainedFinding[]` | Assigns SLA deadlines (24h–90d) and priorities (P0–P3) | `ActionableFinding[]` (`FindingSchema[]`) | Enforces remediation accountability. |
| **12. Persisted Ledger** | `FindingSchema[]` + Stage Events | Stores findings and stage logs in SQLite with WAL mode | Persisted DB tables | Immutable audit trail and query source. |
| **13. Real-Time SSE** | Pipeline stage events | Broadcasts events over SSE stream tickets with event replay | SSE Event stream | Live operational visualization across browser sessions. |
| **14. M8 Dashboard** | Persisted findings | Aggregates risk distribution, top risks, and SLA health | Scoped Command Center UI | Executive and analyst decision intelligence view. |
| **15. RizTrace** | Canonical finding ID | Queries lineage, builds 8-stage visual provenance graph | Interactive RizTrace graph | Full visual auditability of decision lineage. |
