# RizIntel — Team Cross-Module Technical Reference Card

A compact reference card enabling any team member to answer technical questions about any module (M1 through M8) during evaluator cross-examination.

---

## M1 Normalization Engine
- **What it does**: Normalizes native scanner outputs (OWASP ZAP, Nuclei, Wapiti) into Schema v1.0 canonical format.
- **Input**: Native scanner JSON or XML string payloads.
- **Output**: `M1NormalizedFinding[]` array.
- **Consumer**: M2 Deduplication Engine.
- **Algorithm**: Field transformation adapters (`M1NormalizedFindingAdapter`), CWE fallback resolution, fingerprint hashing (`compute_finding_fingerprint`).
- **Why chosen**: Eliminates schema heterogeneity across different scanners.
- **Missing data handling**: Applies default fallback mappings (e.g. `CWE-UNKNOWN`, title-derived severity).

---

## M2 Intelligent Deduplication
- **What it does**: Correlates overlapping findings across scanners on the same asset.
- **Input**: `M1NormalizedFinding[]` array.
- **Output**: `DeduplicatedFinding[]` array + `scanner_consensus` metrics.
- **Consumer**: M3 Confidence Engine.
- **Algorithm**: Hard-boundary asset partitioning $\to$ fingerprint matching $\to$ title/CWE similarity clustering (`Deduplicator`).
- **Why chosen**: Eliminates duplicate JIRA tickets while enforcing asset boundary safety ($FMR = 0.0\%$).
- **Missing data handling**: Falls back to endpoint path, CWE, and parameter similarity matching when CVE is absent.

---

## M3 Confidence & Noise Engine
- **What it does**: Evaluates signal fidelity and routes findings into `ACTIONABLE`, `NEEDS_REVIEW`, or `SUPPRESSED`.
- **Input**: `DeduplicatedFinding[]` array.
- **Output**: `ConfidenceFinding[]` array with confidence scores ($0.0–1.0$).
- **Consumer**: M4 Threat Intelligence Engine.
- **Algorithm**: 5-signal confidence scoring (consensus, scanner reliability, HTTP proof completeness, CWE clarity, noise rules).
- **Why chosen**: Decouples signal certainty from risk impact to prevent false suppressions ($FSR = 0.0\%$).
- **Missing data handling**: Default confidence score assigned based on scanner reliability.

---

## M4 Threat Intelligence Engine
- **What it does**: Enriches findings with real-world threat feeds (EPSS, CISA KEV, NVD CVSS).
- **Input**: `ConfidenceFinding[]` array.
- **Output**: `ThreatEnrichedFinding[]` array.
- **Consumer**: M5 Risk Scoring Engine.
- **Algorithm**: CVE lookup in threat cache (`mem4`) for EPSS exploit probability, KEV active exploitation status, and CVSS vector.
- **Why chosen**: Elevates vulnerabilities actively exploited in the wild over static CVSS scores.
- **Missing data handling**: Graceful fallback (`epss = None`, `kev = False`), downstream M5 computes score without runtime exceptions.

---

## M5 Dynamic Risk Engine
- **What it does**: Computes context-aware risk scores ($0–100$) and risk levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Input**: `ThreatEnrichedFinding[]` + `AssetContext` (environment, criticality, internet facing).
- **Output**: `RiskAssessedFinding[]` with score breakdown.
- **Consumer**: M6 Explainability Engine.
- **Algorithm**: Deterministic weighted scoring formula (`RiskEngine` in `mem5/src/risk_engine.py`): Severity (30%) + Threat (30%) + Asset Context (40%).
- **Why chosen**: Ensures mathematical risk scoring sovereignty where asset criticality drives prioritization.
- **Missing data handling**: `UNMAPPED` assets contribute `0` asset points; risk computed strictly from threat + severity.

---

## M6 Explainable Advisor
- **What it does**: Generates technical root-cause drivers and executive remediation rationales.
- **Input**: `RiskAssessedFinding[]`.
- **Output**: `ExplainedFinding[]` with dual-audience rationales.
- **Consumer**: M7 SLA Engine.
- **Algorithm**: Domain-specific rule matching (`M6ExplainabilityAdapter`) selecting technical drivers and remediation steps.
- **Why chosen**: Translates opaque numerical scores into actionable remediation playbooks for engineers and managers.
- **Missing data handling**: Renders standardized fallback remediation templates.

---

## M7 SLA & Ticketing Engine
- **What it does**: Assigns mandatory SLA remediation deadlines and ticket priorities.
- **Input**: `ExplainedFinding[]`.
- **Output**: `ActionableFinding[]` (`FindingSchema[]`).
- **Consumer**: M8 Command Center & Database Persistence.
- **Algorithm**: SLA matrix mapping risk score to deadline (Critical: 24h/P0, High: 7d/P1, Medium: 30d/P2, Low: 90d/P3).
- **Why chosen**: Enforces organizational SLA accountability and remediation tracking.
- **Missing data handling**: Default SLA assigned based on risk level.

---

## M8 Command Center & RizTrace
- **What it does**: Consolidates findings into executive dashboard views and renders 8-stage decision provenance graph.
- **Input**: Persisted `FindingSchema[]` from database.
- **Output**: Command Center UI, Finding360 Modal, RizTrace Lineage Graph.
- **Consumer**: AppSec Analysts, CISOs, Hackathon Evaluators.
- **Algorithm**: Scoped API queries (`?scan_run_id=...`), graph node-edge traversal (`adapters/m8_adapter.py`).
- **Why chosen**: Delivers complete visual decision auditability and scan-run scoped analytics.
- **Missing data handling**: Historical missing nodes render explicit `NOT_AVAILABLE` status badges.
