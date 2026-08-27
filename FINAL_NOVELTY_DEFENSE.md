# RizIntel — Novelty & Architectural Differentiation Defense

This document provides a defensible breakdown of RizIntel's genuine novelty, engineering differentiators, and UX innovations for hackathon evaluation.

> [!NOTE]
> **WHAT IS NOT CLAIMED AS NOVEL**: RizIntel does **NOT** claim standard industry building blocks (JWT, SSE, SQLite, FastAPI, React, Pydantic, or SHA-256 hashing) as proprietary novelties. Standard technologies are used purely as robust infrastructure.

---

## 1. Core Platform Novelty

### A. RizTrace — 8-Stage Visual Decision Provenance
- **Innovation**: RizTrace is an interactive decision lineage graph that visually traces any vulnerability finding back to its raw scanner source signal through 8 explicit pipeline stages (Raw Signal $\to$ M1 Normalization $\to$ M2 Deduplication $\to$ M3 Confidence $\to$ M4 Threat Intel $\to$ M5 Risk Score $\to$ M6 Explainability $\to$ M7 SLA).
- **Value**: Eliminates the "black box" problem of automated risk scoring. Analysts can click any decision node to inspect raw payload snippets, deduplication cluster logic, threat feed scores, and risk driver breakdowns.

### B. Multi-Scanner Consensus & Remediation-Instance Deduplication
- **Innovation**: Correlates overlapping findings from heterogeneous scanners (ZAP, Nuclei, Wapiti) while enforcing strict hard asset boundaries.
- **Value**: Eliminates duplicate ticketing across scanners without over-merging distinct vulnerabilities on different hosts or ports.

---

## 2. Engineering Differentiators

### A. Separation of Signal Confidence from Risk Impact (M3 vs M5)
- **Differentiator**: Traditional VM systems conflate scanner confidence with vulnerability severity. RizIntel decouples confidence (is the signal real?) from risk impact (how much damage could it cause?).
- **Value**: Prevents false suppression of critical vulnerabilities and eliminates low-confidence scanner noise before risk calculation.

### B. Server-Authoritative Zero-Trust Target Resolution for Machine Agents
- **Differentiator**: Machine scanner agents claim jobs using salted SHA-256 tokens and receive target URLs resolved server-side from assets matching `authorization_status == 'AUTHORIZED'`.
- **Value**: Prevents scanner agents from executing unauthorized scans against external or arbitrary IP addresses.

### C. Safe Subprocess Execution with Explicit Argument Arrays
- **Differentiator**: All scanner connectors (`NucleiConnector`, `ZapConnector`, `WapitiConnector`) invoke binaries using `shell=False` and explicit argument arrays.
- **Value**: Guarantees zero shell command injection vulnerabilities during automated scanner execution.

---

## 3. UX Differentiators

### A. Scoped Command Center & Finding360 Modal
- **Differentiator**: Command Center dashboard dynamically scopes to a specific `scan_run_id`, while Finding360 provides a consolidated 360-degree view of asset context, threat intelligence, risk breakdown, and remediation playbooks.

### B. Live Scan Operations Visualizer
- **Differentiator**: Real-time visualization of scanner agent cards, job claim lifecycle, and pipeline stage progress streamed over SSE with single-use tickets and event replay.
