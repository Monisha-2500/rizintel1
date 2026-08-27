# RizIntel — Final Hackathon Technical Submission Report

## 1. Problem Statement
Modern Application Security (AppSec) teams rely on heterogeneous vulnerability scanners (OWASP ZAP, ProjectDiscovery Nuclei, Wapiti, SonarQube, Snyk). In multi-scanner environments, security teams face severe **alert fatigue**, with up to 70% duplicate or low-priority alerts. Security analysts spend valuable hours manually cross-referencing findings across disparate dashboards.

---

## 2. Existing Approaches & Gaps
Traditional Vulnerability Management (VM) tools aggregate scanner findings into static tables without intelligent correlation:
- **No Cross-Scanner Deduplication**: The same SQL injection on an endpoint reported by ZAP and Nuclei creates two separate tickets.
- **Uncontextualized Scoring**: Standard CVSS scores ignore asset criticality, data sensitivity, and internet exposure.
- **Opaque Decision Logic**: Analysts cannot trace why a vulnerability was prioritized or suppressed.

---

## 3. The RizIntel Solution
RizIntel is an AI-assisted **Security Decision Intelligence Platform** that unifies multi-scanner ingestion, performs cross-scanner deduplication (M2), filters noise (M3), enriches findings with threat intelligence (M4), calculates context-aware risk scores (M5), provides explainable AI remediation rationales (M6), assigns SLA deadlines (M7), visualizes real-time pipeline operations (Phase 3), and renders 8-stage decision provenance via **RizTrace**.

---

## 4. Platform Architecture & Data Flow

```
                   ┌──────────────────┐
                   │ Registered Asset │
                   └────────┬─────────┘
                            │
                     Scan Run Created
                            │
                   ┌────────▼─────────┐
                   │   Scanner Job    │
                   └────────┬─────────┘
                            │
                   Secure Machine Agent
                            │
               ┌────────────▼────────────┐
               │ ZAP / Nuclei / Wapiti  │
               └────────────┬────────────┘
                            │
                       Raw Report
                            │
                       M1 Normalize
                            │
                       M2 Deduplicate
                            │
                       M3 Confidence
                            │
                       M4 Threat Intel
                            │
                       M5 Risk Score
                            │
                       M6 Explain
                            │
                       M7 SLA
                            │
                    Persisted Results
                            │
                           SSE
                            │
                       M8 Dashboard
                            │
             Command Center / Finding360
                            │
                        RizTrace
```

---

## 5. Unified M1–M7 Intelligence Pipeline
1. **M1 Normalization**: Converts native scanner outputs into Schema v1.0 canonical format (`M1NormalizedFindingAdapter`).
2. **M2 Deduplication**: Correlates overlapping findings across scanners on the same asset/endpoint using fingerprinting and similarity matching.
3. **M3 Confidence & Noise Routing**: Evaluates 5 confidence signals to route findings into `ACTIONABLE`, `NEEDS_REVIEW`, or `SUPPRESSED` noise.
4. **M4 Threat Intelligence**: Enriches findings with EPSS exploit probabilities, CISA KEV listings, and NVD CVSS vectors.
5. **M5 Context-Aware Risk Scoring**: Pure mathematical sovereignty computing context-weighted risk scores ($0–100$).
6. **M6 Explainability Engine**: Generates technical root-cause drivers and management remediation rationales.
7. **M7 SLA & Ticketing**: Calculates mandatory remediation deadlines and escalation priorities.

---

## 6. Multi-Scanner Report Ingestion
Supports native ingestion for **OWASP ZAP** (XML/JSON), **Nuclei** (JSON/JSONL), and **Wapiti** (JSON). Ingestion persists raw reports with SHA-256 payload hashing and submission metadata (`ingest_report`).

---

## 7. Automated Real Scanner Agent Execution
- **Machine Identity**: Scanner agents register securely with salted SHA-256 tokens (`X-Scanner-Agent-Token`).
- **Atomic Job Queueing**: Agents poll and claim jobs atomically (`claim_scanner_job_atomically`).
- **Server-Authoritative Target Resolution**: Agents execute scans strictly against server-resolved target URLs matching `authorization_status == 'AUTHORIZED'`.
- **Subprocess Safety**: Executes scanner binaries with `shell=False` and explicit argument arrays (`["nuclei.exe", "-u", target, ...]`).
- **Empirical Proof**: Real Nuclei v3.3.8 binary executed against local WebGoat (`http://127.0.0.1:8085`) with zero manual report upload (`RUN-E2E-CLOSURE-7F89`).

---

## 8. Real-Time Scan Operations & SSE Streaming
Features Server-Sent Events (SSE) broadcasting scan lifecycle events (`WAITING_FOR_INPUT` $\to$ `PROCESSING` $\to$ `COMPLETED`) and real-time pipeline stage progress (`M1_NORMALIZE` $\to$ `M7_SLA`). Uses short-lived single-use stream tickets with server-side `expires_at` checks and `Last-Event-ID` replay.

---

## 9. Security Architecture & Controls
- **Human Authentication**: Signed HMAC-SHA256 JWT tokens.
- **Role-Based Access Control**: `SECURITY_LEAD` vs `ANALYST` vs `VIEWER` access control across all API endpoints.
- **Tenant Isolation**: Mandatory `WHERE organization_id = ?` scoping across database queries, findings, and stream tickets.

---

## 10. RizTrace — Decision Provenance Novelty
RizTrace renders an 8-stage visual decision graph for any vulnerability finding. Analysts can trace a finding from its raw scanner signal through normalization, deduplication, confidence routing, threat intel enrichment, risk scoring, explainability, SLA calculation, and final analyst action.

---

## 11. Ground-Truth Evaluation Framework
Built an independent evaluation package in `backend/evaluation/` evaluating M2 deduplication, M3 noise routing, M5 risk scoring sanity, and Spearman $\rho$ prioritization correlation across real (`OWASP WebGoat`, `OWASP Juice Shop`) and synthetic (`Enterprise Multi-Scanner Corpus`) datasets.

---

## 12. Measurable Operational Impact
- **M2 Deduplication Precision / Recall / F1**: `1.0` / `1.0` / `1.0` ($TP=3, FP=0, FN=0$)
- **M3 False Suppression Rate**: `0.0` (0% false suppression of valid vulnerabilities)
- **Spearman $\rho$ Prioritization Correlation**: `1.0` ($N=7$ findings)
- **Duplicate Reduction**: $0.0\%$ (aggregate real datasets) to $66.7\%$ (multi-scanner overlaps)

---

## 13. Testing & Verification Summary
- **Backend Pytest Regression**: `262 / 262` Passed (`100%`)
- **Frontend Vitest Suite**: `56 / 56` Passed (`100%`)
- **Vite Production Build**: `SUCCESS` (zero warnings $>500\text{kB}$)
- **Playwright Browser E2E Suite**: `15 / 15` E2E acceptance checks passed (`18.0s`)
- **Demo Preflight Check**: `DEMO PREFLIGHT = PASS`

---

## 14. Demo Verification & Reproducibility
- Preflight script (`python -m scripts.demo_preflight`) verifies DB, storage, demo org, authorized target, scanner agent, Nuclei binary, and target URL.
- Demo reset script (`python scripts/reset_demo.py`) seeds demo org and authorized target with environment protection (`RIZINTEL_ENV=production` aborts).

---

## 15. Known Limitations
- Evaluation dataset sample size ($N=14$ real signals); Phase 5 verdict intentionally classified as `PARTIAL`.
- Ground-truth annotations performed by a single project-team reviewer (`reviewer_count: 1`).
- Prototype uses SQLite database; production scaling path recommends PostgreSQL and Redis Pub/Sub.

---

## 16. Future Scalability Roadmap
- PostgreSQL database migration with connection pooling.
- Distributed Redis Pub/Sub SSE event broadcasting.
- Support for additional scanners (Snyk, SonarQube, Trivy).
- Integration with domain LLMs for dynamic remediation playbooks.

---

## 17. Conclusion
RizIntel delivers a verified, security-hardened, real-time Security Decision Intelligence Platform. With empirical real scanner execution, zero-trust target authorization, 8-stage decision provenance, and Playwright browser E2E acceptance, RizIntel transforms multi-scanner alert noise into actionable security decisions.
