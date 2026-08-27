# Evidence Pack 01 — System Architecture & Trust Boundaries

## Core Architecture Overview
RizIntel is built as a Security Decision Intelligence Platform designed to ingest multi-scanner vulnerability reports, deduplicate overlapping signals, filter noise, enrich findings with threat intelligence, calculate context-aware risk scores, generate explainable AI rationales, assign SLA remediation deadlines, and render real-time decision provenance.

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

## Trust Boundaries
1. **Human JWT Boundary**: Authenticates human users (`SECURITY_LEAD`, `ANALYST`, `VIEWER`) via HMAC-SHA256 tokens.
2. **Machine Agent Token Boundary**: Machine scanner agents authenticate using salted SHA-256 tokens (`X-Scanner-Agent-Token`). Plaintext tokens are never stored.
3. **Organization Boundary**: All database queries, scan runs, asset registries, findings, and SSE tickets strictly enforce `organization_id` scoping.
4. **Authorized Asset Boundary**: Scanner jobs strictly execute against server-resolved target URLs matching `authorization_status == 'AUTHORIZED'`. Target injection is prevented.
5. **Scanner Execution Boundary**: Connectors execute subprocesses with `shell=False` and explicit argument arrays.
