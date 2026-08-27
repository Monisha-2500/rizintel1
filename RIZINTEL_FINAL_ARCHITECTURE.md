# RizIntel — Final System Architecture & Technical Specification

## Overview
RizIntel is an AI-assisted Security Decision Intelligence Platform that unifies multi-scanner vulnerability reports, eliminates duplicate alerts, routes noise, enriches findings with threat intelligence, computes context-aware risk scores, generates explainable remediation rationales, assigns SLA deadlines, and visualizes real-time decision provenance via **RizTrace**.

---

## 1. End-to-End Data Path

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

## 2. Trust Boundaries & Security Architecture

1. **Human Authentication & RBAC Boundary**:
   - **Protocol**: HMAC-SHA256 Signed JSON Web Tokens (JWT).
   - **Roles**: `SECURITY_LEAD` (full mutation rights), `ANALYST` (review and SLA mutation), `VIEWER` (read-only).
   - **Enforcement**: Middleware `get_current_user` and RBAC checks across all API routes.

2. **Machine Scanner Agent Token Boundary**:
   - **Header**: `X-Scanner-Agent-Token`
   - **Token Hashing**: Tokens stored as salted SHA-256 hashes (`hashlib.sha256(token + salt)`).
   - **Isolation**: Machine tokens cannot invoke human management endpoints or bypass RBAC.

3. **Multi-Tenant Organization Boundary**:
   - All database queries, scan runs, asset registries, findings, and SSE stream tickets include mandatory `WHERE organization_id = ?` filters.
   - Cross-org queries are rejected with HTTP 403 / HTTP 404.

4. **Server-Authoritative Target Resolution**:
   - Scanner agents receive target URLs resolved server-side from registered assets where `authorization_status == 'AUTHORIZED'`.
   - Prevents scanning unauthorized or arbitrary external target hosts.

5. **Subprocess Execution Boundary**:
   - Connectors (`NucleiConnector`, `ZapConnector`, `WapitiConnector`) execute subprocesses with `shell=False` and explicit argument arrays (`["nuclei.exe", "-u", target, ...]`).
   - Prevents shell command injection vulnerabilities.

6. **Persistent Event Ledger**:
   - All pipeline transitions, scanner job state changes, and ingestion submissions produce immutable audit entries in `scan_run_events` and `audit_log` tables.
