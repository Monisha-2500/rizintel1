# RizIntel Phase 7 — Security Acceptance & Controls Evidence

This document provides formal empirical proof of RizIntel's multi-layered security controls, tenant isolation guarantees, machine authentication mechanisms, and RBAC enforcement.

---

## Verified Security Controls

### 1. Role-Based Access Control (RBAC)
- **`SECURITY_LEAD` / `ADMIN`**: Permitted to register assets, authorize target hosts, register scanner agents, and create scan runs.
- **`ANALYST`**: Permitted to view scan runs, inspect findings, view RizTrace provenance, and update SLA remediation status. Prohibited from asset authorization and agent registration.
- **`VIEWER`**: Read-only access to findings and workspace metrics. Prohibited from mutating actions.
- **Automated Test Proof**: `tests/test_phase1_org_scan_runs.py`, `tests/test_phase4_scanner_agent.py`.

### 2. Tenant & Organization Isolation
- **Scoping**: All database queries, scan runs, asset registries, findings, and SSE tickets explicitly include `WHERE organization_id = ?`.
- **Cross-Org Rejection**: Attempting to query an asset or scan run belonging to another organization returns HTTP 403 Forbidden or HTTP 404 Not Found.
- **Automated Test Proof**: `tests/test_phase1_org_scan_runs.py`, `tests/test_phase3_realtime_stream.py`.

### 3. Machine Agent Identity & Authentication
- **Header**: `X-Scanner-Agent-Token`
- **Security**: Machine agent tokens are generated securely (`secrets.token_urlsafe(32)`) and stored in database using salted SHA-256 hashes (`hashlib.sha256(token + salt)`). Plaintext tokens are never stored.
- **Revocation**: Deactivating an agent (`status = 'DEACTIVATED'`) immediately rejects subsequent job claim requests.
- **Automated Test Proof**: `tests/test_phase4_scanner_agent.py`.

### 4. Server-Authoritative Target Resolution
- **Rule**: Scanner agents execute commands strictly against target URLs resolved server-side from registered assets where `authorization_status == 'AUTHORIZED'`.
- **Target Injection Prevention**: Frontend or machine agent target overrides are strictly rejected.
- **Automated Test Proof**: `tests/test_phase4_scanner_agent.py`.

### 5. Safe Subprocess Execution
- **Rule**: All scanner connectors (`NucleiConnector`, `ZapConnector`, `WapitiConnector`) invoke subprocesses with `shell=False` and explicit argument arrays.
- **Shell Injection Prevention**: Eliminates shell command injection vulnerabilities.
- **Automated Test Proof**: `tests/test_phase4_scanner_agent.py`.

### 6. SSE Stream Ticket Hardening
- **Short-Lived Expiration**: Tickets contain server-side `expires_at` timestamp (default 60s). Expired tickets return HTTP 401.
- **Single-Use Atomic Consumption**: Ticket consumption is atomic (`UPDATE sse_stream_tokens SET used_at = ...`). Re-using a ticket returns HTTP 403.
- **Automated Test Proof**: `tests/test_phase3_realtime_stream.py`.
