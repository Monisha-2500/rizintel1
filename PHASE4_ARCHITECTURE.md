# Phase 4 — Secure Scanner Agent & Automatic Scanner Connectors Architecture

## 1. Executive Overview

Phase 4 transforms RizIntel from a manual vulnerability report ingestion tool into an automated, secure scanner orchestration platform. It introduces:
- **Dedicated Machine Agent Identity**: Independent `scanner_agents` identity decoupled from human JWT user identity.
- **Constant-Time SHA-256 Authentication**: Plaintext secrets shown ONCE (`agt_...`) and stored as salted/SHA-256 hashes server-side.
- **Authoritative Target Resolution**: Target scheme, host, and port are resolved EXCLUSIVELY server-side from `registered_assets` with `authorization_status == 'AUTHORIZED'`. Free-form target overrides are strictly rejected.
- **Race-Safe Atomic Job Queue**: Job queueing (`scanner_jobs` table) with atomic row locking to ensure exactly-once claiming by active scanner agents.
- **Safe Subprocess Connectors**: `BaseScannerConnector` enforcing `shell=False`, argument list execution, configurable timeouts, stdout/stderr capture, and process group cleanup. Supports OWASP ZAP, ProjectDiscovery Nuclei, and Wapiti.
- **Native Ingestion & SSE Pipeline Integration**: Automatically hands scanner output to Phase 2 ingestion parser without double normalization, triggering Phase 3 real-time SSE stream events.

---

## 2. System Architecture Diagram

```mermaid
flowchart TD
    subgraph Human Management Layer
        Admin[Security Lead / Admin] -->|POST /v1/organizations/{id}/scanner-agents| RegAPI[Agent Registration Endpoint]
        RegAPI -->|Store SHA-256 Hash| DB[(SQLite Database)]
        RegAPI -->|Return Secret Once| Admin
    end

    subgraph Scan Run & Job Dispatch
        User[User] -->|POST /v1/organizations/{id}/scan-runs| RunService[Scan Run Service]
        RunService -->|Dispatch Jobs| JobQueue[scanner_jobs Queue]
        RunService -->|Emit SCANNER_JOB_QUEUED| SSE[Phase 3 SSE Stream]
    end

    subgraph Scanner Agent Execution Loop
        AgentExec[Scanner Agent Executable] -->|POST /v1/agent/jobs/claim| MachineAPI[Machine Execution API]
        MachineAPI -->|Atomic Claim| JobQueue
        MachineAPI -->|Resolve Authoritative Target| AssetReg[Registered Assets Catalog]
        MachineAPI -->|Return Job + Target| AgentExec

        AgentExec -->|Execute safe subprocess shell=False| Connectors[ZapConnector / NucleiConnector / WapitiConnector]
        Connectors -->|Raw Scanner Report Bytes| AgentExec

        AgentExec -->|POST /v1/agent/jobs/{id}/report| Ingestion[Phase 2 Ingestion Service]
        Ingestion -->|Single M1 Normalization| M1M7[M1-M7 Processing Engine]
        Ingestion -->|Emit Real-Time Events| SSE
    end
```

---

## 3. Database Schema Extensions

### `scanner_agents` Table
| Column | Type | Constraints | Description |
|---|---|---|---|
| `agent_id` | TEXT | PRIMARY KEY | Collision-safe agent ID (`AGENT-<hex>`) |
| `organization_id` | TEXT | NOT NULL, FK | Owning organization |
| `display_name` | TEXT | NOT NULL | Human-readable name |
| `token_hash` | TEXT | NOT NULL, UNIQUE | SHA-256 hash of `agt_...` secret |
| `status` | TEXT | NOT NULL | `ACTIVE`, `REVOKED`, `DISABLED` |
| `capabilities_json` | TEXT | | JSON map of supported scanners |
| `created_at` | TEXT | NOT NULL | ISO-8601 timestamp |
| `last_seen_at` | TEXT | | Timestamp of last heartbeat/claim |
| `created_by_user_id` | TEXT | NOT NULL | User who registered agent |

### `scanner_jobs` Table
| Column | Type | Constraints | Description |
|---|---|---|---|
| `scanner_job_id` | TEXT | PRIMARY KEY | Collision-safe job ID (`JOB-<hex>`) |
| `organization_id` | TEXT | NOT NULL, FK | Owning organization |
| `scan_run_id` | TEXT | NOT NULL, FK | Target scan run |
| `asset_id` | TEXT | NOT NULL, FK | Target asset |
| `scanner` | TEXT | NOT NULL | `ZAP`, `NUCLEI`, `WAPITI` |
| `agent_id` | TEXT | | Claiming agent ID |
| `status` | TEXT | NOT NULL | `QUEUED`, `CLAIMED`, `RUNNING`, `UPLOADING`, `COMPLETED`, `FAILED`, `CANCELLED` |
| `attempt` | INTEGER | DEFAULT 1 | Attempt count |
| `max_attempts` | INTEGER | DEFAULT 3 | Max retry count |
| `created_at` | TEXT | NOT NULL | ISO-8601 timestamp |
| `claimed_at` | TEXT | | Timestamp when agent claimed job |
| `started_at` | TEXT | | Timestamp when execution started |
| `completed_at` | TEXT | | Timestamp when report uploaded |
| `failed_at` | TEXT | | Timestamp on failure |
| `error_code` | TEXT | | Error classification code |
| `error_message` | TEXT | | Detailed error description |

---

## 4. Security & Compliance Guarantees

1. **Dedicated Machine Identity**: Scanner agents authenticate via `X-Scanner-Agent-Token: agt_<secret>` header. Machine identity is strictly isolated from human user JWT sessions.
2. **Authoritative Target Isolation**: Scanner agents CANNOT scan arbitrary targets. The target URL is generated server-side from `registered_assets` ONLY if `authorization_status == 'AUTHORIZED'`.
3. **Subprocess Isolation**: Subprocesses execute with `shell=False`, argument vectors as `List[str]`, strict timeouts, and stdout/stderr sanitization.
4. **Single Normalization Rule**: Native scanner reports produced by connectors are parsed strictly once by Phase 2 ingestion adapters before passing to M1.
