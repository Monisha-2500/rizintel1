# RizIntel Scanner Agent Production Setup Guide

This guide provides instructions for installing scanner prerequisites, registering an authorized machine identity, running preflight diagnostics, and starting the RizIntel Scanner Agent daemon on Windows and Linux.

---

## 1. Architecture & Scanner Prerequisites

The RizIntel Scanner Agent executes real vulnerability scanner binaries against authorized targets and submits native raw reports to the backend. **Live synthetic mock fallbacks are strictly absent.**

### Supported Scanners:
1. **ProjectDiscovery Nuclei**: `v3.0.0+` (Golden reference fast vulnerability scanner)
2. **OWASP ZAP (Zed Attack Proxy)**: `v2.14.0+` (Comprehensive web security scanner; requires Java 11/17/21)
3. **Wapiti Web Vulnerability Scanner**: `v3.1.0+` (Modular web security scanner; Python 3.10+)

---

## 2. Scanner Installation & Configuration

### A. ProjectDiscovery Nuclei
- **Windows**: Download official binary or install via Scoop/Winget/binary in `backend/nuclei.exe`.
  ```powershell
  # Probe version
  nuclei -version
  ```
- **Linux**:
  ```bash
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  # or download from https://github.com/projectdiscovery/nuclei/releases
  ```

### B. OWASP ZAP & Java Runtime
OWASP ZAP requires a Java Runtime Environment (OpenJDK 11, 17, or 21 LTS).
- **Windows**:
  1. Install Eclipse Adoptium Temurin OpenJDK 21 or place portable JRE in `~/tools/jre` or set `JAVA_HOME`.
  2. Download OWASP ZAP Crossplatform zip from [ZAP Releases](https://github.com/zaproxy/zaproxy/releases).
  3. Extract to `~/tools/zap` or configure `ZAP_EXECUTABLE=C:\path\to\zap.bat`.
  ```powershell
  $env:JAVA_HOME = "C:\Users\<user>\tools\jre"
  & "C:\Users\<user>\tools\zap\zap.bat" -version
  ```
- **Linux**:
  ```bash
  sudo apt-get update && sudo apt-get install -y default-jre zaproxy
  zap.sh -version
  ```

### C. Wapiti Web Vulnerability Scanner
- **Windows & Linux**: Install the official `wapiti3` package into the agent's Python environment:
  ```bash
  pip install wapiti3
  # Probe version
  python -c "import importlib.metadata; print('Wapiti:', importlib.metadata.version('wapiti3'))"
  ```

---

## 3. Environment Variables Reference

| Variable | Description | Default |
| :--- | :--- | :--- |
| `RIZINTEL_SERVER_URL` | Base URL of the RizIntel backend | `http://localhost:8000` |
| `RIZINTEL_AGENT_TOKEN` | Machine agent authentication token (`agt_...`) | *Required* |
| `MAX_CONCURRENT_SCANS` | Maximum concurrent scanner jobs | `1` |
| `POLL_INTERVAL_SECONDS` | Interval between job claim polls | `2.0` |
| `SCANNER_TIMEOUT_SECONDS` | Default timeout for scanner execution | `120` |
| `NUCLEI_SCAN_TIMEOUT_SECONDS` | Nuclei execution timeout | `120` |
| `ZAP_SCAN_TIMEOUT_SECONDS` | OWASP ZAP execution timeout | `300` |
| `WAPITI_SCAN_TIMEOUT_SECONDS` | Wapiti execution timeout | `120` |
| `JAVA_HOME` | Path to Java JRE/JDK for OWASP ZAP | Discovered / System |
| `NUCLEI_EXECUTABLE` | Explicit path to Nuclei binary (optional) | Discovered on PATH |
| `ZAP_EXECUTABLE` | Explicit path to `zap.bat` / `zap.sh` (optional) | Discovered on PATH / Tools |
| `WAPITI_EXECUTABLE` | Explicit path to `wapiti` binary (optional) | Discovered on PATH / Python |

---

## 4. Agent Registration & Token Configuration

1. Log into RizIntel as a **Security Lead** or **Admin**.
2. Navigate to **Scanner Agents** in the top navigation bar (`/scanner-agents`).
3. Click **+ Register Scanner Agent**.
4. Enter an Agent Display Name (e.g. `prod-worker-01`) and click **Register Agent**.
5. **Copy the Secret Token**: Copy the single-time secret token starting with `agt_...`. Store it securely.

---

## 5. Running Preflight Diagnostics

Before starting the daemon, execute the built-in preflight diagnostic tool:

```bash
cd backend
export RIZINTEL_SERVER_URL="http://localhost:8000"
export RIZINTEL_AGENT_TOKEN="agt_YOUR_COPIED_SECRET_HERE"

python -m scanner_agent.preflight
```

### Expected Preflight Output:
```text
=================================================================
           RIZINTEL SCANNER AGENT PREFLIGHT CHECK            
=================================================================
[*] Server URL:          http://localhost:8000
[*] Agent Token:         agt_3x...9a1b (CONFIGURED)
[*] Max Concurrent:      1
[*] Default Timeout:     120s
-----------------------------------------------------------------
[+] Backend Server:      REACHABLE (HTTP 200)
[+] Agent Authentication: VALID (ACTIVE)
-----------------------------------------------------------------
                     SCANNER CAPABILITIES                    
-----------------------------------------------------------------
[+] NUCLEI   AVAILABLE   Version: v3.3.8
[+] ZAP      AVAILABLE   Version: v2.16.0
[+] WAPITI   AVAILABLE   Version: v3.2.3
=================================================================
[SUCCESS] All scanner agent preflight checks passed.
```

---

## 6. Starting the Scanner Agent Daemon

### Windows (PowerShell):
```powershell
cd backend
$env:RIZINTEL_SERVER_URL="http://localhost:8000"
$env:RIZINTEL_AGENT_TOKEN="agt_YOUR_COPIED_SECRET_HERE"
python -m scanner_agent.agent
```

### Linux (Bash):
```bash
cd backend
export RIZINTEL_SERVER_URL="http://localhost:8000"
export RIZINTEL_AGENT_TOKEN="agt_YOUR_COPIED_SECRET_HERE"
python -m scanner_agent.agent
```

---

## 7. Operational Lifecycle & Verification

1. **Heartbeat & Capabilities**: Upon startup, the agent sends an authenticated heartbeat. Navigate to `/scanner-agents` in the UI to see the truthful status and versions for Nuclei, ZAP, and Wapiti.
2. **Atomic Job Claiming**: When a Scan Run is created, the agent claims matching queued jobs, executes the scanner binaries safely (`shell=False`), captures native reports, and uploads them to `/v1/agent/jobs/{job_id}/report`.
3. **Pipeline Ingestion**: Reports are normalized by M1 adapters and proceed through M2–M7 deduplication, AI explainability, and canonical persistence.
