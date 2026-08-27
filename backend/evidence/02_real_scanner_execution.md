# Evidence Pack 02 — Real Scanner Execution Proof

## Real Scanner Binary Execution Details
- **Scanner Engine**: ProjectDiscovery Nuclei (`.\nuclei.exe` v3.3.8)
- **Target URL**: `http://127.0.0.1:8085` (`OWASP WebGoat Target App`, `AUTHORIZED`)
- **Automated Workflow Script**: `run_phase4_e2e_closure.py`
- **Subprocess Safety**: `subprocess.Popen(["nuclei.exe", "-u", "http://127.0.0.1:8085", "-json-export", ...], shell=False)`

## Verifiable Runtime Identifiers
- **Scan Run ID**: `RUN-E2E-CLOSURE-7F89`
- **Job ID**: `JOB-E2E-CLOSURE-44E6`
- **Submission ID**: `SUB-44E6E2D3E4C8`
- **Agent ID**: `AGENT-LOCAL-NUCLEI-01`
- **Raw Finding Count**: `1`
- **Canonical Finding Count**: `1`
- **Final Finding IDs**: `["FIN-2026-F61FAEA95204"]`
- **Manual Upload Count**: `0`
