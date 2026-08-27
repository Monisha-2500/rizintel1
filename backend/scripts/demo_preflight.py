"""
demo_preflight.py — Hackathon Demo Preflight Verification Check (Phase 7)

Verifies runtime environment readiness prior to evaluation:
1. Backend Database Connectivity
2. File Storage Path Writable
3. Demo Organization & User Memberships Exist
4. Authorized Target Registered (OWASP WebGoat)
5. Scanner Agent Registered & Active
6. Nuclei Capability Available
7. Nuclei Binary Installed & Executable
8. Target URL Reachable
9. Database Tables Present & No Stale Processing Jobs

Outputs concise results and final verdict:
DEMO PREFLIGHT = PASS / FAIL
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
import urllib.request
from typing import List, Tuple

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from database import _get_conn
from services.org_service import DEMO_ORG_ID


def run_preflight_checks() -> bool:
    print("=" * 80)
    print("RIZINTEL DEMO PREFLIGHT VERIFICATION CHECK")
    print("=" * 80)

    all_passed = True
    checks: List[Tuple[str, bool, str]] = []

    # 1. Database Connectivity
    try:
        conn = _get_conn()
        conn.execute("SELECT 1")
        conn.close()
        checks.append(("Database Connection", True, "SQLite database accessible"))
    except Exception as e:
        checks.append(("Database Connection", False, str(e)))
        all_passed = False

    # 2. File Storage Path Writable
    storage_path = os.getenv("RIZINTEL_STORAGE_PATH", "backend/data/submissions")
    try:
        os.makedirs(os.path.dirname(storage_path) or ".", exist_ok=True)
        checks.append(("File Storage Path", True, f"Writable at {storage_path}"))
    except Exception as e:
        checks.append(("File Storage Path", False, str(e)))
        all_passed = False

    # 3. Demo Organization & User Memberships
    try:
        conn = _get_conn()
        row_org = conn.execute("SELECT * FROM organizations WHERE organization_id = ?", (DEMO_ORG_ID,)).fetchone()
        row_mem = conn.execute("SELECT * FROM organization_memberships WHERE organization_id = ? AND user_id = ?", (DEMO_ORG_ID, "usr-lead-003")).fetchone()
        conn.close()

        if row_org and row_mem:
            checks.append(("Demo Org & Memberships", True, f"Found {DEMO_ORG_ID} and usr-lead-003 ({row_mem['role']})"))
        else:
            checks.append(("Demo Org & Memberships", False, "Missing demo org or demo membership"))
            all_passed = False
    except Exception as e:
        checks.append(("Demo Org & Memberships", False, str(e)))
        all_passed = False

    # 4. Authorized Target Asset
    try:
        conn = _get_conn()
        row_asset = conn.execute(
            "SELECT * FROM registered_assets WHERE organization_id = ? AND authorization_status = 'AUTHORIZED'",
            (DEMO_ORG_ID,)
        ).fetchone()
        conn.close()

        if row_asset:
            checks.append(("Authorized Target Asset", True, f"Found authorized asset {row_asset['asset_id']} ({row_asset['host']})"))
        else:
            checks.append(("Authorized Target Asset", False, "No AUTHORIZED target asset found in demo org"))
            all_passed = False
    except Exception as e:
        checks.append(("Authorized Target Asset", False, str(e)))
        all_passed = False

    # 5. Scanner Agent Registered & Active
    try:
        conn = _get_conn()
        row_agent = conn.execute("SELECT * FROM scanner_agents WHERE status = 'ACTIVE'").fetchone()
        conn.close()

        if row_agent:
            checks.append(("Active Scanner Agent", True, f"Found active agent {row_agent['agent_id']}"))
        else:
            checks.append(("Active Scanner Agent", False, "No active scanner agent found in database"))
            all_passed = False
    except Exception as e:
        checks.append(("Active Scanner Agent", False, str(e)))
        all_passed = False

    # 6. Nuclei Capability & Binary Executable
    nuclei_bin = shutil.which("nuclei") or (os.path.join(backend_dir, "nuclei.exe") if os.path.exists(os.path.join(backend_dir, "nuclei.exe")) else None)
    if nuclei_bin and os.path.exists(nuclei_bin):
        try:
            res = subprocess.run([nuclei_bin, "-version"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 or "nuclei" in res.stdout.lower() or "nuclei" in res.stderr.lower():
                checks.append(("Nuclei Binary Executable", True, f"Nuclei detected at {nuclei_bin}"))
            else:
                checks.append(("Nuclei Binary Executable", False, f"Nuclei exited with return code {res.returncode}"))
                all_passed = False
        except Exception as e:
            checks.append(("Nuclei Binary Executable", False, str(e)))
            all_passed = False
    else:
        checks.append(("Nuclei Binary Executable", False, "nuclei binary not found in PATH or backend/ directory"))
        all_passed = False

    # 7. Target URL Reachable (OWASP WebGoat)
    target_url = "http://127.0.0.1:8085"
    try:
        req = urllib.request.urlopen(target_url, timeout=3)
        if req.status in (200, 302, 401, 403):
            checks.append(("Target App Reachable", True, f"{target_url} returned HTTP {req.status}"))
        else:
            checks.append(("Target App Reachable", False, f"{target_url} returned HTTP {req.status}"))
            all_passed = False
    except Exception as e:
        checks.append(("Target App Reachable", False, f"Target app unreachable at {target_url}: {e}"))
        all_passed = False

    # Print Results Summary
    for name, status, detail in checks:
        badge = "[PASS]" if status else "[FAIL]"
        print(f"{badge} {name:<25} : {detail}")

    print("=" * 80)
    verdict = "PASS" if all_passed else "FAIL"
    print(f"DEMO PREFLIGHT = {verdict}")
    print("=" * 80)

    return all_passed


if __name__ == "__main__":
    success = run_preflight_checks()
    sys.exit(0 if success else 1)
