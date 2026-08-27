"""
preflight.py — Scanner Agent Preflight Diagnostics & Verification Tool

Runs environment, connectivity, authentication, and scanner tool checks without exposing sensitive secrets.

Usage:
  python -m scanner_agent.preflight
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict

# Ensure backend directory is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import httpx
from scanner_agent.config import AgentConfig
from scanner_agent.discovery import ScannerDiscovery


def run_preflight() -> int:
    """Execute preflight checks and print diagnostic summary."""
    config = AgentConfig()

    print("=" * 65)
    print("           RIZINTEL SCANNER AGENT PREFLIGHT CHECK            ")
    print("=" * 65)

    # 1. Configuration & Token Check
    token = config.agent_token
    token_status = "CONFIGURED" if token else "MISSING"
    redacted_token = f"{token[:7]}...{token[-4:]}" if len(token) > 12 else ("[REDACTED]" if token else "NOT SET")

    print(f"[*] Server URL:          {config.server_url}")
    print(f"[*] Agent Token:         {redacted_token} ({token_status})")
    print(f"[*] Max Concurrent:      {config.max_concurrent_scans}")
    print(f"[*] Default Timeout:     {config.default_timeout_seconds}s")
    print("-" * 65)

    # 2. Server Connectivity Check
    server_healthy = False
    try:
        resp = httpx.get(f"{config.server_url}/health", timeout=5.0)
        if resp.status_code == 200:
            server_healthy = True
            print(f"[+] Backend Server:      REACHABLE (HTTP {resp.status_code})")
        else:
            print(f"[-] Backend Server:      HTTP {resp.status_code} ({resp.text[:100]})")
    except Exception as e:
        print(f"[-] Backend Server:      UNREACHABLE ({e})")

    # 3. Agent Authentication Check
    auth_valid = False
    if token and server_healthy:
        try:
            resp = httpx.post(
                f"{config.server_url}/v1/agent/heartbeat",
                headers={"X-Scanner-Agent-Token": token, "Content-Type": "application/json"},
                json={"capabilities": {}},
                timeout=5.0,
            )
            if resp.status_code in (200, 201):
                auth_valid = True
                print(f"[+] Agent Authentication: VALID (ACTIVE)")
            elif resp.status_code == 401:
                print(f"[-] Agent Authentication: REJECTED (Invalid or revoked token)")
            else:
                print(f"[-] Agent Authentication: HTTP {resp.status_code}")
        except Exception as e:
            print(f"[-] Agent Authentication: FAILED ({e})")
    elif not token:
        print(f"[-] Agent Authentication: SKIPPED (RIZINTEL_AGENT_TOKEN not set)")

    print("-" * 65)
    print("                     SCANNER CAPABILITIES                    ")
    print("-" * 65)

    # 4. Scanner Discovery
    caps = ScannerDiscovery.discover_all(
        nuclei_path=config.nuclei_executable,
        zap_path=config.zap_executable,
        wapiti_path=config.wapiti_executable,
    )

    all_scanners_ok = True
    for s_name in ["NUCLEI", "ZAP", "WAPITI"]:
        info = caps.get(s_name, {})
        avail = info.get("available", False)
        version = info.get("version")
        err = info.get("error")

        if avail:
            print(f"[+] {s_name:<8} AVAILABLE   Version: v{version or 'detected'}")
        else:
            all_scanners_ok = False
            print(f"[-] {s_name:<8} UNAVAILABLE Reason: {err}")

    print("=" * 65)

    if server_healthy and auth_valid and all_scanners_ok:
        print("[SUCCESS] All scanner agent preflight checks passed.")
        return 0
    elif server_healthy and auth_valid:
        print("[WARNING] Agent can start, but some scanners are missing.")
        return 0
    else:
        print("[FAILURE] Agent configuration or backend connectivity failed.")
        return 1


if __name__ == "__main__":
    sys.exit(run_preflight())
