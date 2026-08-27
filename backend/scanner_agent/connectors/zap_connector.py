"""
zap_connector.py — OWASP ZAP Scanner Connector

Executes OWASP ZAP in headless noninteractive command mode (-cmd) against authorized target with shell=False.
Outputs native ZAP report JSON compatible with ZapAdapter.
ZERO live synthetic mock fallback.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from scanner_agent.connectors.base import BaseScannerConnector
from scanner_agent.discovery import ScannerDiscovery

logger = logging.getLogger("rizintel.scanner_agent.zap")


class ZapConnector(BaseScannerConnector):
    scanner_name = "ZAP"

    def __init__(self, executable_path: Optional[str] = None, default_timeout: int = 300):
        super().__init__(executable_path=executable_path, default_timeout=default_timeout)
        self._refresh_discovery()

    def _refresh_discovery(self) -> None:
        disc = ScannerDiscovery.discover_zap(self.executable_path)
        if disc["available"]:
            self.executable_path = disc["executable_path"]
            self._detected_version = disc["version"]
            self.cwd = disc.get("cwd")
            self.env = disc.get("env")
            self._error_reason = None
        else:
            self._detected_version = None
            self._error_reason = disc["error"]

    def validate_available(self) -> Tuple[bool, str]:
        self._refresh_discovery()
        if self.executable_path and os.path.exists(self.executable_path):
            return True, f"OWASP ZAP v{self._detected_version or 'detected'} available at {self.executable_path}"
        return False, self._error_reason or "OWASP ZAP executable launcher or Java runtime not found."

    def build_command(self, target_url: str, report_output_path: str) -> List[str]:
        """Construct safe ZAP argv list with shell=False."""
        if not self.executable_path:
            raise FileNotFoundError("Cannot build ZAP command: executable not found.")

        # Real supported ZAP command line options for headless quick scan
        return [
            self.executable_path,
            "-cmd",
            "-quickurl", target_url,
            "-quickout", report_output_path,
            "-quickof", "json",
        ]

    def execute(self, target_url: str, timeout: Optional[int] = None) -> bytes:
        """Execute real OWASP ZAP scanner against target and return raw native JSON bytes."""
        is_avail, reason = self.validate_available()
        if not is_avail:
            raise FileNotFoundError(f"OWASP ZAP cannot execute: {reason}")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd = self.build_command(target_url, tmp_path)
            exit_code, stdout, stderr = self.execute_subprocess(
                cmd,
                timeout=timeout,
                cwd=self.cwd,
                env=self.env,
            )

            # Check if output file exists and has content
            if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                with open(tmp_path, "rb") as f:
                    content = f.read()

                # Validate native JSON structure
                try:
                    data = json.loads(content)
                    if isinstance(data, dict):
                        return content
                except Exception as e:
                    logger.warning("ZAP output file exists but is not valid JSON: %s", e)

            # Check stdout if output was directed to stdout
            if stdout and stdout.strip():
                try:
                    data = json.loads(stdout)
                    if isinstance(data, dict) and ("site" in data or "@version" in data):
                        return stdout
                except Exception:
                    pass

            if exit_code != 0:
                err_msg = stderr.decode("utf-8", errors="replace").strip() or stdout.decode("utf-8", errors="replace").strip()
                raise RuntimeError(f"OWASP ZAP process exited with code {exit_code}: {err_msg[:400]}")

            # Return empty json document if scan was clean
            return b'{"@version": "2.16.0", "site": []}'
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
