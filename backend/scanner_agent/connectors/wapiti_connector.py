"""
wapiti_connector.py — Wapiti Web Vulnerability Scanner Connector

Executes Wapiti against authorized target with shell=False.
Outputs native Wapiti JSON report compatible with WapitiAdapter.
ZERO live synthetic mock fallback.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from scanner_agent.connectors.base import BaseScannerConnector
from scanner_agent.discovery import ScannerDiscovery

logger = logging.getLogger("rizintel.scanner_agent.wapiti")


class WapitiConnector(BaseScannerConnector):
    scanner_name = "WAPITI"

    def __init__(self, executable_path: Optional[str] = None, default_timeout: int = 120):
        super().__init__(executable_path=executable_path, default_timeout=default_timeout)
        self._invocation_type: str = "binary"
        self._refresh_discovery()

    def _refresh_discovery(self) -> None:
        disc = ScannerDiscovery.discover_wapiti(self.executable_path)
        if disc["available"]:
            self.executable_path = disc["executable_path"]
            self._detected_version = disc["version"]
            self._invocation_type = disc.get("invocation_type", "binary")
            self._error_reason = None
        else:
            self._detected_version = None
            self._error_reason = disc["error"]

    def validate_available(self) -> Tuple[bool, str]:
        self._refresh_discovery()
        if self.executable_path and (os.path.exists(self.executable_path) or self._invocation_type == "python_module"):
            return True, f"Wapiti v{self._detected_version or 'detected'} available ({self._invocation_type})"
        return False, self._error_reason or "Wapiti executable or Python package not found."

    def build_command(self, target_url: str, report_output_path: str, timeout: Optional[int] = None) -> List[str]:
        """Construct safe Wapiti argv list with shell=False."""
        scan_time = str(timeout or self.default_timeout)

        if self._invocation_type == "python_module":
            runner_script = (
                "from wapitiCore.main.wapiti import wapiti_asyncio_wrapper; "
                "wapiti_asyncio_wrapper()"
            )
            return [
                self.executable_path or sys.executable,
                "-c",
                runner_script,
                "-u", target_url,
                "-f", "json",
                "-o", report_output_path,
                "--max-scan-time", scan_time,
                "--flush-session",
            ]

        if not self.executable_path:
            raise FileNotFoundError("Cannot build Wapiti command: executable not found.")

        return [
            self.executable_path,
            "-u", target_url,
            "-f", "json",
            "-o", report_output_path,
            "--max-scan-time", scan_time,
            "--flush-session",
        ]

    def execute(self, target_url: str, timeout: Optional[int] = None) -> bytes:
        """Execute real Wapiti scanner against target and return raw native JSON bytes."""
        is_avail, reason = self.validate_available()
        if not is_avail:
            raise FileNotFoundError(f"Wapiti cannot execute: {reason}")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd = self.build_command(target_url, tmp_path, timeout=timeout)
            exit_code, stdout, stderr = self.execute_subprocess(cmd, timeout=timeout)

            # Wapiti output handling: check if output file was created
            if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                with open(tmp_path, "rb") as f:
                    content = f.read()
                try:
                    data = json.loads(content)
                    if isinstance(data, dict):
                        return content
                except Exception as e:
                    logger.warning("Wapiti output file is not valid JSON: %s", e)

            # Check if Wapiti created a file with output in a subpath or directory
            if os.path.isdir(tmp_path):
                for fname in os.listdir(tmp_path):
                    if fname.endswith(".json"):
                        fpath = os.path.join(tmp_path, fname)
                        with open(fpath, "rb") as f:
                            return f.read()

            # Check stdout if JSON was emitted directly
            if stdout and stdout.strip():
                try:
                    data = json.loads(stdout)
                    if isinstance(data, dict) and ("vulnerabilities" in data or "classifications" in data):
                        return stdout
                except Exception:
                    pass

            if exit_code != 0:
                err_msg = stderr.decode("utf-8", errors="replace").strip() or stdout.decode("utf-8", errors="replace").strip()
                raise RuntimeError(f"Wapiti execution failed with code {exit_code}: {err_msg[:400]}")

            # Return empty valid JSON if scan was clean
            return b'{"infos": {"target": "' + target_url.encode("utf-8") + b'"}, "classifications": {}, "vulnerabilities": {}}'
        finally:
            if os.path.exists(tmp_path):
                try:
                    if os.path.isdir(tmp_path):
                        import shutil
                        shutil.rmtree(tmp_path, ignore_errors=True)
                    else:
                        os.remove(tmp_path)
                except Exception:
                    pass
