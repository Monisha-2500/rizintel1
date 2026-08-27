"""
nuclei_connector.py — ProjectDiscovery Nuclei Scanner Connector

Executes Nuclei against authorized target with shell=False.
Outputs native Nuclei JSONL report compatible with NucleiAdapter.
ZERO live synthetic mock fallback.
"""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from scanner_agent.connectors.base import BaseScannerConnector
from scanner_agent.discovery import ScannerDiscovery

logger = logging.getLogger("rizintel.scanner_agent.nuclei")


class NucleiConnector(BaseScannerConnector):
    scanner_name = "NUCLEI"

    def __init__(self, executable_path: Optional[str] = None, default_timeout: int = 120):
        super().__init__(executable_path=executable_path, default_timeout=default_timeout)
        self._refresh_discovery()

    def _refresh_discovery(self) -> None:
        disc = ScannerDiscovery.discover_nuclei(self.executable_path)
        if disc["available"]:
            self.executable_path = disc["executable_path"]
            self._detected_version = disc["version"]
            self._error_reason = None
        else:
            self._detected_version = None
            self._error_reason = disc["error"]

    def validate_available(self) -> Tuple[bool, str]:
        self._refresh_discovery()
        if self.executable_path and os.path.exists(self.executable_path):
            return True, f"Nuclei v{self._detected_version or 'detected'} available at {self.executable_path}"
        return False, self._error_reason or "Nuclei executable not found."

    def build_command(self, target_url: str, report_output_path: str) -> List[str]:
        """Construct safe Nuclei argv list with shell=False."""
        if not self.executable_path:
            raise FileNotFoundError("Cannot build Nuclei command: executable not found.")

        cmd = [
            self.executable_path,
            "-u", target_url,
            "-jsonl",
            "-o", report_output_path,
            "-silent",
            "-duc",
            "-no-stdin",
            "-ni",
        ]
        template_path = os.getenv("NUCLEI_TEMPLATE_PATH")
        if not template_path:
            default_tmpl = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "custom_templates",
                "webgoat_vulnerabilities.yaml",
            )
            if os.path.exists(default_tmpl):
                template_path = default_tmpl
        if template_path and os.path.exists(template_path):
            cmd.extend(["-t", template_path])
        return cmd

    def execute(self, target_url: str, timeout: Optional[int] = None) -> bytes:
        """Execute real Nuclei scanner against target and return raw JSONL bytes."""
        is_avail, reason = self.validate_available()
        if not is_avail:
            raise FileNotFoundError(f"Nuclei cannot execute: {reason}")

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd = self.build_command(target_url, tmp_path)
            exit_code, stdout, stderr = self.execute_subprocess(cmd, timeout=timeout)
            
            if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                with open(tmp_path, "rb") as f:
                    return f.read()

            # Some versions emit JSONL strictly to stdout
            if stdout and stdout.strip():
                return stdout

            # Clean scan returning 0 findings is an empty byte string (valid)
            return b""
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
