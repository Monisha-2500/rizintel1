"""
config.py — Scanner Agent Configuration

Provides centralized configuration for the scanner agent daemon and CLI tools.
Supports environment variable overrides for cross-platform scanner discovery and execution timeouts.
"""

from __future__ import annotations

import os
from typing import Optional


class AgentConfig:
    def __init__(self):
        self.server_url: str = os.getenv("RIZINTEL_SERVER_URL", "http://localhost:8000").rstrip("/")
        self.agent_token: str = os.getenv("RIZINTEL_AGENT_TOKEN", "")
        self.max_concurrent_scans: int = int(os.getenv("MAX_CONCURRENT_SCANS", "1"))
        self.poll_interval_seconds: float = float(os.getenv("POLL_INTERVAL_SECONDS", "2.0"))
        
        # Global & scanner-specific timeouts
        self.default_timeout_seconds: int = int(os.getenv("SCANNER_TIMEOUT_SECONDS", "120"))
        self.nuclei_timeout_seconds: int = int(os.getenv("NUCLEI_SCAN_TIMEOUT_SECONDS", str(self.default_timeout_seconds)))
        self.zap_timeout_seconds: int = int(os.getenv("ZAP_SCAN_TIMEOUT_SECONDS", "300"))
        self.wapiti_timeout_seconds: int = int(os.getenv("WAPITI_SCAN_TIMEOUT_SECONDS", str(self.default_timeout_seconds)))

        # Explicit executable paths (optional, overrides PATH discovery)
        self.nuclei_executable: Optional[str] = os.getenv("NUCLEI_EXECUTABLE")
        self.zap_executable: Optional[str] = os.getenv("ZAP_EXECUTABLE")
        self.wapiti_executable: Optional[str] = os.getenv("WAPITI_EXECUTABLE")
        self.java_home: Optional[str] = os.getenv("JAVA_HOME")

    def get_timeout_for_scanner(self, scanner: str) -> int:
        """Return scanner-specific timeout in seconds."""
        s = scanner.upper()
        if s == "ZAP":
            return self.zap_timeout_seconds
        elif s == "NUCLEI":
            return self.nuclei_timeout_seconds
        elif s == "WAPITI":
            return self.wapiti_timeout_seconds
        return self.default_timeout_seconds

    def validate(self) -> None:
        if not self.agent_token:
            raise ValueError("RIZINTEL_AGENT_TOKEN environment variable must be set.")
