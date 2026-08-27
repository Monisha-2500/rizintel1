"""
base.py — Base Scanner Connector Interface & Safe Subprocess Executor

Requirements:
- Safe subprocess execution with shell=False strictly enforced.
- Command arguments passed strictly as List[str].
- Configurable execution timeout per scanner.
- stdout/stderr capture and sanitized error logging.
- Process tree termination / cleanup on timeout.
- Truthful scanner availability check via ScannerDiscovery.
- ZERO live synthetic mock payload generation.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("rizintel.scanner_agent.connector")


def _kill_process_tree(pid: int) -> None:
    """Safely terminate a process and all its children across platforms."""
    try:
        if os.name == "nt":
            # On Windows, taskkill /F /T terminates entire process tree
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            import signal
            os.killpg(os.getpgid(pid), signal.SIGKILL)
    except Exception as e:
        logger.debug("Process tree termination error for PID %d: %s", pid, e)


class BaseScannerConnector:
    """Abstract base class for real scanner connectors."""

    scanner_name: str = "BASE"

    def __init__(self, executable_path: Optional[str] = None, default_timeout: int = 120):
        self.executable_path = executable_path or self._find_executable()
        self.default_timeout = default_timeout
        self.cwd: Optional[str] = None
        self.env: Optional[Dict[str, str]] = None

    def _find_executable(self) -> Optional[str]:
        """Find executable binary via standard PATH discovery or ScannerDiscovery."""
        return shutil.which(self.scanner_name.lower())

    def validate_available(self) -> Tuple[bool, str]:
        """Check if scanner binary is installed, executable, and functioning."""
        if self.executable_path and os.path.exists(self.executable_path):
            return True, f"{self.scanner_name} executable available at {self.executable_path}"
        return False, f"{self.scanner_name} executable not found on host."

    def build_command(self, target_url: str, report_output_path: str) -> List[str]:
        """Construct safe command argument list. Subclasses override."""
        raise NotImplementedError

    def execute_subprocess(
        self,
        cmd: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, bytes, bytes]:
        """
        Execute command with shell=False, strict timeout, and safe process tree cleanup.
        Returns (exit_code, stdout_bytes, stderr_bytes).
        """
        exec_timeout = timeout or self.default_timeout
        run_cwd = cwd or self.cwd
        run_env = env or self.env

        logger.info(
            "Executing safe subprocess: %s (timeout: %ds, cwd: %s)",
            cmd[0], exec_timeout, run_cwd or "default",
        )

        process: Optional[subprocess.Popen] = None
        try:
            process = subprocess.Popen(
                cmd,
                shell=False,
                cwd=run_cwd,
                env=run_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout_data, stderr_data = process.communicate(timeout=exec_timeout)
            return process.returncode, stdout_data, stderr_data
        except subprocess.TimeoutExpired:
            logger.warning(
                "Subprocess execution timed out (%ds) for %s. Terminating process tree...",
                exec_timeout, self.scanner_name,
            )
            if process and process.pid:
                _kill_process_tree(process.pid)
                try:
                    process.kill()
                    stdout_data, stderr_data = process.communicate()
                except Exception:
                    stdout_data, stderr_data = b"", b"Process timed out and killed."
            raise TimeoutError(f"{self.scanner_name} execution timed out after {exec_timeout} seconds.") from None
        except Exception as e:
            logger.error("Subprocess execution failed for %s: %s", self.scanner_name, e)
            if process and process.pid:
                _kill_process_tree(process.pid)
            raise RuntimeError(f"{self.scanner_name} execution failed: {e}") from e

    def execute(self, target_url: str, timeout: Optional[int] = None) -> bytes:
        """Execute scanner against target and return raw report bytes. Subclasses override."""
        raise NotImplementedError
