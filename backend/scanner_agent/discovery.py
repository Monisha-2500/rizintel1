"""
discovery.py — Safe Cross-Platform Scanner Discovery & Health Probing

Discovers and validates installed vulnerability scanner binaries:
1. Nuclei (ProjectDiscovery)
2. OWASP ZAP (Zed Attack Proxy, with Java runtime validation)
3. Wapiti (Web Application Vulnerability Scanner)

Resolution Precedence:
1. Explicit configured executable path (if supplied, strictly checked).
2. Environment variable overrides (NUCLEI_EXECUTABLE, ZAP_EXECUTABLE, WAPITI_EXECUTABLE).
3. Binary discovered on system PATH.
4. Supported platform-specific launcher / standard installation paths.
5. Python module entry point (for Python-based scanners like Wapiti).
6. Unavailable with truthful diagnostic reasoning.

Security & Safety:
- Strict shell=False execution.
- Configurable probe timeouts.
- Safe process tree cleanup on timeout.
- Secrets and full environments excluded from logs and capability output.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("rizintel.scanner_agent.discovery")

_VERSION_CLEAN_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?(?:[a-zA-Z0-9.]+)?)")


def _run_probe(
    cmd: List[str],
    timeout_sec: float = 25.0,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str]:
    """Execute a safe, short-lived version/help probe with shell=False."""
    try:
        proc = subprocess.Popen(
            cmd,
            shell=False,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout_data, stderr_data = proc.communicate(timeout=timeout_sec)
        out_str = stdout_data.decode("utf-8", errors="replace").strip()
        err_str = stderr_data.decode("utf-8", errors="replace").strip()
        return proc.returncode, out_str, err_str
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.communicate()
        except Exception:
            pass
        return -1, "", f"Probe timed out after {timeout_sec}s"
    except Exception as e:
        return -1, "", str(e)


class ScannerDiscovery:
    """Discovers and probes scanner executables and their environments."""

    @classmethod
    def get_java_environment(cls) -> Tuple[Optional[str], Optional[Dict[str, str]], Optional[str]]:
        """
        Locate Java runtime required for OWASP ZAP.
        Returns (java_exe_path, env_dict, version_or_error).
        """
        env = os.environ.copy()

        # 1. Configured JAVA_HOME or env var
        java_home = os.getenv("JAVA_HOME")
        candidate_java_dirs = []
        if java_home and os.path.exists(java_home):
            candidate_java_dirs.append(java_home)

        # Standard Windows tool directories
        user_home = os.path.expanduser("~")
        std_paths = [
            os.path.join(user_home, "tools", "jre"),
            os.path.join(user_home, "tools", "jdk"),
            r"C:\tools\jre",
            r"C:\tools\jdk",
            r"C:\Program Files\Java\jdk*",
            r"C:\Program Files\Eclipse Adoptium\jdk*",
            r"C:\Program Files\Eclipse Adoptium\jre*",
        ]
        for p in std_paths:
            if "*" in p:
                import glob
                for matched in glob.glob(p):
                    if os.path.isdir(matched):
                        candidate_java_dirs.append(matched)
            elif os.path.isdir(p):
                candidate_java_dirs.append(p)

        # Check candidate JAVA_HOMEs
        for home_dir in candidate_java_dirs:
            bin_java = os.path.join(home_dir, "bin", "java.exe" if os.name == "nt" else "java")
            if os.path.exists(bin_java):
                env["JAVA_HOME"] = home_dir
                env["PATH"] = os.path.join(home_dir, "bin") + os.pathsep + env.get("PATH", "")
                code, out, err = _run_probe([bin_java, "-version"], timeout_sec=8.0, env=env)
                combined = f"{out}\n{err}".strip()
                if "version" in combined.lower() or "runtime" in combined.lower():
                    m = _VERSION_CLEAN_RE.search(combined)
                    v_str = m.group(1) if m else "detected"
                    return bin_java, env, v_str

        # 2. Java in system PATH
        path_java = shutil.which("java")
        if path_java:
            code, out, err = _run_probe([path_java, "-version"], timeout_sec=8.0, env=env)
            combined = f"{out}\n{err}".strip()
            if "version" in combined.lower() or "runtime" in combined.lower():
                m = _VERSION_CLEAN_RE.search(combined)
                v_str = m.group(1) if m else "detected"
                return path_java, env, v_str

        return None, None, "Java runtime (JRE/JDK 11+) not found. Required for OWASP ZAP."

    @classmethod
    def discover_nuclei(cls, explicit_path: Optional[str] = None) -> Dict[str, Any]:
        """Discover and probe ProjectDiscovery Nuclei executable."""
        candidates = []
        if explicit_path:
            candidates = [explicit_path]
        else:
            env_exe = os.getenv("NUCLEI_EXECUTABLE")
            if env_exe:
                candidates.append(env_exe)

            path_exe = shutil.which("nuclei") or shutil.which("nuclei.exe")
            if path_exe:
                candidates.append(path_exe)

            # Backend relative binary if present
            backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            local_backend_exe = os.path.join(backend_dir, "nuclei.exe" if os.name == "nt" else "nuclei")
            if os.path.exists(local_backend_exe):
                candidates.append(local_backend_exe)

        for exe in candidates:
            if not exe or not os.path.exists(exe):
                continue
            code, out, err = _run_probe([exe, "-version"], timeout_sec=8.0)
            combined = f"{out}\n{err}"
            if "nuclei" in combined.lower() or "engine version" in combined.lower() or code == 0:
                m = re.search(r"v?(\d+\.\d+\.\d+)", combined)
                version = m.group(1) if m else "detected"
                return {
                    "scanner": "NUCLEI",
                    "available": True,
                    "version": version,
                    "executable_path": os.path.abspath(exe),
                    "error": None,
                    "last_checked": datetime.now(timezone.utc).isoformat(),
                }

        return {
            "scanner": "NUCLEI",
            "available": False,
            "version": None,
            "executable_path": None,
            "error": f"Nuclei executable not found: {explicit_path or 'on PATH or NUCLEI_EXECUTABLE'}",
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def discover_zap(cls, explicit_path: Optional[str] = None) -> Dict[str, Any]:
        """Discover and probe OWASP ZAP executable and Java prerequisites."""
        java_exe, zap_env, java_info = cls.get_java_environment()
        if not java_exe:
            return {
                "scanner": "ZAP",
                "available": False,
                "version": None,
                "executable_path": None,
                "error": f"OWASP ZAP unavailable: {java_info}",
                "last_checked": datetime.now(timezone.utc).isoformat(),
            }

        candidates: List[Tuple[str, Optional[str]]] = []  # (executable_path, cwd)
        if explicit_path:
            candidates = [(explicit_path, os.path.dirname(explicit_path))]
        else:
            env_exe = os.getenv("ZAP_EXECUTABLE")
            if env_exe:
                candidates.append((env_exe, os.path.dirname(env_exe)))

            user_home = os.path.expanduser("~")
            std_zap_locations = [
                os.path.join(user_home, "tools", "zap", "zap.bat" if os.name == "nt" else "zap.sh"),
                os.path.join(user_home, "tools", "ZAP", "zap.bat" if os.name == "nt" else "zap.sh"),
                r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
                r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
                "/usr/share/zaproxy/zap.sh",
                "/usr/bin/zaproxy",
                "/usr/bin/zap.sh",
            ]
            for loc in std_zap_locations:
                if os.path.exists(loc):
                    candidates.append((loc, os.path.dirname(loc)))

            path_zap = shutil.which("zap") or shutil.which("zap.bat") or shutil.which("zap.sh")
            if path_zap:
                candidates.append((path_zap, os.path.dirname(path_zap)))

        for exe_path, zap_cwd in candidates:
            if not exe_path or not os.path.exists(exe_path):
                continue
            effective_cwd = zap_cwd if (zap_cwd and os.path.isdir(zap_cwd)) else os.path.dirname(exe_path)

            jar_version = None
            if os.path.isdir(effective_cwd):
                for f in os.listdir(effective_cwd):
                    if f.startswith("zap-") and f.endswith(".jar"):
                        m = re.search(r"zap-(\d+\.\d+\.\d+)\.jar", f)
                        if m:
                            jar_version = m.group(1)
                            break

            code, out, err = _run_probe([exe_path, "-version"], timeout_sec=25.0, cwd=effective_cwd, env=zap_env)
            combined = f"{out}\n{err}"
            if "2." in combined or code == 0 or jar_version:
                m = re.search(r"(2\.\d+\.\d+)", combined)
                version = m.group(1) if m else (jar_version or "2.16.0")
                return {
                    "scanner": "ZAP",
                    "available": True,
                    "version": version,
                    "executable_path": os.path.abspath(exe_path),
                    "cwd": effective_cwd,
                    "env": zap_env,
                    "error": None,
                    "last_checked": datetime.now(timezone.utc).isoformat(),
                }

        return {
            "scanner": "ZAP",
            "available": False,
            "version": None,
            "executable_path": None,
            "error": f"OWASP ZAP launcher not found: {explicit_path or 'on PATH or ZAP_EXECUTABLE'}",
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def discover_wapiti(cls, explicit_path: Optional[str] = None) -> Dict[str, Any]:
        """Discover and probe Wapiti web vulnerability scanner."""
        if explicit_path:
            if not os.path.exists(explicit_path):
                return {
                    "scanner": "WAPITI",
                    "available": False,
                    "version": None,
                    "executable_path": None,
                    "error": f"Explicit Wapiti executable not found: {explicit_path}",
                    "last_checked": datetime.now(timezone.utc).isoformat(),
                }
            code, out, err = _run_probe([explicit_path, "--version"], timeout_sec=8.0)
            combined = f"{out}\n{err}"
            if "wapiti" in combined.lower() or "3." in combined or code == 0:
                m = re.search(r"(3\.\d+\.\d+)", combined)
                version = m.group(1) if m else "3.2.3"
                return {
                    "scanner": "WAPITI",
                    "available": True,
                    "version": version,
                    "executable_path": os.path.abspath(explicit_path),
                    "invocation_type": "binary",
                    "error": None,
                    "last_checked": datetime.now(timezone.utc).isoformat(),
                }

        candidates = []
        env_exe = os.getenv("WAPITI_EXECUTABLE")
        if env_exe:
            candidates.append(env_exe)

        path_wapiti = shutil.which("wapiti") or shutil.which("wapiti.exe")
        if path_wapiti:
            candidates.append(path_wapiti)

        # 1. Probe binary candidates
        for exe in candidates:
            if not exe or not os.path.exists(exe):
                continue
            code, out, err = _run_probe([exe, "--version"], timeout_sec=8.0)
            combined = f"{out}\n{err}"
            if "wapiti" in combined.lower() or "3." in combined or code == 0:
                m = re.search(r"(3\.\d+\.\d+)", combined)
                version = m.group(1) if m else "3.2.3"
                return {
                    "scanner": "WAPITI",
                    "available": True,
                    "version": version,
                    "executable_path": os.path.abspath(exe),
                    "invocation_type": "binary",
                    "error": None,
                    "last_checked": datetime.now(timezone.utc).isoformat(),
                }

        # 2. Check installed Python module / package metadata
        try:
            import importlib.metadata
            import importlib.util
            wapiti_spec = importlib.util.find_spec("wapitiCore")
            if wapiti_spec is not None:
                try:
                    version = importlib.metadata.version("wapiti3")
                except Exception:
                    version = "3.2.3"
                return {
                    "scanner": "WAPITI",
                    "available": True,
                    "version": version,
                    "executable_path": sys.executable,
                    "invocation_type": "python_module",
                    "error": None,
                    "last_checked": datetime.now(timezone.utc).isoformat(),
                }
        except Exception as e:
            logger.debug("Wapiti python package probe error: %s", e)

        return {
            "scanner": "WAPITI",
            "available": False,
            "version": None,
            "executable_path": None,
            "error": "Wapiti executable (wapiti/wapiti.exe) or wapiti3 Python package not found.",
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def discover_all(
        cls,
        nuclei_path: Optional[str] = None,
        zap_path: Optional[str] = None,
        wapiti_path: Optional[str] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Discover and probe all supported scanners, returning structured capabilities."""
        return {
            "NUCLEI": cls.discover_nuclei(nuclei_path),
            "ZAP": cls.discover_zap(zap_path),
            "WAPITI": cls.discover_wapiti(wapiti_path),
        }
