"""
wapiti.py
---------
Built against a REAL Wapiti report (Juice Shop scan).

Real structure — genuinely different shape from ZAP/Nuclei:
{
  "infos": { "target": "...", "date": "Thu, 20 Aug 2026 14:35:14 +0000", ... },
  "classifications": {
      "<Vuln Type Name>": { "desc": "...", "sol": "...", "ref": {"CWE-319: ...": "url", ...}, "wstg": [...] },
      ...
  },
  "vulnerabilities": {
      "<Vuln Type Name>": [
          { "method", "path", "info", "level", "parameter", "http_request", "curl_command", "wstg": [...] },
          ...
      ],
      ...
  }
}

Key differences from ZAP/Nuclei that shaped this adapter:
- Findings are GROUPED BY vulnerability type name (a dict), not a flat list.
  Each type can have 0, 1, or many actual detected instances.
- Description/CWE/CVE data is NOT inside each finding — it lives in a
  SEPARATE parallel dict (`classifications`), keyed by the same type name.
  So we look each finding's type name up in `classifications` to enrich it.
- CVE/CWE aren't dedicated fields at all — they show up as substrings
  inside `classifications[type]["ref"]` keys (e.g. "CWE-319: Cleartext...")
  or occasionally as the vulnerability type name itself (e.g. "CVE-2024-55591",
  "Log4Shell", "Spring4Shell" are literal top-level vulnerability types in Wapiti).
- There's ONE global scan timestamp (infos.date) shared by every finding,
  not a per-finding timestamp.
"""

import json
import re
from datetime import datetime
from typing import List, Optional

from schema import StandardFinding, Severity, generate_source_id
from scanner_adapters.base import BaseAdapter, register_adapter

# Wapiti's "level" is an integer, 1-3 in practice (occasionally higher).
# Wapiti's own docs treat these as roughly: 1=Low/Info, 2=Medium, 3=High.
_WAPITI_LEVEL_MAP = {
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


@register_adapter("Wapiti")
class WapitiAdapter(BaseAdapter):
    scanner_name = "Wapiti"

    def parse(self, raw_data: str) -> List[StandardFinding]:
        findings = []
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as e:
            print(f"[WapitiAdapter] Failed to parse JSON: {e}")
            return findings

        infos = data.get("infos", {})
        host = infos.get("target", "unknown-host")
        timestamp = self._parse_timestamp(infos.get("date"))

        classifications = data.get("classifications", {})
        vulnerabilities = data.get("vulnerabilities", {})

        for vuln_type, instances in vulnerabilities.items():
            if not instances:
                continue  # this vuln type was checked but nothing was found

            classification = classifications.get(vuln_type, {})
            description = classification.get("desc", "")
            cve = self._extract_cve(vuln_type, classification)
            cwe = self._extract_cwe(classification)

            for inst in instances:
                try:
                    path = inst.get("path", "/")
                    param = inst.get("parameter") or None
                    level = inst.get("level", 1)
                    severity = _WAPITI_LEVEL_MAP.get(level, Severity.INFO)

                    # Extract port from host URL if available
                    _port = ""
                    if "://" in host:
                        from urllib.parse import urlparse
                        _parsed = urlparse(host)
                        _port = str(_parsed.port) if _parsed.port else ""

                    findings.append(StandardFinding(
                        finding_id=generate_source_id(
                            scanner="WAPITI",
                            host=host,
                            vuln_name=vuln_type,
                            endpoint=path,
                            port=_port,
                            discriminator=param or "",
                        ),
                        scanner="Wapiti",
                        cve=cve,
                        cwe=cwe,
                        vulnerability_name=vuln_type,
                        severity=severity,
                        host=host,
                        endpoint=path,
                        parameter=param,
                        description=description or inst.get("info", ""),
                        evidence=inst.get("info"),
                        timestamp=timestamp,
                        raw_severity=str(level),
                        extra_fields={
                            "module": inst.get("module"),
                            "method": inst.get("method"),
                            "wstg": inst.get("wstg"),
                            "curl_command": inst.get("curl_command"),
                        },
                    ))
                except Exception as e:
                    print(f"[WapitiAdapter] Skipped malformed instance of '{vuln_type}': {e}")

        return findings

    @staticmethod
    def _extract_cve(vuln_type: str, classification: dict) -> Optional[str]:
        # Wapiti sometimes names the vulnerability type AFTER a specific CVE
        # (e.g. "CVE-2024-55591" is literally a vuln_type name in this report).
        match = _CVE_RE.search(vuln_type)
        if match:
            return match.group(0).upper()
        # Otherwise check the reference links for a CVE mention.
        ref_keys = " ".join(classification.get("ref", {}).keys())
        match = _CVE_RE.search(ref_keys)
        return match.group(0).upper() if match else None

    @staticmethod
    def _extract_cwe(classification: dict) -> Optional[str]:
        ref_keys = " ".join(classification.get("ref", {}).keys())
        match = _CWE_RE.search(ref_keys)
        return match.group(0).upper() if match else None

    @staticmethod
    def _parse_timestamp(date_str) -> datetime:
        # Format seen in real reports: "Thu, 20 Aug 2026 14:35:14 +0000"
        if not date_str:
            return datetime.utcnow()
        try:
            return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z")
        except ValueError:
            return datetime.utcnow()
