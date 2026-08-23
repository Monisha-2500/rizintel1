"""
nuclei.py
---------
Rebuilt against a REAL Nuclei report (WebGoat scan), not a guessed sample.

Real structure: a JSON array (not JSONL in this export), each record:
{
  "template-id": "springboot-health",
  "info": {
      "name", "severity" (lowercase: info/low/medium/high/critical),
      "description",
      "classification": { "cve-id": [...] or null, "cwe-id": [...], "cvss-metrics": "..." }
  },
  "host", "port", "scheme", "url", "path",
  "matched-at":     <- the exact URL the finding was confirmed on
  "ip", "timestamp",
  "request", "response",   <- raw HTTP, good evidence field
  "matcher-status"
}

Real-world note: in this WebGoat scan, classification.cve-id was null for
every single finding (all misconfig/info-disclosure/fingerprinting
templates) — confirming cve should stay optional, and that cwe-id is the
field that's actually populated here.
"""

import json
from datetime import datetime
from typing import List

from schema import StandardFinding, Severity, generate_finding_id
from scanner_adapters.base import BaseAdapter, register_adapter

_NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@register_adapter("Nuclei")
class NucleiAdapter(BaseAdapter):
    scanner_name = "Nuclei"

    def parse(self, raw_data: str) -> List[StandardFinding]:
        records = self._load_records(raw_data)
        findings = []

        for rec in records:
            try:
                info = rec.get("info", {})
                vuln_name = info.get("name", "Unnamed Nuclei Finding")
                severity = _NUCLEI_SEVERITY_MAP.get(
                    (info.get("severity") or "info").lower(), Severity.INFO
                )

                classification = info.get("classification") or {}
                cve = self._first_or_none(classification.get("cve-id"))
                cwe = self._first_or_none(classification.get("cwe-id"))

                host = rec.get("host", "unknown-host")
                matched_at = rec.get("matched-at") or rec.get("url") or host
                evidence = self._build_evidence(rec)

                findings.append(StandardFinding(
                    finding_id=generate_finding_id("Nuclei", matched_at, vuln_name, "", ""),
                    scanner="Nuclei",
                    cve=cve,
                    cwe=cwe,
                    vulnerability_name=vuln_name,
                    severity=severity,
                    host=host,
                    endpoint=self._extract_endpoint(matched_at),
                    parameter=None,  # Nuclei templates don't isolate a single request parameter
                    description=info.get("description", ""),
                    evidence=evidence,
                    timestamp=self._parse_timestamp(rec.get("timestamp")),
                    raw_severity=info.get("severity"),
                    extra_fields={
                        "template_id": rec.get("template-id"),
                        "tags": info.get("tags"),
                        "cvss_metrics": classification.get("cvss-metrics"),
                        "matcher_status": rec.get("matcher-status"),
                    },
                ))
            except Exception as e:
                print(f"[NucleiAdapter] Skipped malformed record: {e}")

        return findings

    @staticmethod
    def _first_or_none(value):
        """classification fields are sometimes a list, sometimes null, sometimes a bare string."""
        if not value:
            return None
        if isinstance(value, list):
            return value[0] if value else None
        return value

    @staticmethod
    def _build_evidence(rec: dict) -> str:
        # No dedicated "evidence" field in real nuclei output — the matched
        # response snippet is the closest equivalent. Keep it short.
        response = rec.get("response", "")
        if response:
            return response[:300]
        return rec.get("curl-command", "")[:300] or None

    @staticmethod
    def _load_records(raw_data: str) -> List[dict]:
        raw_data = raw_data.strip()
        if not raw_data:
            return []
        try:
            parsed = json.loads(raw_data)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass
        # Fall back to JSON Lines in case a different export mode is used
        records = []
        for line in raw_data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[NucleiAdapter] Skipped bad JSON line: {e}")
        return records

    @staticmethod
    def _parse_timestamp(ts_raw) -> datetime:
        if not ts_raw:
            return datetime.utcnow()
        # Real nuclei timestamps look like: 2026-08-14T15:50:43.0993757+05:30
        # Python's strptime chokes on 7-digit microseconds, so trim to 6.
        try:
            if "." in ts_raw:
                head, tail = ts_raw.split(".", 1)
                frac, _, tz = tail.partition("+")
                tz = "+" + tz if tz else ""
                if not tz and "-" in tail[len(frac):]:
                    frac, _, tz = tail.partition("-")
                    tz = "-" + tz if tz else ""
                ts_raw = f"{head}.{frac[:6]}{tz}"
            return datetime.fromisoformat(ts_raw)
        except Exception:
            return datetime.utcnow()

    @staticmethod
    def _extract_endpoint(url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url).path or "/"
        except Exception:
            return url
