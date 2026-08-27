"""
zap.py
------
Rebuilt against a REAL ZAP report (WebGoat scan), not a guessed sample.

Real structure:
report
  └─ site[]                      (one per scanned host)
       @name, @host, @port, @ssl
       alerts[]                  (one per vulnerability TYPE found)
            pluginid, alertRef, alert, name, riskcode, confidence,
            riskdesc ("High (Medium)"), desc (HTML), solution (HTML),
            reference (HTML), cweid, wascid, sourceid, count
            instances[]          (one per exact URL/param it was found on)
                 id, uri, nodeName, method, param, attack, evidence, otherinfo

Important real-world correction vs assumption: ZAP essentially NEVER
populates a literal CVE id. What it reliably gives you is a CWE id
(cweid) — that's why the schema has a dedicated `cwe` field.
"""

import json
import re
from datetime import datetime
from typing import List

from schema import StandardFinding, Severity, generate_source_id
from scanner_adapters.base import BaseAdapter, register_adapter

# ZAP riskcode: "0"-"3"
_ZAP_SEVERITY_MAP = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}

_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    """ZAP's desc/solution/reference fields are HTML (<p>...</p>). Strip tags for a clean description."""
    if not text:
        return ""
    return _HTML_TAG_RE.sub(" ", text).replace("&nbsp;", " ").strip()


@register_adapter("ZAP")
class ZapAdapter(BaseAdapter):
    scanner_name = "ZAP"

    def parse(self, raw_data: str) -> List[StandardFinding]:
        findings = []
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as e:
            print(f"[ZapAdapter] Failed to parse JSON: {e}")
            return findings

        sites = data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            host = site.get("@name") or site.get("@host", "unknown-host")
            site_port = str(site.get("@port") or "").strip()

            for alert in site.get("alerts", []):
                vuln_name = alert.get("name") or alert.get("alert", "Unnamed ZAP Alert")
                riskcode = str(alert.get("riskcode", "0"))
                severity = _ZAP_SEVERITY_MAP.get(riskcode, Severity.INFO)

                cwe = alert.get("cweid")
                cwe = None if cwe in (None, "", "-1") else cwe
                cve = self._extract_cve_if_any(alert.get("reference", ""))

                description = _strip_html(alert.get("desc", ""))
                solution = _strip_html(alert.get("solution", ""))

                instances = alert.get("instances") or [{}]
                # Track seen canonical keys within this alert to detect truly identical instances
                # that ZAP emits more than once (same url+param+evidence+method+attack)
                _seen_instance_keys: set = set()
                for inst in instances:
                    url = inst.get("uri", host)
                    param = inst.get("param") or None
                    evidence = inst.get("evidence") or inst.get("attack") or None
                    method = (inst.get("method") or "GET").upper()
                    inst_id = str(inst.get("id") or "").strip()

                    # Extract query string from URL for identity: /login?error ≠ /login
                    from urllib.parse import urlparse as _urlparse
                    _parsed_url = _urlparse(url)
                    query_part = _parsed_url.query.strip()  # e.g. "error" or ""

                    # ZAP identity: full URL (query string included) + param + method
                    # param is a stable per-instance field (header name, cookie, request param)
                    # query_part differentiates /login vs /login?error
                    canonical_key = f"{url}|{param}|{method}|{evidence}"
                    if canonical_key in _seen_instance_keys:
                        # Genuinely identical instance emitted by ZAP: use inst_id as final tiebreaker
                        discriminator = f"{param or ''}|{query_part}|{inst_id}"
                    else:
                        _seen_instance_keys.add(canonical_key)
                        # discriminator = param + query part: distinguishes same-path instances
                        discriminator = f"{param or ''}|{query_part}"



                    try:
                        findings.append(StandardFinding(
                            finding_id=generate_source_id(
                                scanner="ZAP",
                                host=url,
                                vuln_name=vuln_name,
                                endpoint=self._extract_endpoint(url),
                                port=site_port,
                                discriminator=discriminator,
                            ),
                            scanner="ZAP",
                            cve=cve,
                            cwe=cwe,
                            vulnerability_name=vuln_name,
                            severity=severity,
                            host=host,
                            endpoint=self._extract_endpoint(url),
                            parameter=param,
                            description=description,
                            evidence=evidence,
                            timestamp=datetime.utcnow(),
                            raw_severity=alert.get("riskdesc", riskcode),
                            extra_fields={
                                "pluginid": alert.get("pluginid"),
                                "wascid": alert.get("wascid"),
                                "confidence": alert.get("confidence"),
                                "method": method,
                                "solution": solution,
                            },
                        ))
                    except Exception as e:
                        print(f"[ZapAdapter] Skipped malformed finding '{vuln_name}': {e}")

        return findings

    @staticmethod
    def _extract_cve_if_any(reference: str) -> str:
        # Rare in ZAP, but if a CVE ever appears in the reference links, grab it.
        match = re.search(r"CVE-\d{4}-\d{4,7}", reference or "", re.IGNORECASE)
        return match.group(0).upper() if match else None

    @staticmethod
    def _extract_endpoint(url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url).path or "/"
        except Exception:
            return url
