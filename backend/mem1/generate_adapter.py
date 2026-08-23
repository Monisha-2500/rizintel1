#!/usr/bin/env python3
"""
generate_adapter.py
--------------------
THE piece that answers "instead of me writing zap.py by hand every time,
can a script look at a new scanner's report and draft the adapter for me?"

What it does:
1. Reads a sample report from a scanner you DON'T have an adapter for yet.
2. Finds the list of "finding" records inside it (heuristic).
3. Looks at every field name in one record and guesses which universal
   schema field it corresponds to, using a synonym dictionary
   (e.g. "riskcode", "threat", "priority" all → severity).
4. Writes out a DRAFT adapter .py file with those guesses filled in,
   clearly marked with confidence levels and TODOs.

What it deliberately does NOT do:
- It does not register the draft automatically or wire it into the
  pipeline. A human must review it, fix any wrong/low-confidence
  guesses, then drop it into scanner_adapters/ themselves.
- This is intentional: field-name similarity is a good starting guess,
  not proof of correct meaning (e.g. a field literally called "severity"
  might use a totally different scale than your schema expects).

Usage:
  python3 generate_adapter.py new_scanner_report.json --name Trivy
"""

import argparse
import json
import re
from pathlib import Path

# Each schema field maps to a list of field-name fragments that commonly
# mean the same thing across different scanners. Matching is case-insensitive
# substring matching, ordered by how confident a match on that fragment is.
FIELD_SYNONYMS = {
    "vulnerability_name": ["vulnerability_name", "vulnerability", "alert", "name", "title", "check_name", "rule_id", "issue"],
    "severity":           ["severity", "risk", "riskcode", "threat", "priority", "level"],
    "cve":                ["cve-id", "cveid", "cve_id", "cve"],
    "cwe":                ["cwe-id", "cweid", "cwe_id", "cwe"],
    "host":                ["host", "target", "ip", "hostname"],
    "endpoint":            ["endpoint", "path", "uri", "url", "matched-at", "matched_at", "location"],
    "parameter":           ["parameter", "param", "field", "input"],
    "description":         ["description", "desc", "summary", "details"],
    "evidence":            ["evidence", "matcher", "proof", "snippet", "response"],
    "timestamp":           ["timestamp", "date", "time", "scanned_at", "created"],
}


def find_record_list(data, path="root"):
    """
    Heuristic: find the list-of-dicts inside the JSON that most likely
    represents "one finding per item". Picks the largest such list found
    at any depth (findings lists are usually the biggest list in a report).
    """
    candidates = []

    def walk(node, current_path):
        if isinstance(node, list) and node and all(isinstance(x, dict) for x in node):
            candidates.append((current_path, node))
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{current_path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node[:3]):  # don't explode on huge lists
                walk(v, f"{current_path}[{i}]")

    walk(data, path)
    if not candidates:
        return None, []
    # Prefer the largest list — most likely to be "one entry per finding"
    best_path, best_list = max(candidates, key=lambda c: len(c[1]))
    return best_path, best_list


def flatten_keys(d, prefix=""):
    """Flattens nested dict keys into dot-paths, e.g. info.severity"""
    flat = {}
    for k, v in d.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            flat.update(flatten_keys(v, full_key))
        else:
            flat[full_key] = v
    return flat


def guess_mapping(sample_record: dict) -> dict:
    """
    Returns { schema_field: (matched_raw_key, confidence) }
    confidence is "high" (exact/near match) or "low" (loose substring match),
    or the field is absent entirely if nothing matched.
    """
    flat = flatten_keys(sample_record)
    mapping = {}

    for schema_field, synonyms in FIELD_SYNONYMS.items():
        best_match = None
        best_confidence = None
        for raw_key in flat.keys():
            raw_key_lower = raw_key.lower().split(".")[-1]  # compare on the leaf key name
            for i, synonym in enumerate(synonyms):
                if raw_key_lower == synonym:
                    best_match, best_confidence = raw_key, "high"
                    break
                if synonym in raw_key_lower and best_match is None:
                    best_match, best_confidence = raw_key, "low"
            if best_confidence == "high":
                break
        if best_match:
            mapping[schema_field] = (best_match, best_confidence)

    return mapping


def generate_adapter_code(scanner_name: str, record_path: str, mapping: dict, sample_record: dict) -> str:
    class_name = re.sub(r"[^A-Za-z0-9]", "", scanner_name) + "Adapter"

    lines = []
    lines.append(f'"""')
    lines.append(f'{scanner_name.lower()}.py  —  DRAFT, auto-generated by generate_adapter.py')
    lines.append(f'')
    lines.append(f'Records were found at: {record_path}')
    lines.append(f'This is a STARTING POINT, not a finished adapter. Review every line below')
    lines.append(f'marked "# LOW CONFIDENCE" or "# TODO" before trusting this adapter\'s output.')
    lines.append(f'"""')
    lines.append("")
    lines.append("from datetime import datetime")
    lines.append("from typing import List")
    lines.append("from schema import StandardFinding, Severity, generate_finding_id")
    lines.append("from scanner_adapters.base import BaseAdapter, register_adapter")
    lines.append("")
    lines.append("# TODO: verify this severity mapping against real values seen in your reports.")
    lines.append("# These are guesses based on common conventions — CONFIRM before trusting.")
    lines.append("_SEVERITY_MAP = {")
    lines.append('    "critical": Severity.CRITICAL,')
    lines.append('    "high": Severity.HIGH,')
    lines.append('    "medium": Severity.MEDIUM,')
    lines.append('    "low": Severity.LOW,')
    lines.append('    "info": Severity.INFO,')
    lines.append("}")
    lines.append("")
    lines.append(f'@register_adapter("{scanner_name}")')
    lines.append(f"class {class_name}(BaseAdapter):")
    lines.append(f'    scanner_name = "{scanner_name}"')
    lines.append("")
    lines.append("    def parse(self, raw_data: str) -> List[StandardFinding]:")
    lines.append("        import json")
    lines.append("        findings = []")
    lines.append("        try:")
    lines.append("            data = json.loads(raw_data)")
    lines.append("        except json.JSONDecodeError as e:")
    lines.append(f'            print(f"[{class_name}] Failed to parse JSON: {{e}}")')
    lines.append("            return findings")
    lines.append("")
    lines.append(f"        # TODO: confirm this navigates to the records list correctly.")
    lines.append(f"        # Detected path during generation: {record_path}")
    lines.append("        records = data  # TODO: adjust indexing/navigation to reach the findings list")
    lines.append("")
    lines.append("        for rec in records:")
    lines.append("            try:")

    for schema_field in FIELD_SYNONYMS.keys():
        if schema_field in mapping:
            raw_key, confidence = mapping[schema_field]
            access = _build_access_expr(raw_key)
            comment = "" if confidence == "high" else "  # LOW CONFIDENCE — verify this"
            lines.append(f'                {schema_field}_val = {access}{comment}')
        else:
            lines.append(f'                {schema_field}_val = None  # TODO: no matching field found — map manually')

    lines.append("")
    lines.append("                findings.append(StandardFinding(")
    lines.append('                    finding_id=generate_finding_id("' + scanner_name + '", str(host_val), str(vulnerability_name_val), str(endpoint_val or ""), str(parameter_val or "")),')
    lines.append(f'                    scanner="{scanner_name}",')
    lines.append("                    cve=cve_val,")
    lines.append("                    cwe=cwe_val,")
    lines.append("                    vulnerability_name=str(vulnerability_name_val or 'Unnamed Finding'),")
    lines.append("                    # TODO: severity_val is currently the RAW value — map it through _SEVERITY_MAP")
    lines.append("                    severity=_SEVERITY_MAP.get(str(severity_val).lower(), Severity.INFO),")
    lines.append("                    host=str(host_val or 'unknown-host'),")
    lines.append("                    endpoint=endpoint_val,")
    lines.append("                    parameter=parameter_val,")
    lines.append("                    description=str(description_val or ''),")
    lines.append("                    evidence=evidence_val,")
    lines.append("                    timestamp=datetime.utcnow(),  # TODO: parse timestamp_val properly if present")
    lines.append("                    raw_severity=str(severity_val) if severity_val else None,")
    lines.append("                ))")
    lines.append("            except Exception as e:")
    lines.append(f'                print(f"[{class_name}] Skipped malformed record: {{e}}")')
    lines.append("")
    lines.append("        return findings")

    return "\n".join(lines)


def _build_access_expr(raw_key: str) -> str:
    """Turns a dot-path like 'info.severity' into rec.get('info', {}).get('severity')"""
    parts = raw_key.split(".")
    expr = "rec"
    for i, p in enumerate(parts):
        default = "{}" if i < len(parts) - 1 else "None"
        expr = f'{expr}.get("{p}", {default})' if expr == "rec" else f'({expr} or {{}}).get("{p}", {default})'
    return expr


def main():
    parser = argparse.ArgumentParser(description="Generate a DRAFT scanner adapter from a sample report.")
    parser.add_argument("report_file", help="Sample report from the new/unknown scanner")
    parser.add_argument("--name", required=True, help="Scanner name to register, e.g. Trivy")
    parser.add_argument("--out", default=None, help="Output .py path (default: scanner_adapters/<name>_draft.py)")
    args = parser.parse_args()

    raw = Path(args.report_file).read_text()
    data = json.loads(raw)

    record_path, records = find_record_list(data)
    if not records:
        print("[!] Could not find a list of findings in this report. This generator only handles JSON reports where findings appear as a list of similar dict objects.")
        return

    sample_record = records[0]
    mapping = guess_mapping(sample_record)

    print(f"Found {len(records)} candidate records at: {record_path}\n")
    print("Guessed field mapping:")
    for schema_field in FIELD_SYNONYMS.keys():
        if schema_field in mapping:
            raw_key, confidence = mapping[schema_field]
            print(f"  {schema_field:20} ← {raw_key:30} [{confidence} confidence]")
        else:
            print(f"  {schema_field:20} ← (no match found — needs manual mapping)")

    code = generate_adapter_code(args.name, record_path, mapping, sample_record)
    out_path = Path(args.out) if args.out else Path("scanner_adapters") / f"{args.name.lower()}_draft.py"
    out_path.write_text(code)

    print(f"\nDraft adapter written to: {out_path}")
    print("This is a STARTING POINT ONLY. Review every TODO/LOW CONFIDENCE line,")
    print("test it against a real report, then rename it (drop '_draft') to activate it.")


if __name__ == "__main__":
    main()
