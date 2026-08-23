"""
detect.py
---------
Looks at a raw report's content and guesses which scanner produced it,
based on structural fingerprints unique to each tool's export format.
This is what lets normalize.py accept ANY report file without the user
having to say "this one is ZAP, this one is Nuclei."

Detection strategy: cheap and reliable, not AI-based —
each known scanner format has a distinctive shape/keys that basically
never appears in another tool's output. If you add a new scanner adapter,
add one fingerprint function here too (few lines, same pattern).
"""

import json
import xml.etree.ElementTree as ET


def parse_multi_json(raw_data: str) -> list:
    """
    Parses NDJSON (one JSON value per line) OR "pretty-printed NDJSON"
    (each JSON value pretty-printed across multiple lines, concatenated
    back-to-back with no separator) into a list of Python objects.

    This is the shape Nuclei's `-json`/`-je` output takes: it's a stream
    of JSON objects, not a single JSON array. Tools/users often "pretty
    print" that stream (e.g. via jq) which keeps each record readable but
    spans multiple lines, so a plain json.loads() on the whole file fails
    with "Extra data" after the first record.

    Uses json.JSONDecoder.raw_decode in a loop, skipping whitespace
    between values, so it works whether records are one-per-line or
    pretty-printed across many lines.
    """
    decoder = json.JSONDecoder()
    records = []
    idx = 0
    length = len(raw_data)

    while idx < length:
        # Skip any whitespace (including newlines) between JSON values
        while idx < length and raw_data[idx].isspace():
            idx += 1
        if idx >= length:
            break
        try:
            obj, end_idx = decoder.raw_decode(raw_data, idx)
        except json.JSONDecodeError:
            # Not valid NDJSON either — give up
            return []
        records.append(obj)
        idx = end_idx

    return records


def detect_scanner_format(raw_data: str) -> str:
    """
    Returns the registered scanner name (e.g. "ZAP", "Nuclei", "OpenVAS")
    or None if the format isn't recognized.
    """
    raw_data = raw_data.strip()
    if not raw_data:
        return None

    # --- Try JSON-based formats first ---
    try:
        data = json.loads(raw_data)
        result = _detect_json_format(data)
        if result:
            return result
    except json.JSONDecodeError:
        pass

    # --- Try NDJSON / pretty-printed-multi-document JSON (e.g. raw Nuclei output) ---
    records = parse_multi_json(raw_data)
    if records:
        result = _detect_json_format(records)
        if result:
            return result

    # --- Try XML-based formats ---
    try:
        root = ET.fromstring(raw_data)
        return _detect_xml_format(root)
    except ET.ParseError:
        pass

    return None


def _detect_json_format(data) -> str:
    # ZAP: top-level dict with "site" -> list of {"alerts": [...]}
    if isinstance(data, dict) and "site" in data:
        sites = data.get("site")
        if isinstance(sites, list) and sites and "alerts" in sites[0]:
            return "ZAP"

    # Nuclei: array (or single object) of records each with "template-id" and "info"
    records = data if isinstance(data, list) else [data]
    if records and isinstance(records[0], dict):
        first = records[0]
        if "template-id" in first and "info" in first:
            return "Nuclei"
        
    # Wapiti: top-level dict with "vulnerabilities" (grouped by type) + "classifications" + "infos"
    if isinstance(data, dict) and "vulnerabilities" in data and "classifications" in data:
        return "Wapiti"

    return None


def _detect_xml_format(root) -> str:
    # OpenVAS: <report> root containing <results><result>...
    tag = root.tag.lower()
    if tag == "report" and root.find(".//result") is not None:
        return "OpenVAS"

    return None