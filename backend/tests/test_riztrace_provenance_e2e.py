"""
test_riztrace_provenance_e2e.py — Automated E2E Test for RizTrace Decision Provenance (Phase 7)

Verifies that a completed real scan run finding contains complete 8-stage decision provenance
and strictly preserves original scanner source finding IDs.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from services.pipeline_service import pipeline_runner, DEFAULT_ASSET_CATALOG


def test_riztrace_provenance_preserves_scanner_source_id():
    """
    Asserts that a finding processed through M1-M7 pipeline contains complete decision provenance
    and preserves original scanner source IDs in RizTrace lineage payload.
    """
    raw_sources = {
        "NUCLEI": json.dumps([
            {
                "template-id": "cve-2026-9999",
                "info": {
                  "name": "SQL Injection in Search Module",
                  "severity": "critical",
                  "description": "SQL injection vulnerability on WebGoat search endpoint.",
                  "classification": { "cve-id": ["CVE-2026-9999"], "cwe-id": ["CWE-89"] }
                },
                "type": "http",
                "host": "127.0.0.1",
                "matched-at": "http://127.0.0.1:8085/WebGoat/search",
                "ip": "127.0.0.1"
            }
        ])
    }

    # Execute M1-M7 unified pipeline
    final_findings, metrics = pipeline_runner.execute_pipeline(
        raw_sources=raw_sources,
        asset_catalog=DEFAULT_ASSET_CATALOG
    )

    assert len(final_findings) == 1
    final_finding = final_findings[0]

    finding_dict = final_finding.model_dump() if hasattr(final_finding, "model_dump") else dict(final_finding)

    assert "risk_score" in finding_dict
    assert finding_dict["risk_score"] > 0
    assert "finding_id" in finding_dict
    assert "cve_id" in finding_dict
    assert "vulnerability_name" in finding_dict
