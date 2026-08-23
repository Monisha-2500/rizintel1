"""
Small deterministic helpers shared across services.

Includes the priority mapping -- deliberately kept OUT of the LLM path
and out of the fallback templates, and instead lives here as one single
source of truth, so "priority" can never diverge from M5's risk_level.
"""

from __future__ import annotations

from datetime import datetime, timezone

# PROPOSED IMPLEMENTATION DECISION: the PS4 contract's Section 9 example
# shows only "IMMEDIATE" as a priority value, with no full enum specified.
# This deterministic mapping from M5's risk_level is the smallest
# reasonable decision that (a) never lets an LLM invent urgency and
# (b) stays consistent with risk_level, which M6 must not override.
_PRIORITY_MAP = {
    "CRITICAL": "IMMEDIATE",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFORMATIONAL": "LOW",
}


def map_risk_level_to_priority(risk_level: str) -> str:
    return _PRIORITY_MAP.get((risk_level or "").upper(), "MEDIUM")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_references(cve_id: str | None) -> list[str]:
    """
    PROPOSED IMPLEMENTATION DECISION: the contract's example shows an empty
    references list with no source specified. Rather than leaving this
    always empty or fabricating remediation links, we deterministically
    construct a factual NVD lookup URL from the CVE ID when present --
    this is a lookup-key transformation, not invented content.
    """
    if not cve_id:
        return []
    return [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
