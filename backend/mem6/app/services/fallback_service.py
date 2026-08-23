"""
Deterministic rule-based fallback.

Used when the LLM path is unavailable, times out, returns invalid JSON,
or fails validation. Must ALWAYS succeed and must NEVER compute a risk
score. Every sentence here is built only from fields present on the
RiskAssessedFinding -- if a field is missing, we say so explicitly rather
than omitting the gap silently (per Section 7 grounding rules).
"""

from __future__ import annotations

from app.models.input_models import RiskAssessedFinding
from app.services.llm_service import LLMExplanationResult


def _fmt(value, unit: str = "") -> str:
    return f"{value}{unit}" if value is not None else "not available"


def build_fallback_explanation(finding: RiskAssessedFinding) -> LLMExplanationResult:
    ra = finding.risk_assessment
    ac = finding.asset_context
    ti = finding.threat_intelligence
    sc = finding.scanner_consensus
    fc = finding.finding_confidence

    vuln_name = finding.vulnerability_name or "This finding"
    cve = finding.cve_id or "an unidentified CVE"
    asset_name = ac.asset_name or ac.asset_id

    # --- technical (security analyst view) -------------------------------
    tech_parts = [
        f"{vuln_name} ({cve}) on asset {asset_name} was scored "
        f"{ra.risk_score}/100 ({ra.risk_level}) by the risk engine (M5)."
    ]

    if ti:
        tech_parts.append(
            "Evidence: CVSS "
            + _fmt(ti.cvss_score)
            + (f" ({ti.cvss_vector})" if ti.cvss_vector else "")
            + ", EPSS " + _fmt(ti.epss_score)
            + (f" ({ti.epss_percentile * 100:.0f}th percentile)" if ti.epss_percentile is not None else "")
            + ", CISA KEV listed = " + _fmt(ti.kev_listed)
            + ", exploit available = " + _fmt(ti.exploit_available)
            + (f" (sources: {', '.join(ti.exploit_sources)})" if ti.exploit_sources else "")
            + "."
        )
    else:
        tech_parts.append("Threat intelligence evidence was not supplied by M5 for this finding.")

    tech_parts.append(
        f"Asset context: criticality = {_fmt(ac.criticality)}, "
        f"environment = {_fmt(ac.environment)}, "
        f"internet-facing = {_fmt(ac.internet_facing)}, "
        f"data sensitivity = {_fmt(ac.data_sensitivity)}."
    )

    if sc:
        tech_parts.append(
            f"Detected by {_fmt(sc.detected_by_count)} of {_fmt(sc.total_scanners)} scanners "
            f"(consensus score {_fmt(sc.score)})."
        )

    if fc:
        tech_parts.append(
            f"Finding confidence: {_fmt(fc.score)} ({_fmt(fc.classification)})."
        )

    tech_parts.append(
        "Recommended next step for the analyst: validate the finding against the "
        "live asset, apply the vendor fix or compensating control below, and "
        "confirm remediation before closing."
    )

    technical = " ".join(tech_parts)

    # --- management (business view) ---------------------------------------
    urgency = {
        "CRITICAL": "requires immediate attention",
        "HIGH": "should be prioritized this week",
        "MEDIUM": "should be scheduled in the normal remediation cycle",
        "LOW": "can be tracked at low priority",
    }.get((ra.risk_level or "").upper(), "should be reviewed by the security team")

    crit_phrase = f"a {ac.criticality.lower()} asset" if ac.criticality else "an unclassified asset"
    mgmt_parts = [
        f"A {ra.risk_level.lower() if ra.risk_level else 'unclassified'} severity "
        f"security issue ({vuln_name}) was found on {asset_name}, which is "
        f"{crit_phrase}"
        + (f" and internet-facing" if ac.internet_facing else "")
        + "."
    ]
    if ac.data_sensitivity:
        mgmt_parts.append(f"This system handles {ac.data_sensitivity}-classified data.")
    mgmt_parts.append(f"This finding {urgency}, based on the risk score assigned by the risk engine.")
    if ti and ti.kev_listed:
        mgmt_parts.append("This vulnerability is confirmed to be actively exploited in the wild (CISA KEV).")

    management = " ".join(mgmt_parts)

    # --- recommended action -------------------------------------------------
    action_parts = [f"Apply the vendor patch or code fix addressing {cve}."]
    if ac.internet_facing:
        action_parts.append(
            "As a general security best practice (not a guarantee specific to this "
            "finding), consider an interim WAF or network-layer control while the fix is tested."
        )
    action_parts.append(
        "General best practice: confirm no signs of prior exploitation via log review, "
        "and re-scan after remediation to verify closure."
    )
    recommended_action = " ".join(action_parts)

    return LLMExplanationResult(
        technical=technical,
        management=management,
        recommended_action=recommended_action,
    )
