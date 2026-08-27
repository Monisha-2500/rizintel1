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
    if value is None:
        return "not specified"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    s = str(value).strip()
    if s.upper() == "UNKNOWN":
        return "not specified"
    if "." in s and s.isupper():
        # Handle enum representations like CONFIDENCECLASSIFICATION.HIGH_CONFIDENCE
        s = s.split(".")[-1]
    return f"{s}{unit}"


def build_fallback_explanation(finding: RiskAssessedFinding) -> LLMExplanationResult:
    ra = finding.risk_assessment
    ac = finding.asset_context
    ti = finding.threat_intelligence
    sc = finding.scanner_consensus
    fc = finding.finding_confidence

    vuln_name = finding.vulnerability_name or "This finding"
    cve = finding.cve_id or "an unidentified CVE"
    asset_name = ac.asset_name or ac.asset_id or "Registered Asset"

    # --- technical (security analyst view) -------------------------------
    tech_parts = [
        f"{vuln_name} ({cve}) on asset {asset_name} was scored "
        f"{ra.risk_score}/100 ({ra.risk_level}) contextual risk score."
    ]

    if ti:
        evidence_items = []
        if ti.cvss_score is not None:
            evidence_items.append(f"CVSS {ti.cvss_score}" + (f" ({ti.cvss_vector})" if ti.cvss_vector else ""))
        if ti.epss_score is not None:
            pct_str = f" ({ti.epss_percentile * 100:.0f}th percentile)" if ti.epss_percentile is not None else ""
            evidence_items.append(f"EPSS {ti.epss_score}{pct_str}")
        if ti.kev_listed is not None:
            evidence_items.append("CISA KEV listed" if ti.kev_listed else "not in CISA KEV")
        if ti.exploit_available is not None:
            exploit_str = "known exploit available" if ti.exploit_available else "no known public exploit"
            if ti.exploit_sources:
                exploit_str += f" (sources: {', '.join(ti.exploit_sources)})"
            evidence_items.append(exploit_str)

        if evidence_items:
            tech_parts.append(f"Evidence: {', '.join(evidence_items)}.")
    else:
        tech_parts.append("Threat intelligence evidence was not supplied for this finding.")

    env_str = ac.environment or "not specified"
    crit_str = ac.criticality or "not specified"
    exp_str = "Internet-facing" if ac.internet_facing is True else ("Internal" if ac.internet_facing is False else "not specified")
    data_str = ac.data_sensitivity if (ac.data_sensitivity and ac.data_sensitivity.upper() != "UNKNOWN") else "not specified"

    tech_parts.append(
        f"Asset context: criticality = {crit_str}, "
        f"environment = {env_str}, "
        f"exposure = {exp_str}, "
        f"data classification = {data_str}."
    )

    if sc:
        scanner_count = sc.detected_by_count or 0
        scanner_word = "scanner" if scanner_count == 1 else "scanners"
        tech_parts.append(
            f"Detected by {scanner_count} of {sc.total_scanners or 1} configured {scanner_word} "
            f"(consensus score {sc.score or 0.0})."
        )

    if fc:
        conf_label = _fmt(fc.classification).replace("_", " ").title()
        tech_parts.append(
            f"Finding confidence: {fc.score or 0.0} ({conf_label})."
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

    crit = (ac.criticality or "").strip().upper()
    if crit and crit != "UNKNOWN":
        crit_phrase = f"a {crit.lower()} asset"
    else:
        crit_phrase = "an active system"

    mgmt_parts = [
        f"A {ra.risk_level.lower() if ra.risk_level else 'unclassified'}-risk "
        f"security finding ({vuln_name}) was identified on {asset_name}, which is "
        f"{crit_phrase}"
        + (f" and internet-facing" if ac.internet_facing else "")
        + "."
    ]
    if ac.data_sensitivity and str(ac.data_sensitivity).strip().upper() != "UNKNOWN":
        mgmt_parts.append(f"This system handles {ac.data_sensitivity}-classified data.")
    mgmt_parts.append(f"This finding {urgency}, based on the contextual risk score.")
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
