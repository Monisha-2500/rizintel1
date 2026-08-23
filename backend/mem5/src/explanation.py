"""Score explanation and risk driver generation module for Module M5.

RESPONSIBILITY:
- Synthesizes explainable, deterministic risk drivers (e.g., HIGH_CVSS, KEV_LISTED, CRITICAL_ASSET).
- Generates human-readable audit reasons and explanations.
- Strictly adheres to domain facts: only includes drivers that are triggered.
- Treats confidence as a prioritization/trust signal without claiming it increases technical severity.
"""

from typing import List
from .models import M5RiskEngineInput, ScoreBreakdown
from .rules import DRIVER_THRESHOLDS


class RiskExplanationGenerator:
    """Generates transparent risk drivers and human-readable audit explanations."""

    def __init__(self):
        pass

    def generate_drivers(self, finding: M5RiskEngineInput) -> List[str]:
        """Evaluate and return canonical risk driver codes triggered by the finding.

        Only triggered drivers are returned. No hypothetical or unobserved signals are generated.

        Driver Definitions:
          - HIGH_CVSS: CVSS score >= 7.0 (High or Critical technical severity)
          - HIGH_EPSS: EPSS probability >= 0.50 (Elevated exploitation probability)
          - KEV_LISTED: Confirmed presence in CISA Known Exploited Vulnerabilities catalog
          - EXPLOIT_AVAILABLE: Known public functional exploit code is available
          - CRITICAL_ASSET: Target asset tier is designated as CRITICAL
          - INTERNET_EXPOSED: Target asset has direct internet exposure
          - HIGH_CONFIDENCE: Finding confidence score >= 0.75 (High validation confidence)

        Args:
            finding: Validated M5RiskEngineInput object.

        Returns:
            List[str]: List of triggered driver identifier strings.
        """
        drivers: List[str] = []

        # 1. Technical severity driver
        if finding.threat_intelligence.cvss_score >= DRIVER_THRESHOLDS["HIGH_CVSS"]:
            drivers.append("HIGH_CVSS")

        # 2. Threat intelligence & exploit likelihood drivers
        if finding.threat_intelligence.epss_score >= DRIVER_THRESHOLDS["HIGH_EPSS"]:
            drivers.append("HIGH_EPSS")

        if finding.threat_intelligence.kev_listed:
            drivers.append("KEV_LISTED")

        if finding.threat_intelligence.exploit_available:
            drivers.append("EXPLOIT_AVAILABLE")

        # 3. Asset context drivers
        if finding.asset_context.asset_criticality.upper() == "CRITICAL":
            drivers.append("CRITICAL_ASSET")

        if finding.asset_context.internet_exposure:
            drivers.append("INTERNET_EXPOSED")

        # 4. Confidence driver (prioritization / verification trust signal)
        if finding.finding_confidence_score >= DRIVER_THRESHOLDS["HIGH_CONFIDENCE"]:
            drivers.append("HIGH_CONFIDENCE")

        return drivers

    def generate_explanation(
        self,
        finding: M5RiskEngineInput,
        score: float,
        breakdown: ScoreBreakdown
    ) -> List[str]:
        """Generate human-readable summary statements justifying the computed score.

        Args:
            finding: Validated finding input.
            score: Computed numerical risk score.
            breakdown: Score component breakdown.

        Returns:
            List[str]: List of human-readable rationale statements.
        """
        reasons: List[str] = []

        if finding.threat_intelligence.cvss_score >= DRIVER_THRESHOLDS["HIGH_CVSS"]:
            reasons.append(
                f"High technical vulnerability severity (CVSS {finding.threat_intelligence.cvss_score} → {breakdown.cvss.points} pts)."
            )

        if finding.threat_intelligence.epss_score >= DRIVER_THRESHOLDS["HIGH_EPSS"]:
            reasons.append(
                f"Elevated probability of active exploitation (EPSS {finding.threat_intelligence.epss_score} → {breakdown.epss.points} pts)."
            )

        if finding.threat_intelligence.kev_listed:
            reasons.append(
                f"Confirmed active exploitation in the wild (CISA KEV listed → +{breakdown.kev.points} pts)."
            )

        if finding.threat_intelligence.exploit_available:
            reasons.append(
                f"Publicly available exploit code identified (→ +{breakdown.exploit_available.points} pts)."
            )

        if finding.asset_context.asset_criticality.upper() == "CRITICAL":
            reasons.append(
                f"Target asset is classified as CRITICAL infrastructure (→ +{breakdown.asset_criticality.points} pts)."
            )

        if finding.asset_context.internet_exposure:
            reasons.append(
                f"Asset is directly exposed to the public internet (→ +{breakdown.internet_exposure.points} pts)."
            )

        if finding.finding_confidence_score >= DRIVER_THRESHOLDS["HIGH_CONFIDENCE"]:
            reasons.append(
                f"High scanner verification confidence ({finding.finding_confidence_score} → +{breakdown.finding_confidence.points} pts prioritization signal)."
            )

        return reasons
