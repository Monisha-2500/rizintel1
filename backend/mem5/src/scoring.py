"""Deterministic rule-based risk scoring calculation engine for Module M5.

RESPONSIBILITY:
- Converts validated inputs into individual point contributions based on rules.py policy.
- Calculates the final additive risk score bounded strictly to [0.0 - 100.0].
- Generates the transparent factor-by-factor score breakdown.
"""

from typing import Tuple
from .models import M5RiskEngineInput, ScoreBreakdown, FactorBreakdown
from .rules import (
    get_cvss_points,
    get_epss_points,
    get_kev_points,
    get_exploit_points,
    get_criticality_points,
    get_exposure_points,
    get_confidence_points,
    MIN_SCORE,
    MAX_SCORE,
)


class RiskScoringEngine:
    """Calculates deterministic rule-based risk scores and compiles component score breakdowns."""

    def __init__(self):
        self.scoring_version = "1.0"

    def compute_score(self, finding: M5RiskEngineInput) -> Tuple[float, ScoreBreakdown]:
        """Compute the composite risk score and transparent score breakdown.

        Calculates points for:
          1. CVSS Technical Severity (max 25 pts)
          2. EPSS Exploitation Likelihood (max 20 pts)
          3. CISA KEV Catalog Listing (max 15 pts)
          4. Public Exploit Code Availability (max 10 pts)
          5. Asset Business Criticality (max 10 pts)
          6. Internet Exposure (max 10 pts)
          7. Finding Confidence (max 10 pts)

        NOTE:
          - `scanner_consensus_score` and `epss_percentile` are NOT independently added
            to the score to avoid double-counting evidence.

        Args:
            finding: Validated finding input adhering to M5 schema.

        Returns:
            Tuple[float, ScoreBreakdown]: Bounded composite score [0.0 - 100.0] and component breakdown.
        """
        # 1. Individual factor point calculations
        cvss_input = finding.threat_intelligence.cvss_score
        cvss_pts = get_cvss_points(cvss_input)

        epss_input = finding.threat_intelligence.epss_score
        epss_pts = get_epss_points(epss_input)

        kev_input = finding.threat_intelligence.kev_listed
        kev_pts = get_kev_points(kev_input)

        exploit_input = finding.threat_intelligence.exploit_available
        exploit_pts = get_exploit_points(exploit_input)

        criticality_input = finding.asset_context.asset_criticality
        criticality_pts = get_criticality_points(criticality_input)

        exposure_input = finding.asset_context.internet_exposure
        exposure_pts = get_exposure_points(exposure_input)

        confidence_input = finding.finding_confidence_score
        confidence_pts = get_confidence_points(confidence_input)

        # 2. Build structured ScoreBreakdown
        breakdown = ScoreBreakdown(
            cvss=FactorBreakdown(input=cvss_input, points=cvss_pts),
            epss=FactorBreakdown(input=epss_input, points=epss_pts),
            kev=FactorBreakdown(input=kev_input, points=kev_pts),
            exploit_available=FactorBreakdown(input=exploit_input, points=exploit_pts),
            asset_criticality=FactorBreakdown(input=criticality_input, points=criticality_pts),
            internet_exposure=FactorBreakdown(input=exposure_input, points=exposure_pts),
            finding_confidence=FactorBreakdown(input=confidence_input, points=confidence_pts),
        )

        # 3. Sum total points and bound between [0.0, 100.0]
        total_raw = (
            cvss_pts
            + epss_pts
            + kev_pts
            + exploit_pts
            + criticality_pts
            + exposure_pts
            + confidence_pts
        )

        final_score: float = float(min(MAX_SCORE, max(MIN_SCORE, total_raw)))

        return final_score, breakdown
