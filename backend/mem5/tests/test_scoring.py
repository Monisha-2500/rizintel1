"""Comprehensive test suite for Module M5 Rule-Based Risk Scoring Engine.

Covers:
1. Valid high/critical sample input.
2. Missing CVE (null cve_id).
3. Low asset criticality (2 pts).
4. Medium asset criticality (5 pts).
5. High asset criticality (8 pts).
6. Critical asset (10 pts).
7. Low CVSS (5 pts) and CVSS tiers.
8. High CVSS (20/25 pts).
9. Low EPSS (2 pts) and EPSS tiers.
10. High EPSS (14/20 pts).
11. KEV false (0 pts).
12. KEV true (15 pts).
13. Exploit false (0 pts).
14. Exploit true (10 pts).
15. Internet exposure false (0 pts).
16. Internet exposure true (10 pts).
17. Low finding confidence (2 pts).
18. High finding confidence (8/10 pts).
19. Invalid CVSS (<0, >10).
20. Invalid EPSS (<0, >1).
21. Invalid confidence (<0, >1).
22. Invalid boolean representation (string booleans rejected).
23. Upper bound guarantee (score never exceeds 100).
24. Lower bound guarantee (score never below 0).
25. Correct risk classification boundaries (0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL).
26. Score breakdown match with individual contributions.
27. Correct generation of explainable risk drivers.
28. Monotonic behavior across all scoring dimensions.
"""

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from src.models import (
    M5RiskEngineInput,
    ThreatIntelligence,
    AssetContext,
)
from src.risk_engine import RiskEngine
from src.classifier import RiskClassifier, RiskLevel
from src.rules import (
    get_cvss_points,
    get_epss_points,
    get_kev_points,
    get_exploit_points,
    get_criticality_points,
    get_exposure_points,
    get_confidence_points,
)

BASE_DIR = Path(__file__).parent.parent
INPUT_DIR = BASE_DIR / "input"


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_finding_dict(
    cvss_score: float = 5.0,
    epss_score: float = 0.10,
    epss_percentile: float = 0.50,
    kev_listed: bool = False,
    exploit_available: bool = False,
    asset_criticality: str = "MEDIUM",
    internet_exposure: bool = False,
    finding_confidence_score: float = 0.50,
    cve_id: str = "CVE-2026-1001",
) -> dict:
    """Helper to generate a valid finding dictionary with customized parameters."""
    return {
        "schema_version": "1.0",
        "finding_id": "FIND-TEST-001",
        "cve_id": cve_id,
        "vulnerability_name": "Test Vulnerability",
        "vulnerability_type": "Test Category",
        "scanner_sources": ["TestScanner"],
        "scanner_consensus_score": 0.85,
        "finding_confidence_score": finding_confidence_score,
        "finding_confidence_classification": "MEDIUM",
        "threat_intelligence": {
            "cvss_score": cvss_score,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "kev_listed": kev_listed,
            "exploit_available": exploit_available,
        },
        "asset_context": {
            "asset_id": "AST-TEST-001",
            "asset_name": "test-asset",
            "environment": "PRODUCTION",
            "asset_criticality": asset_criticality,
            "internet_exposure": internet_exposure,
            "data_sensitivity": "CONFIDENTIAL",
        },
    }


class TestRiskScoringEngine:
    """Comprehensive test suite for rule-based risk scoring engine."""

    @pytest.fixture
    def engine(self):
        return RiskEngine()

    # 1. Valid high/critical sample input
    def test_sample_input_critical(self, engine):
        data = load_json(INPUT_DIR / "sample_input.json")
        result = engine.assess_finding(data)
        assert result.risk_assessment.risk_score == 100.0
        assert result.risk_assessment.risk_level == "CRITICAL"
        assert result.risk_assessment.score_breakdown.cvss.points == 25
        assert result.risk_assessment.score_breakdown.epss.points == 20
        assert result.risk_assessment.score_breakdown.kev.points == 15
        assert result.risk_assessment.score_breakdown.exploit_available.points == 10
        assert result.risk_assessment.score_breakdown.asset_criticality.points == 10
        assert result.risk_assessment.score_breakdown.internet_exposure.points == 10
        assert result.risk_assessment.score_breakdown.finding_confidence.points == 10

    # 2. Missing CVE finding
    def test_missing_cve_calculation(self, engine):
        data = load_json(INPUT_DIR / "missing_cve_input.json")
        result = engine.assess_finding(data)
        assert result.cve_id is None
        # CVSS 8.5 (20) + EPSS 0.05 (2) + KEV F (0) + Exploit T (10) + Crit (10) + Exposure T (10) + Conf 0.92 (10) = 62
        assert result.risk_assessment.risk_score == 62.0
        assert result.risk_assessment.risk_level == "HIGH"

    # 3-6. Asset criticality tiers
    @pytest.mark.parametrize(
        "tier, expected_pts",
        [
            ("LOW", 2),
            ("MEDIUM", 5),
            ("HIGH", 8),
            ("CRITICAL", 10),
        ],
    )
    def test_asset_criticality_points(self, tier, expected_pts):
        assert get_criticality_points(tier) == expected_pts

    # 7-8. CVSS tiers
    @pytest.mark.parametrize(
        "cvss, expected_pts",
        [
            (0.0, 5),
            (2.5, 5),
            (3.9, 5),
            (4.0, 12),
            (5.5, 12),
            (6.9, 12),
            (7.0, 20),
            (8.5, 20),
            (8.9, 20),
            (9.0, 25),
            (10.0, 25),
        ],
    )
    def test_cvss_points_tiers(self, cvss, expected_pts):
        assert get_cvss_points(cvss) == expected_pts

    # 9-10. EPSS tiers
    @pytest.mark.parametrize(
        "epss, expected_pts",
        [
            (0.00, 2),
            (0.10, 2),
            (0.19, 2),
            (0.20, 8),
            (0.35, 8),
            (0.49, 8),
            (0.50, 14),
            (0.65, 14),
            (0.79, 14),
            (0.80, 20),
            (0.95, 20),
            (1.00, 20),
        ],
    )
    def test_epss_points_tiers(self, epss, expected_pts):
        assert get_epss_points(epss) == expected_pts

    # 11-12. KEV boolean
    def test_kev_points(self):
        assert get_kev_points(False) == 0
        assert get_kev_points(True) == 15

    # 13-14. Exploit availability boolean
    def test_exploit_points(self):
        assert get_exploit_points(False) == 0
        assert get_exploit_points(True) == 10

    # 15-16. Internet exposure boolean
    def test_exposure_points(self):
        assert get_exposure_points(False) == 0
        assert get_exposure_points(True) == 10

    # 17-18. Finding confidence tiers
    @pytest.mark.parametrize(
        "confidence, expected_pts",
        [
            (0.00, 2),
            (0.25, 2),
            (0.49, 2),
            (0.50, 5),
            (0.60, 5),
            (0.74, 5),
            (0.75, 8),
            (0.85, 8),
            (0.89, 8),
            (0.90, 10),
            (0.98, 10),
            (1.00, 10),
        ],
    )
    def test_confidence_points_tiers(self, confidence, expected_pts):
        assert get_confidence_points(confidence) == expected_pts

    # 19. Invalid CVSS
    @pytest.mark.parametrize("invalid_cvss", [-0.1, 10.1, 15.0])
    def test_invalid_cvss_raises(self, invalid_cvss):
        payload = build_finding_dict(cvss_score=invalid_cvss)
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(payload)

    # 20. Invalid EPSS
    @pytest.mark.parametrize("invalid_epss", [-0.01, 1.01, 2.5])
    def test_invalid_epss_raises(self, invalid_epss):
        payload = build_finding_dict(epss_score=invalid_epss)
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(payload)

    # 21. Invalid confidence
    @pytest.mark.parametrize("invalid_conf", [-0.1, 1.05, 5.0])
    def test_invalid_confidence_raises(self, invalid_conf):
        payload = build_finding_dict(finding_confidence_score=invalid_conf)
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(payload)

    # 22. Invalid boolean representations
    @pytest.mark.parametrize("invalid_bool", ["true", "false", "Yes", "No", 1, 0])
    def test_invalid_boolean_representation_raises(self, invalid_bool):
        payload = build_finding_dict()
        payload["threat_intelligence"]["kev_listed"] = invalid_bool
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(payload)

    # 23. Upper bound never exceeds 100
    def test_score_upper_bound(self, engine):
        payload = build_finding_dict(
            cvss_score=10.0,  # 25
            epss_score=1.0,   # 20
            kev_listed=True,  # 15
            exploit_available=True, # 10
            asset_criticality="CRITICAL", # 10
            internet_exposure=True, # 10
            finding_confidence_score=1.0, # 10
        )
        result = engine.assess_finding(payload)
        assert result.risk_assessment.risk_score == 100.0
        assert result.risk_assessment.risk_score <= 100.0

    # 24. Lower bound never below 0
    def test_score_lower_bound(self, engine):
        payload = build_finding_dict(
            cvss_score=0.0,   # 5
            epss_score=0.0,   # 2
            kev_listed=False, # 0
            exploit_available=False, # 0
            asset_criticality="LOW", # 2
            internet_exposure=False, # 0
            finding_confidence_score=0.0, # 2
        )
        result = engine.assess_finding(payload)
        # 5 + 2 + 0 + 0 + 2 + 0 + 2 = 11.0
        assert result.risk_assessment.risk_score >= 0.0
        assert result.risk_assessment.risk_score == 11.0
        assert result.risk_assessment.risk_level == "LOW"

    # 25. Correct risk classification boundaries
    @pytest.mark.parametrize(
        "score, expected_level",
        [
            (0.0, "LOW"),
            (11.0, "LOW"),
            (24.0, "LOW"),
            (24.99, "LOW"),
            (25.0, "MEDIUM"),
            (35.0, "MEDIUM"),
            (49.0, "MEDIUM"),
            (49.99, "MEDIUM"),
            (50.0, "HIGH"),
            (60.0, "HIGH"),
            (74.0, "HIGH"),
            (74.99, "HIGH"),
            (75.0, "CRITICAL"),
            (85.0, "CRITICAL"),
            (100.0, "CRITICAL"),
        ],
    )
    def test_classification_boundaries(self, score, expected_level):
        classifier = RiskClassifier()
        assert classifier.classify(score) == expected_level

    # 26. Score breakdown matches actual contributions
    def test_score_breakdown_accuracy(self, engine):
        payload = build_finding_dict(
            cvss_score=7.5,      # 20
            epss_score=0.30,     # 8
            kev_listed=False,    # 0
            exploit_available=True, # 10
            asset_criticality="HIGH", # 8
            internet_exposure=True, # 10
            finding_confidence_score=0.80, # 8
        )
        result = engine.assess_finding(payload)
        bd = result.risk_assessment.score_breakdown
        assert bd.cvss.input == 7.5
        assert bd.cvss.points == 20
        assert bd.epss.input == 0.30
        assert bd.epss.points == 8
        assert bd.kev.input is False
        assert bd.kev.points == 0
        assert bd.exploit_available.input is True
        assert bd.exploit_available.points == 10
        assert bd.asset_criticality.input == "HIGH"
        assert bd.asset_criticality.points == 8
        assert bd.internet_exposure.input is True
        assert bd.internet_exposure.points == 10
        assert bd.finding_confidence.input == 0.80
        assert bd.finding_confidence.points == 8

        total_pts = sum(
            [
                bd.cvss.points,
                bd.epss.points,
                bd.kev.points,
                bd.exploit_available.points,
                bd.asset_criticality.points,
                bd.internet_exposure.points,
                bd.finding_confidence.points,
            ]
        )
        assert result.risk_assessment.risk_score == total_pts
        assert result.risk_assessment.risk_score == 64.0
        assert result.risk_assessment.risk_level == "HIGH"

    # 27. Risk drivers generated correctly
    def test_risk_drivers_generation(self, engine):
        # Case A: All triggered
        payload_all = build_finding_dict(
            cvss_score=9.5,
            epss_score=0.85,
            kev_listed=True,
            exploit_available=True,
            asset_criticality="CRITICAL",
            internet_exposure=True,
            finding_confidence_score=0.95,
        )
        result_all = engine.assess_finding(payload_all)
        assert result_all.risk_assessment.risk_drivers == [
            "HIGH_CVSS",
            "HIGH_EPSS",
            "KEV_LISTED",
            "EXPLOIT_AVAILABLE",
            "CRITICAL_ASSET",
            "INTERNET_EXPOSED",
            "HIGH_CONFIDENCE",
        ]

        # Case B: None triggered
        payload_none = build_finding_dict(
            cvss_score=3.5,
            epss_score=0.05,
            kev_listed=False,
            exploit_available=False,
            asset_criticality="LOW",
            internet_exposure=False,
            finding_confidence_score=0.40,
        )
        result_none = engine.assess_finding(payload_none)
        assert result_none.risk_assessment.risk_drivers == []

        # Case C: Partial triggered (only KEV and INTERNET_EXPOSED)
        payload_partial = build_finding_dict(
            cvss_score=4.5,
            epss_score=0.10,
            kev_listed=True,
            exploit_available=False,
            asset_criticality="MEDIUM",
            internet_exposure=True,
            finding_confidence_score=0.50,
        )
        result_partial = engine.assess_finding(payload_partial)
        assert result_partial.risk_assessment.risk_drivers == [
            "KEV_LISTED",
            "INTERNET_EXPOSED",
        ]

    # 28. Individual driver isolation checks
    def test_individual_driver_triggers(self, engine):
        # Base minimal finding with no drivers triggered
        base = {
            "cvss_score": 3.0,
            "epss_score": 0.10,
            "kev_listed": False,
            "exploit_available": False,
            "asset_criticality": "LOW",
            "internet_exposure": False,
            "finding_confidence_score": 0.40,
        }

        # Test HIGH_CVSS alone (>= 7.0)
        p = build_finding_dict(**{**base, "cvss_score": 7.0})
        assert engine.assess_finding(p).risk_assessment.risk_drivers == ["HIGH_CVSS"]

        # Test HIGH_EPSS alone (>= 0.50)
        p = build_finding_dict(**{**base, "epss_score": 0.50})
        assert engine.assess_finding(p).risk_assessment.risk_drivers == ["HIGH_EPSS"]

        # Test KEV_LISTED alone (True)
        p = build_finding_dict(**{**base, "kev_listed": True})
        assert engine.assess_finding(p).risk_assessment.risk_drivers == ["KEV_LISTED"]

        # Test EXPLOIT_AVAILABLE alone (True)
        p = build_finding_dict(**{**base, "exploit_available": True})
        assert engine.assess_finding(p).risk_assessment.risk_drivers == ["EXPLOIT_AVAILABLE"]

        # Test CRITICAL_ASSET alone (CRITICAL)
        p = build_finding_dict(**{**base, "asset_criticality": "CRITICAL"})
        assert engine.assess_finding(p).risk_assessment.risk_drivers == ["CRITICAL_ASSET"]

        # Test INTERNET_EXPOSED alone (True)
        p = build_finding_dict(**{**base, "internet_exposure": True})
        assert engine.assess_finding(p).risk_assessment.risk_drivers == ["INTERNET_EXPOSED"]

        # Test HIGH_CONFIDENCE alone (>= 0.75)
        p = build_finding_dict(**{**base, "finding_confidence_score": 0.75})
        assert engine.assess_finding(p).risk_assessment.risk_drivers == ["HIGH_CONFIDENCE"]

    # 29. Deterministic behavior across repeated executions
    def test_deterministic_behavior(self, engine):
        payload = build_finding_dict(
            cvss_score=8.5,
            epss_score=0.65,
            kev_listed=True,
            exploit_available=True,
            asset_criticality="CRITICAL",
            internet_exposure=True,
            finding_confidence_score=0.92,
        )
        first_result = engine.assess_finding(payload)

        for _ in range(50):
            repeated_result = engine.assess_finding(payload)
            assert repeated_result.risk_assessment.risk_score == first_result.risk_assessment.risk_score
            assert repeated_result.risk_assessment.risk_level == first_result.risk_assessment.risk_level
            assert repeated_result.risk_assessment.risk_drivers == first_result.risk_assessment.risk_drivers
            assert (
                repeated_result.risk_assessment.score_breakdown.model_dump()
                == first_result.risk_assessment.score_breakdown.model_dump()
            )

    # 30. Scoring version explicit representation
    def test_scoring_version_representation(self, engine):
        data = load_json(INPUT_DIR / "sample_input.json")
        result = engine.assess_finding(data)
        assert result.scoring_version == "1.0"
        assert result.schema_version == "1.0"
        assert result.risk_assessment.scoring_version == "1.0"

    # 31. Exact boundary scores test (24, 25, 49, 50, 74, 75, 100)
    @pytest.mark.parametrize(
        "exact_score, expected_level",
        [
            (0.0, "LOW"),
            (24.0, "LOW"),
            (25.0, "MEDIUM"),
            (49.0, "MEDIUM"),
            (50.0, "HIGH"),
            (74.0, "HIGH"),
            (75.0, "CRITICAL"),
            (100.0, "CRITICAL"),
        ],
    )
    def test_exact_boundary_classifications(self, exact_score, expected_level):
        classifier = RiskClassifier()
        assert classifier.classify(exact_score) == expected_level

    # 32. Score breakdown sum invariant across diverse findings
    @pytest.mark.parametrize(
        "cvss, epss, kev, exploit, crit, exp, conf",
        [
            (0.0, 0.0, False, False, "LOW", False, 0.0),       # Min: 5+2+0+0+2+0+2 = 11
            (10.0, 1.0, True, True, "CRITICAL", True, 1.0),    # Max: 25+20+15+10+10+10+10 = 100
            (5.5, 0.35, True, False, "HIGH", False, 0.6),     # Mid 1: 12+8+15+0+8+0+5 = 48
            (7.5, 0.85, False, True, "MEDIUM", True, 0.8),    # Mid 2: 20+20+0+10+5+10+8 = 73
            (4.0, 0.20, False, False, "LOW", False, 0.50),    # Mid 3: 12+8+0+0+2+0+5 = 27
        ],
    )
    def test_score_breakdown_sum_matches_final_score(
        self, engine, cvss, epss, kev, exploit, crit, exp, conf
    ):
        payload = build_finding_dict(
            cvss_score=cvss,
            epss_score=epss,
            kev_listed=kev,
            exploit_available=exploit,
            asset_criticality=crit,
            internet_exposure=exp,
            finding_confidence_score=conf,
        )
        result = engine.assess_finding(payload)
        bd = result.risk_assessment.score_breakdown
        points_sum = (
            bd.cvss.points
            + bd.epss.points
            + bd.kev.points
            + bd.exploit_available.points
            + bd.asset_criticality.points
            + bd.internet_exposure.points
            + bd.finding_confidence.points
        )
        expected_bounded_score = min(100.0, max(0.0, float(points_sum)))
        assert result.risk_assessment.risk_score == expected_bounded_score


class TestMonotonicBehavior:
    """Tests verifying monotonic property across all individual scoring dimensions."""

    @pytest.fixture
    def engine(self):
        return RiskEngine()

    def test_monotonic_cvss(self, engine):
        scores = []
        for cvss in [1.0, 3.5, 4.5, 6.5, 7.5, 8.5, 9.5]:
            payload = build_finding_dict(cvss_score=cvss)
            result = engine.assess_finding(payload)
            scores.append(result.risk_assessment.risk_score)
        # Each subsequent score must be >= previous score
        assert all(scores[i] <= scores[i + 1] for i in range(len(scores) - 1))

    def test_monotonic_epss(self, engine):
        scores = []
        for epss in [0.05, 0.15, 0.25, 0.45, 0.55, 0.75, 0.85, 0.95]:
            payload = build_finding_dict(epss_score=epss)
            result = engine.assess_finding(payload)
            scores.append(result.risk_assessment.risk_score)
        assert all(scores[i] <= scores[i + 1] for i in range(len(scores) - 1))

    def test_monotonic_asset_criticality(self, engine):
        scores = []
        for crit in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            payload = build_finding_dict(asset_criticality=crit)
            result = engine.assess_finding(payload)
            scores.append(result.risk_assessment.risk_score)
        assert all(scores[i] <= scores[i + 1] for i in range(len(scores) - 1))

    def test_monotonic_kev(self, engine):
        payload_f = build_finding_dict(kev_listed=False)
        payload_t = build_finding_dict(kev_listed=True)
        score_f = engine.assess_finding(payload_f).risk_assessment.risk_score
        score_t = engine.assess_finding(payload_t).risk_assessment.risk_score
        assert score_t >= score_f

    def test_monotonic_exploit(self, engine):
        payload_f = build_finding_dict(exploit_available=False)
        payload_t = build_finding_dict(exploit_available=True)
        score_f = engine.assess_finding(payload_f).risk_assessment.risk_score
        score_t = engine.assess_finding(payload_t).risk_assessment.risk_score
        assert score_t >= score_f

    def test_monotonic_internet_exposure(self, engine):
        payload_f = build_finding_dict(internet_exposure=False)
        payload_t = build_finding_dict(internet_exposure=True)
        score_f = engine.assess_finding(payload_f).risk_assessment.risk_score
        score_t = engine.assess_finding(payload_t).risk_assessment.risk_score
        assert score_t >= score_f

    def test_monotonic_confidence(self, engine):
        scores = []
        for conf in [0.10, 0.40, 0.60, 0.80, 0.95]:
            payload = build_finding_dict(finding_confidence_score=conf)
            result = engine.assess_finding(payload)
            scores.append(result.risk_assessment.risk_score)
        assert all(scores[i] <= scores[i + 1] for i in range(len(scores) - 1))
