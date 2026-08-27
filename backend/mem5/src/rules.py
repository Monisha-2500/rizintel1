"""Scoring policy rules, range definitions, and classification thresholds for Module M5.

RESPONSIBILITY:
- Store the declarative scoring ranges, point mappings, and risk classification thresholds.
- Maintain a strict separation of scoring policy from calculation and orchestration logic.
"""

from typing import Dict, List, Tuple


# ============================================================================
# Scoring Maximum Contributions (Total Max = 100)
# ============================================================================

MAX_SCORE: float = 100.0
MIN_SCORE: float = 0.0

MAX_CONTRIBUTIONS: Dict[str, int] = {
    "cvss": 25,
    "epss": 20,
    "kev": 15,
    "exploit_available": 10,
    "asset_criticality": 10,
    "internet_exposure": 10,
    "finding_confidence": 10,
}


# ============================================================================
# CVSS Point Mapping (Max 25 pts)
# ============================================================================
# 0.0–3.9   → 5 points
# 4.0–6.9   → 12 points
# 7.0–8.9   → 20 points
# 9.0–10.0  → 25 points

CVSS_RANGES: List[Tuple[float, float, int]] = [
    (0.0, 3.9, 5),
    (4.0, 6.9, 12),
    (7.0, 8.9, 20),
    (9.0, 10.0, 25),
]


# ============================================================================
# EPSS Point Mapping (Max 20 pts)
# ============================================================================
# 0.00–0.19 → 2 points
# 0.20–0.49 → 8 points
# 0.50–0.79 → 14 points
# 0.80–1.00 → 20 points

EPSS_RANGES: List[Tuple[float, float, int]] = [
    (0.00, 0.19, 2),
    (0.20, 0.49, 8),
    (0.50, 0.79, 14),
    (0.80, 1.00, 20),
]


# ============================================================================
# KEV Point Mapping (Max 15 pts)
# ============================================================================
# true  → 15 points
# false → 0 points

KEV_POINTS: Dict[bool, int] = {
    True: 15,
    False: 0,
}


# ============================================================================
# Exploit Availability Point Mapping (Max 10 pts)
# ============================================================================
# true  → 10 points
# false → 0 points

EXPLOIT_AVAILABLE_POINTS: Dict[bool, int] = {
    True: 10,
    False: 0,
}


# ============================================================================
# Asset Criticality Point Mapping (Max 10 pts)
# ============================================================================
# LOW       → 2 points
# MEDIUM    → 5 points
# HIGH      → 8 points
# CRITICAL  → 10 points
# UNKNOWN   → 0 points  (genuinely unresolved asset — no fabricated tier)

ASSET_CRITICALITY_POINTS: Dict[str, int] = {
    "LOW": 2,
    "MEDIUM": 5,
    "HIGH": 8,
    "CRITICAL": 10,
    "UNKNOWN": 0,
}


# ============================================================================
# Internet Exposure Point Mapping (Max 10 pts)
# ============================================================================
# true  → 10 points
# false → 0 points

INTERNET_EXPOSURE_POINTS: Dict[bool, int] = {
    True: 10,
    False: 0,
}


# ============================================================================
# Finding Confidence Point Mapping (Max 10 pts)
# ============================================================================
# 0.00–0.49 → 2 points
# 0.50–0.74 → 5 points
# 0.75–0.89 → 8 points
# 0.90–1.00 → 10 points

CONFIDENCE_RANGES: List[Tuple[float, float, int]] = [
    (0.00, 0.49, 2),
    (0.50, 0.74, 5),
    (0.75, 0.89, 8),
    (0.90, 1.00, 10),
]


# ============================================================================
# Risk Classification Thresholds
# ============================================================================
# 0–24    → LOW
# 25–49   → MEDIUM
# 50–74   → HIGH
# 75–100  → CRITICAL

CLASSIFICATION_THRESHOLDS: List[Tuple[float, float, str]] = [
    (0.0, 24.999, "LOW"),
    (25.0, 49.999, "MEDIUM"),
    (50.0, 74.999, "HIGH"),
    (75.0, 100.0, "CRITICAL"),
]


# ============================================================================
# Risk Driver Evaluation Thresholds
# ============================================================================

DRIVER_THRESHOLDS = {
    "HIGH_CVSS": 7.0,          # CVSS >= 7.0 (High/Critical technical severity)
    "HIGH_EPSS": 0.50,         # EPSS >= 0.50 (High probability of exploitation)
    "HIGH_CONFIDENCE": 0.75,   # Confidence >= 0.75 (High confidence detection)
}


# ============================================================================
# Helper Policy Evaluators
# ============================================================================

def get_cvss_points(score: float) -> int:
    """Map CVSS score [0.0 - 10.0] to rule-based points.

    0.0 <= score < 4.0   → 5 pts
    4.0 <= score < 7.0   → 12 pts
    7.0 <= score < 9.0   → 20 pts
    9.0 <= score <= 10.0 → 25 pts
    """
    if score >= 9.0:
        return 25
    elif score >= 7.0:
        return 20
    elif score >= 4.0:
        return 12
    else:
        return 5


def get_epss_points(score: float) -> int:
    """Map EPSS score [0.0 - 1.0] to rule-based points.

    0.00 <= score < 0.20 → 2 pts
    0.20 <= score < 0.50 → 8 pts
    0.50 <= score < 0.80 → 14 pts
    0.80 <= score <= 1.00 → 20 pts
    """
    if score >= 0.80:
        return 20
    elif score >= 0.50:
        return 14
    elif score >= 0.20:
        return 8
    else:
        return 2


def get_kev_points(kev_listed: bool) -> int:
    """Map CISA KEV listing boolean to rule-based points."""
    return KEV_POINTS.get(kev_listed, 0)


def get_exploit_points(exploit_available: bool) -> int:
    """Map exploit availability boolean to rule-based points."""
    return EXPLOIT_AVAILABLE_POINTS.get(exploit_available, 0)


def get_criticality_points(criticality: str) -> int:
    """Map asset criticality tier to rule-based points.

    Known tiers (LOW/MEDIUM/HIGH/CRITICAL) are unchanged.
    UNKNOWN returns 0 — no fabricated business impact for unresolved assets.
    Unrecognised values also return 0 (fail-safe).
    """
    return ASSET_CRITICALITY_POINTS.get(criticality.upper(), 0)


def get_exposure_points(internet_exposure) -> int:
    """Map internet exposure to rule-based points.

    True  → 10 points (confirmed internet-facing).
    False → 0 points (confirmed internal).
    None  → 0 points (genuinely unknown — no assumed exposure for unresolved assets).
    """
    if internet_exposure is None:
        return 0
    return INTERNET_EXPOSURE_POINTS.get(bool(internet_exposure), 0)


def get_confidence_points(score: float) -> int:
    """Map finding confidence score [0.0 - 1.0] to rule-based points.

    0.00 <= score < 0.50 → 2 pts
    0.50 <= score < 0.75 → 5 pts
    0.75 <= score < 0.90 → 8 pts
    0.90 <= score <= 1.00 → 10 pts
    """
    if score >= 0.90:
        return 10
    elif score >= 0.75:
        return 8
    elif score >= 0.50:
        return 5
    else:
        return 2
