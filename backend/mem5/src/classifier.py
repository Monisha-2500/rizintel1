"""Risk classification module for Module M5 — Risk Scoring Engine.

RESPONSIBILITY:
- Maps continuous numerical risk scores [0.0 - 100.0] into standardized categorical risk tiers:
  - LOW:       0 – 24
  - MEDIUM:   25 – 49
  - HIGH:     50 – 74
  - CRITICAL: 75 – 100

Separates classification logic from scoring calculation.
"""

from enum import Enum


class RiskLevel(str, Enum):
    """Standardized categorical risk priority tiers."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskClassifier:
    """Categorizes numerical risk scores into standardized risk priority levels."""

    def __init__(self):
        pass

    def classify(self, score: float) -> str:
        """Classify a numerical score into a canonical risk level.

        Thresholds:
          0 – 24   → LOW
          25 – 49  → MEDIUM
          50 – 74  → HIGH
          75 – 100 → CRITICAL

        Args:
            score: Computed numerical score [0.0 - 100.0].

        Returns:
            str: Standardized risk level string (CRITICAL, HIGH, MEDIUM, LOW).
        """
        # Ensure score is evaluated in proper order
        if score >= 75.0:
            return RiskLevel.CRITICAL.value
        elif score >= 50.0:
            return RiskLevel.HIGH.value
        elif score >= 25.0:
            return RiskLevel.MEDIUM.value
        else:
            return RiskLevel.LOW.value
