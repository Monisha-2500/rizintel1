"""
backend/mem7/sla_engine.py
--------------------------
Single source of truth for turning a risk_score (0-100) into:
  - a remediation priority label (CRITICAL, HIGH, MEDIUM, LOW)
  - an SLA window (in hours)

Bands:
  - 90 - 100: CRITICAL (4 hours)
  - 70 - 89:  HIGH     (24 hours)
  - 40 - 69:  MEDIUM   (168 hours / 7 days)
  -  0 - 39:  LOW      (720 hours / 30 days)
"""

from dataclasses import dataclass
from datetime import timedelta
from typing import Union


@dataclass(frozen=True)
class SLARule:
    priority: str
    sla_hours: int


# (min_risk, max_risk, priority_label, sla_hours)
_SLA_TABLE = [
    (90, 100, "CRITICAL", 4),
    (70, 89, "HIGH", 24),
    (40, 69, "MEDIUM", 24 * 7),   # 168 hours (7 days)
    (0, 39, "LOW", 24 * 30),      # 720 hours (30 days)
]


def classify(risk_score: Union[int, float]) -> SLARule:
    """Map a 0-100 risk score to (priority, sla_hours)."""
    if not isinstance(risk_score, (int, float)) or not 0 <= risk_score <= 100:
        raise ValueError(f"risk_score must be a number 0-100, got {risk_score!r}")

    rounded_score = int(round(risk_score))
    for low, high, priority, hours in _SLA_TABLE:
        if low <= rounded_score <= high:
            return SLARule(priority=priority, sla_hours=hours)

    raise ValueError(f"risk_score {risk_score} did not match any SLA band")


def sla_timedelta(risk_score: Union[int, float]) -> timedelta:
    return timedelta(hours=classify(risk_score).sla_hours)
