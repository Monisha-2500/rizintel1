"""
sla_engine.py
-------------
OPERATIONS: SLA Assignment, SLA Deadline Calculation,
            Remaining SLA Time Calculation, SLA Breach Detection,
            SLA Early Warning (status calculation)

This module never recalculates risk_score - it only converts an
existing risk_score into a priority + SLA duration, and later checks
a ticket's live remaining time against its deadline.
"""

from .config import WARNING_THRESHOLD_HOURS
from .time_utils import now_utc, format_timedelta


def createsla(risk_score):
    """
    Given a risk_score, return (priority, sla_hours) using the
    fixed SLA rules for Member 7:

        90-100 -> CRITICAL -> 4 hours
        70-89  -> HIGH     -> 24 hours
        40-69  -> MEDIUM   -> 7 days (168 hours)
        <40    -> LOW      -> 30 days (720 hours)
    """
    if risk_score >= 90:
        return "CRITICAL", 4
    elif risk_score >= 70:
        return "HIGH", 24
    elif risk_score >= 40:
        return "MEDIUM", 24 * 7
    else:
        return "LOW", 24 * 30


def sla_duration_text(sla_hours):
    """Turn an SLA duration in hours into a readable string."""
    if sla_hours < 24:
        return f"{sla_hours} hours"
    days = sla_hours // 24
    return f"{days} days"


def checksla(ticket):
    """
    Recalculate remaining time and SLA status for one ticket, using the
    CURRENT time (never hardcoded). Updates the ticket dictionary in place
    and also returns it.

    Sets ticket["sla_status"] to one of:
        ON_TRACK, WARNING, SLA_BREACHED, RESOLVED
    """
    if ticket["status"] == "RESOLVED":
        ticket["sla_status"] = "RESOLVED"
        ticket["remaining_time"] = "N/A"
        return ticket

    now = now_utc()
    deadline = ticket["sla_deadline_dt"]
    remaining = deadline - now

    if remaining.total_seconds() <= 0:
        ticket["sla_status"] = "SLA_BREACHED"
        ticket["status"] = "SLA_BREACHED"
        ticket["remaining_time"] = "0 minutes (breached)"
    elif remaining.total_seconds() <= WARNING_THRESHOLD_HOURS * 3600:
        ticket["sla_status"] = "WARNING"
        ticket["remaining_time"] = format_timedelta(remaining)
    else:
        ticket["sla_status"] = "ON_TRACK"
        ticket["remaining_time"] = format_timedelta(remaining)

    return ticket
