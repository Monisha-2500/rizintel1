"""
backend/mem7/breach_predictor.py
--------------------------------
Proactive SLA breach predictor and early warning engine.

Evaluates open remediation tickets:
  1. Hard breach: now > due_at and status != RESOLVED -> auto-flags SLA_BREACHED.
  2. Early warning: remaining time drops below warning threshold (<= 25% of SLA window
     or <= 120 minutes remaining).
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Union

from mem7.models import Ticket, TicketStatus

# Warn once remaining time drops below this fraction of the original SLA window.
DEFAULT_WARNING_FRACTION = 0.25

# Regardless of fraction, also warn if less than this many minutes remain
DEFAULT_WARNING_FLOOR_MINUTES = 120


@dataclass
class BreachWarning:
    ticket_id: str
    finding_id: str
    cve_id: Optional[str]
    asset_name: str
    priority: str
    status: str
    minutes_remaining: float
    message: str

    def to_dict(self):
        return {
            "ticket_id": self.ticket_id,
            "finding_id": self.finding_id,
            "cve_id": self.cve_id,
            "asset_name": self.asset_name,
            "priority": self.priority,
            "status": self.status,
            "minutes_remaining": self.minutes_remaining,
            "message": self.message,
        }


def _format_remaining(minutes: float) -> str:
    if minutes < 0:
        return "overdue"
    if minutes < 120:
        return f"{int(minutes)} minutes remaining"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f} hours remaining"
    return f"{hours / 24:.1f} days remaining"


def evaluate_ticket(
    ticket: Ticket,
    now: Optional[datetime] = None,
    warning_fraction: float = DEFAULT_WARNING_FRACTION,
    warning_floor_minutes: int = DEFAULT_WARNING_FLOOR_MINUTES
) -> Optional[BreachWarning]:
    """Return a BreachWarning if this single ticket is at risk, else None."""
    if ticket.status in (TicketStatus.RESOLVED,):
        return None

    if not now:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
    elif now.tzinfo is not None:
        now = now.astimezone(timezone.utc).replace(tzinfo=None)

    due_at = ticket.due_at
    if due_at.tzinfo is not None:
        due_at = due_at.astimezone(timezone.utc).replace(tzinfo=None)

    remaining = due_at - now
    remaining_minutes = remaining.total_seconds() / 60
    total_minutes = ticket.sla_hours * 60
    fraction_remaining = remaining_minutes / total_minutes if total_minutes else 0

    already_overdue = remaining_minutes <= 0
    at_risk = already_overdue or (
        fraction_remaining <= warning_fraction or remaining_minutes <= warning_floor_minutes
    )

    if not at_risk:
        return None

    unassigned_note = " and is still unassigned" if ticket.assigned_to is None else \
                       f" and is still {ticket.status.value.replace('_', ' ').lower()}"

    if already_overdue:
        message = (f"{ticket.priority.title()} finding '{ticket.vulnerability_name}' on "
                   f"{ticket.asset_name} is PAST its SLA deadline{unassigned_note} — SLA breached.")
    else:
        message = (f"{ticket.priority.title()} finding '{ticket.vulnerability_name}' on "
                   f"{ticket.asset_name} has {_format_remaining(remaining_minutes)}{unassigned_note} "
                   f"— high risk of SLA breach.")

    return BreachWarning(
        ticket_id=ticket.ticket_id,
        finding_id=ticket.finding_id,
        cve_id=ticket.cve_id,
        asset_name=ticket.asset_name,
        priority=ticket.priority,
        status=ticket.status.value if isinstance(ticket.status, TicketStatus) else str(ticket.status),
        minutes_remaining=round(remaining_minutes, 1),
        message=message,
    )
