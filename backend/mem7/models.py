"""
backend/mem7/models.py
----------------------
Core data shapes and state machine for the M7 Remediation, Ticketing & SLA Automation Engine.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, Set


class TicketStatus(str, Enum):
    OPEN = "OPEN"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    SLA_BREACHED = "SLA_BREACHED"


# Legal status transitions. Keys = current status, values = allowed next statuses.
# SLA_BREACHED is reachable from any non-terminal state (the monitor sets it),
# and work can still resume/resolve after a breach (breaches don't freeze the ticket).
VALID_TRANSITIONS: Dict[TicketStatus, Set[TicketStatus]] = {
    TicketStatus.OPEN: {TicketStatus.ASSIGNED, TicketStatus.IN_PROGRESS, TicketStatus.SLA_BREACHED, TicketStatus.RESOLVED},
    TicketStatus.ASSIGNED: {TicketStatus.IN_PROGRESS, TicketStatus.OPEN,
                             TicketStatus.SLA_BREACHED, TicketStatus.RESOLVED},
    TicketStatus.IN_PROGRESS: {TicketStatus.RESOLVED, TicketStatus.SLA_BREACHED, TicketStatus.ASSIGNED},
    TicketStatus.RESOLVED: set(),  # terminal
    TicketStatus.SLA_BREACHED: {TicketStatus.ASSIGNED, TicketStatus.IN_PROGRESS, TicketStatus.RESOLVED},
}


class InvalidTransition(Exception):
    pass


@dataclass
class Ticket:
    ticket_id: str
    organization_id: str
    finding_id: str
    cve_id: Optional[str]
    asset_id: str
    asset_name: str
    vulnerability_name: str
    risk_score: int
    priority: str
    sla_hours: int
    discovered_at: datetime
    due_at: datetime
    status: TicketStatus = TicketStatus.OPEN
    assigned_to: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    external_refs: Dict[str, str] = field(default_factory=dict)  # e.g. {"jira": "SEC-42"}

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, TicketStatus) else str(self.status)
        for k in ("discovered_at", "due_at", "created_at", "updated_at", "resolved_at"):
            if d[k] is not None:
                d[k] = d[k] if isinstance(d[k], str) else d[k].isoformat()
        return d
