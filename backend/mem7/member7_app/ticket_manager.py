"""
ticket_manager.py
------------------
OPERATIONS: Ticket Generation, Ticket Creation, Ticket Lookup

Builds ticket dictionaries from findings and stores them in state.tickets.
"""

from datetime import timedelta

from . import state
from .sla_engine import createsla, sla_duration_text, checksla
from .time_utils import now_utc, parse_time
from .storage import save_output


def createticket(finding):
    """Build a single ticket dictionary from one finding."""
    ticket_id = state.next_ticket_id()

    risk_score = finding.get("risk_score", 0)
    priority, sla_hours = createsla(risk_score)

    # SLA start time = when the finding was discovered
    discovered_at = finding.get("discovered_at")
    sla_start_time = parse_time(discovered_at) if discovered_at else now_utc()
    sla_deadline = sla_start_time + timedelta(hours=sla_hours)

    asset_context = finding.get("asset_context", {})
    remediation = finding.get("remediation", {})

    ticket = {
        "ticket_id": ticket_id,
        "finding_id": finding.get("finding_id"),
        "cve_id": finding.get("cve_id"),
        "vulnerability_name": finding.get("vulnerability_name"),
        "asset_id": finding.get("asset_id"),
        "asset_name": asset_context.get("asset_name", "Unknown"),
        "risk_score": risk_score,
        "risk_level": finding.get("risk_level"),
        "priority": priority,
        "sla_duration": sla_duration_text(sla_hours),
        "sla_hours": sla_hours,
        "sla_start_time": sla_start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "sla_deadline": sla_deadline.strftime("%Y-%m-%d %H:%M:%S"),
        "sla_deadline_dt": sla_deadline,   # kept for internal calculations
        "status": "OPEN",
        "assigned_to": "Unassigned",
        "recommended_action": remediation.get(
            "recommended_action", "No recommended action provided."
        ),
        "sla_status": "ON_TRACK",
        "resolved_at": None,
    }

    return ticket


def generatetickets():
    """Generate a remediation ticket for every finding currently loaded."""
    from .views import print_ticket   # local import avoids circular import

    if not state.findings:
        print("\nNo findings loaded. Please choose option 1 first.\n")
        return

    state.reset_tickets()

    for finding in state.findings:
        ticket = createticket(finding)
        checksla(ticket)
        state.tickets.append(ticket)

    print(f"\n{len(state.tickets)} remediation tickets generated successfully.\n")

    for ticket in state.tickets:
        print_ticket(ticket)

    save_output()


def find_ticket(ticket_id):
    """Look up a ticket by its ticket_id (case-insensitive)."""
    for ticket in state.tickets:
        if ticket["ticket_id"].lower() == ticket_id.lower():
            return ticket
    return None
