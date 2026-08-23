"""
views.py
--------
OPERATIONS: View All Tickets, View Critical Tickets, View High Priority
            Tickets, View SLA Warnings, View SLA Breached Tickets,
            Show Ticket Details, and the shared ticket/warning/breach
            print formats.
"""

from . import state
from .sla_engine import checksla
from .ticket_manager import find_ticket


def print_ticket(ticket):
    """Print one ticket in the standard Member 7 format."""
    checksla(ticket)
    print("-" * 50)
    print(f"TICKET: {ticket['ticket_id']}")
    print("-" * 50)
    print(f"Finding ID       : {ticket['finding_id']}")
    print(f"CVE              : {ticket['cve_id']}")
    print(f"Vulnerability    : {ticket['vulnerability_name']}")
    print(f"Asset            : {ticket['asset_name']}")
    print(f"Risk Score       : {ticket['risk_score']}")
    print(f"Risk Level       : {ticket['risk_level']}")
    print(f"Priority         : {ticket['priority']}")
    print()
    print(f"SLA Duration     : {ticket['sla_duration']}")
    print(f"SLA Start        : {ticket['sla_start_time']}")
    print(f"SLA Deadline     : {ticket['sla_deadline']}")
    print()
    print(f"Remaining Time   : {ticket['remaining_time']}")
    print(f"Status           : {ticket['status']}")
    print(f"SLA Status       : {ticket['sla_status']}")
    print(f"Assigned To      : {ticket['assigned_to']}")
    print()
    print("Recommended Action:")
    print(ticket["recommended_action"])
    print("-" * 50)
    print()

    if ticket["sla_status"] == "SLA_BREACHED":
        print_breach_banner(ticket)


def print_breach_banner(ticket):
    """Print the standard SLA breached banner for one ticket."""
    print("=" * 50)
    print("🚨 SLA BREACHED")
    print("=" * 50)
    print(f"Ticket          : {ticket['ticket_id']}")
    print(f"Finding         : {ticket['finding_id']}")
    print(f"Vulnerability   : {ticket['vulnerability_name']}")
    print(f"Risk Score      : {ticket['risk_score']}")
    print(f"Priority        : {ticket['priority']}")
    print(f"SLA Deadline    : {ticket['sla_deadline']}")
    print(f"Status          : {ticket['status']}")
    print("=" * 50)
    print()


def print_warning_banner(ticket):
    """Print the standard SLA early warning banner for one ticket."""
    print("=" * 50)
    print("⚠️  SLA EARLY WARNING")
    print("=" * 50)
    print(f"Ticket          : {ticket['ticket_id']}")
    print(f"Finding         : {ticket['finding_id']}")
    print(f"Vulnerability   : {ticket['vulnerability_name']}")
    print(f"Risk Score      : {ticket['risk_score']}")
    print(f"Priority        : {ticket['priority']}")
    print(f"Remaining Time  : {ticket['remaining_time']}")
    print(f"Status          : {ticket['status']}")
    print(f"Assigned To     : {ticket['assigned_to']}")
    print()
    print("⚠️  HIGH RISK OF SLA BREACH")
    print("=" * 50)
    print()


def viewtickets():
    """View all tickets currently generated."""
    if not state.tickets:
        print("\nNo tickets available. Please generate tickets first.\n")
        return

    for ticket in state.tickets:
        print_ticket(ticket)


def _view_by_priority(priority_level):
    if not state.tickets:
        print("\nNo tickets available. Please generate tickets first.\n")
        return

    matches = [t for t in state.tickets if t["priority"] == priority_level]

    if not matches:
        print(f"\nNo {priority_level} priority tickets found.\n")
        return

    print(f"\nFound {len(matches)} {priority_level} priority ticket(s):\n")
    for ticket in matches:
        print_ticket(ticket)


def viewcritical():
    """View only CRITICAL priority tickets."""
    _view_by_priority("CRITICAL")


def viewhigh():
    """View only HIGH priority tickets."""
    _view_by_priority("HIGH")


def checkwarnings():
    """Print an SLA early warning for every unresolved ticket approaching its deadline."""
    if not state.tickets:
        print("\nNo tickets available. Please generate tickets first.\n")
        return

    found_any = False
    for ticket in state.tickets:
        checksla(ticket)
        if ticket["sla_status"] == "WARNING":
            found_any = True
            print_warning_banner(ticket)

    if not found_any:
        print("\nNo tickets are currently approaching their SLA deadline.\n")


def view_breached():
    """View all tickets that have breached their SLA."""
    if not state.tickets:
        print("\nNo tickets available. Please generate tickets first.\n")
        return

    found_any = False
    for ticket in state.tickets:
        checksla(ticket)
        if ticket["sla_status"] == "SLA_BREACHED":
            found_any = True
            print_breach_banner(ticket)

    if not found_any:
        print("\nNo tickets have breached their SLA.\n")


def showticket():
    """Show full details for one specific ticket, chosen by ticket ID."""
    if not state.tickets:
        print("\nNo tickets available. Please generate tickets first.\n")
        return

    ticket_id = input("\nEnter ticket ID: ").strip()
    ticket = find_ticket(ticket_id)

    if not ticket:
        print(f"\nTicket '{ticket_id}' not found.\n")
        return

    print_ticket(ticket)
