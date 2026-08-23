"""
actions.py
----------
OPERATIONS: Assign Ticket, Update Ticket Status, Resolve Ticket

These are the operations that change a ticket's state based on user
input from the terminal.
"""

from . import state
from .sla_engine import checksla
from .ticket_manager import find_ticket
from .time_utils import now_utc
from .storage import save_output


def assignticket():
    """Assign a ticket to a person by name."""
    if not state.tickets:
        print("\nNo tickets available. Please generate tickets first.\n")
        return

    ticket_id = input("\nEnter ticket ID: ").strip()
    ticket = find_ticket(ticket_id)

    if not ticket:
        print(f"\nTicket '{ticket_id}' not found.\n")
        return

    assignee = input("Enter assignee name: ").strip()
    ticket["assigned_to"] = assignee if assignee else "Unassigned"

    if ticket["status"] == "OPEN":
        ticket["status"] = "ASSIGNED"

    checksla(ticket)
    print(f"\nTicket {ticket['ticket_id']} assigned to {ticket['assigned_to']}.\n")
    save_output()


def resolveticket(ticket_id_input=None):
    """Mark a ticket as RESOLVED and report whether the SLA was met."""
    if not state.tickets:
        print("\nNo tickets available. Please generate tickets first.\n")
        return

    ticket_id = ticket_id_input or input("\nEnter ticket ID: ").strip()
    ticket = find_ticket(ticket_id)

    if not ticket:
        print(f"\nTicket '{ticket_id}' not found.\n")
        return

    now = now_utc()
    deadline = ticket["sla_deadline_dt"]

    ticket["status"] = "RESOLVED"
    ticket["sla_status"] = "RESOLVED"
    ticket["resolved_at"] = now.strftime("%Y-%m-%d %H:%M:%S")
    ticket["remaining_time"] = "N/A"

    print("\nTicket resolved successfully.\n")
    print("SLA Result:")
    if now <= deadline:
        print("✓ SLA MET\n")
    else:
        print("✗ SLA BREACHED\n")

    save_output()


def updatestatus():
    """Change a ticket's status: ASSIGNED / IN_PROGRESS / RESOLVED."""
    if not state.tickets:
        print("\nNo tickets available. Please generate tickets first.\n")
        return

    ticket_id = input("\nEnter ticket ID: ").strip()
    ticket = find_ticket(ticket_id)

    if not ticket:
        print(f"\nTicket '{ticket_id}' not found.\n")
        return

    print("\n1. ASSIGNED")
    print("2. IN_PROGRESS")
    print("3. RESOLVED")
    choice = input("Choose new status: ").strip()

    if choice == "1":
        ticket["status"] = "ASSIGNED"
        print("\nTicket status updated to ASSIGNED.\n")
    elif choice == "2":
        ticket["status"] = "IN_PROGRESS"
        print("\nTicket status updated to IN_PROGRESS.\n")
    elif choice == "3":
        resolveticket(ticket_id_input=ticket_id)
        return
    else:
        print("\nInvalid choice.\n")
        return

    checksla(ticket)
    save_output()
