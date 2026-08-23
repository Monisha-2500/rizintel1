"""
state.py
--------
Simple shared in-memory storage used by every other module.

Keeping this in its own file (instead of a database) means all
modules can import `state` and read/update the same lists without
passing data back and forth manually.
"""

# All findings loaded from the input JSON file
findings = []

# All generated tickets (in-memory storage - no database needed)
tickets = []

# Counter used to build ticket IDs like TKT-0001, TKT-0002, ...
ticket_counter = 0


def next_ticket_id():
    """Return the next ticket ID and increase the counter."""
    global ticket_counter
    ticket_counter += 1
    return f"TKT-{ticket_counter:04d}"


def reset_tickets():
    """Clear all tickets and reset the counter (used before regenerating)."""
    global tickets, ticket_counter
    tickets = []
    ticket_counter = 0
