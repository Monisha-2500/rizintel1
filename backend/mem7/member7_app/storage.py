"""
storage.py
----------
OPERATION: Save generated tickets to member7_output.json

Keeps things simple: no database, just an optional JSON export of the
in-memory ticket list. The terminal remains the primary output.
"""

import json

from . import state
from .config import OUTPUT_FILE


def save_output():
    """Save the current list of tickets to member7_output.json."""
    exportable = []
    for t in state.tickets:
        clean = {k: v for k, v in t.items() if k != "sla_deadline_dt"}
        exportable.append(clean)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(exportable, f, indent=2)
