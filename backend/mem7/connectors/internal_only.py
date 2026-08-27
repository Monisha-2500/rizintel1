"""
backend/mem7/connectors/internal_only.py
----------------------------------------
Default internal-only connector for native RizIntel SOC workflows.
"""

from mem7.models import Ticket
from mem7.connectors.base import TicketConnector


class InternalOnlyConnector(TicketConnector):
    name = "internal_only"

    def create_external_ticket(self, ticket: Ticket) -> str:
        return f"internal:{ticket.ticket_id}"

    def sync_status(self, ticket: Ticket, external_ref: str) -> None:
        pass
