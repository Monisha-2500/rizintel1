"""
backend/mem7/connectors/base.py
-------------------------------
Abstract base class for ticketing and issue tracking connectors.
"""

from abc import ABC, abstractmethod
from mem7.models import Ticket


class TicketConnector(ABC):
    name: str = "base"

    @abstractmethod
    def create_external_ticket(self, ticket: Ticket) -> str:
        """Create the ticket in the external system and return a reference string."""
        raise NotImplementedError

    @abstractmethod
    def sync_status(self, ticket: Ticket, external_ref: str) -> None:
        """Push a status change to the external system."""
        raise NotImplementedError
