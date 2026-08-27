"""
backend/mem7/connectors/github_connector.py
-------------------------------------------
GitHub Issues connector implementing TicketConnector.
"""

import os
import requests
from typing import Optional

from mem7.models import Ticket
from mem7.connectors.base import TicketConnector

GITHUB_API = "https://api.github.com"


class GitHubIssuesConnector(TicketConnector):
    name = "github"

    def __init__(self, token: Optional[str] = None, repo: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.repo = repo or os.environ.get("GITHUB_REPO")  # "owner/repo"
        if not self.token or not self.repo:
            raise ValueError("GitHubIssuesConnector needs GITHUB_TOKEN and GITHUB_REPO")
        self._headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
        }

    def _priority_labels(self, ticket: Ticket):
        return [f"priority:{ticket.priority.lower()}", "rizintel", "security-finding"]

    def create_external_ticket(self, ticket: Ticket) -> str:
        url = f"{GITHUB_API}/repos/{self.repo}/issues"
        body = (
            f"**Finding ID:** {ticket.finding_id}\n"
            f"**CVE:** {ticket.cve_id or 'N/A'}\n"
            f"**Asset:** {ticket.asset_name} ({ticket.asset_id})\n"
            f"**Risk Score:** {ticket.risk_score} ({ticket.priority})\n"
            f"**SLA Due:** {ticket.due_at.isoformat()}\n\n"
            f"_Created automatically by RizIntel Remediation Engine._"
        )
        payload = {
            "title": f"[{ticket.priority}] {ticket.vulnerability_name} on {ticket.asset_name}",
            "body": body,
            "labels": self._priority_labels(ticket),
        }
        resp = requests.post(url, json=payload, headers=self._headers, timeout=15)
        resp.raise_for_status()
        issue = resp.json()
        return f"{self.repo}#{issue['number']}"

    def sync_status(self, ticket: Ticket, external_ref: str) -> None:
        if "#" not in external_ref:
            return
        repo, number = external_ref.split("#")
        url = f"{GITHUB_API}/repos/{repo}/issues/{number}"
        state = "closed" if ticket.status.value == "RESOLVED" else "open"
        resp = requests.patch(url, json={"state": state}, headers=self._headers, timeout=15)
        resp.raise_for_status()
