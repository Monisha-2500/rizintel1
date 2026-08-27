"""
backend/mem7/connectors/jira_connector.py
-----------------------------------------
Jira Cloud Issue connector implementing TicketConnector.
"""

import os
import requests
from typing import Optional

from mem7.models import Ticket
from mem7.connectors.base import TicketConnector

STATUS_TO_JIRA_TRANSITION = {
    "IN_PROGRESS": "In Progress",
    "RESOLVED": "Done",
    "SLA_BREACHED": "In Progress",
}


class JiraConnector(TicketConnector):
    name = "jira"

    def __init__(
        self,
        base_url: Optional[str] = None,
        email: Optional[str] = None,
        api_token: Optional[str] = None,
        project_key: Optional[str] = None
    ):
        self.base_url = (base_url or os.environ.get("JIRA_BASE_URL", "")).rstrip("/")
        self.email = email or os.environ.get("JIRA_EMAIL")
        self.api_token = api_token or os.environ.get("JIRA_API_TOKEN")
        self.project_key = project_key or os.environ.get("JIRA_PROJECT_KEY")

        missing = [n for n, v in [
            ("JIRA_BASE_URL", self.base_url),
            ("JIRA_EMAIL", self.email),
            ("JIRA_API_TOKEN", self.api_token),
            ("JIRA_PROJECT_KEY", self.project_key),
        ] if not v]
        if missing:
            raise ValueError(f"JiraConnector is missing env vars: {', '.join(missing)}")

        self._auth = (self.email, self.api_token)
        self._headers = {"Accept": "application/json", "Content-Type": "application/json"}

    def _description_adf(self, ticket: Ticket) -> dict:
        text = (
            f"Finding ID: {ticket.finding_id}\n"
            f"CVE: {ticket.cve_id or 'N/A'}\n"
            f"Asset: {ticket.asset_name} ({ticket.asset_id})\n"
            f"Risk Score: {ticket.risk_score} ({ticket.priority})\n"
            f"SLA Window: {ticket.sla_hours} hours — Due {ticket.due_at.isoformat()}\n\n"
            f"Created automatically by RizIntel Remediation Engine."
        )
        return {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": line}] if line else [],
                }
                for line in text.split("\n")
            ],
        }

    def create_external_ticket(self, ticket: Ticket) -> str:
        url = f"{self.base_url}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[{ticket.priority}] {ticket.vulnerability_name} on {ticket.asset_name}",
                "description": self._description_adf(ticket),
                "issuetype": {"name": "Task"},
                "labels": ["rizintel", "auto-remediation", f"priority-{ticket.priority.lower()}"],
            }
        }
        resp = requests.post(url, json=payload, headers=self._headers, auth=self._auth, timeout=15)
        if not resp.ok:
            raise RuntimeError(f"Jira issue creation failed ({resp.status_code}): {resp.text}")
        issue = resp.json()
        return issue["key"]

    def sync_status(self, ticket: Ticket, external_ref: str) -> None:
        target_name = STATUS_TO_JIRA_TRANSITION.get(ticket.status.value)
        if not target_name:
            return

        trans_url = f"{self.base_url}/rest/api/3/issue/{external_ref}/transitions"
        resp = requests.get(trans_url, headers=self._headers, auth=self._auth, timeout=15)
        resp.raise_for_status()
        transitions = resp.json().get("transitions", [])

        match = next((t for t in transitions if t["name"].lower() == target_name.lower()), None)
        if not match:
            return

        resp = requests.post(
            trans_url,
            json={"transition": {"id": match["id"]}},
            headers=self._headers,
            auth=self._auth,
            timeout=15
        )
        resp.raise_for_status()
