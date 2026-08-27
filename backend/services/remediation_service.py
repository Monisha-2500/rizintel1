"""
backend/services/remediation_service.py
=======================================
Orchestrator for M7 Remediation, Ticketing, SLA Governance, and Breach Detection.
"""

import os
import uuid
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Any

from mem7.models import Ticket, TicketStatus, VALID_TRANSITIONS, InvalidTransition
from mem7.sla_engine import classify
from mem7.breach_predictor import evaluate_ticket, BreachWarning
from mem7.connectors.base import TicketConnector
from mem7.connectors.internal_only import InternalOnlyConnector
from mem7.connectors.jira_connector import JiraConnector
from mem7.connectors.github_connector import GitHubIssuesConnector
import database

logger = logging.getLogger("rizintel.remediation")


class RemediationService:
    def __init__(self):
        self._init_connector()

    def _init_connector(self):
        """Initialise active external connector based on environment."""
        if os.environ.get("JIRA_BASE_URL") and os.environ.get("JIRA_API_TOKEN"):
            try:
                self.connector: TicketConnector = JiraConnector()
                logger.info("JiraConnector initialized for project %s", getattr(self.connector, "project_key", ""))
            except Exception as e:
                logger.warning("Failed to initialize JiraConnector: %s — falling back to InternalOnlyConnector", e)
                self.connector = InternalOnlyConnector()
        elif os.environ.get("GITHUB_TOKEN") and os.environ.get("GITHUB_REPO"):
            try:
                self.connector = GitHubIssuesConnector()
                logger.info("GitHubIssuesConnector initialized for repo %s", getattr(self.connector, "repo", ""))
            except Exception as e:
                logger.warning("Failed to initialize GitHubIssuesConnector: %s — falling back to InternalOnlyConnector", e)
                self.connector = InternalOnlyConnector()
        else:
            self.connector = InternalOnlyConnector()

    def generate_ticket_for_finding(
        self,
        organization_id: str,
        finding: Dict[str, Any],
        created_by: str = "system"
    ) -> Dict[str, Any]:
        """
        Creates or retrieves an authoritative remediation ticket for a finding.
        Idempotent: if a ticket already exists for finding_id, returns it.
        """
        finding_id = str(finding.get("finding_id"))
        existing = database.get_remediation_ticket_by_finding_id(organization_id, finding_id)
        if existing:
            return existing

        # Workflow Eligibility Check
        f_status = str(finding.get("status") or (finding.get("workflow", {}).get("status") if isinstance(finding.get("workflow"), dict) else "")).upper()
        r_action = str(finding.get("routing_action") or "").upper()
        if f_status in ("SUPPRESSED", "FALSE_POSITIVE") or r_action in ("SUPPRESSED", "LIKELY_NOISE"):
            # Check for authorized human decision override
            events = database.get_audit_events(finding_id)
            has_override = any(ev.get("analyst_action") in ("ACCEPT_PRIORITY", "ESCALATE") for ev in events)
            if not has_override:
                raise ValueError(
                    f"Workflow Ineligible: Finding {finding_id} is in status '{f_status or r_action}' and cannot generate an active remediation ticket without an authorized analyst decision override."
                )

        risk_score = int(finding.get("risk_score", 50))
        rule = classify(risk_score)

        # Compute SLA start and deadline
        disc_raw = finding.get("discovered_at") or finding.get("created_at")
        if disc_raw:
            try:
                clean_disc = disc_raw.replace("Z", "+00:00")
                disc_dt = datetime.fromisoformat(clean_disc)
            except Exception:
                disc_dt = datetime.now(timezone.utc)
        else:
            disc_dt = datetime.now(timezone.utc)

        due_dt = disc_dt + timedelta(hours=rule.sla_hours)

        disc_iso = disc_dt.isoformat()
        due_iso = due_dt.isoformat()

        # Asset context
        ac = finding.get("detail", {}).get("asset_context", {}) if isinstance(finding.get("detail"), dict) else {}
        asset_name = ac.get("asset_name") or finding.get("asset_name") or finding.get("asset_id") or "Target Asset"
        vulnerability_name = finding.get("vulnerability_name") or "Security Vulnerability"
        cve_id = finding.get("cve_id")
        asset_id = str(finding.get("asset_id") or "ASSET-UNMAPPED")

        ticket_id = f"TCK-{uuid.uuid4().hex[:10].upper()}"

        ticket_row = database.create_remediation_ticket(
            ticket_id=ticket_id,
            organization_id=organization_id,
            finding_id=finding_id,
            cve_id=cve_id,
            asset_id=asset_id,
            asset_name=asset_name,
            vulnerability_name=vulnerability_name,
            risk_score=risk_score,
            priority=rule.priority,
            sla_hours=rule.sla_hours,
            discovered_at=disc_iso,
            due_at=due_iso,
            status="OPEN",
            assigned_to=None,
            created_by=created_by,
        )

        # Attempt to mirror out to external connector if configured
        if self.connector and self.connector.name != "internal_only":
            try:
                ticket_obj = self._row_to_model(ticket_row)
                ext_ref = self.connector.create_external_ticket(ticket_obj)
                database.set_remediation_ticket_external_ref(
                    organization_id, ticket_id, self.connector.name, ext_ref
                )
                ticket_row = database.get_remediation_ticket(organization_id, ticket_id)
            except Exception as ex:
                logger.warning("External connector sync failed for ticket %s: %s", ticket_id, ex)

        # Log cryptographic audit trail event
        database.insert_audit_event(
            finding_id=finding_id,
            m5_risk_score=risk_score,
            analyst_action="TICKET_GENERATED",
            rationale=f"Created remediation task {ticket_id} ({rule.priority}, {rule.sla_hours}h SLA)",
            role=created_by,
            data_source="LIVE",
        )

        return ticket_row

    def _clean_role(self, role: Any) -> str:
        s = getattr(role, "value", str(role))
        if s.startswith("UserRole."):
            return s.replace("UserRole.", "")
        return s

    def assign_ticket(
        self,
        organization_id: str,
        ticket_id: str,
        assignee: str,
        user_name: str = "Analyst",
        user_role: Any = "ANALYST"
    ) -> Dict[str, Any]:
        """Assign owner to ticket and record audit event idempotently."""
        clean_assignee = (assignee or "").strip()
        role_str = self._clean_role(user_role)

        current_ticket = database.get_remediation_ticket(organization_id, ticket_id)
        if not current_ticket:
            raise KeyError(f"Ticket {ticket_id} not found in organization {organization_id}")

        if current_ticket.get("assigned_to") == clean_assignee:
            # Strictly idempotent: same owner already assigned, return without duplicate history or audit log
            return current_ticket

        updated = database.assign_remediation_ticket(
            organization_id=organization_id,
            ticket_id=ticket_id,
            assignee=clean_assignee,
            changed_by=f"{user_name} [{role_str}]"
        )
        if not updated:
            raise KeyError(f"Ticket {ticket_id} not found in organization {organization_id}")

        finding_id = updated["finding_id"]
        risk_score = updated["risk_score"]
        display_name = updated.get("assignee_display_name") or clean_assignee

        # Log audit trail event
        database.insert_audit_event(
            finding_id=finding_id,
            m5_risk_score=risk_score,
            analyst_action="TICKET_ASSIGNED",
            rationale=f"Remediation task {ticket_id} assigned to {display_name} ({clean_assignee})",
            role=f"{user_name} [{role_str}]",
            data_source="LIVE",
        )

        return updated

    def update_ticket_status(
        self,
        organization_id: str,
        ticket_id: str,
        new_status: str,
        note: str = "",
        user_name: str = "Analyst",
        user_role: Any = "ANALYST"
    ) -> Dict[str, Any]:
        """Transition ticket status with strict state machine validation."""
        role_str = self._clean_role(user_role)
        ticket_row = database.get_remediation_ticket(organization_id, ticket_id)
        if not ticket_row:
            raise KeyError(f"Ticket {ticket_id} not found in organization {organization_id}")

        current_status_enum = TicketStatus(ticket_row["status"])
        try:
            new_status_enum = TicketStatus(new_status.upper())
        except ValueError:
            raise InvalidTransition(f"Invalid ticket status: {new_status}")

        if new_status_enum != current_status_enum:
            allowed = VALID_TRANSITIONS.get(current_status_enum, set())
            if new_status_enum not in allowed:
                raise InvalidTransition(
                    f"Illegal transition: cannot move ticket {ticket_id} from {current_status_enum.value} to {new_status_enum.value}. Allowed: {[s.value for s in allowed]}"
                )

        updated = database.update_remediation_ticket_status(
            organization_id=organization_id,
            ticket_id=ticket_id,
            new_status=new_status_enum.value,
            note=note,
            changed_by=f"{user_name} [{role_str}]"
        )

        # Sync to external connector if present
        if self.connector and self.connector.name != "internal_only":
            try:
                refs = json.loads(updated.get("external_refs") or "{}")
                ext_ref = refs.get(self.connector.name)
                if ext_ref:
                    ticket_obj = self._row_to_model(updated)
                    self.connector.sync_status(ticket_obj, ext_ref)
            except Exception as ex:
                logger.warning("Failed to sync status change to external connector: %s", ex)

        # Log audit trail event
        database.insert_audit_event(
            finding_id=updated["finding_id"],
            m5_risk_score=updated["risk_score"],
            analyst_action=f"STATUS_{new_status_enum.value}",
            rationale=note or f"Remediation task status changed to {new_status_enum.value}",
            role=f"{user_name} [{role_str}]",
            data_source="LIVE",
        )

        return updated

    def get_checklist(self, organization_id: str, ticket_id: str) -> List[Dict[str, Any]]:
        """Retrieve persisted checklist steps for ticket."""
        return database.get_remediation_checklist(organization_id, ticket_id)

    def update_checklist_step(
        self,
        organization_id: str,
        ticket_id: str,
        step_id: str,
        new_status: str,
        user_name: str = "Analyst",
        user_role: Any = "ANALYST"
    ) -> List[Dict[str, Any]]:
        """Update a specific checklist step status and persist."""
        role_str = self._clean_role(user_role)
        return database.update_remediation_checklist_step(
            organization_id=organization_id,
            ticket_id=ticket_id,
            step_id=step_id,
            new_status=new_status,
            actor_name=user_name,
            actor_role=role_str
        )

    def run_sweep(self, organization_id: str) -> List[Dict[str, Any]]:
        """
        Evaluate all non-resolved tickets for the organization:
        - Auto-flags SLA_BREACHED if now > due_at
        - Returns early breach warnings for tickets approaching deadline
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        open_tickets = database.list_remediation_tickets(organization_id, limit=500)
        warnings: List[BreachWarning] = []

        for row in open_tickets:
            if row["status"] == "RESOLVED":
                continue

            ticket_obj = self._row_to_model(row)

            # Check hard breach
            due_clean = ticket_obj.due_at
            if due_clean.tzinfo is not None:
                due_clean = due_clean.astimezone(timezone.utc).replace(tzinfo=None)

            if now > due_clean and ticket_obj.status != TicketStatus.SLA_BREACHED:
                database.update_remediation_ticket_status(
                    organization_id=organization_id,
                    ticket_id=ticket_obj.ticket_id,
                    new_status="SLA_BREACHED",
                    note="auto-flagged by SLA breach sweep",
                    changed_by="breach_predictor"
                )
                updated_row = database.get_remediation_ticket(organization_id, ticket_obj.ticket_id)
                ticket_obj = self._row_to_model(updated_row)

            warning = evaluate_ticket(ticket_obj, now=now)
            if warning:
                warnings.append(warning)

        # Sort warnings: most urgent first
        warnings.sort(key=lambda w: w.minutes_remaining)
        return [w.to_dict() for w in warnings]

    def _row_to_model(self, row: Dict[str, Any]) -> Ticket:
        """Convert database dictionary row to Ticket model dataclass."""
        disc_raw = row["discovered_at"].replace("Z", "+00:00") if row["discovered_at"] else datetime.now(timezone.utc).isoformat()
        due_raw = row["due_at"].replace("Z", "+00:00") if row["due_at"] else datetime.now(timezone.utc).isoformat()

        disc_dt = datetime.fromisoformat(disc_raw).astimezone(timezone.utc).replace(tzinfo=None)
        due_dt = datetime.fromisoformat(due_raw).astimezone(timezone.utc).replace(tzinfo=None)

        created_dt = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None) if row.get("created_at") else datetime.utcnow()
        updated_dt = datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None) if row.get("updated_at") else datetime.utcnow()
        resolved_dt = datetime.fromisoformat(row["resolved_at"].replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None) if row.get("resolved_at") else None

        refs = json.loads(row.get("external_refs") or "{}") if isinstance(row.get("external_refs"), str) else (row.get("external_refs") or {})

        return Ticket(
            ticket_id=row["ticket_id"],
            organization_id=row["organization_id"],
            finding_id=row["finding_id"],
            cve_id=row.get("cve_id"),
            asset_id=row["asset_id"],
            asset_name=row.get("asset_name") or "Asset",
            vulnerability_name=row.get("vulnerability_name") or "Vulnerability",
            risk_score=row["risk_score"],
            priority=row["priority"],
            sla_hours=row["sla_hours"],
            discovered_at=disc_dt,
            due_at=due_dt,
            status=TicketStatus(row["status"]),
            assigned_to=row.get("assigned_to"),
            created_at=created_dt,
            updated_at=updated_dt,
            resolved_at=resolved_dt,
            external_refs=refs,
        )


remediation_service = RemediationService()
