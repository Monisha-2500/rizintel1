"""
audit_service.py — Business logic layer for the audit trail.
Wraps the database module so routers stay thin.
"""

from database import insert_audit_event, get_audit_events, verify_chain


class AuditService:
    def create_event(
        self,
        finding_id: str,
        m5_risk_score: int,
        analyst_action: str,
        rationale: str,
        role: str,
        timestamp: str,
    ) -> dict:
        return insert_audit_event(
            finding_id=finding_id,
            m5_risk_score=m5_risk_score,
            analyst_action=analyst_action,
            rationale=rationale,
            role=role,
            timestamp=timestamp,
        )

    def get_events(self, finding_id: str) -> list[dict]:
        return get_audit_events(finding_id)

    def verify(self, finding_id: str) -> dict:
        return verify_chain(finding_id)


audit_service = AuditService()
