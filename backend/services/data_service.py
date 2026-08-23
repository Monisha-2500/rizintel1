import json
import os
from typing import List, Dict, Optional, Any
from models import FindingSchema, AuditEventCreate, AuditEventResponse, AnalystFeedbackInput
import database

# Data store service loading mock files dynamically and persisting audit trail to SQLite

class DataService:
    def __init__(self):
        self.findings_path = self._resolve_path("mock_findings.json")
        self.summary_path = self._resolve_path("dashboard_summary.json")
        self._findings_cache = []
        self._summary_cache = {}
        self.load_all()

    def _resolve_path(self, filename: str) -> str:
        candidates = [
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", filename)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", filename)),
            os.path.abspath(os.path.join(os.getcwd(), filename)),
            os.path.abspath(os.path.join(os.getcwd(), "backend", filename))
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return candidates[0]

    def load_all(self):
        # Load findings
        if os.path.exists(self.findings_path):
            with open(self.findings_path, "r") as f:
                data = json.load(f)
                # Parse to validate against Schema v1.0
                self._findings_cache = [FindingSchema(**item) for item in data]
        else:
            self._findings_cache = []

        # Load summary
        if os.path.exists(self.summary_path):
            with open(self.summary_path, "r") as f:
                self._summary_cache = json.load(f)
        else:
            self._summary_cache = {}

    def get_findings(self) -> List[FindingSchema]:
        return self._findings_cache

    def get_finding_by_id(self, finding_id: str) -> Optional[FindingSchema]:
        for f in self._findings_cache:
            if f.finding_id.lower() == finding_id.lower():
                return f
        # Also check dynamic integration pipeline cache if available
        try:
            from routers.integration import _pipeline_cache
            for f in _pipeline_cache.get("findings", []):
                if f.finding_id.lower() == finding_id.lower():
                    return f
        except Exception:
            pass
        return None

    def get_dashboard_summary(self) -> Dict:
        return self._summary_cache

    def add_audit_event(
        self,
        finding_id: str,
        analyst_action: str,
        m5_risk_score: int,
        rationale: str = "",
        role: str = "security_analyst",
        timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Record a cryptographically chained tamper-evident decision into SQLite.
        Preserves original M5 risk score separately.
        """
        return database.insert_audit_event(
            finding_id=finding_id,
            m5_risk_score=m5_risk_score,
            analyst_action=analyst_action,
            rationale=rationale,
            role=role,
            timestamp=timestamp
        )

    def get_audit_events(self, finding_id: str) -> List[Dict[str, Any]]:
        """Retrieve persistent audit trail for a finding from SQLite (newest first)."""
        return database.get_audit_events(finding_id, desc=True)

    def verify_audit_trail(self, finding_id: str) -> Dict[str, Any]:
        """Verify the SHA-256 chain integrity of the audit trail."""
        return database.verify_chain(finding_id)

    # Backward-compatible helper for feedback endpoints
    def add_feedback(self, finding_id: str, feedback: Any, m5_score: Optional[int] = None) -> Dict[str, Any]:
        action = getattr(feedback, "analyst_action", None) or getattr(feedback, "analyst_decision", None) or "ACCEPT_PRIORITY"
        reason = getattr(feedback, "rationale", None) or getattr(feedback, "reason", "") or ""
        role = getattr(feedback, "role", "security_analyst") or "security_analyst"
        ts = getattr(feedback, "timestamp", None)
        
        if m5_score is None:
            f = self.get_finding_by_id(finding_id)
            m5_score = f.risk_score if f else 0

        event = self.add_audit_event(
            finding_id=finding_id,
            analyst_action=action,
            m5_risk_score=m5_score,
            rationale=reason,
            role=role,
            timestamp=ts
        )
        return {"success": True, "event": event, "feedback": event}

    def get_feedback_for_finding(self, finding_id: str) -> List[Dict[str, Any]]:
        return self.get_audit_events(finding_id)

# Singleton instance
data_service = DataService()

