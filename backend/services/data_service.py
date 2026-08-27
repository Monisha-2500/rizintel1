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

    def _get_user_org_ids(self, user: Optional[Any] = None) -> Optional[List[str]]:
        if not user:
            return None
        try:
            role = getattr(user, "role", None) or (user.get("role") if isinstance(user, dict) else None)
            role_val = getattr(role, "value", str(role)).upper()
            if role_val == "ADMIN":
                return None
            user_id = getattr(user, "user_id", None) or (user.get("user_id") if isinstance(user, dict) else None)
            if user_id:
                orgs = database.list_user_organizations(user_id)
                return [o["organization_id"] for o in orgs]
        except Exception:
            pass
        return []

    def get_findings(
        self,
        source: Optional[str] = None,
        user: Optional[Any] = None,
        organization_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
    ) -> List[FindingSchema]:
        src = (source or "").strip().upper()

        # If source is explicitly MOCK or FALLBACK, strictly return mock data
        if src in {"MOCK", "FALLBACK"}:
            return self._findings_cache

        user_org_ids = self._get_user_org_ids(user)

        # 1. Look up real canonical findings from SQLite scan_run_results
        try:
            raw_canonical = database.list_canonical_findings(
                organization_id=organization_id,
                user_org_ids=user_org_ids,
                scan_run_id=scan_run_id,
            )
            if raw_canonical is not None:
                results = []
                for f in raw_canonical:
                    try:
                        results.append(FindingSchema(**f))
                    except Exception:
                        pass
                # If queried with user_org_ids, organization_id, or scan_run_id, this is authoritative
                if user_org_ids is not None or organization_id is not None or scan_run_id is not None:
                    return results
                if results:
                    return results
        except Exception:
            pass

        # 2. Check live pipeline cache
        if src in {"LIVE", "INTEGRATED"}:
            try:
                from routers.integration import _pipeline_cache
                return _pipeline_cache.get("findings", [])
            except Exception:
                return []

        # 3. Check in-memory live pipeline cache if no scan runs exist yet
        try:
            from routers.integration import _pipeline_cache
            live_findings = _pipeline_cache.get("findings", [])
            if live_findings:
                return live_findings
        except Exception:
            pass

        # If user is scoped to orgs or scan run, never fall back to global mock findings
        if user_org_ids is not None or organization_id is not None or scan_run_id is not None:
            return []

        # 4. Fallback to mock findings for unauthenticated/mock dev exploration
        return self._findings_cache

    def get_finding_by_id(
        self,
        finding_id: str,
        source: Optional[str] = None,
        user: Optional[Any] = None,
        organization_id: Optional[str] = None,
    ) -> Optional[FindingSchema]:
        """
        Source-aware and tenant-safe canonical finding lookup.
        1. If source is explicitly MOCK or FALLBACK, searches mock cache strictly.
        2. Checks SQLite scan_run_results scoped to user's authorized organization(s).
        3. Checks live pipeline cache (_pipeline_cache).
        4. If source allows and not found in live data, checks mock findings cache.
        """
        clean_id = (finding_id or "").strip().lower()
        if not clean_id:
            return None

        src = (source or "").strip().upper()

        # If source is explicitly MOCK or FALLBACK, strictly return mock finding
        if src in {"MOCK", "FALLBACK"}:
            for f in self._findings_cache:
                if f.finding_id.lower() == clean_id or (f.cve_id and f.cve_id.lower() == clean_id):
                    return f
            return None

        user_org_ids = self._get_user_org_ids(user)

        # 1. Search persistent SQLite scan_run_results with tenant isolation
        try:
            db_finding = database.get_canonical_finding_by_id(
                finding_id=clean_id,
                organization_id=organization_id,
                user_org_ids=user_org_ids,
            )
            if db_finding:
                return FindingSchema(**db_finding)
        except Exception:
            pass

        # 2. Check live in-memory pipeline cache
        try:
            from routers.integration import _pipeline_cache
            for f in _pipeline_cache.get("findings", []):
                if f.finding_id.lower() == clean_id or (f.cve_id and f.cve_id.lower() == clean_id):
                    return f
        except Exception:
            pass

        # 3. Check mock findings cache if not found in db or live pipeline
        for f in self._findings_cache:
            if f.finding_id.lower() == clean_id or (f.cve_id and f.cve_id.lower() == clean_id):
                return f

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
        timestamp: Optional[str] = None,
        data_source: str = "LIVE",
        finding_snapshot_hash: str = ""
    ) -> Dict[str, Any]:
        """
        Record a cryptographically chained tamper-evident decision into SQLite.
        Preserves original M5 risk score, data source, and finding state fingerprint.
        """
        return database.insert_audit_event(
            finding_id=finding_id,
            m5_risk_score=m5_risk_score,
            analyst_action=analyst_action,
            rationale=rationale,
            role=role,
            timestamp=timestamp,
            data_source=data_source,
            finding_snapshot_hash=finding_snapshot_hash
        )

    def get_audit_events(self, finding_id: str) -> List[Dict[str, Any]]:
        """Retrieve persistent audit trail for a finding from SQLite (newest first)."""
        return database.get_audit_events(finding_id, desc=True)

    def verify_audit_trail(self, finding_id: str) -> Dict[str, Any]:
        """Verify the SHA-256 chain integrity of the audit trail."""
        return database.verify_chain(finding_id)

    def approve_review_finding(
        self,
        finding_id: str,
        assigned_to: Optional[str] = None,
        source: Optional[str] = None
    ) -> Optional[FindingSchema]:
        """Promote a PENDING_REVIEW finding to an active OPEN remediation ticket."""
        f = self.get_finding_by_id(finding_id, source=source)
        if not f:
            return None
        if f.workflow.status == "PENDING_REVIEW":
            f.workflow.status = "OPEN"
            f.workflow.ticket_id = f"TKT-{f.finding_id[-4:]}"
            f.workflow.sla_status = "ON_TRACK"
            f.workflow.sla_hours = 24 if f.risk_level in {"CRITICAL", "HIGH"} else 72
            if assigned_to:
                f.workflow.assigned_to = assigned_to
            for stage in f.detail.provenance.journey:
                if stage.stage == "VALIDATED":
                    stage.status = "DONE"
                elif stage.stage == "ASSIGNED":
                    stage.status = "DONE" if f.workflow.assigned_to else "PENDING"
        return f

    # Backward-compatible helper for feedback endpoints
    def add_feedback(
        self,
        finding_id: str,
        feedback: Any,
        m5_score: Optional[int] = None,
        source: Optional[str] = None,
        actor_role: Optional[str] = None
    ) -> Dict[str, Any]:
        action = getattr(feedback, "analyst_action", None) or getattr(feedback, "analyst_decision", None) or "ACCEPT_PRIORITY"
        reason = getattr(feedback, "rationale", None) or getattr(feedback, "reason", "") or ""
        role = actor_role or getattr(feedback, "role", "security_analyst") or "security_analyst"
        ts = getattr(feedback, "timestamp", None)
        data_source = getattr(feedback, "data_source", None) or source or "LIVE"
        
        f = self.get_finding_by_id(finding_id, source=data_source)
        if m5_score is None:
            m5_score = f.risk_score if f else 0

        from models import compute_finding_fingerprint
        snapshot_hash = getattr(feedback, "finding_snapshot_hash", None) or (compute_finding_fingerprint(f) if f else "")

        # If finding was in PENDING_REVIEW and analyst confirmed/accepted, promote to OPEN
        if action in {"ACCEPT_PRIORITY", "ESCALATE", "CONFIRM"}:
            self.approve_review_finding(finding_id, source=data_source)

        event = self.add_audit_event(
            finding_id=finding_id,
            analyst_action=action,
            m5_risk_score=m5_score,
            rationale=reason,
            role=role,
            timestamp=ts,
            data_source=data_source,
            finding_snapshot_hash=snapshot_hash
        )
        return {"success": True, "event": event, "feedback": event}

    def get_feedback_for_finding(self, finding_id: str) -> List[Dict[str, Any]]:
        return self.get_audit_events(finding_id)

# Singleton instance
data_service = DataService()


