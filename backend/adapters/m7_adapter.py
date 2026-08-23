"""
m7_adapter.py
=============
M7ActionableFindingAdapter: Combines Member 6's Explainable Finding,
Member 7's SLA/Ticketing automation calculations, and upstream pipeline
provenance into the final Schema v1.0 ActionableFinding (FindingSchema) consumed by M8.

Rules:
- M5 risk_score and risk_level are immutable.
- M7 assigns workflow SLA durations and deadlines based on M5 risk_score.
- Preserves full provenance and all source finding IDs for RizTrace and Risk DNA.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class M7ActionableFindingAdapter:
    """
    Constructs the canonical Schema v1.0 ActionableFinding for M8 ingestion.
    """

    @staticmethod
    def build_actionable_finding(
        m6_finding: Dict[str, Any],
        m7_ticket: Dict[str, Any],
        pipeline_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Merges M6 explanation, M7 SLA ticket data, and full pipeline context
        into a valid FindingSchema dictionary.
        """
        # Top-level identity
        finding_id = str(m6_finding.get("finding_id"))
        cve_id = m6_finding.get("cve_id")
        asset_id = str(m6_finding.get("asset_id") or pipeline_context.get("asset_id") or "ASSET-WEB-001")
        vuln_name = str(m6_finding.get("vulnerability_name") or pipeline_context.get("vulnerability_name") or "Vulnerability")
        vuln_type = str(pipeline_context.get("vulnerability_type") or "OTHER")

        # Score & level from M5 / M6
        raw_risk_score = float(m6_finding.get("risk_score", pipeline_context.get("risk_score", 0.0)))
        risk_score = max(0, min(100, int(round(raw_risk_score))))
        risk_level = str(m6_finding.get("risk_level") or pipeline_context.get("risk_level") or "LOW").upper()

        # Asset context
        ac = pipeline_context.get("asset_context") or {}
        asset_crit = str(ac.get("criticality") or ac.get("asset_criticality") or "MEDIUM").upper()
        internet_exp = bool(ac.get("internet_facing") if "internet_facing" in ac else ac.get("internet_exposure", True))

        # Confidence classification
        raw_conf = str(
            m6_finding.get("finding_confidence_classification")
            or pipeline_context.get("finding_confidence_classification")
            or "CONFIRMED"
        ).upper()
        conf_class = raw_conf.split(".")[-1]

        # Explanation & Remediation
        explanation = m6_finding.get("explanation") or {}
        remediation = m6_finding.get("remediation") or {}
        recommended_action = remediation.get(
            "recommended_action",
            "Review finding details and apply vendor security updates."
        )

        # M7 Workflow & SLA
        sla_hours = m7_ticket.get("sla_hours", 24)
        sla_deadline_str = m7_ticket.get("sla_deadline")
        # Format SLA deadline as ISO-8601 UTC if needed
        if sla_deadline_str and "T" not in sla_deadline_str and " " in sla_deadline_str:
            sla_due_at = sla_deadline_str.replace(" ", "T") + "Z"
        elif sla_deadline_str:
            sla_due_at = sla_deadline_str
        else:
            sla_due_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        sla_status = str(m7_ticket.get("sla_status") or "ON_TRACK").upper()
        ticket_id = str(m7_ticket.get("ticket_id") or f"VULN-{finding_id[-4:]}")

        workflow = {
            "ticket_id": ticket_id,
            "status": str(m7_ticket.get("status") or "OPEN").upper(),
            "assigned_to": m7_ticket.get("assigned_to") if m7_ticket.get("assigned_to") != "Unassigned" else None,
            "sla_hours": sla_hours,
            "sla_due_at": sla_due_at,
            "sla_status": sla_status,
            "escalation_level": 0,
        }

        # Timestamps
        discovered_at = pipeline_context.get("discovered_at") or pipeline_context.get("first_seen") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        updated_at = pipeline_context.get("updated_at") or pipeline_context.get("last_seen") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # Provenance source findings
        raw_source_findings = pipeline_context.get("source_findings") or []
        formatted_source_findings = []
        for sf in raw_source_findings:
            if isinstance(sf, dict):
                formatted_source_findings.append({
                    "finding_id": str(sf.get("finding_id", "RAW-001")),
                    "scanner": str(sf.get("scanner", "GENERIC")).upper()
                })
            elif isinstance(sf, str):
                formatted_source_findings.append({
                    "finding_id": sf,
                    "scanner": "SCANNER"
                })

        if not formatted_source_findings:
            formatted_source_findings = [{
                "finding_id": f"{finding_id}-RAW",
                "scanner": "SCANNER"
            }]

        # Determine assignment state for journey provenance
        is_assigned = bool(workflow.get("assigned_to") and workflow.get("assigned_to") != "Unassigned")

        # Standard 8-stage journey
        journey = [
            {"stage": "DETECTED", "status": "DONE"},
            {"stage": "CORRELATED", "status": "DONE"},
            {"stage": "VALIDATED", "status": "DONE"},
            {"stage": "ENRICHED", "status": "DONE"},
            {"stage": "PRIORITIZED", "status": "DONE"},
            {"stage": "EXPLAINED", "status": "DONE"},
            {"stage": "ASSIGNED", "status": "DONE" if is_assigned else "PENDING"},
            {"stage": "REMEDIATED", "status": "DONE" if workflow["status"] == "RESOLVED" else "PENDING"}
        ]

        # Threat intelligence
        ti = pipeline_context.get("threat_intelligence") or {}
        if hasattr(ti, "model_dump"):
            ti = ti.model_dump()
        elif hasattr(ti, "dict"):
            ti = ti.dict()

        # Scanner consensus
        sc = pipeline_context.get("scanner_consensus") or {}
        sc_names = sc.get("scanner_names") or sc.get("scanner_sources") or ["SCANNER"]

        # Finding confidence
        fc = pipeline_context.get("finding_confidence") or {}

        # Risk assessment
        ra = pipeline_context.get("risk_assessment") or {}

        # Construct full detail block
        detail = {
            "scanner_consensus": {
                "score": float(sc.get("score") or sc.get("scanner_consensus_score") or 1.0),
                "scanner_names": list(sc_names),
                "detected_by_count": int(sc.get("detected_by_count") or len(sc_names)),
                "total_scanners": int(sc.get("total_scanners") or max(len(sc_names), 3)),
            },
            "finding_confidence": {
                "score": float(fc.get("score") or fc.get("finding_confidence_score") or 0.95),
                "classification": conf_class,
            },
            "threat_intelligence": {
                "cvss_score": ti.get("cvss_score"),
                "epss_score": ti.get("epss_score"),
                "kev_listed": bool(ti.get("kev_listed") or False),
                "exploit_available": bool(ti.get("exploit_available") or False),
            },
            "asset_context": {
                "asset_name": str(ac.get("asset_name") or f"asset-{asset_id.lower()}"),
                "environment": str(ac.get("environment") or "PRODUCTION").upper(),
                "criticality": asset_crit,
                "internet_facing": internet_exp,
                "data_sensitivity": str(ac.get("data_sensitivity") or "INTERNAL").upper(),
            },
            "risk_assessment": {
                "score_breakdown": ra.get("score_breakdown") or {},
                "scoring_version": "M5-v1.0",
            },
            "explanation": {
                "technical": str(explanation.get("technical") or "Technical risk assessment completed."),
                "management": str(explanation.get("management") or "Management summary generated."),
                "top_risk_drivers": list(explanation.get("top_risk_drivers") or []),
            },
            "provenance": {
                "source_findings": formatted_source_findings,
                "journey": journey,
            },
            "risk_delta": pipeline_context.get("risk_delta"),
        }

        return {
            "schema_version": "1.0",
            "finding_id": finding_id,
            "cve_id": cve_id,
            "asset_id": asset_id,
            "vulnerability_name": vuln_name,
            "vulnerability_type": vuln_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confidence_classification": conf_class,
            "asset_criticality": asset_crit,
            "internet_exposure": internet_exp,
            "recommended_action": recommended_action,
            "workflow": workflow,
            "discovered_at": discovered_at,
            "updated_at": updated_at,
            "detail": detail,
        }
