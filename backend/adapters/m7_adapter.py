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

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from mem7.sla_engine import classify


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
        asset_id = str(m6_finding.get("asset_id") or pipeline_context.get("asset_id") or "UNMAPPED")
        vuln_name = str(m6_finding.get("vulnerability_name") or pipeline_context.get("vulnerability_name") or "Vulnerability")
        vuln_type = str(pipeline_context.get("vulnerability_type") or "OTHER")

        # Score & level from M5 / M6
        raw_risk_score = float(m6_finding.get("risk_score", pipeline_context.get("risk_score", 0.0)))
        risk_score = max(0, min(100, int(round(raw_risk_score))))
        risk_level = str(m6_finding.get("risk_level") or pipeline_context.get("risk_level") or "LOW").upper()

        # Asset context
        ac = pipeline_context.get("asset_context") or {}
        asset_crit = str(ac.get("criticality") or ac.get("asset_criticality") or ("UNKNOWN" if asset_id == "UNMAPPED" else "MEDIUM")).upper()

        # Preserve None for UNMAPPED (genuinely unknown); cast to bool only for known assets
        _facing = ac.get("internet_facing")
        _exposure = ac.get("internet_exposure")
        if _facing is not None:
            internet_exp = bool(_facing)
        elif _exposure is not None:
            internet_exp = bool(_exposure)
        elif asset_id == "UNMAPPED":
            internet_exp = None   # genuinely unknown — preserve, don't assume False
        else:
            internet_exp = True

        # Confidence classification & Noise assessment
        fc = pipeline_context.get("finding_confidence") or {}
        na = pipeline_context.get("noise_assessment") or {}

        raw_conf = str(
            m6_finding.get("finding_confidence_classification")
            or pipeline_context.get("finding_confidence_classification")
            or fc.get("classification")
            or "CONFIRMED"
        ).upper()
        conf_class = raw_conf.split(".")[-1]

        likely_noise = bool(na.get("likely_noise", False) or conf_class == "LIKELY_NOISE")
        review_required = bool(fc.get("review_required", False) or conf_class == "NEEDS_REVIEW")

        # Explanation & Remediation
        explanation = m6_finding.get("explanation") or {}
        remediation = m6_finding.get("remediation") or {}
        recommended_action = remediation.get(
            "recommended_action",
            "Review finding details and apply vendor security updates."
        )

        # Calculate SLA reference duration from M7 authoritative classify()
        rule = classify(risk_score)
        sla_hours = int(m7_ticket.get("sla_hours") or rule.sla_hours)
        sla_deadline_str = m7_ticket.get("sla_deadline") or m7_ticket.get("due_at")
        if sla_deadline_str and "T" not in sla_deadline_str and " " in sla_deadline_str:
            sla_due_at = sla_deadline_str.replace(" ", "T") + "Z"
        elif sla_deadline_str:
            sla_due_at = sla_deadline_str
        else:
            disc_dt = datetime.now(timezone.utc)
            due_dt = disc_dt + timedelta(hours=sla_hours)
            sla_due_at = due_dt.isoformat().replace("+00:00", "Z")

        sla_status = str(m7_ticket.get("sla_status") or "ON_TRACK").upper()
        ticket_id = str(m7_ticket.get("ticket_id") or f"VULN-{finding_id[-4:]}")
        is_assigned = bool(m7_ticket.get("assigned_to") and m7_ticket.get("assigned_to") != "Unassigned")

        # Operational Routing Policy:
        # Track 1: SUPPRESSED (Likely Noise)
        if likely_noise:
            workflow = {
                "ticket_id": None,
                "status": "SUPPRESSED",
                "assigned_to": None,
                "sla_hours": None,
                "sla_due_at": None,
                "sla_status": "NOT_APPLICABLE",
                "escalation_level": 0,
            }
            validated_stage_status = "SUPPRESSED_NOISE"
            assigned_stage_status = "SUPPRESSED"
            remediated_stage_status = "NOT_APPLICABLE"

        # Track 2: PENDING_REVIEW (Needs Analyst Review)
        elif review_required:
            workflow = {
                "ticket_id": None,
                "status": "PENDING_REVIEW",
                "assigned_to": None,
                "sla_hours": sla_hours,
                "sla_due_at": None,
                "sla_status": "PENDING_REVIEW",
                "escalation_level": 0,
            }
            validated_stage_status = "NEEDS_REVIEW"
            assigned_stage_status = "PENDING"
            remediated_stage_status = "PENDING"

        # Track 3: OPEN (Actionable / Confirmed Remediation)
        else:
            workflow = {
                "ticket_id": ticket_id,
                "status": str(m7_ticket.get("status") or "OPEN").upper(),
                "assigned_to": m7_ticket.get("assigned_to") if m7_ticket.get("assigned_to") != "Unassigned" else None,
                "sla_hours": sla_hours,
                "sla_due_at": sla_due_at,
                "sla_status": sla_status,
                "escalation_level": 0,
            }
            validated_stage_status = "DONE"
            assigned_stage_status = "DONE" if is_assigned else "PENDING"
            remediated_stage_status = "DONE" if workflow["status"] == "RESOLVED" else "PENDING"


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

        # Standard 8-stage journey reflecting M3 routing
        journey = [
            {"stage": "DETECTED", "status": "DONE"},
            {"stage": "CORRELATED", "status": "DONE"},
            {"stage": "VALIDATED", "status": validated_stage_status},
            {"stage": "ENRICHED", "status": "DONE"},
            {"stage": "PRIORITIZED", "status": "DONE"},
            {"stage": "EXPLAINED", "status": "DONE"},
            {"stage": "ASSIGNED", "status": assigned_stage_status},
            {"stage": "REMEDIATED", "status": remediated_stage_status}
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
                "asset_name": str(ac.get("asset_name") or ("Unresolved Asset" if asset_id == "UNMAPPED" else f"asset-{asset_id.lower()}")),
                "environment": str(ac.get("environment") or ("UNKNOWN" if asset_id == "UNMAPPED" else "PRODUCTION")).upper(),
                "criticality": asset_crit,
                "internet_facing": internet_exp,
                "data_sensitivity": str(ac.get("data_sensitivity") or ("UNKNOWN" if asset_id == "UNMAPPED" else "INTERNAL")).upper(),
            },
            "risk_assessment": {
                "score_breakdown": ra.get("score_breakdown") or {},
                "scoring_version": "M5-v1.0",
            },
            "explanation": {
                "technical": str(explanation.get("technical") or "Technical risk assessment completed."),
                "management": str(explanation.get("management") or "Management summary generated."),
                "top_risk_drivers": list(explanation.get("top_risk_drivers") or []),
                "generated_at": m6_finding.get("generated_at") or explanation.get("generated_at"),
                "references": list(remediation.get("references") or explanation.get("references") or []),
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
