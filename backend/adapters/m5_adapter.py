"""
m5_adapter.py
=============
M5RiskEngineAdapter: Bridges Member 4 threat intelligence and Asset Context
into Member 5 Risk Scoring Engine, and translates Member 5's output into
Schema v1.0 Section 8 (RiskAssessedFinding) consumed by Member 6.

Rules:
- M5 is the SOLE authority for risk_score and risk_level.
- Never mutates risk math; only formats boundaries.
- Defaults missing boolean flags (e.g. kev_listed, exploit_available) to False
  for M5's strict Pydantic type validator without fabricating positive evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class M5RiskEngineAdapter:
    """
    Adapter for Member 5 Risk Engine inputs and outputs.
    """

    @staticmethod
    def prepare_m5_input(
        m4_finding: Dict[str, Any],
        asset_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Prepares the canonical payload required by M5's M5RiskEngineInput schema.
        """
        ti = m4_finding.get("threat_intelligence") or {}
        if hasattr(ti, "model_dump"):
            ti = ti.model_dump()
        elif hasattr(ti, "dict"):
            ti = ti.dict()

        # Handle null/None values safely for M5's strict boolean & float types
        cvss_score = ti.get("cvss_score")
        if cvss_score is None:
            cvss_score = 0.0
        else:
            cvss_score = float(cvss_score)

        epss_score = ti.get("epss_score")
        if epss_score is None:
            epss_score = 0.0
        else:
            epss_score = float(epss_score)

        epss_percentile = ti.get("epss_percentile")
        if epss_percentile is None:
            epss_percentile = 0.0
        else:
            epss_percentile = float(epss_percentile)

        kev_listed = bool(ti.get("kev_listed") or False)
        exploit_available = bool(ti.get("exploit_available") or False)

        # Asset context formatting
        ac_asset_id = asset_context.get("asset_id") or m4_finding.get("asset_id") or "UNMAPPED"
        ac_asset_name = asset_context.get("asset_name") or (f"host-{ac_asset_id}" if ac_asset_id != "UNMAPPED" else "Unresolved Asset")

        # Environment: UNKNOWN for unresolved assets (no fabricated DEVELOPMENT/PRODUCTION)
        ac_env = str(asset_context.get("environment") or ("UNKNOWN" if ac_asset_id == "UNMAPPED" else "PRODUCTION")).upper()

        # Criticality: pass UNKNOWN directly — M5 now accepts it and scores it 0 pts.
        # Known tiers (LOW/MEDIUM/HIGH/CRITICAL) pass through unchanged.
        raw_crit = str(asset_context.get("asset_criticality") or asset_context.get("criticality") or ("UNKNOWN" if ac_asset_id == "UNMAPPED" else "MEDIUM")).upper()
        if raw_crit in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
            ac_crit = raw_crit
        else:
            ac_crit = "UNKNOWN" if ac_asset_id == "UNMAPPED" else "MEDIUM"

        # Internet exposure: None for UNMAPPED (genuinely unknown) → M5 scores as 0 pts.
        # True/False pass through for known assets.
        if "internet_exposure" in asset_context and asset_context["internet_exposure"] is not None:
            ac_exp = bool(asset_context["internet_exposure"])
        elif "internet_facing" in asset_context and asset_context["internet_facing"] is not None:
            ac_exp = bool(asset_context["internet_facing"])
        elif ac_asset_id == "UNMAPPED":
            ac_exp = None  # genuinely unknown — do NOT default to False
        else:
            ac_exp = True

        # Data sensitivity: UNKNOWN for unresolved assets (no fabricated INTERNAL/PCI)
        ac_sens = str(asset_context.get("data_sensitivity") or ("UNKNOWN" if ac_asset_id == "UNMAPPED" else "INTERNAL")).upper()

        # Scanner sources & consensus
        scanner_sources = m4_finding.get("scanner_sources") or []
        if not scanner_sources and "scanner_consensus" in m4_finding:
            sc = m4_finding["scanner_consensus"]
            scanner_sources = sc.get("scanner_names", ["UNKNOWN_SCANNER"])
        if not scanner_sources:
            scanner_sources = ["UNKNOWN_SCANNER"]

        scanner_consensus_score = float(m4_finding.get("scanner_consensus_score") or (
            m4_finding.get("scanner_consensus", {}).get("score", 1.0) if isinstance(m4_finding.get("scanner_consensus"), dict) else 1.0
        ))

        # Confidence score & classification
        confidence_score = float(m4_finding.get("finding_confidence_score") or (
            m4_finding.get("finding_confidence", {}).get("score", 0.9) if isinstance(m4_finding.get("finding_confidence"), dict) else 0.9
        ))
        confidence_class = str(m4_finding.get("finding_confidence_classification") or (
            m4_finding.get("finding_confidence", {}).get("classification", "CONFIRMED") if isinstance(m4_finding.get("finding_confidence"), dict) else "CONFIRMED"
        )).upper()

        return {
            "schema_version": "1.0",
            "finding_id": str(m4_finding.get("finding_id")),
            "cve_id": m4_finding.get("cve_id"),
            "vulnerability_name": str(m4_finding.get("vulnerability_name") or "Unknown"),
            "vulnerability_type": str(m4_finding.get("vulnerability_type") or "OTHER"),
            "scanner_sources": list(scanner_sources),
            "scanner_consensus_score": min(1.0, max(0.0, scanner_consensus_score)),
            "finding_confidence_score": min(1.0, max(0.0, confidence_score)),
            "finding_confidence_classification": confidence_class,
            "threat_intelligence": {
                "cvss_score": min(10.0, max(0.0, cvss_score)),
                "epss_score": min(1.0, max(0.0, epss_score)),
                "epss_percentile": min(1.0, max(0.0, epss_percentile)),
                "kev_listed": kev_listed,
                "exploit_available": exploit_available,
            },
            "asset_context": {
                "asset_id": ac_asset_id,
                "asset_name": ac_asset_name,
                "environment": ac_env,
                "asset_criticality": ac_crit,
                "internet_exposure": ac_exp,  # None for UNMAPPED, True/False for known
                "data_sensitivity": ac_sens,
            }
        }

    @staticmethod
    def adapt_to_section8(
        m5_output: Any,
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Converts M5RiskEngineOutput into Schema v1.0 Section 8 (RiskAssessedFinding).
        """
        if hasattr(m5_output, "model_dump"):
            data = m5_output.model_dump()
        elif hasattr(m5_output, "dict"):
            data = m5_output.dict()
        elif isinstance(m5_output, dict):
            data = dict(m5_output)
        else:
            raise ValueError(f"Unsupported M5 output type: {type(m5_output)}")

        ra = data.get("risk_assessment") or {}
        sb = ra.get("score_breakdown") or {}
        ac = data.get("asset_context") or {}
        sc = data.get("scanner_consensus") or {}
        fc = data.get("finding_confidence") or {}
        ti = data.get("threat_intelligence") or {}

        # Flatten score breakdown into Section 8 format
        def _get_pts(factor_dict_or_val):
            if isinstance(factor_dict_or_val, dict):
                return float(factor_dict_or_val.get("points", 0))
            return float(factor_dict_or_val or 0)

        flat_breakdown = {
            "cvss_contribution": _get_pts(sb.get("cvss")),
            "epss_contribution": _get_pts(sb.get("epss")),
            "kev_contribution": _get_pts(sb.get("kev")),
            "exploit_contribution": _get_pts(sb.get("exploit_available")),
            "asset_criticality_contribution": _get_pts(sb.get("asset_criticality")),
            "exposure_contribution": _get_pts(sb.get("internet_exposure")),
            "scanner_confidence_contribution": _get_pts(sb.get("finding_confidence")),
        }

        # Scanner sources & names
        scanner_names = sc.get("scanner_sources") or sc.get("scanner_names") or []
        scanner_score = sc.get("scanner_consensus_score") or sc.get("score") or 1.0

        # Finding confidence
        conf_score = fc.get("finding_confidence_score") or fc.get("score") or 1.0
        conf_class = fc.get("finding_confidence_classification") or fc.get("classification") or "CONFIRMED"

        return {
            "schema_version": "1.0",
            "finding_id": data.get("finding_id"),
            "cve_id": data.get("cve_id"),
            "vulnerability_name": data.get("vulnerability_name"),
            "description": description or f"Vulnerability {data.get('vulnerability_name')} identified on asset {ac.get('asset_id')}.",
            "asset_context": {
                "asset_id": ac.get("asset_id"),
                "asset_name": ac.get("asset_name") or ("Unresolved Asset" if str(ac.get("asset_id")).upper() == "UNMAPPED" else f"host-{ac.get('asset_id')}"),
                "environment": ac.get("environment") or ("UNKNOWN" if str(ac.get("asset_id")).upper() == "UNMAPPED" else "PRODUCTION"),
                "criticality": "UNKNOWN" if str(ac.get("asset_id")).upper() == "UNMAPPED" else (ac.get("asset_criticality") or ac.get("criticality") or "MEDIUM"),
                "internet_facing": (
                    None if str(ac.get("asset_id")).upper() == "UNMAPPED"
                    else bool(ac.get("internet_exposure") if "internet_exposure" in ac else ac.get("internet_facing", True))
                ),
                "data_sensitivity": ac.get("data_sensitivity") or ("UNKNOWN" if str(ac.get("asset_id")).upper() == "UNMAPPED" else "INTERNAL"),
            },
            "threat_intelligence": {
                "cvss_score": ti.get("cvss_score"),
                "cvss_vector": ti.get("cvss_vector"),
                "epss_score": ti.get("epss_score"),
                "epss_percentile": ti.get("epss_percentile"),
                "kev_listed": ti.get("kev_listed"),
                "exploit_available": ti.get("exploit_available"),
                "exploit_sources": ti.get("exploit_sources", []),
            },
            "scanner_consensus": {
                "score": float(scanner_score),
                "scanner_names": list(scanner_names),
                "detected_by_count": len(scanner_names),
                "total_scanners": max(len(scanner_names), 3),
            },
            "finding_confidence": {
                "score": float(conf_score),
                "classification": str(conf_class),
            },
            "risk_assessment": {
                "risk_score": float(ra.get("risk_score", 0.0)),
                "risk_level": str(ra.get("risk_level", "LOW")),
                "score_breakdown": flat_breakdown,
                "scoring_version": "M5-v1.0",
            },
            "metadata": {
                "generated_by": (data.get("metadata") or {}).get("engine_name") or (data.get("metadata") or {}).get("generated_by") or "M5",
                "timestamp": (data.get("metadata") or {}).get("assessed_at") or (data.get("metadata") or {}).get("timestamp") or "2026-08-20T00:00:00Z",
            }
        }
