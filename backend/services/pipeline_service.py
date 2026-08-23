"""
pipeline_service.py
===================
UnifiedPipelineRunner: End-to-End Orchestrator connecting M1 through M7 into M8.

Pipeline Flow:
--------------
1. M1: Raw Scanner Reports -> M1 Normalization -> M1NormalizedFindingAdapter -> Section 3 (NormalizedFinding[])
2. M2: Section 3 -> M2 Deduplication -> Section 4 (DeduplicatedFinding[])
3. M3: Section 4 -> M3 Confidence & Noise -> Section 5 (ConfidenceEnrichedFinding[])
4. M4: Section 5 -> M4 Threat Intelligence -> Section 6 (ThreatEnrichedFinding[])
5. Join: ThreatEnrichedFinding + Asset Context (Section 7)
6. M5: M5RiskEngineAdapter.prepare_m5_input() -> M5 Risk Engine -> M5RiskEngineAdapter.adapt_to_section8() -> Section 8 (RiskAssessedFinding)
7. M6: Section 8 -> M6 Explainable AI & Remediation -> Section 9 (ExplainedFinding)
8. M7: Section 9 -> M7 SLA Engine & Ticketing -> M7ActionableFindingAdapter -> Section 10/11 (ActionableFinding[] / FindingSchema[])

Guarantees:
-----------
- M5 is the SOLE mathematical authority for risk_score and risk_level.
- M8 and downstream modules do NOT recalculate upstream values.
- Provenance and source finding IDs are strictly preserved across every transition.
- Zero fabricated security findings.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adapters.m1_adapter import M1NormalizedFindingAdapter
from adapters.m5_adapter import M5RiskEngineAdapter
from adapters.m7_adapter import M7ActionableFindingAdapter
from models import FindingSchema

logger = logging.getLogger("rizintel.pipeline")

# Resolve base directories
_BACKEND_DIR = Path(__file__).resolve().parent.parent


@contextmanager
def _isolated_module_context(module_dir: Path):
    """
    Context manager to execute member modules within an isolated sys.path
    and clean sys.modules namespace to prevent collision on common subpackage names.
    """
    saved_path = list(sys.path)
    colliding_roots = [
        "src", "app", "schemas", "models", "services", "cache",
        "pipeline", "schema", "detect", "scanner_adapters", "member7_app", "confidence_engine"
    ]
    for name in list(sys.modules.keys()):
        for root in colliding_roots:
            if name == root or name.startswith(root + "."):
                sys.modules.pop(name, None)
                break

    sys.path.insert(0, str(module_dir))
    try:
        yield
    finally:
        sys.path = saved_path
        for name in list(sys.modules.keys()):
            for root in colliding_roots:
                if name == root or name.startswith(root + "."):
                    sys.modules.pop(name, None)
                    break


# Default Asset Catalog
DEFAULT_ASSET_CATALOG: Dict[str, Dict[str, Any]] = {
    "ASSET-WEB-001": {
        "asset_id": "ASSET-WEB-001",
        "asset_name": "payments-prod-api-01",
        "environment": "PRODUCTION",
        "criticality": "CRITICAL",
        "asset_criticality": "CRITICAL",
        "internet_facing": True,
        "internet_exposure": True,
        "data_sensitivity": "PCI",
    },
    "ASSET-PAY-001": {
        "asset_id": "ASSET-PAY-001",
        "asset_name": "payment-gateway-core",
        "environment": "PRODUCTION",
        "criticality": "CRITICAL",
        "asset_criticality": "CRITICAL",
        "internet_facing": True,
        "internet_exposure": True,
        "data_sensitivity": "PCI",
    },
    "ASSET-AUTH-002": {
        "asset_id": "ASSET-AUTH-002",
        "asset_name": "auth-service-prod",
        "environment": "PRODUCTION",
        "criticality": "HIGH",
        "asset_criticality": "HIGH",
        "internet_facing": True,
        "internet_exposure": True,
        "data_sensitivity": "RESTRICTED",
    },
    "ASSET-DEV-003": {
        "asset_id": "ASSET-DEV-003",
        "asset_name": "internal-tool-staging",
        "environment": "STAGING",
        "criticality": "LOW",
        "asset_criticality": "LOW",
        "internet_facing": False,
        "internet_exposure": False,
        "data_sensitivity": "INTERNAL",
    },
}


class UnifiedPipelineRunner:
    """
    Orchestrates the entire M1 -> M7 pipeline into M8 findings.
    """

    def __init__(self, backend_dir: Optional[Path] = None):
        self.backend_dir = backend_dir or _BACKEND_DIR
        self.mem1_dir = self.backend_dir / "mem1"
        self.mem2_dir = self.backend_dir / "mem2"
        self.mem3_dir = self.backend_dir / "mem3"
        self.mem4_dir = self.backend_dir / "mem4" / "member4_threat_intelligence"
        self.mem5_dir = self.backend_dir / "mem5"
        self.mem6_dir = self.backend_dir / "mem6"
        self.mem7_dir = self.backend_dir / "mem7"

    # -------------------------------------------------------------------------
    # Stage 1: M1 Normalization & Adaptation
    # -------------------------------------------------------------------------
    def run_m1(self, raw_sources: Dict[str, str], default_asset_id: str = "ASSET-WEB-001") -> List[Dict[str, Any]]:
        """
        Runs M1 scanner parsers and adapts to Schema v1.0 Section 3 (NormalizedFinding[]).
        """
        raw_findings = []
        with _isolated_module_context(self.mem1_dir):
            from pipeline import NormalizationPipeline
            pipeline = NormalizationPipeline()
            available_map = {name.upper(): name for name in pipeline.available_scanners()}
            for scanner_name, raw_content in raw_sources.items():
                matched_scanner = available_map.get(str(scanner_name).upper())
                if matched_scanner:
                    try:
                        parsed = pipeline.normalize(matched_scanner, raw_content)
                        raw_findings.extend(parsed)
                    except Exception as e:
                        logger.warning(f"M1 parser failed for scanner {scanner_name}: {e}")

        # Adapt M1 StandardFinding -> Schema v1.0 Section 3
        return M1NormalizedFindingAdapter.adapt_batch(raw_findings, default_asset_id=default_asset_id)

    # -------------------------------------------------------------------------
    # Stage 2: M2 Deduplication & Scanner Consensus
    # -------------------------------------------------------------------------
    def run_m2(self, normalized_findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Runs M2 deduplication engine. Returns (deduplicated_findings, deduplication_metrics).
        """
        with _isolated_module_context(self.mem2_dir):
            from src.models import NormalizedFinding
            from src.deduplicator import Deduplicator

            pydantic_findings = [NormalizedFinding(**f) for f in normalized_findings]
            deduplicator = Deduplicator(similarity_threshold=0.60)
            result = deduplicator.deduplicate(pydantic_findings)
            return result["findings"], result["deduplication_metrics"]

    # -------------------------------------------------------------------------
    # Stage 3: M3 Confidence & Noise Filtering
    # -------------------------------------------------------------------------
    def run_m3(self, deduplicated_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs M3 5-signal confidence scoring and noise assessment.
        """
        enriched = []
        with _isolated_module_context(self.mem3_dir):
            from schemas import DeduplicatedFinding
            from confidence_engine import assess_confidence

            for item in deduplicated_findings:
                dedup_model = DeduplicatedFinding(**item)
                res = assess_confidence(dedup_model)
                enriched.append(res.model_dump())
        return enriched

    # -------------------------------------------------------------------------
    # Stage 4: M4 Threat Intelligence Enrichment
    # -------------------------------------------------------------------------
    def run_m4(self, confidence_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs M4 threat intelligence (NVD + EPSS + CISA KEV + SQLite Cache).
        """
        threat_enriched = []
        with _isolated_module_context(self.mem4_dir):
            from models.schemas import (
                ConfidenceEnrichedFinding,
                ConfidenceClassification,
                VulnerabilityType,
                SeverityLevel,
                SchemaVersion,
                Asset,
                ScannerConsensus,
                FindingConfidence,
                ConfidenceSignals,
                NoiseAssessment,
            )
            from services.enrichment_service import ThreatIntelligenceEnrichmentService

            service = ThreatIntelligenceEnrichmentService()

            for item in confidence_findings:
                # Format to M4 model expectations safely
                asset_obj = item.get("asset") or {}
                sc_obj = item.get("scanner_consensus") or {}
                fc_obj = item.get("finding_confidence") or {}
                na_obj = item.get("noise_assessment") or {}

                # Map enum values safely
                raw_vtype = (item.get("vulnerability_type") or "OTHER").upper()
                valid_types = {e.value for e in VulnerabilityType}
                v_type = raw_vtype if raw_vtype in valid_types else "OTHER"

                raw_sev = (item.get("severity") or "MEDIUM").upper()
                valid_sevs = {e.value for e in SeverityLevel}
                sev = raw_sev if raw_sev in valid_sevs else "MEDIUM"

                raw_conf = (fc_obj.get("classification") or "CONFIRMED").upper()
                valid_confs = {e.value for e in ConfidenceClassification}
                conf_class = raw_conf if raw_conf in valid_confs else "CONFIRMED"

                m4_input = {
                    "schema_version": "1.0",
                    "finding_id": item["finding_id"],
                    "cve_id": item.get("cve_id"),
                    "vulnerability_name": item["vulnerability_name"],
                    "vulnerability_type": v_type,
                    "severity": sev,
                    "asset": {
                        "asset_id": asset_obj.get("asset_id", "ASSET-WEB-001"),
                        "host": asset_obj.get("host", "localhost"),
                        "endpoint": asset_obj.get("endpoint"),
                        "port": asset_obj.get("port"),
                        "parameter": asset_obj.get("parameter"),
                    },
                    "scanner_consensus": {
                        "scanner_names": sc_obj.get("scanner_names", ["UNKNOWN"]),
                        "detected_by_count": sc_obj.get("detected_by_count", 1),
                        "total_scanners": sc_obj.get("total_scanners", 1),
                        "score": sc_obj.get("score", 1.0),
                    },
                    "finding_confidence": {
                        "score": fc_obj.get("score", 0.9),
                        "classification": conf_class,
                        "signals": {
                            "scanner_consensus": fc_obj.get("signals", {}).get("scanner_consensus", 1.0),
                            "evidence_quality": fc_obj.get("signals", {}).get("evidence_strength", 0.9),
                            "cve_mapping": 1.0 if item.get("cve_id") else 0.5,
                            "repeatability": fc_obj.get("signals", {}).get("cross_scanner_consistency", 0.9),
                        },
                        "review_required": fc_obj.get("review_required", False),
                    },
                    "noise_assessment": {
                        "likely_noise": na_obj.get("likely_noise", False),
                        "reason": na_obj.get("reason"),
                    },
                    "source_findings": item.get("source_findings", []),
                }

                res = service.enrich_finding(m4_input)
                threat_enriched.append(res.model_dump())

        return threat_enriched

    # -------------------------------------------------------------------------
    # Stage 5: M5 Dynamic Risk Scoring Engine
    # -------------------------------------------------------------------------
    def run_m5(
        self,
        threat_findings: List[Dict[str, Any]],
        asset_catalog: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Joins Asset Context and runs M5 deterministic scoring. Returns Section 8 findings.
        """
        catalog = asset_catalog or DEFAULT_ASSET_CATALOG
        assessed = []

        with _isolated_module_context(self.mem5_dir):
            from src.risk_engine import RiskEngine

            engine = RiskEngine()

            for item in threat_findings:
                asset_id = item.get("asset_id") or "ASSET-WEB-001"
                asset_ctx = catalog.get(asset_id) or catalog.get("ASSET-WEB-001", {
                    "asset_id": asset_id,
                    "asset_name": f"host-{asset_id.lower()}",
                    "environment": "PRODUCTION",
                    "asset_criticality": "MEDIUM",
                    "internet_exposure": True,
                    "data_sensitivity": "INTERNAL",
                })

                m5_input = M5RiskEngineAdapter.prepare_m5_input(item, asset_ctx)
                m5_output = engine.assess_finding(m5_input)
                section8_finding = M5RiskEngineAdapter.adapt_to_section8(m5_output)
                assessed.append(section8_finding)

        return assessed

    # -------------------------------------------------------------------------
    # Stage 6: M6 Explainable AI & Remediation
    # -------------------------------------------------------------------------
    def run_m6(self, risk_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs M6 explanation service (with deterministic fallback).
        """
        explained = []
        with _isolated_module_context(self.mem6_dir):
            from app.models.input_models import RiskAssessedFinding
            from app.services.explanation_service import generate_explained_finding

            for item in risk_findings:
                input_model = RiskAssessedFinding(**item)
                res = generate_explained_finding(input_model)
                explained.append(res.model_dump())

        return explained

    # -------------------------------------------------------------------------
    # Stage 7: M7 SLA Automation & Actionable Finding Packaging
    # -------------------------------------------------------------------------
    def run_m7(
        self,
        explained_findings: List[Dict[str, Any]],
        pipeline_context_map: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Runs M7 SLA calculations and packages final ActionableFindings (Schema v1.0).
        """
        actionable_findings = []
        with _isolated_module_context(self.mem7_dir):
            from member7_app.ticket_manager import createticket
            from member7_app.sla_engine import checksla

            for item in explained_findings:
                finding_id = item["finding_id"]
                ctx = pipeline_context_map.get(finding_id, {})

                # Build ticket
                ticket = createticket(item)
                checksla(ticket)

                # Format into canonical FindingSchema
                final_finding = M7ActionableFindingAdapter.build_actionable_finding(
                    m6_finding=item,
                    m7_ticket=ticket,
                    pipeline_context=ctx
                )
                actionable_findings.append(final_finding)

        return actionable_findings

    # -------------------------------------------------------------------------
    # End-to-End Pipeline Execution
    # -------------------------------------------------------------------------
    def execute_pipeline(
        self,
        raw_sources: Optional[Dict[str, str]] = None,
        normalized_input: Optional[List[Dict[str, Any]]] = None,
        asset_catalog: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Tuple[List[FindingSchema], Dict[str, Any]]:
        """
        Executes complete M1 -> M7 pipeline and produces validated M8 FindingSchema[]
        along with summary metrics.
        """
        catalog = asset_catalog or DEFAULT_ASSET_CATALOG

        # Stage 1: M1
        if normalized_input:
            s1_normalized = [M1NormalizedFindingAdapter.adapt_single(f) for f in normalized_input]
            raw_count = len(s1_normalized)
        elif raw_sources:
            s1_normalized = self.run_m1(raw_sources)
            raw_count = len(s1_normalized)
        else:
            # Fallback to load M2 sample input
            sample_input_path = self.mem2_dir / "data" / "sample_input.json"
            if sample_input_path.exists():
                with open(sample_input_path, "r") as f:
                    s_data = json.load(f)
                    s1_normalized = [M1NormalizedFindingAdapter.adapt_single(f) for f in s_data.get("findings", [])]
                raw_count = len(s1_normalized)
            else:
                s1_normalized = []
                raw_count = 0

        if not s1_normalized:
            logger.warning("No findings normalized in pipeline.")
            return [], {}

        # Stage 2: M2 Deduplication
        s2_deduped, dedup_metrics = self.run_m2(s1_normalized)

        # Stage 3: M3 Confidence
        s3_confidence = self.run_m3(s2_deduped)

        # Stage 4: M4 Threat Intelligence
        s4_threat = self.run_m4(s3_confidence)

        # Stage 5: M5 Risk Engine
        s5_assessed = self.run_m5(s4_threat, asset_catalog=catalog)

        # Stage 6: M6 Explainability
        s6_explained = self.run_m6(s5_assessed)

        # Build context map linking finding_id to upstream data
        context_map = {}
        for d in s2_deduped:
            fid = d["finding_id"]
            context_map[fid] = {
                "source_findings": d.get("source_findings", []),
                "deduplication": d.get("deduplication", {}),
                "scanner_consensus": d.get("scanner_consensus", {}),
                "first_seen": d.get("first_seen"),
                "last_seen": d.get("last_seen"),
                "vulnerability_type": d.get("vulnerability_type"),
                "asset_id": d.get("asset", {}).get("asset_id"),
            }

        for c in s3_confidence:
            fid = c["finding_id"]
            if fid in context_map:
                context_map[fid]["finding_confidence"] = c.get("finding_confidence", {})
                context_map[fid]["noise_assessment"] = c.get("noise_assessment", {})

        for t in s4_threat:
            fid = t["finding_id"]
            if fid in context_map:
                context_map[fid]["threat_intelligence"] = t.get("threat_intelligence", {})

        for a in s5_assessed:
            fid = a["finding_id"]
            if fid in context_map:
                context_map[fid]["risk_assessment"] = a.get("risk_assessment", {})
                context_map[fid]["asset_context"] = a.get("asset_context", {})
                context_map[fid]["risk_score"] = a.get("risk_assessment", {}).get("risk_score", 0)
                context_map[fid]["risk_level"] = a.get("risk_assessment", {}).get("risk_level", "LOW")

        # Stage 7: M7 SLA & Final Actionable Findings
        s7_actionable = self.run_m7(s6_explained, context_map)

        # Validate each against M8's Pydantic FindingSchema
        validated_findings = [FindingSchema(**item) for item in s7_actionable]

        # Calculate Summary Metrics
        critical_count = sum(1 for f in validated_findings if f.risk_level == "CRITICAL")
        high_count = sum(1 for f in validated_findings if f.risk_level == "HIGH")
        medium_count = sum(1 for f in validated_findings if f.risk_level == "MEDIUM")
        low_count = sum(1 for f in validated_findings if f.risk_level == "LOW")
        breach_count = sum(1 for f in validated_findings if f.workflow.sla_status == "SLA_BREACHED")
        noise_count = sum(1 for c in s3_confidence if c.get("noise_assessment", {}).get("likely_noise", False))

        summary = {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "summary": {
                "raw_findings": raw_count,
                "unique_findings": len(validated_findings),
                "duplicates_correlated": raw_count - len(validated_findings),
                "duplicate_reduction_rate": round(
                    (raw_count - len(validated_findings)) / raw_count, 4
                ) if raw_count > 0 else 0.0,
                "likely_noise_findings": noise_count,
                "actionable_findings": len(validated_findings),
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "open_tickets": len(validated_findings),
                "sla_breaches": breach_count,
            },
            "top_risks": [
                {
                    "finding_id": f.finding_id,
                    "vulnerability_name": f.vulnerability_name,
                    "asset_id": f.asset_id,
                    "risk_score": f.risk_score,
                    "risk_level": f.risk_level,
                    "confidence_classification": f.confidence_classification,
                    "sla_status": f.workflow.sla_status,
                }
                for f in sorted(validated_findings, key=lambda x: x.risk_score, reverse=True)[:5]
            ]
        }

        return validated_findings, summary


# Singleton pipeline runner
pipeline_runner = UnifiedPipelineRunner()
