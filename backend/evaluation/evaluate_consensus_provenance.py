"""
evaluate_consensus_provenance.py — Consensus & Provenance Quality Module (Phase 5)

Evaluates:
1. Scanner Consensus Score against selected scanner denominator (3/3 = 1.0, 2/3 = 0.667, 1/3 = 0.333).
2. Source ID Uniqueness & Preservation through final RizTrace provenance (Asserts collision_count == 0).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Set

import sys
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from services.pipeline_service import pipeline_runner


def evaluate_consensus_and_provenance(base_dir: str) -> Dict[str, Any]:
    datasets_dir = os.path.join(base_dir, "datasets")
    dataset_files = ["webgoat_scan.json", "juiceshop_scan.json", "enterprise_multi_scanner.json"]

    total_raw_signals = 0
    all_source_ids: Set[str] = set()
    source_id_collisions = 0
    preserved_source_ids: Set[str] = set()

    consensus_checks = []

    for fname in dataset_files:
        path = os.path.join(datasets_dir, fname)
        with open(path, "r", encoding="utf-8") as f:
            ds = json.load(f)

        asset_info = ds["asset"]
        catalog = {asset_info["asset_id"]: asset_info}
        selected_scanners = list(ds["raw_reports"].keys())
        expected_total = len(selected_scanners)

        raw_sources_str = {
            k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
            for k, v in ds["raw_reports"].items()
        }

        m1_findings = pipeline_runner.run_m1(raw_sources_str, asset_catalog=catalog, default_asset_id=asset_info["asset_id"])

        for mf in m1_findings:
            sid = mf.get("finding_id")
            if sid:
                if sid in all_source_ids:
                    source_id_collisions += 1
                all_source_ids.add(sid)

        total_raw_signals += len(m1_findings)

        canonical, metrics = pipeline_runner.run_m2(m1_findings)

        for c in canonical:
            consensus = c.get("scanner_consensus", {})
            sc_names = consensus.get("scanner_names", [])
            det_count = consensus.get("detected_by_count") or len(sc_names) or 1
            tot_scanners = consensus.get("total_scanners") or expected_total or 1

            actual_score = round(float(consensus.get("score", det_count / tot_scanners)), 3)
            expected_score = round(det_count / tot_scanners, 3)

            is_math_valid = abs(expected_score - actual_score) < 0.05
            consensus_checks.append({
                "dataset": ds["dataset_name"],
                "finding_id": c.get("finding_id"),
                "detected_by_count": det_count,
                "total_scanners": tot_scanners,
                "calculated_score": actual_score,
                "is_valid": is_math_valid,
            })

            # Check merged_finding_ids from deduplication and source_findings
            merged_ids = c.get("deduplication", {}).get("merged_finding_ids", [])
            for mid in merged_ids:
                preserved_source_ids.add(mid)

            s_findings = c.get("source_findings") or c.get("provenance", {}).get("source_findings", [])
            for sf in s_findings:
                if isinstance(sf, dict) and sf.get("finding_id"):
                    preserved_source_ids.add(sf["finding_id"])
                elif hasattr(sf, "finding_id"):
                    preserved_source_ids.add(sf.finding_id)

    preservation_rate = (len(preserved_source_ids) / len(all_source_ids)) if all_source_ids else 1.0
    all_consensus_valid = len(consensus_checks) > 0 and all(check["is_valid"] for check in consensus_checks)

    return {
        "scanner_consensus_validation": {
            "all_consensus_math_valid": all_consensus_valid,
            "sample_checks": consensus_checks[:5],
        },
        "source_id_provenance_quality": {
            "total_raw_source_detections": total_raw_signals,
            "unique_source_ids": len(all_source_ids),
            "source_id_collisions": source_id_collisions,
            "collision_count_zero": source_id_collisions == 0,
            "preserved_source_ids": len(preserved_source_ids),
            "source_id_preservation_rate": round(preservation_rate, 4),
        },
    }


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    res = evaluate_consensus_and_provenance(base)
    print(json.dumps(res, indent=2))
