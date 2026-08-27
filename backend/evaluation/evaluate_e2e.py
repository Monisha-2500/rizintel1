"""
evaluate_e2e.py — End-to-End Operational Impact Module (Phase 5)

Calculates the operational funnel metrics and potential analyst review reduction
across WebGoat, Juice Shop, and Enterprise datasets.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import sys
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from services.pipeline_service import pipeline_runner


def load_json(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_dataset_funnel(dataset_file: str) -> Dict[str, Any]:
    ds = load_json(dataset_file)
    asset_info = ds["asset"]
    catalog = {asset_info["asset_id"]: asset_info}

    raw_sources_str = {
        k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        for k, v in ds["raw_reports"].items()
    }

    # Execute M1-M7 pipeline using pipeline_runner
    findings, summary_metrics = pipeline_runner.execute_pipeline(
        raw_sources=raw_sources_str,
        asset_catalog=catalog,
    )

    raw_count = summary_metrics.get("raw_findings_count", len(findings))
    canonical_count = summary_metrics.get("deduplicated_count", len(findings))
    actionable_count = summary_metrics.get("actionable_count", len(findings))
    review_count = summary_metrics.get("needs_review_count", 0)
    suppressed_count = summary_metrics.get("suppressed_count", 0)

    dup_reduction = ((raw_count - canonical_count) / raw_count * 100) if raw_count > 0 else 0.0
    noise_reduction = (suppressed_count / raw_count * 100) if raw_count > 0 else 0.0
    queue_reduction = ((raw_count - (actionable_count + review_count)) / raw_count * 100) if raw_count > 0 else 0.0

    return {
        "dataset_name": ds["dataset_name"],
        "dataset_type": ds["dataset_type"],
        "funnel": {
            "raw_scanner_alerts": raw_count,
            "normalized_findings": raw_count,
            "canonical_findings": canonical_count,
            "actionable_confirmed": actionable_count,
            "needs_review": review_count,
            "suppressed_noise": suppressed_count,
        },
        "metrics": {
            "duplicate_reduction_pct": round(dup_reduction, 2),
            "noise_reduction_pct": round(noise_reduction, 2),
            "potential_analyst_review_reduction_pct": round(queue_reduction, 2),
            "actionable_to_raw_ratio": round(actionable_count / raw_count if raw_count > 0 else 0.0, 4),
        },
    }


def run_e2e_funnel_evaluations(base_dir: str) -> Dict[str, Any]:
    datasets_dir = os.path.join(base_dir, "datasets")

    webgoat_funnel = evaluate_dataset_funnel(os.path.join(datasets_dir, "webgoat_scan.json"))
    juiceshop_funnel = evaluate_dataset_funnel(os.path.join(datasets_dir, "juiceshop_scan.json"))
    enterprise_funnel = evaluate_dataset_funnel(os.path.join(datasets_dir, "enterprise_multi_scanner.json"))

    real_raw = webgoat_funnel["funnel"]["raw_scanner_alerts"] + juiceshop_funnel["funnel"]["raw_scanner_alerts"]
    real_canonical = webgoat_funnel["funnel"]["canonical_findings"] + juiceshop_funnel["funnel"]["canonical_findings"]
    real_actionable = webgoat_funnel["funnel"]["actionable_confirmed"] + juiceshop_funnel["funnel"]["actionable_confirmed"]
    real_review = webgoat_funnel["funnel"]["needs_review"] + juiceshop_funnel["funnel"]["needs_review"]
    real_suppressed = webgoat_funnel["funnel"]["suppressed_noise"] + juiceshop_funnel["funnel"]["suppressed_noise"]

    real_dup_red = ((real_raw - real_canonical) / real_raw * 100) if real_raw > 0 else 0.0
    real_queue_red = ((real_raw - (real_actionable + real_review)) / real_raw * 100) if real_raw > 0 else 0.0

    return {
        "per_dataset_funnels": {
            "webgoat": webgoat_funnel,
            "juiceshop": juiceshop_funnel,
            "enterprise_synthetic": enterprise_funnel,
        },
        "aggregate_real_datasets_funnel": {
            "raw_scanner_alerts": real_raw,
            "canonical_findings": real_canonical,
            "actionable_confirmed": real_actionable,
            "needs_review": real_review,
            "suppressed_noise": real_suppressed,
            "duplicate_reduction_pct": round(real_dup_red, 2),
            "potential_analyst_review_reduction_pct": round(real_queue_red, 2),
        },
        "time_effort_impact_label": "Potential Analyst Review Reduction (Safe Measurable Proxy)",
    }


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    res = run_e2e_funnel_evaluations(base)
    print(json.dumps(res, indent=2))
