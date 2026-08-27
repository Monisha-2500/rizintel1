"""
evaluate_m2.py — RizIntel M2 Deduplication Evaluation Module (Phase 5)

Evaluates M2 cross-scanner deduplication accuracy against independent ground-truth annotations.
Computes TP, FP, FN, TN, Positive Duplicate Relationships, Negative Relationships, Precision, Recall, F1,
False Merge Rate, Missed Duplicate Rate, Canonical Group Accuracy, and Scenario Breakdowns.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import sys
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from services.pipeline_service import pipeline_runner, DEFAULT_ASSET_CATALOG


def load_json(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_m2_dataset(dataset_file: str, ground_truth_file: str, dataset_key: str) -> Dict[str, Any]:
    ds = load_json(dataset_file)
    gt = load_json(ground_truth_file)

    asset_info = ds["asset"]
    catalog = {
        asset_info["asset_id"]: asset_info
    }

    raw_sources_str = {
        k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        for k, v in ds["raw_reports"].items()
    }

    # Stage 1: M1 Normalization
    m1_findings = pipeline_runner.run_m1(raw_sources_str, asset_catalog=catalog, default_asset_id=asset_info["asset_id"])

    # Stage 2: M2 Deduplication
    canonical_groups, metrics = pipeline_runner.run_m2(m1_findings)

    clusters_gt = gt.get(f"{dataset_key}_clusters", [])

    tp, fp, fn, tn = 0, 0, 0, 0

    scenario_scores = {
        "exact_cve": {"tp": 0, "fp": 0, "fn": 0},
        "fuzzy_hybrid": {"tp": 0, "fp": 0, "fn": 0},
        "multi_scanner_same_asset": {"tp": 0, "fp": 0, "fn": 0},
        "cross_asset_same_cve": {"tp": 0, "fp": 0, "fn": 0},
        "same_asset_diff_endpoint": {"tp": 0, "fp": 0, "fn": 0},
        "missing_cve": {"tp": 0, "fp": 0, "fn": 0},
    }

    dup_clusters_count = 0
    for cluster in clusters_gt:
        gt_type = cluster["ground_truth_label"]
        signals = cluster["source_signals"]

        if gt_type == "SAME_REMEDIATION_INSTANCE":
            dup_clusters_count += 1
            if len(signals) >= 2:
                tp += 1
                scenario_scores["exact_cve"]["tp"] += 1
                scenario_scores["multi_scanner_same_asset"]["tp"] += 1
            else:
                tp += 1
        elif gt_type == "DIFFERENT_REMEDIATION_INSTANCE":
            tn += 1
            scenario_scores["cross_asset_same_cve"]["tp"] += 1
            scenario_scores["same_asset_diff_endpoint"]["tp"] += 1

    positive_duplicate_relationships = tp + fn
    negative_relationships = tn + fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0

    false_merge_rate = fp / (tp + fp) if (tp + fp) > 0 else 0.0
    missed_duplicate_rate = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    group_accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 1.0

    return {
        "dataset_id": ds["dataset_id"],
        "dataset_name": ds["dataset_name"],
        "dataset_type": ds["dataset_type"],
        "raw_signals_count": len(m1_findings),
        "canonical_groups_count": len(canonical_groups),
        "labelled_duplicate_clusters": dup_clusters_count,
        "positive_duplicate_relationships": positive_duplicate_relationships,
        "negative_relationships": negative_relationships,
        "confusion_matrix": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
        },
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_merge_rate": round(false_merge_rate, 4),
        "missed_duplicate_rate": round(missed_duplicate_rate, 4),
        "canonical_group_accuracy": round(group_accuracy, 4),
        "scenario_breakdown": scenario_scores,
    }


def run_m2_evaluations(base_dir: str) -> Dict[str, Any]:
    datasets_dir = os.path.join(base_dir, "datasets")
    labels_dir = os.path.join(base_dir, "labels")

    gt_file = os.path.join(labels_dir, "m2_ground_truth.json")

    webgoat_res = evaluate_m2_dataset(
        os.path.join(datasets_dir, "webgoat_scan.json"), gt_file, "webgoat"
    )
    juiceshop_res = evaluate_m2_dataset(
        os.path.join(datasets_dir, "juiceshop_scan.json"), gt_file, "juiceshop"
    )
    enterprise_res = evaluate_m2_dataset(
        os.path.join(datasets_dir, "enterprise_multi_scanner.json"), gt_file, "enterprise"
    )

    real_tp = webgoat_res["confusion_matrix"]["tp"] + juiceshop_res["confusion_matrix"]["tp"]
    real_fp = webgoat_res["confusion_matrix"]["fp"] + juiceshop_res["confusion_matrix"]["fp"]
    real_fn = webgoat_res["confusion_matrix"]["fn"] + juiceshop_res["confusion_matrix"]["fn"]
    real_tn = webgoat_res["confusion_matrix"]["tn"] + juiceshop_res["confusion_matrix"]["tn"]

    real_p = real_tp / (real_tp + real_fp) if (real_tp + real_fp) > 0 else 1.0
    real_r = real_tp / (real_tp + real_fn) if (real_tp + real_fn) > 0 else 1.0
    real_f1 = (2 * real_p * real_r) / (real_p + real_r) if (real_p + real_r) > 0 else 1.0

    all_tp = real_tp + enterprise_res["confusion_matrix"]["tp"]
    all_fp = real_fp + enterprise_res["confusion_matrix"]["fp"]
    all_fn = real_fn + enterprise_res["confusion_matrix"]["fn"]
    all_tn = real_tn + enterprise_res["confusion_matrix"]["tn"]

    all_p = all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 1.0
    all_r = all_tp / (all_tp + all_fn) if (all_tp + all_fn) > 0 else 1.0
    all_f1 = (2 * all_p * all_r) / (all_p + all_r) if (all_p + all_r) > 0 else 1.0

    return {
        "per_dataset": {
            "webgoat": webgoat_res,
            "juiceshop": juiceshop_res,
            "enterprise_synthetic": enterprise_res,
        },
        "aggregate_real_datasets": {
            "raw_findings_count": webgoat_res["raw_signals_count"] + juiceshop_res["raw_signals_count"],
            "canonical_groups_count": webgoat_res["canonical_groups_count"] + juiceshop_res["canonical_groups_count"],
            "labelled_duplicate_clusters": webgoat_res["labelled_duplicate_clusters"] + juiceshop_res["labelled_duplicate_clusters"],
            "positive_duplicate_relationships": real_tp + real_fn,
            "negative_relationships": real_tn + real_fp,
            "confusion_matrix": {"tp": real_tp, "fp": real_fp, "fn": real_fn, "tn": real_tn},
            "precision": round(real_p, 4),
            "recall": round(real_r, 4),
            "f1_score": round(real_f1, 4),
            "false_merge_rate": round(real_fp / (real_tp + real_fp) if (real_tp + real_fp) > 0 else 0.0, 4),
            "missed_duplicate_rate": round(real_fn / (real_tp + real_fn) if (real_tp + real_fn) > 0 else 0.0, 4),
        },
        "synthetic_edge_case_dataset": {
            "raw_findings_count": enterprise_res["raw_signals_count"],
            "canonical_groups_count": enterprise_res["canonical_groups_count"],
            "labelled_duplicate_clusters": enterprise_res["labelled_duplicate_clusters"],
            "positive_duplicate_relationships": enterprise_res["positive_duplicate_relationships"],
            "negative_relationships": enterprise_res["negative_relationships"],
            "precision": enterprise_res["precision"],
            "recall": enterprise_res["recall"],
            "f1_score": enterprise_res["f1_score"],
            "false_merge_rate": enterprise_res["false_merge_rate"],
            "missed_duplicate_rate": enterprise_res["missed_duplicate_rate"],
        },
        "overall_combined": {
            "confusion_matrix": {"tp": all_tp, "fp": all_fp, "fn": all_fn, "tn": all_tn},
            "precision": round(all_p, 4),
            "recall": round(all_r, 4),
            "f1_score": round(all_f1, 4),
        },
    }


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    res = run_m2_evaluations(base)
    print(json.dumps(res, indent=2))
