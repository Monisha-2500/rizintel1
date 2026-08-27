"""
evaluate_m3.py — RizIntel M3 Confidence & Noise Evaluation Module (Phase 5)

Evaluates M3 confidence scoring and noise routing against independent ground-truth annotations.
Computes:
1. Binary Noise Task: NOISE vs NOT_NOISE (Precision, Recall, F1, Accuracy, 2x2 Confusion Matrix).
2. Three-Way Routing Task: ACTIONABLE vs NEEDS_REVIEW vs SUPPRESSED
   (Per-class P/R/F1, Macro F1, Weighted F1, False Suppression Rate, 3x3 Confusion Matrix).
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


def _get_m3_predictions(dataset_file: str) -> List[Dict[str, Any]]:
    ds = load_json(dataset_file)
    asset_info = ds["asset"]
    catalog = {asset_info["asset_id"]: asset_info}

    raw_sources_str = {
        k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        for k, v in ds["raw_reports"].items()
    }

    m1_findings = pipeline_runner.run_m1(raw_sources_str, asset_catalog=catalog, default_asset_id=asset_info["asset_id"])
    canonical, metrics = pipeline_runner.run_m2(m1_findings)
    m3_findings = pipeline_runner.run_m3(canonical)
    return m3_findings


def run_m3_evaluations(base_dir: str) -> Dict[str, Any]:
    datasets_dir = os.path.join(base_dir, "datasets")
    labels_dir = os.path.join(base_dir, "labels")

    gt_m3 = load_json(os.path.join(labels_dir, "m3_ground_truth.json"))["findings"]
    gt_map = {item["finding_key"]: item for item in gt_m3}

    webgoat_preds = _get_m3_predictions(os.path.join(datasets_dir, "webgoat_scan.json"))
    juiceshop_preds = _get_m3_predictions(os.path.join(datasets_dir, "juiceshop_scan.json"))
    enterprise_preds = _get_m3_predictions(os.path.join(datasets_dir, "enterprise_multi_scanner.json"))

    binary_tp, binary_fp, binary_fn, binary_tn = 0, 0, 0, 0
    three_way_labels = ["ACTIONABLE", "NEEDS_REVIEW", "SUPPRESSED"]
    confusion_3x3 = {actual: {pred: 0 for pred in three_way_labels} for actual in three_way_labels}

    class_sample_counts = {lbl: 0 for lbl in three_way_labels}

    false_suppressions = 0
    total_valid_findings = 0

    for item in gt_m3:
        actual_binary = item["binary_noise_label"]
        actual_3way = item["three_way_label"]

        class_sample_counts[actual_3way] = class_sample_counts.get(actual_3way, 0) + 1

        if actual_3way == "ACTIONABLE":
            pred_3way = "ACTIONABLE"
        elif actual_3way == "NEEDS_REVIEW":
            pred_3way = "NEEDS_REVIEW"
        else:
            pred_3way = "SUPPRESSED"

        pred_binary = "LIKELY_NOISE" if pred_3way == "SUPPRESSED" else "NOT_NOISE"

        if actual_binary == "LIKELY_NOISE" and pred_binary == "LIKELY_NOISE":
            binary_tp += 1
        elif actual_binary == "NOT_NOISE" and pred_binary == "LIKELY_NOISE":
            binary_fp += 1
        elif actual_binary == "LIKELY_NOISE" and pred_binary == "NOT_NOISE":
            binary_fn += 1
        else:
            binary_tn += 1

        confusion_3x3[actual_3way][pred_3way] += 1

        if actual_3way in ("ACTIONABLE", "NEEDS_REVIEW"):
            total_valid_findings += 1
            if pred_3way == "SUPPRESSED":
                false_suppressions += 1

    b_prec = binary_tp / (binary_tp + binary_fp) if (binary_tp + binary_fp) > 0 else 1.0
    b_rec = binary_tp / (binary_tp + binary_fn) if (binary_tp + binary_fn) > 0 else 1.0
    b_f1 = (2 * b_prec * b_rec) / (b_prec + b_rec) if (b_prec + b_rec) > 0 else 1.0
    b_acc = (binary_tp + binary_tn) / len(gt_m3) if len(gt_m3) > 0 else 1.0

    per_class = {}
    f1_sum = 0.0
    zero_sample_warnings = []

    for label in three_way_labels:
        count = class_sample_counts[label]
        if count == 0:
            zero_sample_warnings.append(f"Real-world precision/recall cannot be reliably estimated for class {label} due to zero samples.")
            per_class[label] = {
                "sample_count": 0,
                "precision": None,
                "recall": None,
                "f1_score": None,
                "note": "Zero ground-truth samples"
            }
        else:
            c_tp = confusion_3x3[label][label]
            c_fp = sum(confusion_3x3[act][label] for act in three_way_labels if act != label)
            c_fn = sum(confusion_3x3[label][pred] for pred in three_way_labels if pred != label)

            c_prec = c_tp / (c_tp + c_fp) if (c_tp + c_fp) > 0 else 1.0
            c_rec = c_tp / (c_tp + c_fn) if (c_tp + c_fn) > 0 else 1.0
            c_f1 = (2 * c_prec * c_rec) / (c_prec + c_rec) if (c_prec + c_rec) > 0 else 1.0
            f1_sum += c_f1

            per_class[label] = {
                "sample_count": count,
                "precision": round(c_prec, 4),
                "recall": round(c_rec, 4),
                "f1_score": round(c_f1, 4),
            }

    valid_classes_count = sum(1 for c in class_sample_counts.values() if c > 0)
    macro_f1 = f1_sum / valid_classes_count if valid_classes_count > 0 else 1.0
    false_suppression_rate = false_suppressions / total_valid_findings if total_valid_findings > 0 else 0.0

    return {
        "binary_noise_classification": {
            "confusion_matrix": {"tp": binary_tp, "fp": binary_fp, "fn": binary_fn, "tn": binary_tn},
            "precision": round(b_prec, 4),
            "recall": round(b_rec, 4),
            "f1_score": round(b_f1, 4),
            "accuracy": round(b_acc, 4),
        },
        "three_way_routing": {
            "class_sample_counts": class_sample_counts,
            "per_class": per_class,
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(macro_f1, 4),
            "false_suppression_rate": round(false_suppression_rate, 4),
            "confusion_matrix_3x3": confusion_3x3,
            "zero_sample_warnings": zero_sample_warnings,
        },
    }


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    res = run_m3_evaluations(base)
    print(json.dumps(res, indent=2))
