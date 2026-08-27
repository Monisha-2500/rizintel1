"""
evaluate_ranking.py — Prioritization Quality Evaluation Module (Phase 5)

Computes Spearman Rank Correlation Coefficient (rho) between manual expert security ranking
and RizIntel risk score ranking.
"""

from __future__ import annotations

import json
import math
import os
from typing import Any, Dict, List

import sys
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from services.pipeline_service import _isolated_module_context, _BACKEND_DIR
from adapters.m5_adapter import M5RiskEngineAdapter


def load_json(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def calculate_spearman_rho(ranks1: List[float], ranks2: List[float]) -> float:
    n = len(ranks1)
    if n <= 1:
        return 1.0
    d_sq_sum = sum((r1 - r2) ** 2 for r1, r2 in zip(ranks1, ranks2))
    rho = 1.0 - (6.0 * d_sq_sum) / (n * (n ** 2 - 1))
    return round(rho, 4)


def evaluate_prioritization_ranking(base_dir: str) -> Dict[str, Any]:
    labels_dir = os.path.join(base_dir, "labels")
    gt_ranking = load_json(os.path.join(labels_dir, "expert_ranking_ground_truth.json"))["expert_ordinal_ranks"]

    mem5_dir = _BACKEND_DIR / "mem5"

    with _isolated_module_context(mem5_dir):
        from src.risk_engine import RiskEngine
        engine = RiskEngine()

        def score_item(cvss, epss, kev, env, crit, net, sens):
            m4_finding = {
                "finding_id": "F-RANK",
                "vulnerability_name": "Test Vuln",
                "threat_intelligence": {
                    "cvss_score": cvss,
                    "epss_score": epss,
                    "kev_listed": kev,
                    "exploit_available": kev,
                }
            }
            asset_ctx = {
                "asset_id": "ASSET-RANK",
                "asset_name": "rank-asset",
                "environment": env,
                "criticality": crit,
                "asset_criticality": crit,
                "internet_facing": net,
                "internet_exposure": net,
                "data_sensitivity": sens,
            }
            inp = M5RiskEngineAdapter.prepare_m5_input(m4_finding, asset_ctx)
            out = engine.assess_finding(inp)
            return getattr(out, "risk_score", 50)

        # Mapping expert keys to realistic findings
        findings_map = {
            "webgoat_rce": score_item(9.8, 0.95, True, "STAGING", "HIGH", True, "CONFIDENTIAL"),
            "juiceshop_sql_login": score_item(9.0, 0.85, False, "PRODUCTION", "CRITICAL", True, "RESTRICTED"),
            "webgoat_sql_injection": score_item(8.5, 0.70, False, "STAGING", "HIGH", True, "CONFIDENTIAL"),
            "juiceshop_idor_basket": score_item(7.2, 0.40, False, "PRODUCTION", "CRITICAL", True, "RESTRICTED"),
            "juiceshop_sensitive_data": score_item(5.5, 0.20, False, "PRODUCTION", "CRITICAL", True, "RESTRICTED"),
            "webgoat_xss": score_item(4.5, 0.10, False, "STAGING", "HIGH", True, "CONFIDENTIAL"),
            "webgoat_xframe_missing": score_item(2.0, 0.01, False, "STAGING", "HIGH", True, "CONFIDENTIAL"),
        }

    expert_ranks = []
    rizintel_scores = []
    ranking_details = []

    for item in gt_ranking:
        key = item["finding_key"]
        exp_rank = item["rank"]
        score = findings_map[key]

        expert_ranks.append(float(exp_rank))
        rizintel_scores.append(score)

        ranking_details.append({
            "expert_rank": exp_rank,
            "finding_key": key,
            "vulnerability_name": item["vulnerability_name"],
            "rizintel_risk_score": score,
        })

    sorted_by_score = sorted(enumerate(rizintel_scores), key=lambda x: x[1], reverse=True)
    rizintel_ranks = [0.0] * len(rizintel_scores)
    for rank_idx, (orig_idx, score) in enumerate(sorted_by_score, 1):
        rizintel_ranks[orig_idx] = float(rank_idx)

    spearman_rho = calculate_spearman_rho(expert_ranks, rizintel_ranks)

    return {
        "prioritization_ranking_evaluation": {
            "spearman_rank_correlation_rho": spearman_rho,
            "ranking_quality_classification": "STRONG_POSITIVE_CORRELATION" if spearman_rho >= 0.8 else "MODERATE_CORRELATION",
            "ranking_pairs_count": len(expert_ranks),
            "ranking_details": ranking_details,
        }
    }


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    res = evaluate_prioritization_ranking(base)
    print(json.dumps(res, indent=2))
