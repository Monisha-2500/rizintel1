"""
tests/test_performance_benchmarks.py
====================================
Comprehensive Scalability, Performance & Load Validation Suite for Fix #10:
- Pipeline throughput and execution profiling across multiple scales (100, 500, 1000)
- Correctness under scale: source ID retention, cross-asset hard wall, Schema v1.0, M5 sovereignty
- API backward-compatible pagination (limit/offset & page/page_size) with X-Total-Count
- Read-side API concurrency & load testing
- Failure under load & cache preservation
"""

import os
import sys
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Dict, Any
import pytest
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app
from users import get_user_by_email
from auth import create_access_token
from services.pipeline_service import UnifiedPipelineRunner, DEFAULT_ASSET_CATALOG
from services.asset_resolver import AssetResolver
from adapters.m1_adapter import M1NormalizedFindingAdapter
import database

client = TestClient(app)

SCANNERS = ["ZAP", "NUCLEI", "WAPITI", "OPENVAS"]
VULN_TYPES = [
    ("SQL Injection", "SQL_INJECTION", "CVE-2024-1234", "/login", "username", "HIGH"),
    ("Cross-Site Scripting", "XSS", "CVE-2024-5678", "/search", "q", "MEDIUM"),
    ("Remote Code Execution", "RCE", "CVE-2021-44228", "/api/upload", "file", "CRITICAL"),
    ("Server-Side Request Forgery", "SSRF", "CVE-2022-22965", "/fetch", "url", "HIGH"),
    ("Path Traversal", "PATH_TRAVERSAL", "CVE-2020-5902", "/download", "path", "HIGH"),
    ("Authentication Bypass", "AUTH_BYPASS", "CVE-2023-38606", "/admin", "token", "CRITICAL"),
    ("Information Disclosure", "INFO_DISCLOSURE", None, "/debug", "none", "LOW"),
    ("Insecure Direct Object Reference", "IDOR", None, "/profile", "id", "MEDIUM"),
]

ASSETS = [
    ("ASSET-LAB-WEBGOAT", "localhost", 8080),
    ("ASSET-LAB-JUICESHOP", "localhost", 3000),
    ("ASSET-WEB-PROD", "app.rizintel.internal", 443),
    ("ASSET-PAYMENT-GATEWAY", "pay.rizintel.internal", 8443),
    ("UNMAPPED", "partner.external.net", 443),
]


def _get_auth_headers(email: str = "lead@rizintel.demo") -> dict:
    user = get_user_by_email(email)
    assert user is not None
    return {"Authorization": f"Bearer {create_access_token(user)}"}


def _generate_synthetic_findings(n: int, seed: int = 42) -> List[Dict[str, Any]]:
    """Generates N schema-valid Section 3 normalized findings."""
    random.seed(seed)
    num_templates = max(1, int(n * 0.5))
    templates = []
    for _ in range(num_templates):
        v_name, v_type, cve, ep, param, sev = random.choice(VULN_TYPES)
        asset_id, host, port = random.choice(ASSETS)
        templates.append({
            "vulnerability_name": v_name,
            "vulnerability_type": v_type,
            "cve_id": cve,
            "severity": sev,
            "asset_id": asset_id,
            "host": host,
            "port": port,
            "endpoint": ep,
            "parameter": param,
            "description": f"Detected {v_name} on {host}:{port}{ep}",
        })

    findings = []
    for i in range(n):
        tmpl = random.choice(templates)
        scanner = random.choice(SCANNERS)
        finding_id = f"SYNTH-{scanner}-{i:06d}"
        findings.append({
            "finding_id": finding_id,
            "scanner": scanner,
            "cve_id": tmpl["cve_id"],
            "vulnerability_name": tmpl["vulnerability_name"] if random.random() > 0.3 else f"{tmpl['vulnerability_name']} Alert",
            "vulnerability_type": tmpl["vulnerability_type"],
            "severity": tmpl["severity"],
            "asset_id": tmpl["asset_id"],
            "host": tmpl["host"],
            "url": f"http://{tmpl['host']}:{tmpl['port']}{tmpl['endpoint']}",
            "endpoint": tmpl["endpoint"],
            "port": tmpl["port"],
            "parameter": tmpl["parameter"],
            "description": tmpl["description"],
            "evidence": f"Synthetic test evidence for {finding_id}",
            "timestamp": "2026-08-23T12:00:00Z",
        })
    return findings


@pytest.fixture(autouse=True)
def setup_benchmark_env():
    database.init_db()
    old_env = os.environ.get("RIZINTEL_ENV")
    os.environ["RIZINTEL_ENV"] = "development"
    yield
    if old_env is not None:
        os.environ["RIZINTEL_ENV"] = old_env
    else:
        os.environ.pop("RIZINTEL_ENV", None)


# ── 1. Pipeline Execution Throughput at Multiple Scales ────────────────────────
@pytest.mark.parametrize("scale", [100, 500, 1000])
def test_pipeline_throughput_at_scale(scale: int):
    """Measures pipeline execution throughput across scale variants."""
    dataset = _generate_synthetic_findings(scale)
    runner = UnifiedPipelineRunner()

    t0 = time.perf_counter()
    findings, summary = runner.execute_pipeline(
        normalized_input=dataset,
        asset_catalog=DEFAULT_ASSET_CATALOG,
        data_origin="LIVE_SCAN"
    )
    elapsed = time.perf_counter() - t0

    assert len(findings) > 0
    assert len(findings) <= scale
    assert summary["summary"]["raw_findings"] == scale

    throughput = scale / elapsed if elapsed > 0 else 0
    print(f"\n[BENCHMARK] N={scale:<5}: Elapsed={elapsed:6.3f}s | Throughput={throughput:8.1f} findings/sec | Canonical={len(findings)}")
    # Invariant: Must process at healthy throughput (> 200 findings/sec)
    assert throughput > 200


# ── 2. Correctness Invariants Under Scale ──────────────────────────────────────
def test_source_id_retention_under_scale():
    """100% of raw finding IDs are preserved in canonical findings or provenance source lists."""
    scale = 200
    dataset = _generate_synthetic_findings(scale)
    expected_ids = {f["finding_id"] for f in dataset}

    runner = UnifiedPipelineRunner()
    findings, _ = runner.execute_pipeline(
        normalized_input=dataset,
        asset_catalog=DEFAULT_ASSET_CATALOG,
    )

    retained_ids = set()
    for cf in findings:
        for sf in cf.detail.provenance.source_findings:
            retained_ids.add(sf.finding_id)

    assert retained_ids == expected_ids, f"Lost {len(expected_ids - retained_ids)} source IDs under scale!"


def test_cross_asset_dedup_hard_wall_under_scale():
    """Findings on different assets NEVER merge regardless of identical CVE or vulnerability name."""
    scale = 300
    dataset = _generate_synthetic_findings(scale)

    runner = UnifiedPipelineRunner()
    findings, _ = runner.execute_pipeline(
        normalized_input=dataset,
        asset_catalog=DEFAULT_ASSET_CATALOG,
    )

    # Build raw finding lookup
    raw_by_id = {f["finding_id"]: f for f in dataset}
    resolver = AssetResolver(DEFAULT_ASSET_CATALOG)

    for cf in findings:
        source_raws = [raw_by_id[sf.finding_id] for sf in cf.detail.provenance.source_findings]
        # Resolve expected asset for each source raw finding
        resolved_assets = {resolver.resolve(r)[0] for r in source_raws}
        assert len(resolved_assets) == 1, f"Cross-asset leakage detected in finding {cf.finding_id}: {resolved_assets}"


def test_determinism_across_repeated_runs():
    """Consecutive runs with identical raw inputs produce bit-identical canonical results."""
    dataset = _generate_synthetic_findings(150, seed=123)
    runner = UnifiedPipelineRunner()

    findings_1, summary_1 = runner.execute_pipeline(normalized_input=dataset)
    findings_2, summary_2 = runner.execute_pipeline(normalized_input=dataset)

    assert len(findings_1) == len(findings_2)
    assert summary_1["summary"]["unique_findings"] == summary_2["summary"]["unique_findings"]
    assert [f.risk_score for f in findings_1] == [f.risk_score for f in findings_2]
    assert [f.vulnerability_name for f in findings_1] == [f.vulnerability_name for f in findings_2]


# ── 3. API Pagination Verification ────────────────────────────────────────────
def test_api_pagination_limit_offset():
    """GET /api/integration/pipeline/findings supports limit and offset with X-Total-Count."""
    headers = _get_auth_headers("lead@rizintel.demo")
    # Ensure sample pipeline is executed
    run_resp = client.post("/api/integration/pipeline/run", headers=headers, json={"use_demo_dataset": True})
    assert run_resp.status_code == 200

    # 1. Unpaginated (full list for backward compatibility)
    full_resp = client.get("/api/integration/pipeline/findings", headers=headers)
    assert full_resp.status_code == 200
    total_count = int(full_resp.headers.get("X-Total-Count", 0))
    assert total_count > 0
    all_findings = full_resp.json()
    assert len(all_findings) == total_count

    # 2. Limit and offset
    limit = 3
    offset = 2
    paginated_resp = client.get(
        f"/api/integration/pipeline/findings?limit={limit}&offset={offset}",
        headers=headers
    )
    assert paginated_resp.status_code == 200
    assert paginated_resp.headers.get("X-Total-Count") == str(total_count)
    assert paginated_resp.headers.get("X-Limit") == str(limit)
    assert paginated_resp.headers.get("X-Offset") == str(offset)
    p_findings = paginated_resp.json()
    assert len(p_findings) == min(limit, max(0, total_count - offset))
    assert p_findings[0]["finding_id"] == all_findings[offset]["finding_id"]


def test_api_pagination_page_page_size():
    """GET /api/integration/pipeline/findings supports page and page_size."""
    headers = _get_auth_headers("lead@rizintel.demo")
    page_resp = client.get(
        "/api/integration/pipeline/findings?page=1&page_size=4",
        headers=headers
    )
    assert page_resp.status_code == 200
    assert page_resp.headers.get("X-Page") == "1"
    assert page_resp.headers.get("X-Page-Size") == "4"
    assert "X-Total-Pages" in page_resp.headers
    data = page_resp.json()
    assert len(data) <= 4


# ── 4. Read-Side API Concurrency & Load ───────────────────────────────────────
def test_read_side_concurrency_under_load():
    """Simultaneous concurrent read requests to multiple endpoints succeed with 0 errors."""
    headers = _get_auth_headers("analyst@rizintel.demo")
    endpoints = [
        "/api/integration/pipeline/findings",
        "/api/integration/pipeline/summary",
        "/api/integration/health",
        "/api/health",
        "/api/findings",
    ]

    results = []
    latencies = []

    def _worker(ep: str):
        t0 = time.perf_counter()
        resp = client.get(ep, headers=headers)
        elapsed = time.perf_counter() - t0
        results.append((ep, resp.status_code))
        latencies.append(elapsed)

    num_requests = 50
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_worker, random.choice(endpoints)) for _ in range(num_requests)]
        for f in futures:
            f.result()

    assert len(results) == num_requests
    assert all(status_code == 200 for _, status_code in results), f"Failures in read concurrency: {results}"

    latencies.sort()
    median_lat = latencies[len(latencies) // 2]
    p95_lat = latencies[int(len(latencies) * 0.95)]
    print(f"\n[LOAD TEST] {num_requests} concurrent reads: 100% success | Median={median_lat*1000:.1f}ms | p95={p95_lat*1000:.1f}ms")


# ── 5. Failure Under Load & Cache Preservation ────────────────────────────────
def test_cache_preserved_when_run_fails():
    """A failed or rejected pipeline execution does not corrupt or clear the existing cache."""
    lead_headers = _get_auth_headers("lead@rizintel.demo")
    viewer_headers = _get_auth_headers("viewer@rizintel.demo")

    # 1. Successful run populates cache
    ok_resp = client.post("/api/integration/pipeline/run", headers=lead_headers, json={"use_demo_dataset": True})
    assert ok_resp.status_code == 200
    cache_findings = client.get("/api/integration/pipeline/findings", headers=viewer_headers).json()
    assert len(cache_findings) > 0

    # 2. Reject unauthenticated/unauthorized or invalid run
    os.environ["RIZINTEL_ENV"] = "production"
    fail_resp = client.post("/api/integration/pipeline/run", headers=lead_headers, json={})
    assert fail_resp.status_code == 400

    # 3. Cache still intact
    after_findings = client.get("/api/integration/pipeline/findings", headers=viewer_headers).json()
    assert len(after_findings) == len(cache_findings)
