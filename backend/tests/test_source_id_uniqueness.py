"""
test_source_id_uniqueness.py
============================
Focused test suite for RizIntel Issue #5: Guarantee Globally Unique & Deterministic Source Finding IDs.

Validates:
1. Nuclei IDs are unique across different hosts (same template).
2. Nuclei IDs are unique across different ports (same template and host).
3. Nuclei IDs are unique across different endpoints (same template and host).
4. Nuclei IDs are unique across different discriminators/matcher-names (multi-matcher templates).
5. Determinism: Identical inputs produce byte-for-byte identical IDs across repeated pipeline runs.
6. Missing CVE still generates a stable, unique ID.
7. Identical detection processed twice generates identical ID (collision-free deduplication anchor).
8. Scanner namespaces (NUCLEI-*, ZAP-*, WAPITI-*) are strictly isolated and never collide.
9. M2 deduplication preserves every unique source ID in merged_finding_ids and source_findings.
10. RizTrace provenance preserves all source finding IDs through the entire M1->M8 pipeline.
11. Real WebGoat (55 detections) and Juice Shop (2 detections) datasets contain ZERO duplicate source IDs.
12. Mathematical invariant: len(source_ids) == len(set(source_ids)) holds for all raw scanner detections.
"""

import json
import sys
from pathlib import Path
import pytest

_BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BACKEND_DIR / "mem1"))

from schema import generate_source_id, StandardFinding, Severity
from scanner_adapters.nuclei import NucleiAdapter
from scanner_adapters.zap import ZapAdapter
from scanner_adapters.wapiti import WapitiAdapter
from services.pipeline_service import UnifiedPipelineRunner, DEFAULT_ASSET_CATALOG


# =============================================================================
# 1. Determinism and Collision Safety Tests
# =============================================================================

def test_nuclei_ids_unique_across_different_hosts():
    """Same Nuclei template on different hosts generates distinct source IDs."""
    id1 = generate_source_id("NUCLEI", "http://host-a.com/login", "springboot-health", "/login", "80", "")
    id2 = generate_source_id("NUCLEI", "http://host-b.com/login", "springboot-health", "/login", "80", "")
    assert id1 != id2
    assert id1.startswith("NUCLEI-")
    assert id2.startswith("NUCLEI-")


def test_nuclei_ids_unique_across_different_ports():
    """Same Nuclei template on same host but different ports generates distinct source IDs."""
    id1 = generate_source_id("NUCLEI", "http://127.0.0.1:8001/login", "springboot-health", "/login", "8001", "")
    id2 = generate_source_id("NUCLEI", "http://127.0.0.1:9000/login", "springboot-health", "/login", "9000", "")
    assert id1 != id2


def test_nuclei_ids_unique_across_different_endpoints():
    """Same Nuclei template on same host but different endpoints generates distinct source IDs."""
    id1 = generate_source_id("NUCLEI", "http://127.0.0.1:8001/actuator/health", "springboot-health", "/actuator/health", "8001", "")
    id2 = generate_source_id("NUCLEI", "http://127.0.0.1:8001/actuator/env", "springboot-health", "/actuator/env", "8001", "")
    assert id1 != id2


def test_nuclei_ids_unique_across_different_matchers():
    """Multi-matcher template (e.g. http-missing-security-headers) produces unique IDs per matcher-name."""
    matchers = [
        "content-security-policy",
        "permissions-policy",
        "x-content-type-options",
        "strict-transport-security",
        "x-frame-options",
        "x-permitted-cross-domain-policies",
        "referrer-policy",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
    ]
    ids = [
        generate_source_id("NUCLEI", "http://127.0.0.1:8001/WebGoat/login", "http-missing-security-headers", "/WebGoat/login", "8001", m)
        for m in matchers
    ]
    assert len(ids) == len(set(ids))
    assert len(ids) == 10


def test_determinism_across_repeated_runs():
    """Generating source ID multiple times with identical inputs produces identical output (no random UUIDs)."""
    id_run1 = generate_source_id("NUCLEI", "http://example.com/app", "cve-2024-1234", "/app", "443", "header_param")
    id_run2 = generate_source_id("NUCLEI", "http://example.com/app", "cve-2024-1234", "/app", "443", "header_param")
    assert id_run1 == id_run2
    assert isinstance(id_run1, str)
    assert id_run1.startswith("NUCLEI-")


def test_missing_cve_generates_stable_unique_id():
    """Detections lacking a CVE ID (e.g. misconfigurations/headers) generate stable unique IDs."""
    id_cveless1 = generate_source_id("NUCLEI", "http://127.0.0.1:8001/login", "Missing CSP Header", "/login", "8001", "csp")
    id_cveless2 = generate_source_id("NUCLEI", "http://127.0.0.1:8001/login", "Missing XFO Header", "/login", "8001", "xfo")
    assert id_cveless1 != id_cveless2
    assert id_cveless1.startswith("NUCLEI-")


def test_identical_detection_produces_identical_id():
    """The exact same detection payload must hash to the exact same source finding ID."""
    args = ("ZAP", "http://127.0.0.1:8001/login", "SQL Injection", "/login", "8001", "username")
    assert generate_source_id(*args) == generate_source_id(*args)


def test_scanner_namespaces_cannot_collide():
    """Identical vulnerability on identical host/endpoint across different scanners receive isolated IDs."""
    nuc_id = generate_source_id("NUCLEI", "http://127.0.0.1:8001/login", "SQL Injection", "/login", "8001", "username")
    zap_id = generate_source_id("ZAP", "http://127.0.0.1:8001/login", "SQL Injection", "/login", "8001", "username")
    wap_id = generate_source_id("WAPITI", "http://127.0.0.1:8001/login", "SQL Injection", "/login", "8001", "username")

    assert nuc_id.startswith("NUCLEI-")
    assert zap_id.startswith("ZAP-")
    assert wap_id.startswith("WAPITI-")
    assert len({nuc_id, zap_id, wap_id}) == 3


# =============================================================================
# 2. Real Presentation Datasets (WebGoat & Juice Shop) Zero Collision Test
# =============================================================================

def test_real_webgoat_dataset_has_zero_source_id_collisions():
    """All 55 raw scanner detections from WebGoat (ZAP+Nuclei+Wapiti) must have 100% unique source IDs."""
    webgoat_dir = _BACKEND_DIR / "mem1" / "webgoat"

    # 1. Nuclei
    nuc = NucleiAdapter()
    with open(webgoat_dir / "webgoat_nuclei_results.json") as f:
        raw_nuc = f.read()
    findings_nuc = nuc.parse(raw_nuc)
    ids_nuc = [f.finding_id for f in findings_nuc]
    assert len(ids_nuc) == 22
    assert len(set(ids_nuc)) == 22, f"Nuclei has {22 - len(set(ids_nuc))} collisions"

    # 2. ZAP
    zap = ZapAdapter()
    with open(webgoat_dir / "webgoat-ZAP-Report.json") as f:
        raw_zap = f.read()
    findings_zap = zap.parse(raw_zap)
    ids_zap = [f.finding_id for f in findings_zap]
    assert len(ids_zap) == 29
    assert len(set(ids_zap)) == 29, f"ZAP has {29 - len(set(ids_zap))} collisions"

    # 3. Wapiti
    wap = WapitiAdapter()
    with open(webgoat_dir / "wapiti_webgoat_report.json") as f:
        raw_wap = f.read()
    findings_wap = wap.parse(raw_wap)
    ids_wap = [f.finding_id for f in findings_wap]
    assert len(ids_wap) == 4
    assert len(set(ids_wap)) == 4, f"Wapiti has {4 - len(set(ids_wap))} collisions"

    # Combined cross-scanner invariant
    all_source_ids = ids_nuc + ids_zap + ids_wap
    assert len(all_source_ids) == 55
    assert len(set(all_source_ids)) == 55, "Cross-scanner source ID collision detected!"


def test_real_juiceshop_dataset_has_zero_source_id_collisions():
    """All raw detections from Juice Shop Wapiti report must have 100% unique source IDs."""
    js_path = _BACKEND_DIR / "mem1" / "juice_shop" / "wapiti_juice_shop_report.json"
    wap = WapitiAdapter()
    with open(js_path) as f:
        raw_js = f.read()
    findings_js = wap.parse(raw_js)
    ids_js = [f.finding_id for f in findings_js]
    assert len(ids_js) == 2
    assert len(set(ids_js)) == 2


# =============================================================================
# 3. End-to-End Pipeline Provenance Retention
# =============================================================================

def test_m2_and_m8_preserve_all_source_finding_ids_without_loss():
    """M2 deduplication and M8 FindingSchema must retain all 55 source IDs across canonical findings."""
    webgoat_dir = _BACKEND_DIR / "mem1" / "webgoat"
    with open(webgoat_dir / "webgoat-ZAP-Report.json") as f:
        zap_data = f.read()
    with open(webgoat_dir / "webgoat_nuclei_results.json") as f:
        nuclei_data = f.read()
    with open(webgoat_dir / "wapiti_webgoat_report.json") as f:
        wapiti_data = f.read()

    runner = UnifiedPipelineRunner()
    findings, summary = runner.execute_pipeline(
        raw_sources={"ZAP": zap_data, "Nuclei": nuclei_data, "Wapiti": wapiti_data},
        asset_catalog=DEFAULT_ASSET_CATALOG
    )

    assert len(findings) == 21
    assert summary["summary"]["raw_findings"] == 55
    assert summary["summary"]["unique_findings"] == 21
    assert summary["summary"]["duplicates_correlated"] == 34

    # Extract all preserved source finding IDs
    preserved_ids = []
    for f in findings:
        assert f.finding_id.startswith("DEDUP-")
        for sf in f.detail.provenance.source_findings:
            preserved_ids.append(sf.finding_id)
            assert sf.scanner in {"ZAP", "NUCLEI", "WAPITI"}

    assert len(preserved_ids) == 55
    assert len(set(preserved_ids)) == 55, "Source IDs were lost or overwritten during deduplication!"
