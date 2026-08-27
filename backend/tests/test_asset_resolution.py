"""
test_asset_resolution.py
========================
Focused test suite for RizIntel Issue #1: Deterministic Asset Resolution.

Tests:
1. Exact hostname match
2. URL -> hostname resolution
3. Hostname with port match (e.g. 127.0.0.1:8001 vs localhost:3000)
4. Case and whitespace normalization
5. Unknown / unmapped hostname resolution
6. Absolutely no silent fallback to default production asset
7. WebGoat findings mapping to WebGoat lab asset
8. Juice Shop findings mapping to Juice Shop lab asset
9. Strict isolation: two different assets cannot cross-map
10. Safe end-to-end pipeline execution with unmapped assets
11. Real scanner dataset resolution verification
"""

import json
from pathlib import Path
import pytest

from services.asset_resolver import (
    AssetResolver,
    normalize_identifier,
    UNMAPPED_ASSET_ID,
    UNMAPPED_ENVIRONMENT,
    UNMAPPED_CRITICALITY,
    UNMAPPED_INTERNET_EXPOSURE,
)
from services.pipeline_service import UnifiedPipelineRunner, DEFAULT_ASSET_CATALOG
from models import FindingSchema


_BACKEND_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture
def sample_catalog():
    return {
        "ASSET-WEB-001": {
            "asset_id": "ASSET-WEB-001",
            "asset_name": "payments-prod-api-01",
            "hosts": ["payments.internal.corp", "https://payments.internal.corp"],
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
            "hosts": ["auth.internal.corp"],
            "environment": "PRODUCTION",
            "criticality": "HIGH",
            "asset_criticality": "HIGH",
            "internet_facing": True,
            "internet_exposure": True,
            "data_sensitivity": "RESTRICTED",
        },
        "ASSET-LAB-WEBGOAT": {
            "asset_id": "ASSET-LAB-WEBGOAT",
            "asset_name": "WebGoat Vulnerable Lab",
            "hosts": ["127.0.0.1:8001", "localhost:8001", "http://127.0.0.1:8001"],
            "environment": "DEVELOPMENT",
            "criticality": "LOW",
            "asset_criticality": "LOW",
            "internet_facing": False,
            "internet_exposure": False,
            "data_sensitivity": "INTERNAL",
        },
        "ASSET-LAB-JUICESHOP": {
            "asset_id": "ASSET-LAB-JUICESHOP",
            "asset_name": "OWASP Juice Shop Lab",
            "hosts": ["localhost:3000", "127.0.0.1:3000", "http://localhost:3000"],
            "environment": "DEVELOPMENT",
            "criticality": "LOW",
            "asset_criticality": "LOW",
            "internet_facing": False,
            "internet_exposure": False,
            "data_sensitivity": "INTERNAL",
        },
    }


# -----------------------------------------------------------------------------
# 1. Identifier Normalization Tests
# -----------------------------------------------------------------------------
def test_normalize_identifier_url():
    host, port = normalize_identifier("https://payments.internal.corp/api/v1/checkout?debug=true#section")
    assert host == "payments.internal.corp"
    assert port == 443

    host, port = normalize_identifier("http://127.0.0.1:8001/WebGoat/start.mvc")
    assert host == "127.0.0.1"
    assert port == 8001


def test_normalize_identifier_host_port():
    host, port = normalize_identifier("localhost:3000/")
    assert host == "localhost"
    assert port == 3000

    host, port = normalize_identifier("127.0.0.1:8001")
    assert host == "127.0.0.1"
    assert port == 8001


def test_normalize_identifier_case_and_whitespace():
    host, port = normalize_identifier("  HTTPS://PAYMENTS.INTERNAL.CORP:443/  ")
    assert host == "payments.internal.corp"
    assert port == 443


def test_normalize_identifier_bare_host():
    host, port = normalize_identifier("payments.internal.corp")
    assert host == "payments.internal.corp"
    assert port is None


# -----------------------------------------------------------------------------
# 2. Asset Resolution Matching Tests
# -----------------------------------------------------------------------------
def test_exact_hostname_match(sample_catalog):
    resolver = AssetResolver(sample_catalog)
    aid, ctx = resolver.resolve({"host": "payments.internal.corp"})
    assert aid == "ASSET-WEB-001"
    assert ctx["asset_name"] == "payments-prod-api-01"
    assert ctx["criticality"] == "CRITICAL"


def test_url_to_hostname_resolution(sample_catalog):
    resolver = AssetResolver(sample_catalog)
    aid, ctx = resolver.resolve({
        "url": "https://payments.internal.corp/api/v1/auth/login",
        "host": "payments.internal.corp"
    })
    assert aid == "ASSET-WEB-001"
    assert ctx["data_sensitivity"] == "PCI"


def test_hostname_with_port_webgoat(sample_catalog):
    resolver = AssetResolver(sample_catalog)
    aid, ctx = resolver.resolve({"host": "127.0.0.1", "port": 8001})
    assert aid == "ASSET-LAB-WEBGOAT"
    assert ctx["asset_name"] == "WebGoat Vulnerable Lab"
    assert ctx["environment"] == "DEVELOPMENT"
    assert ctx["criticality"] == "LOW"


def test_hostname_with_port_juiceshop(sample_catalog):
    resolver = AssetResolver(sample_catalog)
    aid, ctx = resolver.resolve({"url": "http://localhost:3000/rest/user/login"})
    assert aid == "ASSET-LAB-JUICESHOP"
    assert ctx["asset_name"] == "OWASP Juice Shop Lab"
    assert ctx["environment"] == "DEVELOPMENT"


def test_case_and_port_normalization(sample_catalog):
    resolver = AssetResolver(sample_catalog)
    aid, ctx = resolver.resolve({"host": "AUTH.INTERNAL.CORP"})
    assert aid == "ASSET-AUTH-002"
    assert ctx["asset_name"] == "auth-service-prod"


# -----------------------------------------------------------------------------
# 3. Isolation & No Default Fallback Tests
# -----------------------------------------------------------------------------
def test_unknown_hostname_remains_unmapped(sample_catalog):
    resolver = AssetResolver(sample_catalog)
    aid, ctx = resolver.resolve({"host": "unknown-internal-host.domain.org"})
    assert aid == UNMAPPED_ASSET_ID
    assert ctx["asset_id"] == UNMAPPED_ASSET_ID
    assert "Unresolved Asset" in ctx["asset_name"]
    assert ctx["environment"] == "UNKNOWN"
    assert ctx["criticality"] == "UNKNOWN"
    assert ctx["data_sensitivity"] == "UNKNOWN"
    assert ctx["internet_exposure"] is None    # genuinely unknown — not False
    assert ctx["internet_facing"] is None     # genuinely unknown — not False
    # Must NOT be ASSET-WEB-001
    assert aid != "ASSET-WEB-001"


def test_no_arbitrary_fallback_on_empty_catalog():
    resolver = AssetResolver({})
    aid, ctx = resolver.resolve({"host": "payments.internal.corp"})
    assert aid == UNMAPPED_ASSET_ID
    assert ctx["asset_id"] == UNMAPPED_ASSET_ID
    assert ctx["environment"] == "UNKNOWN"
    assert ctx["criticality"] == "UNKNOWN"
    assert aid != "ASSET-WEB-001"


def test_different_ports_on_same_ip_cannot_cross_map(sample_catalog):
    resolver = AssetResolver(sample_catalog)
    # WebGoat is on 8001. A scan on 127.0.0.1:9999 must NOT map to WebGoat!
    aid_9999, ctx_9999 = resolver.resolve({"host": "127.0.0.1", "port": 9999})
    assert aid_9999 == UNMAPPED_ASSET_ID

    # 127.0.0.1:8001 must map to WebGoat
    aid_8001, ctx_8001 = resolver.resolve({"host": "127.0.0.1", "port": 8001})
    assert aid_8001 == "ASSET-LAB-WEBGOAT"

    # 127.0.0.1:3000 must map to Juice Shop
    aid_3000, ctx_3000 = resolver.resolve({"host": "127.0.0.1", "port": 3000})
    assert aid_3000 == "ASSET-LAB-JUICESHOP"


def test_webgoat_cannot_map_to_payments_asset(sample_catalog):
    resolver = AssetResolver(sample_catalog)
    aid, ctx = resolver.resolve({
        "host": "127.0.0.1",
        "port": 8001,
        "url": "http://127.0.0.1:8001/WebGoat/start.mvc"
    })
    assert aid == "ASSET-LAB-WEBGOAT"
    assert aid != "ASSET-WEB-001"
    assert ctx["criticality"] != "CRITICAL"
    assert ctx["data_sensitivity"] != "PCI"


# -----------------------------------------------------------------------------
# 4. End-to-End Live Pipeline Safety & Real Data Tests
# -----------------------------------------------------------------------------
def test_pipeline_continues_safely_with_unresolved_asset():
    """Verify an unmapped host safely executes through M1..M8 without crashing and with UNKNOWN semantics."""
    raw_zap = {
        "site": [
            {
                "@name": "http://unregistered-foreign-host.net:8080",
                "@host": "unregistered-foreign-host.net",
                "@port": "8080",
                "alerts": [
                    {
                        "name": "Missing Anti-clickjacking Header",
                        "riskcode": "1",
                        "desc": "X-Frame-Options header is not set.",
                        "cweid": "1021",
                        "instances": [{"uri": "http://unregistered-foreign-host.net:8080/"}]
                    }
                ]
            }
        ]
    }

    runner = UnifiedPipelineRunner()
    findings, summary = runner.execute_pipeline(
        raw_sources={"ZAP": json.dumps(raw_zap)}
    )

    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, FindingSchema)
    assert f.asset_id == UNMAPPED_ASSET_ID
    assert f.asset_criticality == "UNKNOWN"
    assert f.internet_exposure is None        # genuinely unknown, not False
    assert f.risk_score >= 0
    assert f.detail.asset_context.environment == "UNKNOWN"
    assert f.detail.asset_context.data_sensitivity == "UNKNOWN"
    assert f.detail.asset_context.criticality == "UNKNOWN"
    assert f.detail.asset_context.internet_facing is None  # genuinely unknown, not False

    # Verify SLA is derived strictly from M5 risk score via M7 policy (createsla)
    if f.risk_score >= 90:
        assert f.workflow.sla_hours == 4
    elif f.risk_score >= 70:
        assert f.workflow.sla_hours == 24
    elif f.risk_score >= 40:
        assert f.workflow.sla_hours == 168
    else:
        assert f.workflow.sla_hours == 720


def test_real_webgoat_and_juiceshop_datasets(sample_catalog):
    """Test resolution with actual raw scanner reports present in the repo."""
    webgoat_zap_path = _BACKEND_DIR / "mem1" / "webgoat" / "webgoat-ZAP-Report.json"
    juiceshop_wapiti_path = _BACKEND_DIR / "mem1" / "juice_shop" / "wapiti_juice_shop_report.json"

    assert webgoat_zap_path.exists()
    assert juiceshop_wapiti_path.exists()

    with open(webgoat_zap_path) as f:
        webgoat_zap_raw = f.read()
    with open(juiceshop_wapiti_path) as f:
        juiceshop_wapiti_raw = f.read()

    runner = UnifiedPipelineRunner()

    # 1. Run WebGoat scanner report
    wg_findings, _ = runner.execute_pipeline(
        raw_sources={"ZAP": webgoat_zap_raw},
        asset_catalog=sample_catalog
    )
    assert len(wg_findings) > 0
    for f in wg_findings:
        assert f.asset_id == "ASSET-LAB-WEBGOAT"
        assert f.asset_criticality == "LOW"
        assert f.internet_exposure is False
        assert f.detail.asset_context.asset_name == "WebGoat Vulnerable Lab"

    # 2. Run Juice Shop scanner report
    js_findings, _ = runner.execute_pipeline(
        raw_sources={"WAPITI": juiceshop_wapiti_raw},
        asset_catalog=sample_catalog
    )
    assert len(js_findings) > 0
    for f in js_findings:
        assert f.asset_id == "ASSET-LAB-JUICESHOP"
        assert f.asset_criticality == "LOW"
        assert f.internet_exposure is False
        assert f.detail.asset_context.asset_name == "OWASP Juice Shop Lab"


# =============================================================================
# 5. M5 Zero-Point Proofs — UNKNOWN Criticality and None Exposure
# =============================================================================
def test_m5_unknown_criticality_contributes_zero_points():
    """
    Directly verify M5 scoring rules: UNKNOWN criticality → 0 pts (not 2 pts as LOW would give).
    Existing known tiers remain unchanged.
    """
    from mem5.src.rules import get_criticality_points, ASSET_CRITICALITY_POINTS

    # UNKNOWN → 0 pts
    assert get_criticality_points("UNKNOWN") == 0
    # Known tiers byte-for-byte unchanged
    assert get_criticality_points("LOW") == ASSET_CRITICALITY_POINTS["LOW"] == 2
    assert get_criticality_points("MEDIUM") == ASSET_CRITICALITY_POINTS["MEDIUM"] == 5
    assert get_criticality_points("HIGH") == ASSET_CRITICALITY_POINTS["HIGH"] == 8
    assert get_criticality_points("CRITICAL") == ASSET_CRITICALITY_POINTS["CRITICAL"] == 10


def test_m5_none_internet_exposure_contributes_zero_points():
    """
    Directly verify M5 scoring rules:
    - None (unknown exposure) → 0 pts (never assumes internet-facing)
    - True → 10 pts (unchanged)
    - False → 0 pts (unchanged)
    """
    from mem5.src.rules import get_exposure_points

    assert get_exposure_points(None) == 0    # genuinely unknown → 0 pts
    assert get_exposure_points(True) == 10   # confirmed internet-facing → 10 pts (unchanged)
    assert get_exposure_points(False) == 0   # confirmed internal → 0 pts (unchanged)


def test_m5_unknown_asset_total_score_zero_from_asset_factors():
    """
    Verify combined: UNMAPPED → asset_criticality=0 pts + internet_exposure=0 pts = 0 total
    from asset context, independent of threat factors.
    """
    from mem5.src.rules import get_criticality_points, get_exposure_points

    criticality_pts = get_criticality_points("UNKNOWN")
    exposure_pts = get_exposure_points(None)

    assert criticality_pts == 0, f"Expected 0, got {criticality_pts}"
    assert exposure_pts == 0, f"Expected 0, got {exposure_pts}"
    assert criticality_pts + exposure_pts == 0


# =============================================================================
# 6. Known-Asset Regression — Scores Are Byte-for-Byte Unchanged
# =============================================================================
def test_known_asset_regression_payments_prod():
    """
    A CRITICAL/internet-facing asset must still receive exactly 10 + 10 = 20 pts
    from asset factors, unchanged by the UNMAPPED shim removal.
    """
    from mem5.src.rules import get_criticality_points, get_exposure_points

    crit_pts = get_criticality_points("CRITICAL")
    exp_pts = get_exposure_points(True)
    assert crit_pts == 10
    assert exp_pts == 10
    assert crit_pts + exp_pts == 20


def test_known_asset_regression_lab_webgoat():
    """
    A LOW-criticality/non-internet-facing lab asset must still receive exactly
    2 + 0 = 2 pts from asset factors.
    UNMAPPED (0 pts) and LOW (2 pts) are now provably distinct.
    """
    from mem5.src.rules import get_criticality_points, get_exposure_points

    crit_pts = get_criticality_points("LOW")
    exp_pts = get_exposure_points(False)
    assert crit_pts == 2
    assert exp_pts == 0
    assert crit_pts + exp_pts == 2  # Distinct from UNMAPPED (0 pts)


def test_low_and_unknown_are_scored_differently():
    """
    Regression: UNKNOWN must not be treated as LOW.
    LOW → 2 pts, UNKNOWN → 0 pts. These must be distinct.
    """
    from mem5.src.rules import get_criticality_points

    assert get_criticality_points("LOW") == 2
    assert get_criticality_points("UNKNOWN") == 0
    assert get_criticality_points("LOW") != get_criticality_points("UNKNOWN")


def test_e2e_unmapped_asset_score_breakdown_shows_zero_asset_factors():
    """
    End-to-end test: run an unknown-host finding through the full pipeline
    and inspect the flattened M5 score breakdown stored in FindingSchema.
    asset_criticality_contribution and exposure_contribution must both be 0.
    """
    unk_zap = json.dumps({
        "site": [{
            "@name": "http://foreign-unknown-host.net:7777",
            "@host": "foreign-unknown-host.net",
            "@port": "7777",
            "alerts": [{
                "name": "Server Leaks Information via 'X-Powered-By'",
                "riskcode": "1",
                "desc": "X-Powered-By header set.",
                "cweid": "200",
                "instances": [{"uri": "http://foreign-unknown-host.net:7777/"}]
            }]
        }]
    })

    runner = UnifiedPipelineRunner()
    findings, _ = runner.execute_pipeline(raw_sources={"ZAP": unk_zap})
    assert len(findings) >= 1

    f = findings[0]
    assert f.asset_id == "UNMAPPED"
    assert f.asset_criticality == "UNKNOWN"
    assert f.internet_exposure is None

    # Score breakdown is the flattened dict produced by adapt_to_section8
    # Keys: asset_criticality_contribution, exposure_contribution
    sb = f.detail.risk_assessment.score_breakdown
    crit_contribution = sb.get("asset_criticality_contribution", -999)
    exp_contribution = sb.get("exposure_contribution", -999)

    assert crit_contribution == 0, (
        f"Expected 0 asset_criticality_contribution for UNMAPPED, got {crit_contribution}. "
        f"Full breakdown: {sb}"
    )
    assert exp_contribution == 0, (
        f"Expected 0 exposure_contribution for UNMAPPED, got {exp_contribution}. "
        f"Full breakdown: {sb}"
    )

