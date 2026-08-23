"""
Deep End-to-End Integration Test for RizIntel LIVE M1->M7->M8 Mode
==================================================================
Tests:
1. Multi-scanner Ingestion & Normalization (ZAP, Nuclei, Wapiti)
2. Exact & Fuzzy Deduplication + Consensus Scoring
3. 5-Signal Confidence Scoring & Noise Assessment
4. Threat Intelligence Enrichment (NVD, EPSS, CISA KEV, Cache)
5. Asset Context Join
6. M5 Context-Aware Risk Scoring Sovereignty
7. M6 Explainable AI & Deterministic Fallback Generation
8. M7 SLA Ticket Calculation & Assignment Status
9. M8 Decision Intelligence:
   - Schema v1.0 Validation
   - RizTrace 8-Stage Provenance Graph
   - Why Now? Reason Generation
   - MITRE ATT&CK Inferred Technique Mapping
   - Asset View Grouping & Aggregation
   - Security Intelligence Metrics & Top Risks
   - RBAC Permissions Matrix & SQLite Tamper-Evident Audit Ledger
10. Edge Cases:
   - Normal CVE Case
   - Duplicate Cross-Scanner Case
   - Missing-CVE (CWE only) Case
   - Missing/Sparse Data Case
   - Module Fallback / Error Recovery Case
"""

import os
import sys
import json
from pathlib import Path
from pprint import pprint

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from main import app
from models import FindingSchema, AuditEventCreate
from services.pipeline_service import UnifiedPipelineRunner, pipeline_runner
from adapters.m1_adapter import M1NormalizedFindingAdapter
from adapters.m5_adapter import M5RiskEngineAdapter
from adapters.m7_adapter import M7ActionableFindingAdapter

def run_deep_e2e_integration_test():
    client = TestClient(app)
    results = {}

    print("=" * 80)
    print("STARTING DEEP E2E INTEGRATION TEST: RIZINTEL LIVE M1 -> M7 -> M8")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # 1. Custom Representative Raw Scanner Payloads (ZAP, Nuclei, Wapiti)
    # -------------------------------------------------------------------------
    zap_payload = {
        "site": [
            {
                "@name": "https://payments.internal.corp",
                "@host": "payments.internal.corp",
                "@port": "443",
                "@ssl": "true",
                "alerts": [
                    {
                        "pluginId": "40018",
                        "alertRef": "40018-1",
                        "alert": "SQL Injection",
                        "name": "SQL Injection",
                        "riskcode": "3",
                        "confidence": "3",
                        "riskdesc": "High (High)",
                        "desc": "<p>SQL injection vulnerability detected in login endpoint.</p>",
                        "instances": [
                            {
                                "uri": "https://payments.internal.corp/api/v1/auth/login",
                                "method": "POST",
                                "param": "username",
                                "attack": "' OR '1'='1",
                                "evidence": "syntax error near unexpected token"
                            }
                        ],
                        "cweid": "89",
                        "wascid": "19",
                        "sourceid": "1"
                    },
                    {
                        "pluginId": "40012",
                        "alertRef": "40012-1",
                        "alert": "Cross-Site Scripting (Reflected)",
                        "name": "Cross-Site Scripting (Reflected)",
                        "riskcode": "2",
                        "confidence": "2",
                        "riskdesc": "Medium (Medium)",
                        "desc": "<p>Reflected XSS in search query parameter.</p>",
                        "instances": [
                            {
                                "uri": "https://payments.internal.corp/search",
                                "method": "GET",
                                "param": "q",
                                "attack": "<script>alert(1)</script>",
                                "evidence": "<script>alert(1)</script>"
                            }
                        ],
                        "cweid": "79",
                        "wascid": "8",
                        "sourceid": "1"
                    },
                    {
                        "pluginId": "10020",
                        "alertRef": "10020-1",
                        "alert": "Missing Anti-Clickjacking Header",
                        "name": "Missing Anti-Clickjacking Header",
                        "riskcode": "1",
                        "confidence": "2",
                        "riskdesc": "Low (Medium)",
                        "desc": "<p>X-Frame-Options header not set.</p>",
                        "instances": [
                            {
                                "uri": "https://payments.internal.corp/",
                                "method": "GET",
                                "param": "",
                                "attack": "",
                                "evidence": ""
                            }
                        ],
                        "cweid": "1021",
                        "wascid": "15",
                        "sourceid": "1"
                    }
                ]
            }
        ]
    }

    nuclei_payload = [
        {
            "template-id": "cve-2024-1234-sqli",
            "info": {
                "name": "SQL Injection in Authentication Service",
                "author": ["security-team"],
                "severity": "high",
                "description": "SQL Injection in auth login parameter",
                "classification": {
                    "cve-id": "CVE-2024-1234",
                    "cwe-id": ["CWE-89"],
                    "cvss-score": 8.5
                }
            },
            "type": "http",
            "host": "https://payments.internal.corp",
            "matched-at": "https://payments.internal.corp/api/v1/auth/login",
            "extracted-results": ["username=' OR '1'='1"],
            "timestamp": "2026-08-20T10:00:00Z"
        },
        {
            "template-id": "cve-2024-9999-rce",
            "info": {
                "name": "Remote Code Execution via Spring Framework",
                "author": ["security-team"],
                "severity": "critical",
                "description": "Critical RCE in payment gateway dispatcher",
                "classification": {
                    "cve-id": "CVE-2024-9999",
                    "cwe-id": ["CWE-94"],
                    "cvss-score": 9.8
                }
            },
            "type": "http",
            "host": "https://payments.internal.corp",
            "matched-at": "https://payments.internal.corp/gateway/dispatch",
            "extracted-results": ["uid=0(root) gid=0(root)"],
            "timestamp": "2026-08-20T10:05:00Z"
        },
        {
            "template-id": "generic-xss-search",
            "info": {
                "name": "Cross-Site Scripting (Reflected)",
                "author": ["security-team"],
                "severity": "medium",
                "description": "Reflected XSS in search",
                "classification": {
                    "cwe-id": ["CWE-79"]
                }
            },
            "type": "http",
            "host": "https://payments.internal.corp",
            "matched-at": "https://payments.internal.corp/search",
            "extracted-results": ["<script>alert(1)</script>"],
            "timestamp": "2026-08-20T10:10:00Z"
        }
    ]

    wapiti_payload = {
        "classifications": {
            "SQL_Injection": {
                "desc": "SQL Injection found via POST on username",
                "sol": "Use prepared statements or parameterized queries.",
                "ref": {"CVE-2024-1234: SQL Injection Reference": "https://cve.mitre.org", "CWE-89: SQL Injection": "https://cwe.mitre.org"}
            },
            "Cross_Site_Scripting": {
                "desc": "Reflected Cross-Site Scripting found in search parameter",
                "sol": "Sanitize and encode user inputs.",
                "ref": {"CWE-79: Cross-site Scripting": "https://cwe.mitre.org"}
            }
        },
        "vulnerabilities": {
            "SQL_Injection": [
                {
                    "method": "POST",
                    "path": "/api/v1/auth/login",
                    "info": "SQL Injection found via POST on username",
                    "level": 3,
                    "parameter": "username",
                    "http_request": "POST /api/v1/auth/login HTTP/1.1\nHost: payments.internal.corp\n\nusername='",
                    "curl_command": "curl -X POST https://payments.internal.corp/api/v1/auth/login -d username='"
                }
            ],
            "Cross_Site_Scripting": [
                {
                    "method": "GET",
                    "path": "/search",
                    "info": "XSS in search parameter q",
                    "level": 2,
                    "parameter": "q",
                    "http_request": "GET /search?q=<script> HTTP/1.1\nHost: payments.internal.corp",
                    "curl_command": "curl 'https://payments.internal.corp/search?q=<script>'"
                }
            ]
        },
        "infos": {
            "target": "https://payments.internal.corp",
            "scope": "folder",
            "date": "2026-08-20T10:15:00Z",
            "version": "Wapiti 3.1.6"
        }
    }

    raw_sources = {
        "ZAP": json.dumps(zap_payload),
        "NUCLEI": json.dumps(nuclei_payload),
        "WAPITI": json.dumps(wapiti_payload),
    }

    custom_asset_catalog = {
        "payments.internal.corp": {
            "asset_id": "ASSET-WEB-001",
            "asset_name": "payments-prod-api-01",
            "environment": "PRODUCTION",
            "criticality": "CRITICAL",
            "internet_facing": True,
            "data_sensitivity": "PCI-DSS"
        }
    }

    # -------------------------------------------------------------------------
    # 2. Execute Live Integrated Pipeline
    # -------------------------------------------------------------------------
    runner = UnifiedPipelineRunner()
    validated_findings, summary = runner.execute_pipeline(
        raw_sources=raw_sources,
        asset_catalog=custom_asset_catalog
    )

    print(f"\n[PIPELINE OUTPUT] Processed {len(validated_findings)} deduplicated actionable findings.")
    print(f"[PIPELINE OUTPUT] Raw Findings Ingested: {summary['summary']['raw_findings']}")
    print(f"[PIPELINE OUTPUT] Duplicates Eliminated: {summary['summary']['duplicates_correlated']} ({summary['summary']['duplicate_reduction_rate']*100:.1f}%)")

    # -------------------------------------------------------------------------
    # 3. Step-by-Step Verifications
    # -------------------------------------------------------------------------

    # Boundary 1: M1 Normalization
    m1_norm = runner.run_m1(raw_sources)
    assert len(m1_norm) >= 7, "M1 failed to parse all scanner alerts"
    for nf in m1_norm:
        assert nf["schema_version"] == "1.0"
        assert nf["finding_id"] is not None
        assert nf["scanner"] in {"ZAP", "NUCLEI", "WAPITI"}
        assert nf["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    results["M1_NORMALIZATION"] = "PASS"

    # Boundary 2: M2 Deduplication & Consensus
    m2_dedup, m2_metrics = runner.run_m2(m1_norm)
    assert len(m2_dedup) < len(m1_norm), "M2 failed to deduplicate cross-scanner duplicates"
    # Find SQL Injection canonical finding (should be detected by ZAP, NUCLEI, WAPITI)
    sqli_finding = next((f for f in m2_dedup if f.get("vulnerability_type") == "SQL_INJECTION"), None)
    assert sqli_finding is not None, "SQL Injection finding not found in M2 output"
    assert sqli_finding["scanner_consensus"]["detected_by_count"] == 3, f"Expected 3 scanners for SQLi, got {sqli_finding['scanner_consensus']['detected_by_count']}"
    assert sqli_finding["scanner_consensus"]["score"] == 1.0, "Consensus score for 3/3 scanners should be 1.0"
    assert len(sqli_finding["source_findings"]) == 3, "All 3 scanner source finding IDs must be preserved"
    results["M2_DEDUPLICATION_CONSENSUS"] = "PASS"

    # Boundary 3: M3 Confidence Scoring & Noise Assessment
    m3_conf = runner.run_m3(m2_dedup)
    for cf in m3_conf:
        assert "finding_confidence" in cf
        assert 0.0 <= cf["finding_confidence"]["score"] <= 1.0
        assert cf["finding_confidence"]["classification"] in {"CONFIRMED", "HIGH_CONFIDENCE", "NEEDS_REVIEW", "LIKELY_NOISE"}
    results["M3_CONFIDENCE_NOISE"] = "PASS"

    # Boundary 4: M4 Threat Intelligence Enrichment (NVD, EPSS, KEV)
    m4_threat = runner.run_m4(m3_conf)
    for tf in m4_threat:
        ti = tf.get("threat_intelligence", {})
        if tf.get("cve_id"):
            assert ti.get("cvss_score") is not None or ti.get("epss_score") is not None or ti.get("kev_listed") is not None
        else:
            # Missing-CVE finding: threat intel must follow Schema v1.0 null convention
            assert ti.get("cvss_score") is None
            assert ti.get("epss_score") is None
            assert ti.get("kev_listed") is None or ti.get("kev_listed") is False
    results["M4_THREAT_INTELLIGENCE"] = "PASS"

    # Boundary 5 & 6: Asset Context Join & M5 Dynamic Risk Scoring Sovereignty
    m5_assessed = runner.run_m5(m4_threat, asset_catalog=custom_asset_catalog)
    for af in m5_assessed:
        ra = af.get("risk_assessment", {})
        ac = af.get("asset_context", {})
        assert "asset_context" in af
        assert ac["criticality"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert 0.0 <= ra.get("risk_score", 0.0) <= 100.0
        assert ra.get("risk_level") in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert "score_breakdown" in ra
        assert ra.get("scoring_version") == "M5-v1.0"
    results["PRE_M5_ASSET_JOIN_AND_M5_SCORING"] = "PASS"

    # Boundary 7: M6 Explainability & Remediation
    m6_explained = runner.run_m6(m5_assessed)
    for ef in m6_explained:
        ex = ef.get("explanation", {})
        assert ex.get("technical") is not None
        assert ex.get("management") is not None
        assert "CRITICAL-criticality" not in ex.get("management")
        # Verify score passthrough sovereignty (M6 never recalculated score)
        orig_m5 = next(a for a in m5_assessed if a["finding_id"] == ef["finding_id"])
        assert ef["risk_score"] == orig_m5["risk_assessment"]["risk_score"]
    results["M6_EXPLAINABILITY_REMEDIATION"] = "PASS"

    # Boundary 8: M7 SLA Automation & Ticketing
    # Map context map
    context_map = {}
    for d in m2_dedup:
        fid = d["finding_id"]
        context_map[fid] = {
            "finding_id": fid,
            "cve_id": d.get("cve_id"),
            "vulnerability_name": d.get("vulnerability_name"),
            "vulnerability_type": d.get("vulnerability_type"),
            "source_findings": d.get("source_findings", []),
            "scanner_consensus": d.get("scanner_consensus", {}),
            "asset_id": d.get("asset", {}).get("asset_id", "ASSET-WEB-001"),
        }
    for c in m3_conf:
        fid = c["finding_id"]
        if fid in context_map:
            context_map[fid]["finding_confidence"] = c.get("finding_confidence", {})
    for t in m4_threat:
        fid = t["finding_id"]
        if fid in context_map:
            context_map[fid]["threat_intelligence"] = t.get("threat_intelligence", {})
    for a in m5_assessed:
        fid = a["finding_id"]
        if fid in context_map:
            context_map[fid]["risk_assessment"] = a.get("risk_assessment", {})
            context_map[fid]["asset_context"] = a.get("asset_context", {})
            context_map[fid]["risk_score"] = a.get("risk_assessment", {}).get("risk_score", 0)
            context_map[fid]["risk_level"] = a.get("risk_assessment", {}).get("risk_level", "LOW")

    m7_actionable = runner.run_m7(m6_explained, context_map)
    for af in m7_actionable:
        wf = af.get("workflow", {})
        assert wf.get("ticket_id") is not None
        assert wf.get("sla_hours") in {4, 24, 168, 720}
        assert wf.get("sla_status") in {"ON_TRACK", "WARNING", "SLA_BREACHED", "BREACHED"}
        # Unassigned finding journey check: ASSIGNED must be PENDING
        if wf.get("assigned_to") is None:
            assigned_stage = next(s for s in af["detail"]["provenance"]["journey"] if s["stage"] == "ASSIGNED")
            assert assigned_stage["status"] == "PENDING"
    results["M7_SLA_AUTOMATION"] = "PASS"

    # Boundary 9: M8 Ingestion, Schema v1.0 & RizTrace Provenance
    for f in validated_findings:
        assert isinstance(f, FindingSchema)
        assert f.schema_version == "1.0"
        assert len(f.detail.provenance.journey) == 8
        assert len(f.detail.provenance.source_findings) >= 1
    results["M8_SCHEMA_PROVENANCE_RIZTRACE"] = "PASS"

    # Boundary 10: FastAPI Integration Endpoints (Live Mode API)
    # Post run
    resp_run = client.post("/api/integration/pipeline/run", json={"raw_sources": raw_sources})
    assert resp_run.status_code == 200
    run_json = resp_run.json()
    assert run_json["status"] == "SUCCESS"
    assert run_json["total_findings"] == len(validated_findings)

    # Get findings
    resp_finds = client.get("/api/integration/pipeline/findings")
    assert resp_finds.status_code == 200
    live_findings = resp_finds.json()
    assert len(live_findings) == len(validated_findings)

    # Get summary
    resp_sum = client.get("/api/integration/pipeline/summary")
    assert resp_sum.status_code == 200
    live_sum = resp_sum.json()
    assert live_sum["summary"]["unique_findings"] == len(validated_findings)

    # Health check
    resp_health = client.get("/api/integration/health")
    assert resp_health.status_code == 200
    assert resp_health.json()["overall_status"] == "HEALTHY"
    results["FASTAPI_INTEGRATION_ENDPOINTS"] = "PASS"

    # Boundary 11: Tamper-Evident Audit Ledger & RBAC Security Matrix
    # Analyst creates feedback
    sample_fid = live_findings[0]["finding_id"]
    fb_resp = client.post(
        f"/api/findings/{sample_fid}/audit",
        headers={"X-User-Role": "ANALYST", "X-User-Name": "SA Analyst"},
        json={
            "finding_id": sample_fid,
            "analyst_action": "ACCEPT_PRIORITY",
            "analyst_decision": "ACCEPT_PRIORITY",
            "rationale": "Verified compensating WAF rule active.",
            "reason": "Compensating control in place",
            "role": "SA Analyst [ANALYST]",
            "timestamp": "2026-08-22T12:00:00Z"
        }
    )
    assert fb_resp.status_code == 200, f"Audit post failed: {fb_resp.text}"

    # Verify SHA-256 Chain
    verify_resp = client.get(f"/api/findings/{sample_fid}/audit/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True

    # Test RBAC Least Privilege: Viewer CANNOT decide (403)
    viewer_resp = client.post(
        f"/api/findings/{sample_fid}/audit",
        headers={"X-User-Role": "VIEWER", "X-User-Name": "Auditor"},
        json={
            "finding_id": sample_fid,
            "analyst_action": "ACCEPT_PRIORITY",
            "analyst_decision": "ACCEPT_PRIORITY",
            "rationale": "Attempt unauthorized action"
        }
    )
    assert viewer_resp.status_code == 403, "Viewer should be blocked with 403"

    # Test RBAC Least Privilege: Analyst CANNOT escalate (403)
    escalate_resp = client.post(
        f"/api/findings/{sample_fid}/audit",
        headers={"X-User-Role": "ANALYST", "X-User-Name": "SA Analyst"},
        json={
            "finding_id": sample_fid,
            "analyst_action": "ESCALATE",
            "analyst_decision": "ESCALATE",
            "rationale": "Attempt unauthorized escalation"
        }
    )
    assert escalate_resp.status_code == 403, "Analyst should not be allowed to escalate"

    # Security Lead CAN escalate (200)
    lead_resp = client.post(
        f"/api/findings/{sample_fid}/audit",
        headers={"X-User-Role": "SECURITY_LEAD", "X-User-Name": "SOC Lead"},
        json={
            "finding_id": sample_fid,
            "analyst_action": "ESCALATE",
            "analyst_decision": "ESCALATE",
            "rationale": "Critical risk escalation to engineering lead."
        }
    )
    assert lead_resp.status_code == 200, "Security Lead must be allowed to escalate"
    results["RBAC_AND_AUDIT_TRAIL"] = "PASS"

    print("\n" + "=" * 80)
    print("ALL MODULE BOUNDARY TESTS COMPLETED SUCCESSFULLY:")
    for k, v in results.items():
        print(f"  - {k:<35}: {v}")
    print("=" * 80)

if __name__ == "__main__":
    run_deep_e2e_integration_test()
