# Member 4 — Threat Intelligence Enrichment Engine

## Pipeline Position

```
Member 3
   ↓  (ConfidenceEnrichedFinding)
Member 4 — Threat Intelligence Enrichment   ← THIS MODULE
   ↓  (ThreatEnrichedFinding)
Member 5 — Context-Aware Risk Engine
```

Member 4 accepts a `ConfidenceEnrichedFinding` from Member 3, enriches it
with real-world threat intelligence, and returns a `ThreatEnrichedFinding`
ready for Member 5.

---

## Core Responsibilities

| Responsibility | File |
|---|---|
| NVD / CVSS threat intelligence | `services/nvd_service.py` |
| FIRST EPSS threat intelligence | `services/epss_service.py` |
| CISA KEV threat intelligence | `services/kev_service.py` |
| SQLite threat intelligence cache | `cache/database.py` |
| Single-finding enrichment orchestration | `services/enrichment_service.py` |
| Input / output schema validation | `models/schemas.py` |

### Out of Scope (Member 4 does NOT implement)

- Exploit intelligence (`exploit_available` / `exploit_sources` remain `null` / `[]`)
- Risk scoring or risk levels
- Asset criticality or business impact
- Batch processing infrastructure
- FastAPI or any HTTP endpoints
- Member 5 functionality

---

## Project Structure

```
member4_threat_intelligence/
│
├── cache/
│   ├── __init__.py
│   └── database.py             # SQLite cache — HIT / MISS / STALE / TTL / UPSERT
│
├── models/
│   ├── __init__.py
│   └── schemas.py              # ConfidenceEnrichedFinding, ThreatEnrichedFinding
│
├── services/
│   ├── __init__.py
│   ├── nvd_service.py          # NVD 2.0 API → cvss_score & cvss_vector
│   ├── epss_service.py         # FIRST EPSS API → epss_score & epss_percentile
│   ├── kev_service.py          # CISA KEV feed → kev_listed & kev_date_added
│   └── enrichment_service.py   # Core orchestrator (Cache → NVD / EPSS / KEV)
│
├── tests/
│   ├── __init__.py
│   ├── test_schemas.py
│   ├── test_nvd.py
│   ├── test_epss.py
│   ├── test_kev.py
│   ├── test_cache.py
│   └── test_enrichment.py
│
├── .env.example
├── .gitignore
├── README.md
└── requirements.txt
```

---

## Integration Interface

The primary integration point for other team members is:

```python
from services.enrichment_service import ThreatIntelligenceEnrichmentService

service = ThreatIntelligenceEnrichmentService()

# Accepts ConfidenceEnrichedFinding (Member 3 output) or equivalent dict
result = service.enrich_finding(finding)

# result is a validated ThreatEnrichedFinding (Member 5 input)
print(result.threat_intelligence.cvss_score)
print(result.threat_intelligence.epss_score)
print(result.threat_intelligence.kev_listed)
```

---

## Enrichment Pipeline

```
Member 3
   ↓
ConfidenceEnrichedFinding
   ↓
Member 4 Enrichment Service
   ↓
SQLite Cache (cache/database.py)
   │
   ├── HIT  → return cached threat intelligence immediately (0 API calls)
   │
   └── MISS / STALE
          ↓
       NVD + EPSS + CISA KEV
          ↓
       Store in SQLite (UPSERT)
          ↓
       ThreatEnrichedFinding
   ↓
Member 5
```

**Null CVE handling:** if `cve_id` is `None`, Member 4 returns all-null
`threat_intelligence` immediately without making any external API calls.

---

## Input / Output Contract

### Input — `ConfidenceEnrichedFinding` (from Member 3)

```python
ConfidenceEnrichedFinding(
    schema_version="1.0",
    finding_id="DEDUP-000001",
    cve_id="CVE-2021-44228",        # may be None
    vulnerability_name="Log4Shell Remote Code Execution",
    vulnerability_type="REMOTE_CODE_EXECUTION",
    severity="CRITICAL",
    asset=Asset(asset_id="ASSET-SRV-042", host="srv-042.example.org", ...),
    scanner_consensus=ScannerConsensus(scanner_names=["ZAP", "NUCLEI"], score=0.75, ...),
    finding_confidence=FindingConfidence(score=0.952, classification="CONFIRMED", ...),
    noise_assessment=NoiseAssessment(likely_noise=False, ...),
    source_findings=["ZAP-101", "NUCLEI-202"],
)
```

### Output — `ThreatEnrichedFinding` (to Member 5)

```python
ThreatEnrichedFinding(
    schema_version="1.0",
    finding_id="DEDUP-000001",
    cve_id="CVE-2021-44228",
    asset_id="ASSET-SRV-042",
    vulnerability_name="Log4Shell Remote Code Execution",
    vulnerability_type="REMOTE_CODE_EXECUTION",
    scanner_sources=["ZAP", "NUCLEI"],
    scanner_consensus_score=0.75,
    finding_confidence_score=0.952,
    finding_confidence_classification="CONFIRMED",
    threat_intelligence=ThreatIntelligence(
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        epss_score=0.9753,
        epss_percentile=0.9998,
        kev_listed=True,
        kev_date_added="2021-12-10",
        exploit_available=None,     # Not implemented — out of scope
        exploit_sources=[],         # Not implemented — out of scope
        last_updated="2026-08-20T08:00:00Z",
    ),
)
```

---

## Threat Intelligence Sources

### NVD / CVSS — `services/nvd_service.py`
- **API**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Returns**: `cvss_score` (0–10), `cvss_vector`
- **CVSS version precedence**: v3.1 → v4.0 → v3.0 → v2.0
- **Source precedence**: Primary (NVD) → Secondary (CNA)

### FIRST EPSS — `services/epss_service.py`
- **API**: `https://api.first.org/data/v1/epss`
- **Returns**: `epss_score` (exploitation probability 0–1), `epss_percentile` (0–1)

### CISA KEV — `services/kev_service.py`
- **Feed**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **Returns**: `kev_listed` (True / False / None), `kev_date_added` (YYYY-MM-DD)
- **Three-state logic**:
  - `True`  = CVE is listed in CISA KEV (actively exploited)
  - `False` = Feed successfully checked, CVE is NOT listed
  - `None`  = Feed was unreachable or returned an error

---

## SQLite Cache — `cache/database.py`

The SQLite cache is the unique Member 4 feature. It prevents redundant
external API calls by persisting threat intelligence keyed by `cve_id`.

| Status | Meaning |
|---|---|
| **HIT** | Entry exists and `last_updated` is within `CACHE_TTL_HOURS` |
| **MISS** | No entry found for this CVE ID |
| **STALE** | Entry exists but `last_updated` is older than `CACHE_TTL_HOURS` |

- **Cache key**: `cve_id` (TEXT PRIMARY KEY)
- **Default TTL**: 24 hours (configurable via `CACHE_TTL_HOURS`)
- **Stored fields**: `cvss_score`, `cvss_vector`, `epss_score`, `epss_percentile`, `kev_listed`, `kev_date_added`, `exploit_available`, `exploit_sources`, `last_updated`
- **Write strategy**: UPSERT — repeated enrichment updates existing rows
- **SQLite file**: `cache/threat_cache.db` (auto-created; git-ignored)
- **Exploit fields**: always stored as `NULL` / `[]` (exploit intelligence is out of scope)

The cache is completely independent of NVD, EPSS, and CISA KEV. It only stores, retrieves, and checks freshness.

---

## Error Handling

- If any individual service (NVD, EPSS, or KEV) fails, its fields are returned as `null`
- Successful data from the remaining services is always preserved (partial enrichment)
- The pipeline never crashes due to a single source failure

---

## Configuration

Copy `.env.example` to `.env` and set values:

```env
NVD_API_KEY=your_nvd_api_key_here     # Optional — increases NVD rate limits
CACHE_TTL_HOURS=24                     # Cache time-to-live in hours (default: 24)
```

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Running Tests

All tests are fully offline, deterministic, and use mocked external APIs:

```bash
python -m pytest -q
```

| Test File | What it covers |
|---|---|
| `tests/test_schemas.py` | Pydantic schema validation — all contract fields |
| `tests/test_nvd.py` | NVD API client, CVSS parsing, error handling |
| `tests/test_epss.py` | EPSS API client, score validation, error handling |
| `tests/test_kev.py` | CISA KEV feed parsing, three-state logic |
| `tests/test_cache.py` | SQLite HIT / MISS / STALE, TTL, UPSERT |
| `tests/test_enrichment.py` | Full orchestration: cache reuse, partial enrichment, null CVE |
