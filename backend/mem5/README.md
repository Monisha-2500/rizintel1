# Module M5: Asset Context + Dynamic Risk Scoring Engine

## 1. Module Responsibility
Module **M5** is exclusively responsible for **Asset Contextualization and Dynamic Rule-Based Risk Scoring**.

### Pipeline Execution Flow
- **M5 Receives**:
  - Validated Threat-Enriched Vulnerability Findings (Module M4) + Target Asset Context
- **M5 Performs**:
  - **Validation**: Pydantic model validation against Interface Contract v1.0
  - **Risk Calculation**: Deterministic, rule-based additive scoring (0–100 points)
  - **Classification**: Standardized risk tier mapping (LOW, MEDIUM, HIGH, CRITICAL)
  - **Breakdown**: Itemized factor point contributions
  - **Risk Drivers**: Signal extraction for triggered risk drivers
- **M5 Produces**:
  - Contract-compliant Risk Assessment Output for Module M6

### Explicit Scope Boundaries
- **IN SCOPE (M5 Responsibilities):**
  - Ingestion of Threat-Enriched findings according to Interface Contract v1.0.
  - Asset context mapping, range validation, and strict type enforcement.
  - Deterministic, explainable, rule-based additive scoring (0–100 points).
  - Categorical risk priority classification (LOW, MEDIUM, HIGH, CRITICAL).
  - Itemized score breakdown (`cvss`, `epss`, `kev`, `exploit_available`, `asset_criticality`, `internet_exposure`, `finding_confidence`).
  - Explainable risk driver generation (`HIGH_CVSS`, `HIGH_EPSS`, `KEV_LISTED`, `EXPLOIT_AVAILABLE`, `CRITICAL_ASSET`, `INTERNET_EXPOSED`, `HIGH_CONFIDENCE`).
  - Graceful support for findings without CVEs (`cve_id: null`).
  - Preservation of explicit schema and scoring versions (`schema_version: "1.0"`, `scoring_version: "1.0"`).
- **OUT OF SCOPE (M5 Does NOT do):**
  - **Does NOT store data** (no database integration).
  - **Does NOT display data** (no frontend, UI, or web dashboard).
  - **Does NOT create tickets** (no Jira integration or SLA management — handled by Module M6).
  - **Does NOT collect scanner data** (scanner ingestion & normalization handled by Modules M1/M2).
  - **Does NOT collect threat intelligence** (threat intel enrichment handled by Module M4).
  - **Does NOT execute machine learning or simulation workloads** during standard pipeline assessment.

---

## 2. Rule-Based Scoring Policy (Max 100 Points)

M5 uses an **additive, deterministic, explainable scoring engine**:

$$\text{Final Risk Score} = \min\left(100, \sum \text{Factor Contributions}\right)$$

### Point Contribution Structure
| Factor | Max Points | Value Range | Point Mapping |
| :--- | :--- | :--- | :--- |
| **CVSS** | 25 pts | 0.0 – 10.0 | `0.0–3.9` → 5 pts, `4.0–6.9` → 12 pts, `7.0–8.9` → 20 pts, `9.0–10.0` → 25 pts |
| **EPSS** | 20 pts | 0.0 – 1.0 | `0.00–0.19` → 2 pts, `0.20–0.49` → 8 pts, `0.50–0.79` → 14 pts, `0.80–1.00` → 20 pts |
| **KEV Listed** | 15 pts | boolean | `true` → 15 pts, `false` → 0 pts |
| **Exploit Available** | 10 pts | boolean | `true` → 10 pts, `false` → 0 pts |
| **Asset Criticality** | 10 pts | string | `LOW` → 2 pts, `MEDIUM` → 5 pts, `HIGH` → 8 pts, `CRITICAL` → 10 pts |
| **Internet Exposure** | 10 pts | boolean | `true` → 10 pts, `false` → 0 pts |
| **Finding Confidence** | 10 pts | 0.0 – 1.0 | `0.00–0.49` → 2 pts, `0.50–0.74` → 5 pts, `0.75–0.89` → 8 pts, `0.90–1.00` → 10 pts |
| **TOTAL MAX** | **100 pts** | | |

> [!IMPORTANT]
> **No Double-Counting**: `scanner_consensus_score` and `epss_percentile` are retained as supporting context and are **not** independently added to the score, preventing double-counting of correlated signals.
>
> **Confidence as Trust Signal**: High finding confidence is treated strictly as a verification/prioritization signal, not as a multiplier that alters the intrinsic danger of the vulnerability.

---

## 3. Categorical Risk Classification

| Score Range | Risk Level | Meaning |
| :--- | :--- | :--- |
| **75.0 – 100.0** | `CRITICAL` | Expedited mitigation required immediately |
| **50.0 – 74.9** | `HIGH` | High priority remediation |
| **25.0 – 49.9** | `MEDIUM` | Standard scheduled remediation |
| **0.0 – 24.9** | `LOW` | Informational or backlog tracking |

---

## 4. Input Sources & Interface Contract v1.0
M5 receives inputs from upstream:
1. **Threat-Enriched Findings (Module M4)**: Base vulnerability attributes, scanner consensus, finding confidence, CVSS, EPSS, CISA KEV status, and exploit availability.
2. **Asset Context Repository**: Asset identity, environment, criticality tier, internet exposure flag, and data sensitivity.

### Canonical Ingestion Fields & Constraints
| Category | Canonical Field | Scale / Type | Constraint / Rule |
| :--- | :--- | :--- | :--- |
| **Contract** | `schema_version` | String | Must be `"1.0"` |
| **Finding Identity** | `finding_id` | String | Unique finding identifier |
| | `cve_id` | String / Null | Canonical CVE format or `null` if unassigned |
| | `vulnerability_name` | String | Human-readable title |
| | `vulnerability_type` | String | CWE or vulnerability category |
| **Scanner Evidence** | `scanner_sources` | List[String] | Minimum 1 scanner |
| | `scanner_consensus_score` | Float | Scale: `0.0` – `1.0` (Contextual) |
| | `finding_confidence_score` | Float | Scale: `0.0` – `1.0` (Scored max 10 pts) |
| | `finding_confidence_classification` | String | e.g., `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW` |
| **Threat Intel** | `cvss_score` | Float | Scale: `0.0` – `10.0` (Scored max 25 pts) |
| | `epss_score` | Float | Scale: `0.0` – `1.0` (Scored max 20 pts) |
| | `epss_percentile` | Float | Scale: `0.0` – `1.0` (Contextual) |
| | `kev_listed` | Boolean | Strict JSON boolean (Scored max 15 pts) |
| | `exploit_available` | Boolean | Strict JSON boolean (Scored max 10 pts) |
| **Asset Context** | `asset_id` | String | Target asset identifier |
| | `asset_name` | String | Host / workload name |
| | `environment` | String | `PRODUCTION`, `STAGING`, `DEVELOPMENT` |
| | `asset_criticality` | String | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` (Scored max 10 pts) |
| | `internet_exposure` | Boolean | Strict JSON boolean (Scored max 10 pts) |
| | `data_sensitivity` | String | `RESTRICTED`, `CONFIDENTIAL`, `INTERNAL`, `PUBLIC` |

---

## 5. Output Contract (M5 → M6)
Module M5 emits a contract-compliant risk assessment JSON object containing:
- `schema_version`: Contract version (`"1.0"`).
- `scoring_version`: Algorithm identifier (`"1.0"`).
- `finding_id`, `cve_id`, `vulnerability_name`: Finding traceability.
- `scanner_consensus` & `finding_confidence`: Preserved scanner evidence.
- `threat_intelligence` & `asset_context`: Preserved input parameters.
- `risk_assessment`:
  - `risk_score`: Quantitative risk score (`0.0` – `100.0`).
  - `risk_level`: Categorical priority (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - `score_breakdown`: Itemized factor breakdown with original inputs and awarded points.
  - `risk_drivers`: List of triggered explainable drivers (`HIGH_CVSS`, `KEV_LISTED`, etc.).
- `metadata`: Assessment timestamp, engine version, and status.

---

## 6. Project Structure & File Responsibilities

```
M5_Risk_Engine/
├── input/
│   ├── sample_input.json          # Valid critical CVE finding with full context
│   ├── missing_cve_input.json     # Valid finding with cve_id: null
│   ├── malformed_input.json       # Intentionally invalid data for validation tests
│   └── asset_context.json         # Standalone canonical asset context record
├── output/
│   └── expected_output.json       # Target M5 -> M6 output contract
├── src/
│   ├── __init__.py                # Package declaration
│   ├── models.py                  # Pydantic validation models for input & output contracts
│   ├── rules.py                   # Declarative scoring tables, ranges, and thresholds
│   ├── scoring.py                 # Deterministic additive scoring engine
│   ├── classifier.py              # Categorical risk priority classifier
│   ├── explanation.py             # Score breakdown and risk driver generator
│   ├── simulator.py               # "What-if" environmental risk simulation placeholder
│   └── risk_engine.py             # End-to-end pipeline orchestrator
├── tests/
│   ├── __init__.py
│   ├── test_validation.py         # Pytest suite for schema validation & range checks
│   └── test_scoring.py            # Comprehensive test suite (27+ tests & monotonic invariants)
├── docs/
│   ├── contract_v1.0.md           # Interface Contract v1.0 technical specification
│   └── scoring_policy.md          # Comprehensive scoring policy documentation
├── main.py                        # Entrypoint running pipeline demo on mock data
├── requirements.txt               # Dependencies (pydantic, pytest)
├── README.md                      # Architecture and interface documentation
└── .gitignore                     # Standard Python gitignore
```

---

## 7. Running the Pipeline Demo & Tests

### Setup Environment
```bash
pip install -r requirements.txt
```

### Run Demonstration
```bash
python main.py
```

### Run Test Suite
```bash
pytest tests/ -v
```
