# Module M5 — Interface Contract v1.0 Specification

## 1. Overview
Module M5 (**Asset Context + Dynamic Risk Scoring Engine**) is responsible for taking threat-enriched vulnerability findings from **Module M4** and contextualizing them with target **Asset Context** to compute dynamic risk scores and transparent explanations for downstream prioritization in **Module M6**.

---

## 2. Ingestion Interface (M4 & Asset Context → M5)

### Canonical Fields
| Field Name | Type | Scale / Range | Description |
| :--- | :--- | :--- | :--- |
| `schema_version` | String | `"1.0"` | Schema version identifier |
| `finding_id` | String | Unique ID | Identifier for vulnerability finding |
| `cve_id` | String / Null | CVE Format / null | Associated CVE ID if assigned |
| `vulnerability_name` | String | Text | Descriptive name of vulnerability |
| `vulnerability_type` | String | Text / CWE | Categorical vulnerability type |
| `scanner_sources` | Array[String] | Min length: 1 | Originating scanners (e.g., Trivy, Snyk) |
| `scanner_consensus_score` | Float | `0.0` to `1.0` | Agreement metric across scanners |
| `finding_confidence_score` | Float | `0.0` to `1.0` | Confidence in finding validity |
| `finding_confidence_classification` | String | Enum / Text | Categorical confidence (e.g., CONFIRMED, HIGH) |

### Threat Intelligence Fields (`threat_intelligence`)
| Field Name | Type | Scale / Range | Description |
| :--- | :--- | :--- | :--- |
| `cvss_score` | Float | `0.0` to `10.0` | CVSS base severity score |
| `epss_score` | Float | `0.0` to `1.0` | EPSS probability of exploitation |
| `epss_percentile` | Float | `0.0` to `1.0` | EPSS relative percentile rank |
| `kev_listed` | Strict Boolean | `true` / `false` | Presence in CISA KEV catalog |
| `exploit_available` | Strict Boolean | `true` / `false` | Public exploit code availability |

### Asset Context Fields (`asset_context`)
| Field Name | Type | Allowed Values | Description |
| :--- | :--- | :--- | :--- |
| `asset_id` | String | Unique ID | Asset identifier |
| `asset_name` | String | Text | Service / host name |
| `environment` | String | `PRODUCTION`, `STAGING`, `DEVELOPMENT` | Deployment environment |
| `asset_criticality` | String | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | Business impact tier |
| `internet_exposure` | Strict Boolean | `true` / `false` | Direct internet exposure |
| `data_sensitivity` | String | `RESTRICTED`, `CONFIDENTIAL`, `INTERNAL`, `PUBLIC` | Data classification |

---

## 3. Output Interface (M5 → M6 Risk Assessment)
| Field Name | Type | Description |
| :--- | :--- | :--- |
| `schema_version` | String | `"1.0"` |
| `scoring_version` | String | Version tag of scoring algorithm used |
| `finding_id` | String | Unique finding identifier |
| `cve_id` | String / Null | CVE identifier |
| `vulnerability_name` | String | Vulnerability name |
| `scanner_consensus` | Object | Summary of scanner sources & consensus score |
| `finding_confidence` | Object | Confidence score and classification |
| `threat_intelligence` | Object | Preserved threat intel metrics |
| `asset_context` | Object | Preserved asset context parameters |
| `risk_assessment` | Object | Contains `risk_score`, `risk_level`, and `score_breakdown` |
| `metadata` | Object | Engine execution timestamp, version, and audit status |
