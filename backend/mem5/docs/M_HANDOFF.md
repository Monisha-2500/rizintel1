# Module M5 → Module M6 Integration & Handoff Guide

## 1. M5 Purpose
Module **M5 (Asset Context + Dynamic Risk Scoring Engine)** takes threat-enriched vulnerability findings (from **Module M4**) and contextualizes them with target enterprise **Asset Context** to compute deterministic, transparent, rule-based risk scores, categorical priority tiers, itemized score breakdowns, and explainable risk drivers for downstream consumption by **Module M6 (Triage, Remediation & Ticketing)**.

---

## 2. M5 Input Source
M5 ingests data directly compliant with **Interface Contract v1.0**:
- **Threat-Enriched Finding Attributes (from M4)**: `finding_id`, `cve_id`, `vulnerability_name`, `vulnerability_type`, `scanner_sources`, `scanner_consensus_score`, `finding_confidence_score`, `finding_confidence_classification`, and `threat_intelligence` (`cvss_score`, `epss_score`, `epss_percentile`, `kev_listed`, `exploit_available`).
- **Asset Context Attributes**: `asset_id`, `asset_name`, `environment`, `asset_criticality`, `internet_exposure`, `data_sensitivity`.

---

## 3. M5 Output
M5 produces a canonical JSON object structured strictly under Interface Contract v1.0 containing:
- Finding identification and preserved M4 threat intelligence
- Preserved asset business context
- Evaluated `risk_assessment` payload (`risk_score`, `risk_level`, `score_breakdown`, `risk_drivers`, `scoring_version`)
- Execution audit `metadata`

---

## 4. Exact Execution Method & Output Access

### Programmatic Python Invocation (M5 as a Library)
```python
from src.risk_engine import RiskEngine
from src.models import M5RiskEngineOutput

engine = RiskEngine()
# raw_input is a Python dict adhering to Interface Contract v1.0
assessment_output: M5RiskEngineOutput = engine.assess_finding(raw_input)

# Convert to JSON / dict for downstream pipeline processing
output_dict = assessment_output.model_dump()
```

### Direct CLI Execution
```powershell
python main.py
```

### Reference Output Contract Location
- `output/expected_output.json`

---

## 5. Important Canonical Fields Module M6 Should Read

| Field Path | Type | Scale / Range | Description for M6 |
| :--- | :--- | :--- | :--- |
| `finding_id` | String | Unique ID | Primary key for ticket creation / finding tracking |
| `cve_id` | String / null | Canonical CVE or `null` | Associated CVE identifier for external knowledge linking |
| `vulnerability_name` | String | Text | Descriptive title for ticketing |
| `asset_context.asset_id` | String | Unique ID | Target asset identifier for asset owner routing |
| `asset_context.environment` | String | `PRODUCTION`, `STAGING`, `DEVELOPMENT` | Environment tier for deployment blast radius |
| `risk_assessment.risk_score` | Float | `0.0` – `100.0` | Quantitative composite risk score for sorting / queuing |
| `risk_assessment.risk_level` | String | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | Categorical priority tier for SLA assignment |
| `risk_assessment.risk_drivers` | List[String] | Array of codes | Key drivers justifying the assigned priority |
| `risk_assessment.score_breakdown` | Object | Factor details | Audit trail showing point contributions per factor |
| `scoring_version` | String | `"1.0"` | Policy version tag for audit compliance |

---

## 6. Meaning of `risk_score`
- `risk_score` is a **bounded continuous metric from 0.0 to 100.0**.
- It represents the combined additive risk of the vulnerability given its technical severity, real-world exploitation likelihood, active CISA KEV exploitation status, exploit code availability, asset business criticality, internet exposure, and detection confidence.
- M6 should use `risk_score` as the primary numerical sorting key to rank-order findings within the same tier.

---

## 7. Meaning of `risk_level`
`risk_level` maps `risk_score` to four standardized operational action tiers:

| `risk_level` | Numerical Range | Recommended M6 Action / Remediation SLA |
| :--- | :--- | :--- |
| **`CRITICAL`** | `75.0` – `100.0` | Immediate expedited mitigation (e.g., 24–48 hour SLA, on-call alert) |
| **`HIGH`** | `50.0` – `74.9` | Priority remediation in current sprint / standard SLA (e.g., 7–14 days) |
| **`MEDIUM`** | `25.0` – `49.9` | Scheduled remediation in next maintenance cycle (e.g., 30 days) |
| **`LOW`** | `0.0` – `24.9` | Backlog tracking / informational monitoring (e.g., 90 days / accept risk) |

---

## 8. Meaning of `score_breakdown`
`score_breakdown` provides an **itemized, transparent factor-by-factor accounting** of how the score was calculated. Each factor contains the original input value and the points awarded:
- `cvss`: Points from technical severity (Max 25 pts)
- `epss`: Points from EPSS exploitation probability (Max 20 pts)
- `kev`: Points from active CISA KEV exploitation (Max 15 pts)
- `exploit_available`: Points from public exploit availability (Max 10 pts)
- `asset_criticality`: Points from asset business tier (Max 10 pts)
- `internet_exposure`: Points from public internet accessibility (Max 10 pts)
- `finding_confidence`: Points from detection verification confidence (Max 10 pts)

> [!NOTE]
> Invariant Guarantee: $\text{risk\_score} = \min\left(100.0, \sum \text{score\_breakdown.points}\right)$.

---

## 9. Meaning of `risk_drivers`
`risk_drivers` are deterministic domain fact signals that triggered during assessment:
- `HIGH_CVSS`: CVSS score $\ge 7.0$ (High or Critical technical severity)
- `HIGH_EPSS`: EPSS probability $\ge 0.50$ (Elevated probability of exploitation)
- `KEV_LISTED`: Confirmed active exploitation in the CISA KEV catalog
- `EXPLOIT_AVAILABLE`: Public functional exploit code is available
- `CRITICAL_ASSET`: Asset is classified as CRITICAL infrastructure
- `INTERNET_EXPOSED`: Asset is directly exposed to the public internet
- `HIGH_CONFIDENCE`: Scanner verification confidence $\ge 0.75$

M6 should include these driver tags directly in Jira ticket summaries and notifications for instant analyst context.

---

## 10. Example M5 Output

```json
{
  "schema_version": "1.0",
  "scoring_version": "1.0",
  "finding_id": "FIND-2026-0892",
  "cve_id": "CVE-2021-44228",
  "vulnerability_name": "Apache Log4j Remote Code Execution (Log4Shell)",
  "scanner_consensus": {
    "scanner_sources": [
      "Trivy",
      "Snyk",
      "Qualys"
    ],
    "scanner_consensus_score": 0.95
  },
  "finding_confidence": {
    "finding_confidence_score": 0.98,
    "finding_confidence_classification": "CONFIRMED"
  },
  "threat_intelligence": {
    "cvss_score": 10.0,
    "epss_score": 0.975,
    "epss_percentile": 0.998,
    "kev_listed": true,
    "exploit_available": true
  },
  "asset_context": {
    "asset_id": "AST-PROD-PAY-001",
    "asset_name": "payment-auth-service",
    "environment": "PRODUCTION",
    "asset_criticality": "CRITICAL",
    "internet_exposure": true,
    "data_sensitivity": "RESTRICTED"
  },
  "risk_assessment": {
    "risk_score": 100.0,
    "risk_level": "CRITICAL",
    "score_breakdown": {
      "cvss": {
        "input": 10.0,
        "points": 25
      },
      "epss": {
        "input": 0.975,
        "points": 20
      },
      "kev": {
        "input": true,
        "points": 15
      },
      "exploit_available": {
        "input": true,
        "points": 10
      },
      "asset_criticality": {
        "input": "CRITICAL",
        "points": 10
      },
      "internet_exposure": {
        "input": true,
        "points": 10
      },
      "finding_confidence": {
        "input": 0.98,
        "points": 10
      }
    },
    "risk_drivers": [
      "HIGH_CVSS",
      "HIGH_EPSS",
      "KEV_LISTED",
      "EXPLOIT_AVAILABLE",
      "CRITICAL_ASSET",
      "INTERNET_EXPOSED",
      "HIGH_CONFIDENCE"
    ],
    "scoring_version": "1.0"
  },
  "metadata": {
    "engine_name": "M5_Risk_Engine",
    "engine_version": "1.0.0",
    "assessed_at": "2026-08-20T14:00:00Z",
    "status": "SUCCESS",
    "notes": "Evaluated by Module M5 Deterministic Rule-Based Scoring Engine."
  }
}
```

---

## 11. How Module M6 Should Use the Output
1. **Assign Remediation SLA**: Map `risk_level` directly to response SLAs.
2. **Prioritize Work Queues**: Sort actionable tickets descending by `risk_score`.
3. **Route Tickets to Asset Owners**: Direct tickets using `asset_context.asset_id` and `asset_context.environment`.
4. **Populate Remediation Context**: Embed `risk_drivers` and `score_breakdown` in ticket descriptions to show remediation engineers why the finding was prioritized.
5. **Track Audit Records**: Store `metadata.assessed_at` and `scoring_version` alongside tickets for compliance audit trails.

---

## 12. Critical Architecture Invariant: Do NOT Recalculate Risk Scores

> [!CAUTION]
> **Module M6 must NEVER recalculate, re-weight, or override `risk_score` or `risk_level`**.
>
> Module M5 is the **single source of truth** for risk assessment in the pipeline. Recalculating or mutating scores downstream breaks system auditability, violates Interface Contract v1.0, and creates inconsistent prioritization across security operations.
