# Module M5 — Rule-Based Risk Scoring Policy & Design Specification

## 1. Executive Summary & Scoring Philosophy

Module M5 (**Asset Context + Dynamic Risk Scoring Engine**) implements a **deterministic, explainable, rule-based additive scoring model** to prioritize security vulnerabilities discovered across an organization's software and infrastructure assets.

In modern vulnerability management, raw vulnerability scores (e.g., CVSS base scores) lack the contextual awareness needed to prioritize remediation effectively. Module M5 synthesizes:
1. **Technical Vulnerability Severity** (CVSS)
2. **Real-World Threat Intelligence** (EPSS, CISA KEV, Public Exploit Availability)
3. **Asset Business & Environmental Context** (Business Criticality, Internet Exposure)
4. **Validation & Detection Confidence** (Scanner Confidence)

The engine computes an explainable composite risk score bounded strictly between **0.0 and 100.0** and assigns a categorical risk priority tier (**CRITICAL**, **HIGH**, **MEDIUM**, **LOW**).

---

## 2. Why a Rule-Based Additive Model Was Selected

- **100% Explainability & Auditability**: Security analysts and auditors need to understand exactly why a finding was flagged as CRITICAL. Black-box machine learning models or non-transparent heuristics create ambiguity and reduce analyst trust.
- **Deterministic & Reproducible**: Given the same input findings and asset context, the engine guarantees identical scoring results without stochastic drift or random variations.
- **Configurability & Maintainability**: Point tables and thresholds are cleanly separated into declarative policy tables (`src/rules.py`), allowing security teams to adjust policy parameters without refactoring algorithmic code.
- **Zero Hallucination / Zero Speculation**: Only observed evidence is evaluated; missing attributes (such as unassigned CVEs) are handled without inventing artificial penalties or unverified data.

---

## 3. Score Weighting Architecture (Max 100 Points)

The maximum cumulative score is **100 points**, allocated across 7 orthogonal factors:

| Scoring Factor | Maximum Points | Percentage of Max Score | Category |
| :--- | :--- | :--- | :--- |
| **CVSS Score** | **25 points** | 25% | Technical Severity |
| **EPSS Score** | **20 points** | 20% | Threat Intelligence (Likelihood) |
| **CISA KEV Listing** | **15 points** | 15% | Threat Intelligence (Active Exploitation) |
| **Exploit Availability** | **10 points** | 10% | Threat Intelligence (Exploit Weaponization) |
| **Asset Criticality** | **10 points** | 10% | Asset Context (Business Impact) |
| **Internet Exposure** | **10 points** | 10% | Asset Context (Attack Surface) |
| **Finding Confidence** | **10 points** | 10% | Finding Validation & Trust Signal |
| **TOTAL MAXIMUM** | **100 points** | **100%** | |

---

## 4. Factor Justifications & Point Mappings

### 4.1 CVSS Technical Severity (Max 25 Points)
- **Rationale**: CVSS measures intrinsic technical characteristics (attack vector, complexity, privileges, scope, impact to confidentiality/integrity/availability). It provides the largest single technical-severity contribution (25 points).
- **Mapping**:
  - `0.0` – `3.9` → **5 points** (Low technical severity)
  - `4.0` – `6.9` → **12 points** (Medium technical severity)
  - `7.0` – `8.9` → **20 points** (High technical severity)
  - `9.0` – `10.0` → **25 points** (Critical technical severity)

### 4.2 EPSS Exploitation Likelihood (Max 20 Points)
- **Rationale**: The Exploit Prediction Scoring System (EPSS) models the probability that a vulnerability will be exploited in the wild within the next 30 days. It serves as a quantitative measure of imminent exploitation likelihood.
- **Mapping**:
  - `0.00` – `0.19` → **2 points** (Low likelihood)
  - `0.20` – `0.49` → **8 points** (Moderate likelihood)
  - `0.50` – `0.79` → **14 points** (High likelihood)
  - `0.80` – `1.00` → **20 points** (Imminent / Very high likelihood)

### 4.3 CISA KEV Catalog Listing (Max 15 Points)
- **Rationale**: Presence on the Cybersecurity and Infrastructure Security Agency (CISA) Known Exploited Vulnerabilities (KEV) catalog confirms active, observed weaponization and exploitation by threat actors in the wild.
- **Mapping**:
  - `true` → **15 points**
  - `false` → **0 points**

### 4.4 Public Exploit Availability (Max 10 Points)
- **Rationale**: Public availability of functional exploit code (e.g., in Metasploit, Exploit-DB, or GitHub PoCs) significantly lowers the barrier to entry for adversaries.
- **Mapping**:
  - `true` → **10 points**
  - `false` → **0 points**

### 4.5 Asset Criticality (Max 10 Points)
- **Rationale**: Business criticality contextualizes the potential blast radius. A vulnerability on a mission-critical payment processing system poses substantially greater enterprise risk than the same flaw on a non-critical dev sandbox.
- **Mapping**:
  - `LOW` → **2 points**
  - `MEDIUM` → **5 points**
  - `HIGH` → **8 points**
  - `CRITICAL` → **10 points**

### 4.6 Internet Exposure (Max 10 Points)
- **Rationale**: Directly internet-facing assets are accessible to arbitrary remote attackers without requiring internal network access or prior lateral movement.
- **Mapping**:
  - `true` → **10 points**
  - `false` → **0 points**

### 4.7 Finding Confidence (Max 10 Points)
- **Rationale**: Finding confidence reflects scanner accuracy and confirmation levels.
- **Important Design Principle**: Confidence is treated strictly as a **prioritization and verification trust signal**—ensuring high-certainty findings receive triage attention first. High confidence does **not** make the vulnerability technically more dangerous; rather, it increases operational trust in the finding.
- **Mapping**:
  - `0.00` – `0.49` → **2 points** (Low confidence / potential false positive)
  - `0.50` – `0.74` → **5 points** (Moderate confidence)
  - `0.75` – `0.89` → **8 points** (High confidence)
  - `0.90` – `1.00` → **10 points** (Confirmed / Very high confidence)

---

## 5. Explicit Avoidance of Double-Counting

To maintain statistical and methodological integrity, the following signals are **not** added as independent scoring contributions:

1. **Scanner Consensus Score (`scanner_consensus_score`)**:
   - *Design Decision*: Consensus across scanners is already factored into `finding_confidence_score` during upstream enrichment. Adding scanner consensus as an additional additive weight would double-count the same multi-scanner confirmation evidence.
   - *Treatment*: Retained in output as contextual/supporting audit metadata.

2. **EPSS Percentile (`epss_percentile`)**:
   - *Design Decision*: `epss_percentile` is a relative ranking derived directly from `epss_score`. Adding both `epss_score` and `epss_percentile` into the additive point formula would double-count the identical underlying threat probability distribution.
   - *Treatment*: Retained in threat intelligence metadata for analyst review.

---

## 6. Categorical Risk Classification

Calculated composite scores are categorized into 4 discrete risk tiers:

| Score Range | Risk Tier | Action Priority |
| :--- | :--- | :--- |
| **75.0 – 100.0** | **CRITICAL** | Immediate expedited mitigation required |
| **50.0 – 74.9** | **HIGH** | High-priority remediation within standard SLA |
| **25.0 – 49.9** | **MEDIUM** | Medium-priority remediation in scheduled cycle |
| **0.0 – 24.9** | **LOW** | Low-priority / backlog tracking |

---

## 7. Explainable Risk Drivers

The engine evaluates and emits canonical risk drivers when triggered:

| Driver Code | Trigger Condition | Rationale |
| :--- | :--- | :--- |
| `HIGH_CVSS` | `cvss_score >= 7.0` | Vulnerability has high/critical technical severity. |
| `HIGH_EPSS` | `epss_score >= 0.50` | Vulnerability has elevated exploitation probability (≥50%). |
| `KEV_LISTED` | `kev_listed == true` | Listed in CISA Known Exploited Vulnerabilities catalog. |
| `EXPLOIT_AVAILABLE` | `exploit_available == true` | Functional exploit code is publicly accessible. |
| `CRITICAL_ASSET` | `asset_criticality == "CRITICAL"` | Target asset is mission-critical infrastructure. |
| `INTERNET_EXPOSED` | `internet_exposure == true` | Target asset is directly exposed to the internet. |
| `HIGH_CONFIDENCE` | `finding_confidence_score >= 0.75` | Finding has high verification and detection confidence. |

---

## 8. Missing CVE Support (`cve_id: null`)

Findings without a formal CVE identifier (e.g., hardcoded secrets, misconfigurations, proprietary SAST findings) are fully supported. If all required contextual and threat metrics are present, the scoring engine calculates the risk score normally. The CVE identifier itself carries zero numeric score points.

---

## 9. Policy Configurability Disclaimer

> [!NOTE]
> The weights, tier boundaries, and classification thresholds defined herein represent specific, calibrated scoring-policy choices for this hackathon implementation. While grounded in industry best practices (CVSS v3.1, EPSS v3, CISA KEV, SSVC), they are configurable policy choices rather than universal immutable standards.
