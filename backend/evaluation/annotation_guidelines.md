# RizIntel Ground-Truth Annotation Guidelines

## Overview
This document defines the formal rules used by human domain annotators to create independent ground-truth labels for evaluating RizIntel's correlation (M2), noise routing (M3), and risk prioritization engines.

---

## 1. Reviewer Metadata & Truthfulness
- **Annotation Date**: 2026-08-25
- **Reviewer Count**: 1 (Single Project-Team Reviewer)
- **Reviewer Identity**: Single project-team security engineer
- **Human Review Truthfulness Statement**: Ground-truth annotations were performed independently by a single project-team reviewer based on manual security domain inspection of scanner evidence, NOT derived from RizIntel predictions. Multi-annotator inter-rater reliability (e.g. Cohen's Kappa) was not computed due to team size constraints; this limitation is explicitly reported.

---

## 2. M2 Deduplication Annotation Rules

Findings are compared pairwise and clustered based on security remediation scope:

### `SAME_REMEDIATION_INSTANCE` (Duplicate Pair / Cluster)
Two or more findings MUST be merged into a single canonical finding ONLY IF:
1. They represent the exact same underlying vulnerability on the **SAME ASSET**.
2. Fixing the issue once in code or configuration resolves all associated scanner reports.
3. Criteria:
   - Same CVE on the same host & endpoint (e.g. `CVE-2026-9999` on `webgoat.demo.corp:8080/WebGoat/search`).
   - Different scanners (e.g. ZAP, Nuclei, Wapiti) observing the exact same issue on the same asset and path.
   - Same endpoint vulnerability with identical root cause even if parameter naming varies slightly across scanners.

### `DIFFERENT_REMEDIATION_INSTANCE` (Distinct Pair / Cluster)
Findings MUST NOT be merged (must remain separate canonical findings) IF:
1. **Different Assets**: Findings on different hosts/assets (e.g. `webgoat.demo.corp` vs `juiceshop.demo.corp`), even if they share the same CVE.
2. **Different Ports**: Findings on different ports on the same host (e.g. port 80 vs port 8080), representing distinct service instances.
3. **Different Endpoints**: Findings on distinct API endpoints or paths (e.g. `/WebGoat/search` vs `/WebGoat/admin/exec`), requiring separate code fixes.
4. **Different Parameters**: Distinct parameters on the same endpoint representing independent vulnerability injection points.
5. **Different Vulnerabilities**: Distinct CVE/CWE classifications on the same asset.

---

## 3. M3 Confidence & Noise Classification Rules

Each finding is assigned an independent ground-truth label based strictly on scanner evidence and vulnerability severity:

### `ACTIONABLE`
- Critical or High severity vulnerability on an active asset with confirmed exploitability or high CVSS/KEV indicators (e.g. SQL Injection, RCE, Authentication Bypass, IDOR).
- Requires immediate remediation or ticket creation.

### `NEEDS_REVIEW`
- Medium or Low severity finding, ambiguous vulnerability description, missing CVE with CWE only, or single-scanner observation requiring analyst verification before ticket creation (e.g. Reflected XSS, Path Traversal, CSRF, Sensitive Data Exposure).

### `SUPPRESSED` / `LIKELY_NOISE`
- Informational / zero-risk finding, deprecated header warning, or known false positive indicator (e.g. `Server header disclosure`, `X-Frame-Options missing`, `HTTP info disclosure`).

---

## 4. Prioritization Ranking Rules

Findings are manually ordered by security priority based on:
1. CISA KEV listing & exploit availability (highest priority).
2. Asset criticality (CRITICAL > HIGH > MEDIUM > LOW).
3. Internet exposure (Internet-facing > Internal).
4. Vulnerability severity & CVSS score.
