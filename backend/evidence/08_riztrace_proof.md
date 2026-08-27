# Evidence Pack 08 — RizTrace Decision Provenance Proof

## 8-Stage Decision Lineage
RizTrace renders the complete decision lineage for any finding:
1. **Raw Signal**: Original scanner output and payload.
2. **M1 Normalization**: Normalized vulnerability schema.
3. **M2 Correlation**: Deduplication cluster and scanner consensus score.
4. **M3 Confidence**: 5-signal confidence classification and noise routing.
5. **M4 Threat Intel**: EPSS score, CISA KEV listing, and NVD exploit availability.
6. **M5 Risk Score**: Asset criticality weighting and score breakdown.
7. **M6 Explainability**: Technical root-cause drivers and management recommendations.
8. **M7 SLA & Ticketing**: Assigned SLA deadline, priority, and remediation status.

## Automated Test Proof
- `tests/test_riztrace_provenance_e2e.py`
- `frontend/src/pages/RizTracePage.jsx`
