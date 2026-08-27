# Evidence Pack 04 — Deduplication & Cross-Scanner Correlation Proof

## M2 Deduplication Performance (Real Datasets)
- **Datasets**: `OWASP WebGoat` + `OWASP Juice Shop` ($N=14$ raw signals).
- **Labelled Duplicate Clusters**: 3 multi-scanner duplicate clusters.
- **Precision**: `1.0` (100%)
- **Recall**: `1.0` (100%)
- **F1-Score**: `1.0` (100%)
- **False Merge Rate**: `0.0` (0%)
- **Missed Duplicate Rate**: `0.0` (0%)

## Hard Boundary Enforcement
- **Cross-Asset CVE Isolation**: Same CVE on different assets (e.g. `webgoat.demo.corp` vs `juiceshop.demo.corp`) MUST NOT merge. Verified in `tests/test_m2_deduplication.py`.
- **Different Ports**: Port 80 vs Port 8080 MUST NOT merge. Verified in `tests/test_m2_deduplication.py`.
