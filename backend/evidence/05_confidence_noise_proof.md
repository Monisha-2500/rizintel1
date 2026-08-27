# Evidence Pack 05 — Confidence & Noise Routing Proof

## M3 Confidence & Noise Classification
- **Binary Classification (Noise vs Not-Noise)**: Precision = `1.0`, Recall = `1.0`, F1 = `1.0`, Accuracy = `1.0`.
- **Three-Way Routing (ACTIONABLE / NEEDS_REVIEW / SUPPRESSED)**:
  - `ACTIONABLE`: 5 samples (High/Critical severity, high CVSS/KEV).
  - `NEEDS_REVIEW`: 6 samples (Medium/Low severity, ambiguous CWE).
  - `SUPPRESSED`: 3 samples (Missing security headers, server version disclosure).
- **False Suppression Rate**: `0.0` (0% false suppression of valid vulnerabilities).

## Automated Test Proof
- `tests/test_m3_noise_routing.py`
- `evaluation/evaluate_m3.py`
