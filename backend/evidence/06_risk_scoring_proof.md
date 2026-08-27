# Evidence Pack 06 — Risk Scoring Sanity Proof

## M5 Risk Scoring Sovereignty
- **Mathematical Authority**: `RiskEngine` in `mem5/src/risk_engine.py` is the sole mathematical authority for `risk_score` and `risk_level`.
- **Deterministic Rule Ordering Verification**:
  - **Scenario A** (High Threat vs Low Threat): Passed (`90` vs `20`).
  - **Scenario B** (Prod vs Lab Asset): Passed (`75` vs `40`).
  - **Scenario C** (`UNMAPPED` Asset Zero Contribution): Passed (`asset_factors_score == 0`).
  - **Scenario D** (KEV Monotonicity): Passed (`85` vs `70`).

## Automated Test Proof
- `evaluation/evaluate_m5_sanity.py`
- `tests/test_deep_e2e_integration.py`
