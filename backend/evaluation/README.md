# RizIntel Phase 5 — Ground-Truth Evaluation Package

This package provides reproducible, quantitative ground-truth evaluation for the RizIntel Security Platform.

## Architecture & Principles
1. **Isolated Evaluation Scope**: All evaluation logic, datasets, and ground-truth labels reside strictly inside `backend/evaluation/`. Production runtime code (`services/`, `adapters/`, `routers/`) does not depend on `evaluation/`.
2. **Zero Production Code Mutation**: Production algorithms, thresholds, and scoring logic remain frozen. No tuning is performed against evaluation datasets.
3. **Dataset Categorization**: Datasets are categorized into:
   - `REAL`: WebGoat multi-scanner findings & Juice Shop multi-scanner findings
   - `SYNTHETIC EDGE-CASE`: Enterprise multi-scanner dataset with edge cases (missing CVEs, ambiguous names, cross-asset CVEs)
4. **Independent Ground Truth**: Ground-truth labels are created manually by a human security domain reviewer and recorded with metadata (`reviewer_count: 1`, `annotation_date: 2026-08-25`). Ground truth is NEVER derived from RizIntel predictions.

## Evaluation Execution
To run the full evaluation suite and generate reports:

```bash
cd backend
python -m evaluation.run_all_evaluations
```

Generated Output:
- `evaluation/reports/evaluation_results.json` (Machine-readable metrics)
- `PHASE5_EVALUATION_REPORT.md` (Human-readable markdown report)
