# M3 — Confidence / Noise Module

Implements exactly PS4 Interface Contract v1.0, Sections 4→5. Nothing more.

**What this module does:** takes M2's `DeduplicatedFinding` output as-is,
computes a `finding_confidence` score + classification and a
`noise_assessment`, and passes everything else through unchanged for M4.

**What this module explicitly does NOT do:** deduplication (M2), threat
intel enrichment (M4), 0–100 risk scoring (M5), explanations/recommendations
(M6), SLA/ticketing (M7), or the dashboard (M8). No fields from those
modules' contracts appear here.

## Files

| File | Purpose |
|---|---|
| `schemas.py` | Pydantic transcription of Section 4 (input) and Section 5 (output). Not a new contract — a direct copy of the frozen schema, so M2's actual output plugs straight in with zero changes on their side. |
| `confidence_engine.py` | The scoring logic: 5 weighted signals → score → classification → noise assessment. |
| `main.py` | FastAPI service wrapping the engine (`POST /assess`, `POST /assess/batch`). |
| `data/labeled_dataset.py` | 34 hand-labeled `DeduplicatedFinding` examples for evaluation. |
| `evaluate.py` | Computes precision/recall/F1 per class + noise-suppression metrics against the labeled set. |
| `tests/test_m3.py` | The 3 required test cases (happy path, missing CVE, malformed/partial data) + 1 extra. |
| `sample_input.json` / `expected_output.json` | Per Section 13's rule that every module maintains these for integration testing. |

## Quick start

```
pip install -r requirements.txt
pytest tests/test_m3.py -v      # verify correctness
python3 evaluate.py             # see accuracy metrics
uvicorn main:app --reload --port 8003
```

Then `POST` a `DeduplicatedFinding` (see `sample_input.json`) to
`http://localhost:8003/assess`.

## Why 5 signals, not just scanner count

Per the team's explicit direction: M2 already computes `scanner_consensus.score`,
so using scanner count *again* as the primary confidence driver would be
circular — M3 needs to add information M2 doesn't already have. The five
signals:

1. **`scanner_consensus`** — passthrough of M2's own `scanner_consensus.score`. Still a real signal, just not the only one.
2. **`match_confidence`** — passthrough of M2's `deduplication.match_score`.
3. **`evidence_strength`** — independent check: what fraction of the merged sources actually carry real evidence text, vs. an empty/null field? A finding "confirmed" by 3 scanners with zero evidence text is weaker than one with rich per-scanner detail.
4. **`cross_scanner_consistency`** — independent check: do M2's own `match_features` agree with each other? `cve_match=1.0` but `endpoint_similarity=0.2` is an internally inconsistent merge, regardless of what `match_score` says.
5. **`data_completeness`** — how many of the fields downstream modules want are actually populated. Deliberately soft — a missing CVE alone should not crater this (see the missing-CVE test case).

Weights (`confidence_engine.py::WEIGHTS`) sum to 1.0 and are tunable.

## Evaluation methodology — an honest caveat

`data/labeled_dataset.py` has two parts:

- **28 "designed" examples**, written with the same reasoning as the
  classifier itself. Against these alone, the classifier scores 100% —
  which is **not meaningful**. When the same person writes both the labels
  and the logic, perfect agreement mostly proves self-consistency, not
  real-world accuracy.
- **6 "adversarial boundary" examples** (`B-001` through `B-006`),
  constructed specifically to surface disagreement — cases where a human's
  snap judgment plausibly diverges from where the formula's thresholds
  land (e.g. 4-scanner consensus but zero evidence text; single scanner
  but detailed evidence).

Against the full labeled set (34 examples), current metrics:

```
Overall accuracy:          0.912 (31/34)
Macro F1:                  0.916
Noise suppression recall:  0.875   (of true LIKELY_NOISE, 87.5% correctly flagged)
Critical miss rate:        0.000   (0% of real vulnerabilities wrongly marked noise)
```

**Critical miss rate is the number that matters most operationally** — it's
zero across every test run, meaning the classifier never threw away a
genuine finding as noise. The one noise-recall miss (`B-006`, a
well-corroborated but low-value "missing HSTS header" finding scored
HIGH_CONFIDENCE) illustrates a real, worth-knowing property: **confidence
and severity are different axes.** A boring finding can legitimately be
confidently-detected without being important — prioritization by severity
is M5's job, not M3's.

**Before trusting these numbers for anything beyond a hackathon demo**,
replace or supplement this dataset with findings labeled by someone who
did *not* write the classifier — ideally a security analyst reviewing
real M1/M2 output blind to how `confidence_engine.py` works. That's the
only way to get a genuinely independent accuracy measurement.

## Known limitations

- Weights in `WEIGHTS` are reasoned defaults, not fit to real labeled data.
- `evidence_strength` only checks whether the `evidence` string is
  non-empty, not its actual quality/specificity — a one-word evidence
  field scores the same as a detailed one. Worth improving if real data
  shows this matters.
- Classification thresholds (0.90 / 0.75 / 0.50) are the contract's own
  suggested defaults (Section 5), explicitly marked there as "initial
  engineering defaults... should later be validated on labeled data."
