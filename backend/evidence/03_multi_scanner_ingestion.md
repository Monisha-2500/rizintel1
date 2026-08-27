# Evidence Pack 03 — Multi-Scanner Ingestion Proof

## Scanner Formats Supported & Tested
1. **OWASP ZAP**: XML / JSON alert report parsing via `M1NormalizedFindingAdapter`.
2. **ProjectDiscovery Nuclei**: JSON / JSONL template output parsing via `M1NormalizedFindingAdapter`.
3. **Wapiti**: JSON vulnerability output parsing via `M1NormalizedFindingAdapter`.

## Automated Test Proof
- `tests/test_phase2_ingestion_pipeline.py`: Verifies native report ingestion and Schema v1.0 normalization across all 3 scanners.
- `mem2/data/sample_input.json`: Tested 15 multi-scanner findings across ZAP, Nuclei, and OpenVAS.
