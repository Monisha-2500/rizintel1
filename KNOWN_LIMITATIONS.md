# RizIntel — Documented Platform Limitations & Production Roadmap

This document provides a transparent, defensible account of RizIntel's current architectural and dataset limitations, along with recommended production scaling paths.

---

## 1. Ground-Truth Evaluation Dataset Scale (Phase 5)
- **Sample Size**: Ground-truth evaluation dataset evaluates 14 real scanner signals across OWASP WebGoat and OWASP Juice Shop (`DS-WEBGOAT-001` and `DS-JUICESHOP-001`).
- **Verdict**: Phase 5 verdict is intentionally classified as **`PARTIAL`** (`EVIDENCE STRENGTH = MODERATE`) to maintain scientific accuracy and avoid overstating accuracy.
- **Reviewer Count**: Annotations were created by a single project-team security reviewer (`reviewer_count: 1`). Inter-rater reliability (Cohen's Kappa) was not computed.

## 2. Scanner Binary Environment Verification (Phase 4)
- **Nuclei**: Real binary execution is empirically verified using ProjectDiscovery `nuclei.exe` v3.3.8 scanning local OWASP WebGoat on port 8085.
- **ZAP & Wapiti**: Connector adapters (`ZapConnector`, `WapitiConnector`) are fully implemented and verified against native report payloads. Real containerized binary execution for ZAP and Wapiti requires pre-installed local Docker environments.

## 3. Database Persistence Architecture
- **Prototype Setup**: Local deployment uses SQLite with Write-Ahead Logging (`WAL`) mode.
- **Production Scaling**: High-concurrency enterprise deployment requires migration to PostgreSQL with connection pooling.

## 4. Real-Time SSE Event Delivery
- **Prototype Setup**: Event streaming polls SQLite `scan_run_events` table per connection.
- **Production Scaling**: Multi-node horizontal scaling requires Redis Pub/Sub or Apache Kafka event broker.

## 5. Machine Learning & LLM Explanation Fallbacks
- **Implementation**: M6 explainability uses deterministic root-cause drivers and security rationales.
- **Production Scaling**: Integration with fine-tuned domain LLMs (e.g. Gemini 1.5 Pro) for dynamic remediation playbooks.
