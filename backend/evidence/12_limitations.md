# Evidence Pack 12 — Documented System Limitations

## Truthful Platform Limitations
1. **Evaluation Dataset Size**: Real-world evaluation corpus contains 14 raw signals across 2 target applications (WebGoat and Juice Shop). Classified as `MODERATE` evidence strength (`PARTIAL` Phase 5 verdict).
2. **Ground-Truth Annotator Count**: Annotations performed by a single project-team security reviewer (`reviewer_count: 1`). Inter-rater reliability (Cohen's Kappa) was not computed.
3. **Scanner Binary Availability**: Real binary execution is verified empirically for **Nuclei v3.3.8**. ZAP and Wapiti connectors are verified in code and payload parsing, but local binary execution requires external container setup.
4. **SQLite Prototype Persistence**: Prototype database uses SQLite with WAL mode. Production multi-node scaling requires PostgreSQL migration.
5. **SSE Database Polling**: Real-time event streaming polls SQLite events table in prototype configuration. Enterprise scaling requires Redis Pub/Sub.
