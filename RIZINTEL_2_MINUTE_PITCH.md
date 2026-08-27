# RizIntel — 2-Minute Spoken Evaluator Pitch

This script provides a natural, conversational 2-minute pitch for presenting RizIntel to hackathon evaluators.

---

## 2-Minute Spoken Script

*"Good morning, evaluators. Modern AppSec teams face a critical challenge: multi-scanner alert fatigue. When security teams run OWASP ZAP, Nuclei, and Wapiti across their infrastructure, they get flooded with duplicate alerts, non-actionable scanner noise, and unprioritized CVSS scores. Analysts waste up to 70% of their time manually cross-referencing findings across separate tools.*

*That is why we built **RizIntel**—an AI-assisted Security Decision Intelligence Platform.*

*Instead of just piling scanner alerts into another static table, RizIntel automates the end-to-end intelligence lifecycle through our M1 to M7 pipeline:*
- *First, M1 normalizes disparate scanner outputs into a unified Schema v1.0 format.*
- *M2 correlates cross-scanner duplicates on the same asset while strictly preventing cross-host over-merging.*
- *M3 filters out scanner noise and missing-header clutter without suppressing real threats.*
- *M4 enriches findings with real-time threat intelligence from EPSS and CISA KEV.*
- *M5 calculates context-aware risk scores based on asset business criticality and data sensitivity.*
- *M6 provides explainable AI rationales for both engineers and management.*
- *And M7 assigns mandatory SLA remediation deadlines.*

*Our core novelty is **RizTrace**—an interactive 8-stage decision provenance graph. Analysts don't have to trust a black-box score. With RizTrace, they can visually trace any vulnerability from its raw scanner signal all the way to its final risk score and SLA deadline.*

*RizIntel is not a mockup. Our active machine scanner agent executed a real ProjectDiscovery Nuclei binary against an authorized local target with zero manual report upload. On our Phase 5 ground-truth evaluation set across WebGoat and Juice Shop, RizIntel achieved 100% precision and zero false suppressions.*

*RizIntel transforms multi-scanner alert noise into clear, auditable, and actionable security decisions. Thank you."*
