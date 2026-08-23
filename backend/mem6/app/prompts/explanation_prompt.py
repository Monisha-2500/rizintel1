"""
Prompt construction for the LLM explanation path.

Grounding rule enforced here: we only put fields into the prompt that M5
actually supplied (None/missing fields are omitted rather than sent as
"null", so the LLM never sees a slot it might feel entitled to fill in).
The system prompt explicitly instructs the model to say information is
unavailable rather than guess, and to never state or imply a risk score
other than the one given.

top_risk_drivers and priority are NOT requested from the LLM -- those are
computed deterministically in risk_driver_service.py / utils/validation.py
so they can never diverge from M5's numbers. The LLM is only asked for the
prose: technical explanation, management explanation, and a recommended
remediation action.
"""

from __future__ import annotations

import json

from app.models.input_models import RiskAssessedFinding

SYSTEM_PROMPT = """You are M6, the Explainable AI Security Advisor in a vulnerability \
prioritization pipeline. Another module (M5) has already collected evidence and \
calculated a risk score. Your ONLY job is to explain that evidence in plain, \
accurate language for two audiences -- you do not calculate or influence the score.

STRICT GROUNDING RULES:
- You may only make claims supported by the evidence JSON you are given.
- Do not invent or guess at any CVE, CVSS value, EPSS value, KEV status, \
exploit availability, asset information, or scanner evidence.
- If a piece of information is missing from the evidence, say plainly that it \
is not available -- do not fill the gap with an assumption.
- Do not state or imply a risk score or risk level different from the one \
given in the evidence.
- For your recommended action, clearly distinguish between something the \
evidence directly supports (e.g. "patch the specific CVE") and general \
security best practice (e.g. "apply defense in depth") -- do not present a \
best practice as if the evidence specifically proved it necessary.

Respond with ONLY a single JSON object (no markdown fences, no commentary), \
matching exactly this shape:

{
  "technical": "string - security analyst view: why dangerous, why this score, evidence, potential impact, what to do",
  "management": "string - business view: why it matters, which asset, business impact, urgency, what to prioritize",
  "recommended_action": "string - a specific, evidence-grounded remediation recommendation"
}
"""


def _evidence_dict(finding: RiskAssessedFinding) -> dict:
    """Serialize only the fields M5 actually supplied (drop Nones)."""
    return json.loads(finding.model_dump_json(exclude_none=True))


def build_user_prompt(finding: RiskAssessedFinding) -> str:
    evidence = _evidence_dict(finding)
    return (
        "Here is the structured evidence from M5 (RiskAssessedFinding). "
        "Any field not present below was not supplied -- treat it as unavailable, "
        "do not guess its value:\n\n"
        f"{json.dumps(evidence, indent=2)}"
    )
