"""
LLM service, built behind a small provider abstraction so the app isn't
tightly coupled to one LLM vendor.

Usage: llm_service.generate(finding) -> LLMExplanationResult | None
Returns None (never raises) on any failure so the caller can cleanly fall
back to the rule-based path -- see explanation_service.py.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Optional

from pydantic import BaseModel, ValidationError

from app import config
from app.models.input_models import RiskAssessedFinding
from app.prompts.explanation_prompt import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger("m6.llm_service")


class LLMExplanationResult(BaseModel):
    technical: str
    management: str
    recommended_action: str


class LLMProvider(ABC):
    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Return raw text completion. Raise on failure."""
        raise NotImplementedError


class AnthropicProvider(LLMProvider):
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        import anthropic  # imported lazily so the app runs without the pkg if unused

        if not config.ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")

        client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        response = client.messages.create(
            model=config.ANTHROPIC_MODEL,
            max_tokens=config.LLM_MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            timeout=config.LLM_TIMEOUT_SECONDS,
        )
        text_blocks = [b.text for b in response.content if b.type == "text"]
        return "\n".join(text_blocks).strip()


def _strip_markdown_fence(raw: str) -> str:
    if raw.startswith("```"):
        raw = raw.strip("`")
        if "\n" in raw:
            first_line, rest = raw.split("\n", 1)
            if first_line.strip().lower() in ("json", ""):
                raw = rest
    return raw.strip()


class LLMService:
    def __init__(self, provider: Optional[LLMProvider] = None):
        self.provider = provider or AnthropicProvider()

    def generate(self, finding: RiskAssessedFinding) -> Optional[LLMExplanationResult]:
        if not config.ANTHROPIC_API_KEY:
            logger.info("No ANTHROPIC_API_KEY configured -- skipping LLM path.")
            return None

        try:
            user_prompt = build_user_prompt(finding)
            raw = self.provider.complete(SYSTEM_PROMPT, user_prompt)
            cleaned = _strip_markdown_fence(raw)
            parsed = json.loads(cleaned)
            return LLMExplanationResult(**parsed)
        except (json.JSONDecodeError, ValidationError) as exc:
            logger.warning("LLM returned malformed/unvalidatable output: %s", exc)
            return None
        except Exception as exc:  # noqa: BLE001 - any LLM failure -> fallback, never raise
            logger.warning("LLM call failed (%s) -- will use rule-based fallback.", exc)
            return None
