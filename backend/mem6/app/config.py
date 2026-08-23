import os

from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# NOTE: check https://docs.claude.com for the current recommended model
# string at build/demo time -- model names change over time.
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")

LLM_TIMEOUT_SECONDS = float(os.getenv("M6_LLM_TIMEOUT_SECONDS", "20"))
LLM_MAX_TOKENS = int(os.getenv("M6_LLM_MAX_TOKENS", "1200"))

APP_VERSION = "1.0.0"
CONTRACT_VERSION = "PS4-v1.0"
