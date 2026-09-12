"""
app/ai — AegisIQ AI Copilot.

Adds an LLM layer on top of the SIEM's structured alerts:

  * Natural-language explanations of what an alert means and why
    (bilingual: Arabic + English).
  * Cross-alert triage: given N raw alerts, produce M narrative
    "investigation stories" (typically N is 10-100, M is 3-8).
  * Adversarial-plausibility scoring: how likely is this to be a real
    attack vs a false positive, with reasoning.
  * Suggested response playbook per alert (block IP, disable user,
    isolate endpoint, investigate further) with a confidence score.
  * Interactive chat: analyst can ask questions in natural language
    ("show me all logins from Russia in the last hour").

Multi-provider by design (`AI_PROVIDER` env var):
  * `openai`     — GPT-4o / GPT-4o-mini via api.openai.com
  * `anthropic`  — Claude 3.5 Sonnet / Haiku via api.anthropic.com
  * `ollama`     — local LLM (llama3.2, mistral, qwen) — FREE, offline
  * `disabled`   — feature turned off (default)

The provider abstraction (`providers.py`) makes swapping engines a
config change, not a code change.
"""
from app.ai.copilot import CopilotService  # noqa: F401
