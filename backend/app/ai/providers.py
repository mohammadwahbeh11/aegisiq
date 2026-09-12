"""
app/ai/providers.py -- multi-provider LLM abstraction.

One class per LLM backend, each implementing a minimal `chat()` method.
The service layer (copilot.py) targets this interface only, so a
customer can swap OpenAI for a self-hosted Ollama with zero code
changes -- just `AI_PROVIDER=ollama` in the environment.

All providers:
  * time out at AI_TIMEOUT_SECONDS (default 30 s)
  * return the assistant's message content as a plain string
  * raise `AIProviderError` with a compact message on failure -- the
    caller decides whether to fall back to a rules-only summary
  * NEVER let a provider outage take down the SIEM: the copilot
    endpoints treat all AIProviderError as "degraded" and return the
    structured evidence with a note that AI enrichment is unavailable.

No third-party SDKs required -- everything is stdlib http.client, so
the SIEM stays a single `pip install -r requirements.txt` away from
an air-gapped operator's laptop even with AI enabled.
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("aegisiq.ai")

DEFAULT_TIMEOUT = int(os.environ.get("AI_TIMEOUT_SECONDS", "30"))


class AIProviderError(RuntimeError):
    """Raised when the upstream LLM call fails or the config is wrong.

    Callers should catch this and degrade gracefully -- the SIEM stays
    usable even when the AI provider is down."""


@dataclass
class ChatMessage:
    role: str        # "system" | "user" | "assistant"
    content: str


# ----------------------------------------------------------------------
# Base HTTP helper (stdlib only, no requests/httpx dep for prod paths)
# ----------------------------------------------------------------------
def _http_post_json(url: str, body: dict, headers: dict[str, str],
                    timeout: int = DEFAULT_TIMEOUT) -> dict:
    data = json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json", **headers}
    req = urllib.request.Request(url, method="POST", headers=hdrs, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=ssl.create_default_context()) as resp:
            raw = resp.read().decode()
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        body_txt = ""
        try:
            body_txt = exc.read().decode()[:500]
        except Exception:  # noqa: BLE001
            pass
        raise AIProviderError(f"HTTP {exc.code} from {url}: {body_txt}") from exc
    except urllib.error.URLError as exc:
        raise AIProviderError(f"network error to {url}: {exc.reason}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise AIProviderError(f"bad JSON from {url}: {exc}") from exc


# ----------------------------------------------------------------------
# Provider: OpenAI (GPT-4o family)
# ----------------------------------------------------------------------
class OpenAIProvider:
    """OpenAI-compatible provider. Also works with Azure OpenAI, Groq,
    Together, and any other OpenAI-API-compatible endpoint by pointing
    AI_BASE_URL at their host."""

    def __init__(self, api_key: str, model: str,
                 base_url: str = "https://api.openai.com/v1"):
        if not api_key:
            raise AIProviderError("OpenAI: OPENAI_API_KEY not set")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    def chat(self, messages: list[ChatMessage],
             max_tokens: int = 800, temperature: float = 0.2,
             json_mode: bool = False) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        result = _http_post_json(
            f"{self.base_url}/chat/completions",
            body,
            {"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            return result["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise AIProviderError(f"OpenAI: unexpected response shape: {exc}") from exc


# ----------------------------------------------------------------------
# Provider: Anthropic (Claude family)
# ----------------------------------------------------------------------
class AnthropicProvider:
    """Anthropic Messages API (Claude 3.5 Sonnet, Haiku, etc.)."""

    def __init__(self, api_key: str, model: str,
                 base_url: str = "https://api.anthropic.com/v1"):
        if not api_key:
            raise AIProviderError("Anthropic: ANTHROPIC_API_KEY not set")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    def chat(self, messages: list[ChatMessage],
             max_tokens: int = 800, temperature: float = 0.2,
             json_mode: bool = False) -> str:
        # Anthropic separates the system prompt from the message list.
        system_text = "\n\n".join(m.content for m in messages if m.role == "system")
        convo = [{"role": m.role, "content": m.content}
                 for m in messages if m.role != "system"]
        body: dict[str, Any] = {
            "model": self.model,
            "system": system_text or "You are a helpful SOC assistant.",
            "messages": convo,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        result = _http_post_json(
            f"{self.base_url}/messages",
            body,
            {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        try:
            # Claude returns a list of content blocks; concatenate text ones.
            parts = [b.get("text", "") for b in result.get("content", [])
                     if b.get("type") == "text"]
            return "".join(parts)
        except (KeyError, TypeError) as exc:
            raise AIProviderError(f"Anthropic: unexpected response: {exc}") from exc


# ----------------------------------------------------------------------
# Provider: Ollama (LOCAL, FREE, offline)
# ----------------------------------------------------------------------
class OllamaProvider:
    """Local LLM via Ollama (https://ollama.com). Zero cost, offline,
    keeps SOC data on-premises -- the killer feature for regulated
    industries (finance, healthcare, defense) that can't ship alerts
    to a US cloud vendor."""

    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def chat(self, messages: list[ChatMessage],
             max_tokens: int = 800, temperature: float = 0.2,
             json_mode: bool = False) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if json_mode:
            body["format"] = "json"
        result = _http_post_json(f"{self.base_url}/api/chat", body, {})
        try:
            return result["message"]["content"]
        except KeyError as exc:
            raise AIProviderError(f"Ollama: unexpected response: {exc}") from exc


# ----------------------------------------------------------------------
# Factory
# ----------------------------------------------------------------------
def get_provider() -> "OpenAIProvider | AnthropicProvider | OllamaProvider | None":
    """Return the configured provider, or None if AI is disabled.

    Callers must treat None as "AI unavailable" and skip enrichment."""
    kind = os.environ.get("AI_PROVIDER", "disabled").strip().lower()
    if kind in ("", "disabled", "off", "none"):
        return None
    if kind == "openai":
        return OpenAIProvider(
            api_key=os.environ.get("OPENAI_API_KEY", ""),
            model=os.environ.get("AI_MODEL", "gpt-4o-mini"),
            base_url=os.environ.get("AI_BASE_URL", "https://api.openai.com/v1"),
        )
    if kind == "anthropic":
        return AnthropicProvider(
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            model=os.environ.get("AI_MODEL", "claude-3-5-haiku-latest"),
        )
    if kind == "ollama":
        return OllamaProvider(
            model=os.environ.get("AI_MODEL", "llama3.2"),
            base_url=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
        )
    raise AIProviderError(f"unknown AI_PROVIDER={kind!r} — "
                          f"pick openai, anthropic, ollama, or disabled")
