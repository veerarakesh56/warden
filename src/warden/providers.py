"""Model providers.

WARDEN is not tied to one vendor. That is a design position, not a cost saving:

- **A safety layer that only works against one model is not a safety layer.** The verifier, the
  redaction and the policy gate are provider-independent by construction, and the way to prove that
  is to run the same graph against different models.
- **Free tiers make the live path testable.** Every test in this repo runs in mock mode; without a
  free provider the real call path — retries, JSON extraction, token accounting — would never
  execute outside someone's paid account.
- **Local models are a real requirement.** Incident logs are the most sensitive data an
  organisation has. Plenty of teams cannot send them to any third party, and Ollama support means
  the answer is "run it locally", not "you cannot use this".

Select with `WARDEN_PROVIDER`:

    mock      (default in tests)  no network, deterministic
    anthropic ANTHROPIC_API_KEY
    gemini    GEMINI_API_KEY      free tier at aistudio.google.com
    openai    OPENAI_API_KEY      also Groq / OpenRouter / Ollama via WARDEN_BASE_URL

Every provider returns the same tuple: (text, input_tokens, output_tokens). Token counts are used
for the budget ceiling, so a provider that cannot report them must estimate rather than return zero
— a budget fed zeros never fires.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Protocol


class ProviderError(RuntimeError):
    """The provider could not be reached or refused the request."""


class _SuppressAFCNotice(logging.Filter):
    """Drop google-genai's 'automatic function calling' chatter, and nothing else.

    google-genai logs 'AFC is enabled ...' and 'Direct use of automatic function calling (AFC) in
    Models.generate_content is not recommended ...' on EVERY generate_content call. WARDEN passes no
    tools, so AFC is irrelevant here - it is pure noise on every live call. This filters only those
    two records by message content, so any real error from the same logger still gets through.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage().lower()
        return "automatic function calling" not in msg and "afc is enabled" not in msg


_afc_filter_installed = False


def _quiet_gemini_afc_notice() -> None:
    """Install the AFC filter once. Idempotent so repeated GeminiProvider construction cannot stack it."""
    global _afc_filter_installed
    if not _afc_filter_installed:
        logging.getLogger("google_genai.models").addFilter(_SuppressAFCNotice())
        _afc_filter_installed = True


@dataclass(frozen=True)
class Completion:
    text: str
    input_tokens: int
    output_tokens: int


class Provider(Protocol):
    name: str
    model: str

    def complete(self, *, system: str, user: str) -> Completion: ...


def _estimate_tokens(text: str) -> int:
    """Rough fallback when a provider does not report usage.

    ⚠ Deliberately an over-estimate (3 chars/token rather than 4). A budget that under-counts is
    worse than one that is slightly pessimistic — it fails to stop the thing it exists to stop.
    """
    return max(1, len(text) // 3)


def _sdk_timeout_s() -> float:
    """Seconds a single provider request may take before its own socket times out.

    Read from the SAME env var as llm.LLM_CALL_TIMEOUT_S (read directly here to avoid a
    providers<-llm import cycle). This is the bound that actually MATTERS: it makes the SDK's own
    socket give up, so the worker thread ends and the process can exit. Without it, a hung request
    (a just-rotated key made the client retry endlessly) blocks the run past every higher-level
    deadline, because a thread stuck in a blocking C call cannot be force-killed. Each provider is
    also told NOT to retry internally — WARDEN has its own retry loop, and stacking them multiplies
    the wall-clock a slow endpoint costs.
    """
    return float(os.environ.get("WARDEN_LLM_TIMEOUT", "45.0"))


# --------------------------------------------------------------------------- anthropic


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None) -> None:
        from anthropic import Anthropic

        self.model = model or os.environ.get("WARDEN_MODEL", "claude-sonnet-5")
        self._client = Anthropic(timeout=_sdk_timeout_s(), max_retries=0)

    def complete(self, *, system: str, user: str) -> Completion:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=1500,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        return Completion(text, resp.usage.input_tokens, resp.usage.output_tokens)


# --------------------------------------------------------------------------- gemini


class GeminiProvider:
    """Google AI Studio. Has a genuine free tier, which is why it is the default live provider."""

    name = "gemini"

    def __init__(self, model: str | None = None) -> None:
        from google import genai
        from google.genai import types

        _quiet_gemini_afc_notice()
        # ⚠ Model names expire. `gemini-2.0-flash` was the default here and the API answered
        # "no longer available ... use models/gemini-3.6-flash". A hardcoded model id is a dated
        # assumption, which is why WARDEN_MODEL overrides it without touching code.
        self.model = model or os.environ.get("WARDEN_MODEL", "gemini-3.6-flash")
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise ProviderError("GEMINI_API_KEY is not set. Get a free key at aistudio.google.com.")
        # timeout is in MILLISECONDS here; attempts=1 means no internal retry (see _sdk_timeout_s).
        self._client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(
                timeout=int(_sdk_timeout_s() * 1000),
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )

    def complete(self, *, system: str, user: str) -> Completion:
        from google.genai import types

        resp = self._client.models.generate_content(
            model=self.model,
            contents=user,
            config=types.GenerateContentConfig(
                system_instruction=system,
                response_mime_type="application/json",
            ),
        )
        text = resp.text or ""
        usage = getattr(resp, "usage_metadata", None)
        if usage is not None:
            return Completion(
                text,
                getattr(usage, "prompt_token_count", 0) or _estimate_tokens(system + user),
                getattr(usage, "candidates_token_count", 0) or _estimate_tokens(text),
            )
        return Completion(text, _estimate_tokens(system + user), _estimate_tokens(text))


# --------------------------------------------------------------------------- openai-compatible


class OpenAICompatProvider:
    """One class for every OpenAI-shaped API.

    Covers OpenAI, Groq, OpenRouter, Together and a local Ollama server — they all speak the same
    wire format, so supporting four vendors costs one `base_url`.
    """

    name = "openai"

    def __init__(self, model: str | None = None, base_url: str | None = None) -> None:
        from openai import OpenAI

        self.model = model or os.environ.get("WARDEN_MODEL", "gpt-4o-mini")
        # Passed in by resolve() for the aliases; falls back to the env for an explicit custom host.
        base_url = base_url or os.environ.get("WARDEN_BASE_URL")  # e.g. http://localhost:11434/v1
        # Ollama ignores the key but the client requires one to be present.
        api_key = os.environ.get("OPENAI_API_KEY") or ("ollama" if base_url else None)
        if not api_key:
            raise ProviderError("OPENAI_API_KEY is not set (or set WARDEN_BASE_URL for a local model).")
        kw = {"api_key": api_key, "timeout": _sdk_timeout_s(), "max_retries": 0}
        if base_url:
            kw["base_url"] = base_url
        self._client = OpenAI(**kw)

    def complete(self, *, system: str, user: str) -> Completion:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            response_format={"type": "json_object"},
        )
        text = resp.choices[0].message.content or ""
        usage = getattr(resp, "usage", None)
        if usage is not None:
            return Completion(text, usage.prompt_tokens, usage.completion_tokens)
        return Completion(text, _estimate_tokens(system + user), _estimate_tokens(text))


# --------------------------------------------------------------------------- resolution

_REGISTRY = {
    "anthropic": AnthropicProvider,
    "gemini": GeminiProvider,
    "openai": OpenAICompatProvider,
    "groq": OpenAICompatProvider,
    "openrouter": OpenAICompatProvider,
    "ollama": OpenAICompatProvider,
}

DEFAULT_BASE_URLS = {
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "ollama": "http://localhost:11434/v1",
}


def resolve(name: str | None = None) -> Provider:
    """Build the configured provider. Raises a readable error rather than failing at call time."""
    name = (name or os.environ.get("WARDEN_PROVIDER") or "anthropic").lower()
    if name not in _REGISTRY:
        raise ProviderError(f"unknown provider '{name}'. Known: {', '.join(sorted(_REGISTRY))}")
    # Point the OpenAI-compatible client at the right host by PASSING it, never by mutating the
    # process env. Writing WARDEN_BASE_URL used to persist: a later resolve('ollama') then reused a
    # prior resolve('groq') endpoint, so a "local" Ollama client silently pointed at a cloud API —
    # breaking the local-only guarantee and mutating the library caller's global env. An explicit
    # WARDEN_BASE_URL still wins (custom self-hosted host).
    if name in DEFAULT_BASE_URLS:
        return OpenAICompatProvider(base_url=os.environ.get("WARDEN_BASE_URL") or DEFAULT_BASE_URLS[name])
    return _REGISTRY[name]()
