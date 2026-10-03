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

    mock       (default in tests)  no network, deterministic
    anthropic  ANTHROPIC_API_KEY
    claude_cli the local `claude` CLI in headless mode - a subscription instead of API credit.
               ⚠ Every tool disabled and run outside the repo, or it could read the benchmark's
               own fixtures. Results are not reproducible by a reader; see the class docstring.
    gemini     GEMINI_API_KEY      free tier at aistudio.google.com. ⚠ 20 requests/DAY per model on
               the free tier, which is four WARDEN runs. A benchmark wave needs far more.
    bedrock    IAM (no key)        Amazon Bedrock Converse, WARDEN_BEDROCK_MODEL = an inference-profile id;
                                   the production path (D12), refused until qualified (M20)
    openai     OPENAI_API_KEY      also Groq (GROQ_API_KEY) / OpenRouter (OPENROUTER_API_KEY) / Ollama
                                   (no key) / any WARDEN_BASE_URL (WARDEN_API_KEY)

Every provider returns the same tuple: (text, input_tokens, output_tokens). Token counts are used
for the budget ceiling, so a provider that cannot report them must estimate rather than return zero
— a budget fed zeros never fires.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

# The claude CLI's own words for an API error status and for a connection that never opened.
_CLI_API_ERROR = re.compile(r"API Error:\s*(\d{3})\b")
_CLI_UNSENT = re.compile(r"(?i)ECONNREFUSED|ENOTFOUND|EAI_AGAIN|getaddrinfo|Connection error|Unable to connect")


class ProviderError(RuntimeError):
    """The provider could not be reached or refused the request."""


class ProviderExhausted(ProviderError):
    """The provider has no capacity left for this account - a usage limit or a daily quota.

    ⛔ Distinct from ProviderError because the right response is different. A transient error is
    worth retrying; an exhausted pool is not, and retrying it only spends calls that do not exist.
    More importantly, every LATER call will fail the same way, so a benchmark wave that meets this
    should stop and resume after the reset - not carry on injecting real faults into an account and
    recording an ERROR for each one, which is what it did before this existed.
    """


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

    # `schema` is the pydantic model the caller needs back, passed so a provider whose API can
    # ENFORCE a response shape does so. Optional, and ignored by providers that cannot: the prompt
    # already describes the schema, and that is the fallback.
    #
    # ⛔ It is not decoration. Told only "return JSON", Gemini intermittently returned the SCHEMA it
    # had been shown - {"description": "...", "properties": {...}} - instead of an instance of it.
    # Three retries, three schemas, ModelRefused, and a scenario recorded as ERROR. Found by a real
    # benchmark run, not by a test.
    def complete(self, *, system: str, user: str, schema: Any = None) -> Completion: ...


def _estimate_tokens(text: str) -> int:
    """Rough fallback when a provider does not report usage.

    ⚠ Deliberately an over-estimate (3 chars/token rather than 4). A budget that under-counts is
    worse than one that is slightly pessimistic — it fails to stop the thing it exists to stop.
    """
    return max(1, len(text) // 3)


# Register M15: an alias - `sonnet`, `opus`, `*-latest`, ollama's `:latest` - moves when the vendor ships a new model,
# so the same WARDEN, unchanged, diagnosed with a different model from one day to the next. Only an exact id is
# accepted. Verified 2026-10-02 on the Claude models page: every Claude API id is a pinned snapshot, the dateless
# ones from the 4.6 generation on included; the CLI's `sonnet` resolved to claude-sonnet-5-5 that day - a model that
# then failed WARDEN's replay qualification (register M20), which is the drift this refuses.
_FLOATING = re.compile(r"(?i)^(?:sonnet|opus|haiku|fable|default|best|opusplan)(?:\[1m\])?$|[-:]latest$")


def pinned(model: str) -> str:
    """The model id, if it names one model; an alias that can move is refused."""
    if not model or _FLOATING.search(model.strip()):
        raise ProviderError(f"model {model!r} is an alias that moves to new models; name an exact model id "
                            "(register M15)")
    return model


def _sdk_version(package: str) -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return f"{package} {version(package)}"
    except PackageNotFoundError:
        return f"{package} unknown"


def _sdk_timeout_s() -> float:
    """Seconds a single provider request may take before its own socket times out.

    Read from the SAME env var as the LLMClient's per-call ceiling (`call_timeout_s`). This is the bound that actually MATTERS: it makes the SDK's own
    socket give up, so the worker thread ends and the process can exit. Without it, a hung request
    (a just-rotated key made the client retry endlessly) blocks the run past every higher-level
    deadline, because a thread stuck in a blocking C call cannot be force-killed. Each provider is
    also told NOT to retry internally — WARDEN has its own retry loop, and stacking them multiplies
    the wall-clock a slow endpoint costs.
    """
    return float(os.environ.get("WARDEN_LLM_TIMEOUT", "45.0"))


def call_timeout_s(provider: Any = None) -> float:
    """The per-call ceiling for `provider`: WARDEN_LLM_TIMEOUT when set, else the provider's own
    default (`default_timeout_s`), else 45 s. One place, so the provider's inner bound and the
    LLMClient's outer backstop can never disagree."""
    env = os.environ.get("WARDEN_LLM_TIMEOUT")
    if env:
        return float(env)
    return float(getattr(provider, "default_timeout_s", 45.0))


# --------------------------------------------------------------------------- anthropic


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None) -> None:
        from anthropic import Anthropic

        self.model = pinned(model or os.environ.get("WARDEN_MODEL", "claude-sonnet-5"))
        self.version = _sdk_version("anthropic")
        # Explicit base URL: the SDK would otherwise honour ANTHROPIC_BASE_URL and send the key there.
        self._client = Anthropic(base_url=ANTHROPIC_BASE_URL, timeout=_sdk_timeout_s(), max_retries=0)

    def complete(self, *, system: str, user: str, schema: Any = None) -> Completion:
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
        self.model = pinned(model or os.environ.get("WARDEN_MODEL", "gemini-3.6-flash"))
        self.version = _sdk_version("google-genai")
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise ProviderError("GEMINI_API_KEY is not set. Get a free key at aistudio.google.com.")
        # timeout is in MILLISECONDS here; attempts=1 means no internal retry (see _sdk_timeout_s).
        from google.genai.client import DebugConfig

        self._client = genai.Client(
            api_key=api_key,
            # ALWAYS explicit: the SDK otherwise reads GOOGLE_GENAI_CLIENT_MODE, where `replay` answers
            # from files on disk and `record` writes every prompt to disk (third review, 2026-09-30).
            debug_config=DebugConfig(client_mode=None, replays_directory=None, replay_id=None),
            http_options=types.HttpOptions(
                # ALWAYS explicit: the SDK otherwise reads GOOGLE_GEMINI_BASE_URL itself, and the key
                # went to whatever host that named, plain http included (second review, 2026-09-30).
                base_url=GEMINI_BASE_URL,
                timeout=int(_sdk_timeout_s() * 1000),
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )

    def complete(self, *, system: str, user: str, schema: Any = None) -> Completion:
        from google.genai import types

        # ⭐ response_schema makes Google enforce the shape server-side. Without it, `response_mime_type`
        # alone says "some JSON" - and this model intermittently answered with the JSON SCHEMA from the
        # prompt rather than an instance of it, which no amount of retrying fixes.
        config: dict[str, Any] = {
            "system_instruction": system,
            "response_mime_type": "application/json",
        }
        if schema is not None:
            config["response_schema"] = schema
        resp = self._client.models.generate_content(
            model=self.model,
            contents=user,
            config=types.GenerateContentConfig(**config),
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

        self.model = pinned(model or os.environ.get("WARDEN_MODEL", "gpt-4o-mini"))
        self.version = _sdk_version("openai")
        # Passed in by resolve() for the aliases; falls back to the env for an explicit custom host.
        # ALWAYS an explicit base URL: without one the SDK reads OPENAI_BASE_URL on its own, and the
        # OpenAI key then went to whatever host that named (independent review 2026-09-28).
        base_url = base_url or os.environ.get("WARDEN_BASE_URL") or OPENAI_DEFAULT_BASE_URL
        key_env = key_env_for(base_url)
        if key_env and not base_url.lower().startswith("https://"):
            raise ProviderError(f"refusing to send {key_env} over plain http to {base_url!r}")
        # A local model ignores the key, but the client requires one to be present.
        api_key = os.environ.get(key_env) if key_env else "local-no-key"
        if not api_key:
            raise ProviderError(f"{key_env} is not set (or set WARDEN_BASE_URL for a local model).")
        # The SDK reads OPENAI_CUSTOM_HEADERS itself and sends those headers - Authorization included -
        # to whatever host it talks to (third review, 2026-09-30). They are meant for OpenAI only.
        if os.environ.get("OPENAI_CUSTOM_HEADERS") is not None and base_url.rstrip("/") != OPENAI_DEFAULT_BASE_URL:
            raise ProviderError("OPENAI_CUSTOM_HEADERS is set; the SDK would send those headers to "
                                f"{urlparse(base_url).hostname}. Unset it for any host but OpenAI.")
        kw = {"api_key": api_key, "timeout": _sdk_timeout_s(), "max_retries": 0}
        kw["base_url"] = base_url
        self._client = OpenAI(**kw)
        if base_url.rstrip("/") != OPENAI_DEFAULT_BASE_URL:
            # The SDK reads OPENAI_ORG_ID / OPENAI_PROJECT_ID itself and sends them as headers; they
            # identify the OpenAI account and go to OpenAI only (second review, 2026-09-30).
            self._client.organization = self._client.project = None

    def complete(self, *, system: str, user: str, schema: Any = None) -> Completion:
        # `schema` is accepted and not used. `json_object` mode is the only shape control every
        # OpenAI-compatible host here supports — Groq, OpenRouter and Ollama do not all implement
        # `json_schema`, and one that silently ignores it is worse than not sending it. The schema
        # is in the prompt, and llm.structured validates what comes back either way.
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


# --------------------------------------------------------------------------- claude cli

# ⚠ Matched broadly, and not verified against the exact wording: the only time the limit was hit,
# the message was discarded (see complete()). These are the phrasings the CLI and the API use for
# an exhausted account. A miss here degrades to a plain ProviderError - still an error, still
# recorded - rather than to a false success.
_USAGE_LIMIT = re.compile(
    # ⛔ "session limit" was MISSING, and it is the wording the CLI actually uses. The live wave hit
    # it verbatim - "You've hit your session limit · resets 7:40pm (Asia/Kolkata)" - and because
    # only "usage limit" / "limit reached" were matched, it was classified as an ordinary error:
    # retried three times per call against an empty pool, and the wave did not stop. The message was
    # only readable at all because complete() reports stdout as well as stderr.
    r"usage limit|session limit|hit your \w+ limit|limit reached|rate limit|quota"
    r"|credit balance is too low|out of credits",
    re.IGNORECASE,
)


class ClaudeCliProvider:
    """Inference through the locally installed `claude` CLI in headless (`-p`) mode.

    For someone who has a Claude subscription and no API credit. The CLI is driven as a plain
    text-in / text-out process, so WARDEN's graph, verifier and budget behave exactly as with any
    other provider.

    ⛔ EVERY TOOL IS DISABLED, AND THAT IS THE LOAD-BEARING PART. A headless Claude launched inside
    this repository can read files, and this repository also contains the fault-injection benchmark's
    own fixtures and grading rules. A diagnosing model that can grep for those is not being measured,
    it is looking the answer up. So tools are refused explicitly AND the process runs from a scratch
    directory outside the repository — two independent reasons it cannot reach them, because one
    would be an assumption.

    ⚠ WHAT THIS COSTS THE BENCHMARK, STATED PLAINLY:

    - **Reproducibility.** A reader cannot re-run a result produced this way without the same
      subscription and CLI version. An API call pins a model id; `claude -p` pins considerably less.
      Results from this provider should be labelled as such and never mixed into a table with
      API-sourced runs as though they were the same instrument.
    - **Cost accounting is notional.** Tokens are ESTIMATED (the CLI reports none) and the USD figure
      is computed from `WARDEN_PRICE_*` like any other provider — but nothing is metered per call. The
      real limit is the subscription's own, which WARDEN cannot see and the budget ceiling cannot
      protect you from.
    - **Check your plan's terms** before using a subscription as a batch inference backend for
      dozens of runs. That is a question about your agreement, not about this code.

    ⛔ IT IS FAR HEAVIER THAN AN API CALL, AND THIS IS MEASURED, NOT ESTIMATED. Each call boots a
    whole Claude Code process, not an HTTP request. Running a 14-scenario benchmark wave through it
    (2 calls per run, 3 runs per scenario = 84 process launches) was measured at ~700 MB resident and
    several CPU-seconds per call, took roughly 20 minutes per scenario against 2 minutes for the same
    wave on an HTTP provider, and made the machine visibly sluggish for its owner.

    ⭐ So: fine for a handful of calls, wrong for a batch. For a wave, use a free HTTP tier
    (`gemini`, or `groq` via WARDEN_PROVIDER=groq) and keep this for the case it was built for -
    having no API credit and needing a few real inferences.
    """

    name = "claude_cli"
    # ⛔ Measured, not guessed (Wave 4, 2026-09-26): a real full-stack diagnosis (analyse + propose +
    # verify, ~12k input tokens each) took 69 s end to end, and at the shared 45 s ceiling every
    # attempt of one call timed out - the first measured run got no report at all. A `claude -p`
    # call is a whole process plus the full answer, not a socket read. 180 s is ~3x the need.
    default_timeout_s = 180.0

    def __init__(self, model: str | None = None) -> None:
        import shutil

        # The model that passed WARDEN's replay set (data/providers.yaml, register M20). Not claude-sonnet-5-5: the
        # newer model scored 16 of 30 where this one scored 19 (2026-10-02).
        self.model = pinned(model or os.environ.get("WARDEN_MODEL", "claude-sonnet-5"))
        self._version = ""
        self._exe = shutil.which("claude")
        if not self._exe:
            raise ProviderError(
                "WARDEN_PROVIDER=claude_cli needs the `claude` CLI on PATH. Install Claude Code, or "
                "use an API-backed provider instead."
            )

    # Named rather than a wildcard: a tool added to the CLI in a later version must not silently
    # become available to a model that is supposed to have none.
    _NO_TOOLS = (
        "Read", "Write", "Edit", "NotebookEdit", "Bash", "Glob", "Grep",
        "WebFetch", "WebSearch", "Task", "Agent", "TodoWrite",
    )

    # ⛔ Variables that REDIRECT the CLI to other configuration: CLAUDE_CONFIG_DIR and
    # XDG_CONFIG_HOME are never passed. What keeps the operator's CLAUDE.md, hooks, skills and modes
    # out of the model is the flags in complete() - no setting sources, no tools, no MCP servers -
    # not the environment: the CLI finds the home directory without HOME/USERPROFILE (Node falls back
    # to the OS profile), which is why stripping them "did not hide it" (found 2026-09-26).
    #
    # History (A-C-19, decided 2026-09-30 on evidence; owner: "whichever is best"). HOME/USERPROFILE
    # were stripped after a 2026-09 measurement: with USERPROFILE set a run loaded the operator's
    # configuration (26 s and a refusal vs 11 s and clean JSON). That measurement predates the
    # isolation flags. Re-measured 2026-09-30 through this provider, same prompt, both ways: no
    # instructions loaded either way, 6.8 s vs 7.1 s. Stripping them now isolates nothing and can
    # break the CLI where the home directory is not otherwise resolvable (a minimal container whose
    # user has no passwd entry), so they pass. tests/test_claude_cli_provider.py pins the flags.
    #
    # ⛔ An ALLOWLIST, not a denylist. The child is a model: it gets only what a process needs to start,
    # find its home and temp directories, and authenticate. WARDEN's own environment holds cloud
    # credentials, database DSNs and a kubeconfig (the harness puts them there for the evidence
    # readers); a denylist let every one of them into the model's process (found 2026-09-27).
    #
    # - Proxy and CA-bundle variables (audit A-C-19): behind a corporate proxy or a private CA the CLI
    #   could not reach its API at all.
    # - CLAUDE_CODE_OAUTH_TOKEN: the documented credential for the CLI where no browser login exists
    #   (`claude setup-token`; it can only make model requests). Never ANTHROPIC_API_KEY: that would
    #   silently switch the CLI from the subscription to per-token API billing - the `anthropic`
    #   provider is the one for API keys.
    _ENV_ALLOW = ("PATH", "PATHEXT", "SYSTEMROOT", "SystemRoot", "WINDIR", "COMSPEC",
                  "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "TZ",
                  "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
                  "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
                  "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE",
                  "CLAUDE_CODE_OAUTH_TOKEN")

    def complete(self, *, system: str, user: str, schema: Any = None) -> Completion:
        import os as _os
        import subprocess
        import tempfile

        env = {k: v for k, v in _os.environ.items() if k in self._ENV_ALLOW}

        cmd = [
            self._exe, "-p",
            "--model", self.model,
            "--system-prompt", system,
            "--disallowed-tools", *self._NO_TOOLS,
            # ⛔ The deny list alone left 25 tools callable on the owner's machine (Skill, Workflow,
            # CronCreate, the claude.ai Docs MCP *write* tools...) and still loaded the operator's
            # CLAUDE.md, hooks and skills - the CLI finds the profile without HOME/USERPROFILE, so
            # stripping env did not hide it (found 2026-09-26 building Helios's copy of this
            # provider). An empty tool list, no MCP servers and no setting sources close all three.
            "--tools", "",
            "--strict-mcp-config",
            "--setting-sources", "",
            # Not saved to the operator's profile: every call used to leave the whole prompt there as
            # a session transcript (second review, 2026-09-30).
            "--no-session-persistence",
        ]
        try:
            proc = subprocess.run(
                cmd,
                # ⛔ The prompt goes in on STDIN, not as an argument. The evidence blob plus the JSON
                # schema runs to several KB and Windows caps a command line at ~32k; an argument that
                # long fails in a way that looks like the model refusing.
                input=user,
                capture_output=True,
                text=True,
                # ⛔ EXPLICIT UTF-8, both directions. Without it Python uses the Windows code page
                # (cp1252), and measured against the real CLI that did two separate things:
                #   - a character cp1252 cannot encode - the `→` the model itself writes into its
                #     hypothesis, which the propose step then sends back - crashed the call before
                #     it was sent: "'charmap' codec can't encode character '→'", three
                #     retries, ModelRefused, and a benchmark run recorded as ERROR;
                #   - a character cp1252 CAN encode - the em dash in every prompt's ALERT line -
                #     went out as a cp1252 byte to a CLI that reads UTF-8, so it arrived corrupt.
                #     Every prompt sent this way carried one garbled character.
                # UTF-8 was verified to round-trip `→ — é` exactly. `replace` only guards decoding
                # a reply; encoding a Python str as UTF-8 cannot fail.
                encoding="utf-8",
                errors="replace",
                timeout=call_timeout_s(self),
                check=False,
                env=env,
                # ⛔ Outside the repository. Combined with --disallowed-tools, the answer key is out
                # of reach twice over.
                cwd=tempfile.gettempdir(),
            )
        except subprocess.TimeoutExpired as exc:
            raise ProviderError(f"claude CLI exceeded {call_timeout_s(self):.0f}s") from exc
        if proc.returncode != 0:
            # ⛔ BOTH streams. The CLI writes its reason for refusing - including "usage limit
            # reached" - to STDOUT, and this used to report stderr only. So when the limit was hit
            # mid-wave every failure read `claude CLI exited 1:` followed by nothing at all, and the
            # one fact that explained five ERROR rows had been thrown away.
            detail = " | ".join(
                part.strip() for part in (proc.stdout, proc.stderr) if part and part.strip()
            )[:400]
            if _USAGE_LIMIT.search(detail):
                raise ProviderExhausted(f"claude CLI usage limit: {detail}")
            error = ProviderError(f"claude CLI exited {proc.returncode}: {detail or '(no output)'}")
            # What the CLI says of the API, so a Claude outage reads as one: an error status is not billed, and a
            # connection that never opened sent nothing (ninth review - neither is carried to the next run).
            api = _CLI_API_ERROR.search(detail)
            error.status_code = int(api.group(1)) if api else None
            error.sent = not _CLI_UNSENT.search(detail)
            raise error
        text = proc.stdout or ""
        return Completion(text, _estimate_tokens(system + user), _estimate_tokens(text))

    @property
    def version(self) -> str:
        """`claude --version`, for the audit (register M15): `claude -p` pins the model, the CLI pins the rest."""
        if not self._version:
            import subprocess

            try:
                out = subprocess.run([self._exe, "--version"], capture_output=True, text=True, timeout=15,
                                     check=False).stdout or ""
            except (OSError, subprocess.SubprocessError):
                out = ""
            found = re.search(r"\d+(?:\.\d+)+", out)
            self._version = f"claude-cli {found.group(0) if found else 'unknown'}"
        return self._version


# --------------------------------------------------------------------------- bedrock


class BedrockProvider:
    """Amazon Bedrock's Converse API - the production path (decision D12: Claude Sonnet 5 on Bedrock, IAM, no key).

    The model is an inference-profile id from WARDEN_BEDROCK_MODEL (the India geo profile is
    `in.anthropic.claude-sonnet-5`); like every provider it must pass the replay set first (register M20), so it is
    refused until W-B qualifies it. With a schema the answer is forced through one tool whose input schema IS the
    schema - Converse `toolChoice: {"tool": {"name": ...}}`, read 2026-10-03 - so the API enforces the shape rather
    than the prompt asking for it. The region is WARDEN's configured one, never a literal."""

    name = "bedrock"
    TOOL = "submit_answer"

    def __init__(self, model: str | None = None, client: Any = None) -> None:
        chosen = model or os.environ.get("WARDEN_BEDROCK_MODEL", "")
        if not chosen:
            raise ProviderError("WARDEN_PROVIDER=bedrock needs WARDEN_BEDROCK_MODEL: an exact inference-profile id")
        self.model = pinned(chosen)
        self.version = _sdk_version("boto3")
        if client is None:
            import boto3
            from botocore.config import Config

            from .environments import region

            # One attempt and a bounded socket: WARDEN's own retry loop and per-call ceiling decide, not the SDK's.
            client = boto3.client("bedrock-runtime", region_name=region(), config=Config(
                read_timeout=_sdk_timeout_s(), connect_timeout=10, retries={"max_attempts": 1, "mode": "standard"}))
        self._client = client

    def complete(self, *, system: str, user: str, schema: Any = None) -> Completion:
        import json

        request: dict[str, Any] = {"modelId": self.model, "system": [{"text": system}],
                                   "messages": [{"role": "user", "content": [{"text": user}]}],
                                   "inferenceConfig": {"maxTokens": 1500}}
        if schema is not None:
            request["toolConfig"] = {
                "tools": [{"toolSpec": {"name": self.TOOL, "description": "Return the answer in this exact shape.",
                                        "inputSchema": {"json": schema.model_json_schema()}}}],
                "toolChoice": {"tool": {"name": self.TOOL}}}
        try:
            resp = self._client.converse(**request)
        except Exception as exc:
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if code in ("ThrottlingException", "ServiceQuotaExceededException"):
                raise ProviderExhausted(f"bedrock: {code}") from exc
            raise ProviderError(f"bedrock: {code or type(exc).__name__}") from exc
        content = resp["output"]["message"]["content"]
        tool = next((c["toolUse"]["input"] for c in content if "toolUse" in c), None)
        text = json.dumps(tool) if tool is not None else "".join(c.get("text", "") for c in content)
        usage = resp.get("usage") or {}
        return Completion(text, int(usage.get("inputTokens") or _estimate_tokens(system + user)),
                          int(usage.get("outputTokens") or _estimate_tokens(text)))


# --------------------------------------------------------------------------- resolution

_REGISTRY = {
    "anthropic": AnthropicProvider,
    "bedrock": BedrockProvider,
    "claude_cli": ClaudeCliProvider,
    "claude-cli": ClaudeCliProvider,
    "gemini": GeminiProvider,
    "openai": OpenAICompatProvider,
    "groq": OpenAICompatProvider,
    "openrouter": OpenAICompatProvider,
    "ollama": OpenAICompatProvider,
}

# ⛔ Audit A-C-18: OPENAI_API_KEY used to go to whichever host the client pointed at - Groq,
# OpenRouter, or any custom WARDEN_BASE_URL. A key is a credential for ONE vendor; each host reads
# its own variable, and only a loopback host needs none.
OPENAI_DEFAULT_BASE_URL = "https://api.openai.com/v1"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/"
ANTHROPIC_BASE_URL = "https://api.anthropic.com"
_KEY_ENV_BY_HOST = {
    "api.openai.com": "OPENAI_API_KEY",
    "api.groq.com": "GROQ_API_KEY",
    "openrouter.ai": "OPENROUTER_API_KEY",
}
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def key_env_for(base_url: str | None) -> str | None:
    """The environment variable holding the key for this host; None for a loopback model."""
    host = (urlparse(base_url).hostname or "") if base_url else "api.openai.com"
    if host in _LOOPBACK:
        return None
    return _KEY_ENV_BY_HOST.get(host, "WARDEN_API_KEY")


DEFAULT_BASE_URLS = {
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "ollama": "http://localhost:11434/v1",
}


def load_qualified() -> dict:
    """data/providers.yaml: the bar, and the provider/model pairs measured to pass it (register M20)."""
    from importlib import resources

    import yaml

    doc = yaml.safe_load((resources.files("warden") / "data" / "providers.yaml").read_text(encoding="utf-8")) or {}
    if not isinstance(doc.get("bar"), dict) or not isinstance(doc.get("qualified"), list):
        raise ProviderError("data/providers.yaml needs a `bar` mapping and a `qualified` list")
    return doc


def qualified(provider: Provider) -> Provider:
    """The provider, if its exact model passed WARDEN's replay set; otherwise refused (register M20). A fallback to
    another vendor's model is a different model, so it is held to the same bar. scripts/qualify_provider.py alone
    sets WARDEN_QUALIFYING, to measure a model that has not passed yet."""
    if os.environ.get("WARDEN_QUALIFYING") == "1":
        return provider
    doc = load_qualified()
    bar = doc["bar"]
    for entry in doc["qualified"]:
        if (isinstance(entry, dict) and entry.get("provider") == provider.name and entry.get("model") == provider.model
                and int(entry.get("wrong_and_allowed", 1 << 30)) <= int(bar["wrong_and_allowed"])
                and int(entry.get("correct", -1)) >= int(bar["min_correct"])):
            return provider
    raise ProviderError(f"{provider.name} {provider.model} has not passed WARDEN's replay set (register M20); "
                        "measure it with scripts/qualify_provider.py")


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
        return qualified(OpenAICompatProvider(base_url=os.environ.get("WARDEN_BASE_URL") or DEFAULT_BASE_URLS[name]))
    return qualified(_REGISTRY[name]())
