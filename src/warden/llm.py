"""The only place a model is called.

Three things matter here and none of them is the prompt:

1. **Structured output.** The model returns a typed object or the call fails. Free text cannot be
   verified, and anything that cannot be verified cannot be gated.
2. **A budget that actually stops things.** Token and cost limits are enforced in the call path and
   raise; they are not advisory numbers in a dashboard nobody reads.
3. **No vendor in this file.** Which model answers is a deployment decision, not an architectural
   one — see `providers.py`. A safety layer that only works against one vendor is not a safety
   layer.

`WARDEN_MOCK=1` runs the whole pipeline deterministically with no network and no key, which is what
CI and the eval suite use. A demo that only works with a paid key is a demo nobody can reproduce.
"""

from __future__ import annotations

import json
import math
import os
import threading
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .models import CostRecord
from .providers import Provider, ProviderExhausted, resolve

T = TypeVar("T", bound=BaseModel)

# USD per 1M tokens. ⚠ Configuration, not fact — vendors change pricing and the free tiers cost
# nothing at all. Verify before quoting these figures anywhere.
PRICE_PER_MTOK_IN = float(os.environ.get("WARDEN_PRICE_IN", "3.00"))
PRICE_PER_MTOK_OUT = float(os.environ.get("WARDEN_PRICE_OUT", "15.00"))
MAX_PROMPT_TOKENS = int(os.environ.get("WARDEN_MAX_PROMPT_TOKENS", "60000"))

# Wall-clock ceiling for a single model call. The budget above stops COST; this stops TIME. Without
# it a slow, retrying or hung provider hangs the whole run forever — observed live: a Gemini key
# that had just been rotated made the SDK retry past every internal timeout, and `warden run` never
# returned. The tools already have this (tools.py); the model call did not, which was the gap.
# The ceiling itself is providers.call_timeout_s(provider): WARDEN_LLM_TIMEOUT, else the provider's
# own default, else 45 s.


class BudgetExceeded(RuntimeError):
    """The run cost more than it was allowed to. Fatal by design."""


class ModelCallTimeout(RuntimeError):
    """A single model call exceeded the wall-clock ceiling. Fatal — better a loud stop than a hang."""


def _complete_within(provider: Provider, *, system: str, user: str, seconds: float,
                     schema: Any = None):
    """Run provider.complete() under a wall-clock deadline, on a DAEMON thread.

    A daemon thread so a genuinely hung SDK call (bad key, dead socket, endless retry) cannot block
    interpreter exit the way a normal worker would — the caller stops waiting, and the process can
    still shut down. The abandoned thread is the same accepted trade-off tools.py documents: Python
    cannot force-kill a thread, so a real deployment also sets a socket timeout on the client.
    """
    box: dict[str, Any] = {}

    def _worker() -> None:
        try:
            box["ok"] = provider.complete(system=system, user=user, schema=schema)
        except BaseException as exc:  # noqa: BLE001 - carried across the thread boundary, re-raised below
            box["err"] = exc

    th = threading.Thread(target=_worker, name="warden-llm-call", daemon=True)
    th.start()
    th.join(seconds)
    if th.is_alive():
        raise ModelCallTimeout(f"model call exceeded {seconds:.0f}s and was abandoned")
    if "err" in box:
        raise box["err"]
    return box["ok"]


class ModelRefused(RuntimeError):
    """The model did not return something matching the contract, after retries."""


class LLMClient:
    def __init__(
        self,
        *,
        provider: Provider | None = None,
        max_usd: float | None = None,
        max_calls: int = 8,
        mock: bool | None = None,
        call_timeout_s: float | None = None,
    ) -> None:
        # The explicit argument wins; the environment is only the default (audit A-C-16). A budget
        # that is not a positive finite number is refused: nan compared False everywhere and
        # switched the ceiling off.
        self.max_usd = float(max_usd if max_usd is not None else os.environ.get("WARDEN_MAX_USD", "0.50"))
        if not math.isfinite(self.max_usd) or self.max_usd <= 0:
            raise ValueError(f"the model budget must be a positive number of USD, not {self.max_usd!r}")
        # A price that is not a finite, non-negative number switched the USD ceiling off: nan made every
        # cost nan, a negative price made it shrink (fourth review, 2026-09-30). Zero is a free tier.
        for name, price in (("WARDEN_PRICE_IN", PRICE_PER_MTOK_IN), ("WARDEN_PRICE_OUT", PRICE_PER_MTOK_OUT)):
            if not math.isfinite(price) or price < 0:
                raise ValueError(f"{name} must be a non-negative number of USD per 1M tokens, not {price!r}")
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls < 1:
            raise ValueError(f"max_calls must be a positive whole number, not {max_calls!r}")
        self.max_calls = max_calls
        self.cost = CostRecord()
        # Requests that failed without an answer (a refused connection, a 5xx): counted against this run's call
        # ceiling, but not carried to the incident's next run - they reached no model (eighth review, 2026-10-01).
        self.unanswered = 0
        self.mock = (os.environ.get("WARDEN_MOCK") == "1") if mock is None else mock
        self._provider = provider if provider is not None else (None if self.mock else resolve())
        if call_timeout_s is None:
            # Function-level import: providers must not import llm at module load (cycle).
            from .providers import call_timeout_s as _provider_timeout
            call_timeout_s = _provider_timeout(self._provider)
        self.call_timeout_s = call_timeout_s

    @property
    def provider_name(self) -> str:
        return "mock" if self.mock else getattr(self._provider, "name", "unknown")

    @property
    def model(self) -> str:
        return "mock" if self.mock else getattr(self._provider, "model", "unknown")

    @property
    def processed_in(self) -> str:
        """Where the provider processes the prompt (register S11), as far as WARDEN can know it."""
        if self.mock:
            return "nowhere (mock)"
        return str(getattr(self._provider, "geography", "set by the provider, outside WARDEN's configuration"))

    @property
    def provider_version(self) -> str:
        """The CLI or SDK version that made the call (register M15)."""
        return "mock" if self.mock else str(getattr(self._provider, "version", "unknown"))

    # ------------------------------------------------------------------ budget

    def _charge(self, in_tok: int, out_tok: int) -> None:
        usd = (in_tok / 1e6) * PRICE_PER_MTOK_IN + (out_tok / 1e6) * PRICE_PER_MTOK_OUT
        self.cost.add(in_tok, out_tok, usd)
        if self.cost.usd > self.max_usd:
            raise BudgetExceeded(
                f"run cost ${self.cost.usd:.4f} exceeded the ${self.max_usd:.2f} ceiling"
            )
        if self.cost.calls > self.max_calls:
            raise BudgetExceeded(f"run made {self.cost.calls} calls, ceiling is {self.max_calls}")

    def _before_a_call(self, est_usd: float) -> None:
        if self.cost.calls + 1 > self.max_calls:
            raise BudgetExceeded(f"a call would be number {self.cost.calls + 1}; the ceiling is {self.max_calls}")
        if self.cost.usd + est_usd > self.max_usd:
            raise BudgetExceeded(f"this call (~${est_usd:.4f} of input) would take the run past ${self.max_usd:.2f}")

    # ------------------------------------------------------------------ public

    def structured(
        self,
        *,
        system: str,
        user: str,
        schema: type[T],
        mock_factory: Any = None,
        retries: int = 2,
    ) -> T:
        """Ask for one typed object. Raises rather than returning something unvalidated."""
        if self.mock:
            if mock_factory is None:
                raise ModelRefused(f"mock mode needs a mock_factory for {schema.__name__}")
            self._before_a_call(0.0)
            self._charge(len(system) // 4 + len(user) // 4, 120)
            # Called with NO arguments on purpose. An earlier version passed the prompt text and
            # the mock branched on substrings in it - which matched the field LABELS ("RECENT
            # DEPLOYS:", "error_rate") rather than the values, so every incident produced the same
            # hypothesis. Mocks read typed state through a closure now; text matching is banned.
            return mock_factory()

        prompt = (
            f"{user}\n\nReturn ONLY a JSON object matching this schema:\n"
            f"{json.dumps(schema.model_json_schema())}"
        )
        # Refused BEFORE the call (2026-09-27 audit): charging after it meant one oversized prompt
        # could spend past max_usd before the budget ever looked. ~4 characters per token.
        est_in = (len(system) + len(prompt)) // 4
        if est_in > MAX_PROMPT_TOKENS:
            raise BudgetExceeded(f"prompt of ~{est_in} tokens exceeds the {MAX_PROMPT_TOKENS} ceiling")
        est_usd = (est_in / 1e6) * PRICE_PER_MTOK_IN

        last: Exception | None = None
        attempts = 0
        for _ in range(retries + 1):
            attempts += 1
            # Before EVERY attempt, retries included (audit A-C-15, A-C-17): the call over the ceiling
            # is never made, and a retry that would pass the budget on its input alone is not sent.
            # Honest limit: a response's OUTPUT cost is known only after it arrives, so one call can
            # still end above the ceiling; the next is then refused.
            self._before_a_call(est_usd)
            completion = None
            try:
                # Two nested bounds. The PROVIDER's own socket timeout (providers._sdk_timeout_s,
                # same env var) is the one that actually ends the worker thread and lets the process
                # exit. This wall-clock is a BACKSTOP set just after it, for the rare case the SDK
                # timeout does not fire (e.g. an OAuth-style key whose validation hangs below the
                # request layer).
                completion = _complete_within(
                    self._provider, system=system, user=prompt,
                    seconds=self.call_timeout_s + 2.0, schema=schema,
                )
                # Charged BEFORE validation: a malformed response still costs money, and a budget
                # that only counts successful calls can be exhausted by a model that keeps failing.
                self._charge(completion.input_tokens, completion.output_tokens)
                return schema.model_validate_json(extract_json(completion.text))
            except ModelCallTimeout:
                # Fatal by design: a hung call must stop the run, not be retried into three hangs. It was sent
                # and may still be billed: it counts as a call, its cost unknown (eighth review: it counted
                # nowhere, so restarts of a hanging model were never bounded).
                self.cost.add(0, 0, 0.0)
                raise
            except (BudgetExceeded, ProviderExhausted):
                # Fatal by design: a blown budget must stop the run immediately, not be retried into an
                # overspend. An exhausted provider likewise: it has no error code, so _is_transient() would
                # call it transient and retry it twice more against a pool that has nothing left.
                raise
            except (ValidationError, ValueError) as exc:
                last = exc  # the model answered, it just was not valid JSON — retry
                if completion is None:
                    # Raised inside the provider - it could not read what came back (an HTML 200): the request was
                    # answered and may be billed, and it counted as no call at all (ninth review).
                    self.cost.add(0, 0, 0.0)
            except Exception as exc:  # noqa: BLE001
                # A provider/network error. The SDKs' internal retries are DISABLED (providers.py) so
                # this loop re-handles them — but only the TRANSIENT ones (429/5xx/connection reset).
                # A permanent 4xx (401 bad key, 400 malformed) will fail identically every attempt, so
                # retrying it just delays a failure the operator must fix — fail fast instead.
                last = exc
                # The request was made: it counts toward the call ceiling like any other (fourth review:
                # 15 failed requests were made under a ceiling of 2, none counted). Its cost is unknown.
                self.cost.add(0, 0, 0.0)
                if not _reached_the_model(exc):
                    self.unanswered += 1
                if not _is_transient(exc):
                    break
        plural = "attempt" if attempts == 1 else "attempts"
        raise ModelRefused(f"{schema.__name__} not produced after {attempts} {plural}: {last}")


# Failures before the request was written: refused, unresolved, never connected.
_UNSENT = frozenset({"ConnectError", "ConnectTimeout", "ConnectionRefusedError", "gaierror", "NameResolutionError",
                     "NewConnectionError"})


def _reached_the_model(exc: BaseException) -> bool:
    """May this failed request have been processed - and billed? Only one provably never sent, or answered with an
    error status (an API error is not billed), is not: those are what an outage makes, and carrying them locked an
    incident for good (eighth review). Everything else is - a provider's own read timeout (the request processed,
    the client gone), a 200 it could not parse (ninth review: classed "reached no model", 18 requests went where the
    ceiling allowed 4)."""
    seen: list[BaseException] = []
    e: BaseException | None = exc
    while e is not None and e not in seen and len(seen) < 8:
        seen.append(e)
        e = e.__cause__ or e.__context__
    for x in seen:
        status = getattr(x, "status_code", None)
        status = getattr(x, "code", None) if status is None else status
        if getattr(x, "sent", True) is False or type(x).__name__ in _UNSENT \
                or (isinstance(status, int) and 400 <= status < 600):
            return False
    return True


def _is_transient(exc: Exception) -> bool:
    """Is this provider error worth retrying? A connection/socket error (no HTTP status) or a
    429/5xx is transient; a 4xx (401/403/400) is permanent. Duck-typed across SDKs, which expose the
    status as `.status_code` (openai, anthropic) or `.code` (google-genai)."""
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(exc, "code", None)
    if status is None:
        return True  # no HTTP status → a connection/DNS/socket failure → transient
    try:
        status = int(status)
    except (TypeError, ValueError):
        return True
    return status == 429 or status >= 500


def extract_json(text: str) -> str:
    """Pull the JSON object out of a model response.

    Public and separately tested because it is the most provider-sensitive code in the project:
    some return bare JSON, some wrap it in ```json fences, some add a sentence of prose first.
    """
    original = text.strip()
    candidate = original
    if candidate.startswith("```"):
        # The JSON is usually the FIRST fenced block, but a model (Anthropic without JSON-mode) may
        # put reasoning in a ```text fence first and the JSON in a LATER one. Blindly taking the
        # first block then broke a response the plain scan below would have handled. So: pick the
        # first fenced block that actually contains an object, else fall back to the whole response.
        fenced = [p.removeprefix("json").strip() for p in original.split("```")[1::2]]
        candidate = next((p for p in fenced if "{" in p and "}" in p), original)
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in model output")
    return candidate[start : end + 1]
