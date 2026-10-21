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

import contextvars
import json
import math
import os
import threading
import typing
from types import TracebackType
from typing import Any

from pydantic import BaseModel, ValidationError
from pydantic_core.core_schema import ErrorType

from .models import CostRecord
from .providers import Provider, ProviderExhausted, resolve

# USD per 1M tokens. ⚠ Configuration, not fact — vendors change pricing and the free tiers cost
# nothing at all. Verify before quoting these figures anywhere.
PRICE_PER_MTOK_IN = float(os.environ.get("WARDEN_PRICE_IN", "3.00"))
PRICE_PER_MTOK_OUT = float(os.environ.get("WARDEN_PRICE_OUT", "15.00"))
MAX_PROMPT_TOKENS = int(os.environ.get("WARDEN_MAX_PROMPT_TOKENS", "60000"))


def model_prices(model: str) -> tuple[float, float]:
    """USD per 1M tokens (input, output) for `model`: WARDEN_PRICE_IN/OUT when a person sets them, else the model's
    own row in data/providers.yaml `prices`, else the defaults above. One price for every model under-counted Opus 5.5
    ($4/$20) and over-counted Sonnet ($2/$10) against the incident's USD ceiling (2026-10-15)."""
    if os.environ.get("WARDEN_PRICE_IN") or os.environ.get("WARDEN_PRICE_OUT"):
        return PRICE_PER_MTOK_IN, PRICE_PER_MTOK_OUT
    from .providers import load_qualified

    row = (load_qualified().get("prices") or {}).get(model)
    if isinstance(row, (list, tuple)) and len(row) == 2:
        return float(row[0]), float(row[1])
    return PRICE_PER_MTOK_IN, PRICE_PER_MTOK_OUT

# Wall-clock ceiling for a single model call. The budget above stops COST; this stops TIME. Without
# it a slow, retrying or hung provider hangs the whole run forever — observed live: a Gemini key
# that had just been rotated made the SDK retry past every internal timeout, and `warden run` never
# returned. The tools already have this (tools.py); the model call did not, which was the gap.
# The ceiling itself is providers.call_timeout_s(provider): WARDEN_LLM_TIMEOUT, else the provider's
# own default, else 45 s.


# Owner item 5 (2026-10-21): a retry after an answer that failed validation says what failed, instead of sending the
# same prompt again. Only field paths and error types are fed back, never an input value: the answer echoes redacted
# evidence, and a validation error can quote it. Part of the prompt a model is qualified on (qualify_provider.py
# prompt_fingerprint), so changing it changes the pin in data/providers.yaml.
RETRY_FEEDBACK = ("Your last answer failed validation: {errors}. Return ONLY valid JSON for this schema: nothing "
                  "else.")
_MAX_FED_BACK = 8  # errors named; the rest are counted
# pydantic's own error types (`missing`, `enum`, `int_parsing` ...): a validator can name a custom one after a value
# from the answer (PydanticCustomError), so only these are told (review, PR 132); any other is "invalid".
_ERROR_TYPES = frozenset(typing.get_args(ErrorType))


def _schema_names(schema: Any) -> frozenset[str]:
    """Every property name the schema declares, nested models included: the only words of a path fed back."""
    names: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            names.update(k for k in node.get("properties") or {} if isinstance(k, str))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema.model_json_schema())
    return frozenset(names)


def _path(loc: tuple[Any, ...], names: frozenset[str]) -> str:
    """A field path from the schema's own names and list positions; any other step (a key the answer made up, which is
    answer text) is shown as `*`."""
    steps = [str(x) if isinstance(x, int) or x in names else "*" for x in loc]
    return ".".join(steps) or "(the whole answer)"


def _error_type(error: Any) -> str:
    """pydantic's error type (`missing`, `enum`, `too_long`): a fixed word, never the answer's text."""
    kind = str(error.get("type", ""))
    return kind if kind in _ERROR_TYPES else "invalid"


def _paths_and_types(exc: ValidationError, schema: Any) -> str:
    """Each error's field path and pydantic error type, the first _MAX_FED_BACK of them: never an input value."""
    names = _schema_names(schema)
    errors = exc.errors(include_url=False, include_context=False, include_input=False)
    shown = [f"{_path(tuple(e.get('loc') or ()), names)} ({_error_type(e)})" for e in errors[:_MAX_FED_BACK]]
    more = len(errors) - len(shown)
    return "; ".join(shown) + (f"; and {more} more" if more > 0 else "")


def refusal_reason(exc: BaseException | None, schema: Any) -> str:
    """Why no answer came, as ModelRefused says it. Its text reaches the diagnose audit row, the rules-only root cause
    in the report and the workflow's failure (graph.node_diagnose): a validation error is told by its paths and types,
    never by pydantic's own text, which quotes the answer (`input_value=...`), and the answer echoes evidence."""
    if not isinstance(exc, ValidationError):
        return str(exc)
    n = exc.error_count()
    return f"{n} validation error{'' if n == 1 else 's'} for {schema.__name__}: {_paths_and_types(exc, schema)}"


def validation_feedback(exc: Exception, schema: Any) -> str:
    """What a retry tells the model about its last answer: each error's field path and pydantic error type, or the
    JSON parser's own fixed message and position. Never an input value, a quote of the answer or a validator's own
    message (which may carry one)."""
    if isinstance(exc, ValidationError):
        text = _paths_and_types(exc, schema)
    elif isinstance(exc, json.JSONDecodeError):
        text = f"not valid JSON ({exc.msg}, line {exc.lineno} column {exc.colno})"
    else:
        text = "no JSON object was found in it"
    return RETRY_FEEDBACK.format(errors=text)


def _retry_prompt(system: str, prompt: str, feedback: str) -> str:
    """The prompt again with the feedback after it - within the prompt ceiling, else the prompt as it was."""
    retry = f"{prompt}\n\n{feedback}"
    return retry if (len(system) + len(retry)) // 4 <= MAX_PROMPT_TOKENS else prompt


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
        with _CarriedToCaller(box):
            box["ok"] = provider.complete(system=system, user=user, schema=schema)

    # In the caller's context: the egress ledger names the incident from the Temporal activity running the call.
    th = threading.Thread(target=contextvars.copy_context().run, args=(_worker,), name="warden-llm-call", daemon=True)
    th.start()
    th.join(seconds)
    if th.is_alive():
        raise ModelCallTimeout(f"model call exceeded {seconds:.0f}s and was abandoned")
    if "err" in box:
        raise box["err"]
    return box["ok"]


class _CarriedToCaller:
    """Ends the model call's thread quietly and keeps what the call raised in `box["err"]`, for the calling thread
    to raise as it was (_complete_within). Every exception, SystemExit and KeyboardInterrupt too: none is silenced,
    each reaches the caller; the thread itself ends without one, so no thread hook logs or prints it."""

    def __init__(self, box: dict[str, Any]) -> None:
        self._box = box

    def __enter__(self) -> None:
        return None

    def __exit__(self, kind: type[BaseException] | None, err: BaseException | None,
                 tb: TracebackType | None) -> bool:
        if err is not None:
            self._box["err"] = err
        return True


class ModelRefused(RuntimeError):
    """The model did not return something matching the contract, after retries."""


class ModelCutOff(ModelRefused):
    """The answer reached the output cap: it was charged, and the same prompt would be cut off again."""


class ModelDeclined(ModelCutOff):
    """The model refused to answer (stop_reason "refusal"). Handled exactly as a cut-off (B11): charged, never asked
    again - the same prompt would be declined again - and the incident goes to a person on the evidence alone."""


class LLMClient:
    def __init__(
        self,
        *,
        provider: Provider | None = None,
        max_usd: float | None = None,
        max_calls: int | None = None,
        mock: bool | None = None,
        call_timeout_s: float | None = None,
    ) -> None:
        # The explicit argument wins; the environment is only the default (audit A-C-16). A budget
        # that is not a positive finite number is refused: nan compared False everywhere and
        # switched the ceiling off.
        self.max_usd = float(max_usd if max_usd is not None else os.environ.get("WARDEN_MAX_USD", "0.50"))
        if not math.isfinite(self.max_usd) or self.max_usd <= 0:
            raise ValueError(f"the model budget must be a positive number of USD, not {self.max_usd!r}")

        self.max_calls = _max_calls(max_calls)
        self.cost = CostRecord()
        # Requests that failed without an answer (a refused connection, a 5xx): counted against this run's call
        # ceiling, but not carried to the incident's next run - they reached no model (eighth review, 2026-10-01).
        self.unanswered = 0
        self.mock = (os.environ.get("WARDEN_MOCK") == "1") if mock is None else mock
        if provider is None and not self.mock:
            provider = resolve()
        self._provider = provider
        # The model's own prices (model_prices). A price that is not a finite, non-negative number switched the USD
        # ceiling off: nan made every cost nan, a negative price made it shrink (fourth review, 2026-09-30). Zero is a
        # free tier.
        self.price_in, self.price_out = model_prices(self.model)
        for name, price in (("WARDEN_PRICE_IN", self.price_in), ("WARDEN_PRICE_OUT", self.price_out)):
            if not math.isfinite(price) or price < 0:
                raise ValueError(f"{name} must be a non-negative number of USD per 1M tokens, not {price!r}")
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
        usd = (in_tok / 1e6) * self.price_in + (out_tok / 1e6) * self.price_out
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

    def structured[T: BaseModel](
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
            return self._mock_answer(system=system, user=user, schema=schema, mock_factory=mock_factory)

        prompt = (
            f"{user}\n\nReturn ONLY a JSON object matching this schema:\n"
            f"{json.dumps(schema.model_json_schema())}"
        )
        # Refused BEFORE the call (2026-09-27 audit): charging after it meant one oversized prompt
        # could spend past max_usd before the budget ever looked. ~4 characters per token.
        est_in = (len(system) + len(prompt)) // 4
        if est_in > MAX_PROMPT_TOKENS:
            raise BudgetExceeded(f"prompt of ~{est_in} tokens exceeds the {MAX_PROMPT_TOKENS} ceiling")

        last: Exception | None = None
        attempts = 0
        sent: str | None = prompt
        for _ in range(retries + 1):
            attempts += 1
            answer, last, sent = self._attempt(system=system, prompt=prompt, sent=sent, schema=schema)
            if answer is not None:
                return answer
            if sent is None:
                break
        plural = "attempt" if attempts == 1 else "attempts"
        raise ModelRefused(f"{schema.__name__} not produced after {attempts} {plural}: {refusal_reason(last, schema)}")

    def _mock_answer[T: BaseModel](self, *, system: str, user: str, schema: type[T], mock_factory: Any) -> T:
        if mock_factory is None:
            raise ModelRefused(f"mock mode needs a mock_factory for {schema.__name__}")
        self._before_a_call(0.0)
        self._charge(len(system) // 4 + len(user) // 4, 120)
        # Called with NO arguments on purpose. An earlier version passed the prompt text and
        # the mock branched on substrings in it - which matched the field LABELS ("RECENT
        # DEPLOYS:", "error_rate") rather than the values, so every incident produced the same
        # hypothesis. Mocks read typed state through a closure now; text matching is banned.
        return mock_factory()

    def _attempt[T: BaseModel](self, *, system: str, prompt: str, sent: str,
                 schema: type[T]) -> tuple[T | None, Exception | None, str | None]:
        """One request of `sent`, the first prompt or `prompt` with feedback: (the validated answer, None, sent), or
        (None, why it failed, what to send next - None to stop asking)."""
        # Before EVERY attempt, retries included (audit A-C-15, A-C-17): the call over the ceiling
        # is never made, and a retry that would pass the budget on its input alone is not sent.
        # Honest limit: a response's OUTPUT cost is known only after it arrives, so one call can
        # still end above the ceiling; the next is then refused. Estimated on what is sent: a retry
        # carries the validation feedback (item 5), and its input is priced with it.
        self._before_a_call(((len(system) + len(sent)) // 4 / 1e6) * self.price_in)
        completion = None
        try:
            # Two nested bounds. The PROVIDER's own socket timeout (providers._sdk_timeout_s,
            # same env var) is the one that actually ends the worker thread and lets the process
            # exit. This wall-clock is a BACKSTOP set just after it, for the rare case the SDK
            # timeout does not fire (e.g. an OAuth-style key whose validation hangs below the
            # request layer).
            completion = _complete_within(
                self._provider, system=system, user=sent,
                seconds=self.call_timeout_s + 2.0, schema=schema,
            )
            return self._validated(completion, schema), None, sent
        except ModelCallTimeout:
            # Fatal by design: a hung call must stop the run, not be retried into three hangs. It was sent
            # and may still be billed: it counts as a call, its cost unknown (eighth review: it counted
            # nowhere, so restarts of a hanging model were never bounded).
            self.cost.add(0, 0, 0.0)
            raise
        except ModelCutOff as exc:
            return None, exc, None  # charged above; the same prompt would be cut off (or declined) the same way
        except (BudgetExceeded, ProviderExhausted):
            # Fatal by design: a blown budget must stop the run immediately, not be retried into an
            # overspend. An exhausted provider likewise: it has no error code, so _is_transient() would
            # call it transient and retry it twice more against a pool that has nothing left.
            raise
        except (ValidationError, ValueError) as exc:
            # the model answered, it just was not valid JSON — retry
            if completion is None:
                # Raised inside the provider - it could not read what came back (an HTML 200): the request was
                # answered and may be billed, and it counted as no call at all (ninth review).
                self.cost.add(0, 0, 0.0)
                return None, exc, sent
            # The model's own answer failed: the next attempt says why (item 5). No call is added.
            return None, exc, _retry_prompt(system, prompt, validation_feedback(exc, schema))
        except Exception as exc:  # noqa: BLE001
            # A provider/network error. The SDKs' internal retries are DISABLED (providers.py) so
            # this loop re-handles them — but only the TRANSIENT ones (429/5xx/connection reset).
            # A permanent 4xx (401 bad key, 400 malformed) will fail identically every attempt, so
            # retrying it just delays a failure the operator must fix — fail fast instead.
            # The request was made: it counts toward the call ceiling like any other (fourth review:
            # 15 failed requests were made under a ceiling of 2, none counted). Its cost is unknown.
            self.cost.add(0, 0, 0.0)
            if not _reached_the_model(exc):
                self.unanswered += 1
            return None, exc, sent if _is_transient(exc) else None

    def _validated[T: BaseModel](self, completion: Any, schema: type[T]) -> T:
        # Charged BEFORE validation: a malformed response still costs money, and a budget
        # that only counts successful calls can be exhausted by a model that keeps failing.
        self._charge(completion.input_tokens, completion.output_tokens)
        if getattr(completion, "refused", False):
            category = getattr(completion, "refusal_category", "") or "not named"
            raise ModelDeclined(f"the model declined to answer (refusal, category {category}); asking again "
                                "would be declined again")
        if getattr(completion, "cut_off", False):
            raise ModelCutOff("the answer was cut off at the output cap; asking again would cut it off again")
        return schema.model_validate_json(extract_json(completion.text))


def _max_calls(max_calls: int | None) -> int:
    """Per incident: the explicit argument, else WARDEN_MAX_CALLS (the cloud llm zone: 6, owner 2026-10-10), else 8."""
    if max_calls is None:
        raw = os.environ.get("WARDEN_MAX_CALLS", "8")
        max_calls = int(raw) if raw.isdigit() else -1
    if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls < 1:
        raise ValueError(f"max_calls must be a positive whole number, not {max_calls!r}")
    return max_calls


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
    # The LAST complete top-level object: a model may draft its answer before the final one, and the span from the
    # first "{" to the last "}" then joins the two into one invalid text (Anthropic's guidance for its current models,
    # read 2026-10-15). With no complete object at all, that span is still returned, so validation says why.
    decoder, found, i = json.JSONDecoder(), None, candidate.find("{")
    while i != -1:
        try:
            value, end = decoder.raw_decode(candidate, i)
        except ValueError:
            i = candidate.find("{", i + 1)
            continue
        if isinstance(value, dict):
            found = candidate[i:end]
        i = candidate.find("{", end)
    if found is not None:
        return found
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in model output")
    return candidate[start : end + 1]
