"""The only place a model is called.

Three things matter here and none of them is the prompt:

1. **Structured output.** The model returns a typed object or the call fails. Free text cannot be
   verified, and anything that cannot be verified cannot be gated.
2. **A budget that actually stops things.** Token and cost limits are enforced in the call path and
   raise; they are not advisory numbers in a dashboard nobody reads.
3. **No vendor in this file.** Which model answers is a deployment decision, not an architectural
   one — see `providers.py`. A safety layer that only works against one vendor is not a safety
   layer.

`AEGIS_MOCK=1` runs the whole pipeline deterministically with no network and no key, which is what
CI and the eval suite use. A demo that only works with a paid key is a demo nobody can reproduce.
"""

from __future__ import annotations

import json
import os
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .models import CostRecord
from .providers import Provider, resolve

T = TypeVar("T", bound=BaseModel)

# USD per 1M tokens. ⚠ Configuration, not fact — vendors change pricing and the free tiers cost
# nothing at all. Verify before quoting these figures anywhere.
PRICE_PER_MTOK_IN = float(os.environ.get("AEGIS_PRICE_IN", "3.00"))
PRICE_PER_MTOK_OUT = float(os.environ.get("AEGIS_PRICE_OUT", "15.00"))


class BudgetExceeded(RuntimeError):
    """The run cost more than it was allowed to. Fatal by design."""


class ModelRefused(RuntimeError):
    """The model did not return something matching the contract, after retries."""


class LLMClient:
    def __init__(
        self,
        *,
        provider: Provider | None = None,
        max_usd: float = 0.50,
        max_calls: int = 8,
        mock: bool | None = None,
    ) -> None:
        self.max_usd = float(os.environ.get("AEGIS_MAX_USD", max_usd))
        self.max_calls = max_calls
        self.cost = CostRecord()
        self.mock = (os.environ.get("AEGIS_MOCK") == "1") if mock is None else mock
        self._provider = provider if provider is not None else (None if self.mock else resolve())

    @property
    def provider_name(self) -> str:
        return "mock" if self.mock else getattr(self._provider, "name", "unknown")

    @property
    def model(self) -> str:
        return "mock" if self.mock else getattr(self._provider, "model", "unknown")

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

        last: Exception | None = None
        for _ in range(retries + 1):
            completion = self._provider.complete(system=system, user=prompt)
            # Charged BEFORE validation: a malformed response still costs money, and a budget that
            # only counts successful calls can be exhausted by a model that keeps failing.
            self._charge(completion.input_tokens, completion.output_tokens)
            try:
                return schema.model_validate_json(extract_json(completion.text))
            except (ValidationError, ValueError) as exc:
                last = exc
        raise ModelRefused(f"{schema.__name__} not produced after {retries + 1} attempts: {last}")


def extract_json(text: str) -> str:
    """Pull the JSON object out of a model response.

    Public and separately tested because it is the most provider-sensitive code in the project:
    some return bare JSON, some wrap it in ```json fences, some add a sentence of prose first.
    """
    text = text.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) > 1:
            text = parts[1]
        text = text.removeprefix("json").strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in model output")
    return text[start : end + 1]
