"""Minimal fake Anthropic client for tests and HELIOS_AI_MOCK smoke paths.

Shipped inside the package (not only in tests/) so the Rust end-to-end
test can trigger it via `HELIOS_AI_MOCK=1 python -m helios_ai explain`
without the tests/ directory being on sys.path.
"""

from __future__ import annotations

import contextlib
import json as _json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class _TextBlock:
    type: str
    text: str


@dataclass
class _Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


@dataclass
class _Message:
    content: list[_TextBlock]
    usage: _Usage
    stop_reason: str = "end_turn"


class _Messages:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> _Message:
        self.calls.append(kwargs)

        # Structured-output call (propose_fix) — emit a valid FixProposal JSON.
        if "output_config" in kwargs:
            return _fake_fix_proposal(kwargs)

        # Plain call (explain) — emit a markdown narrative.
        scenario = "unknown"
        for m in kwargs.get("messages", []):
            content = m.get("content", "")
            if isinstance(content, str) and '"scenario"' in content:
                with contextlib.suppress(_json.JSONDecodeError):
                    scenario = _json.loads(content).get("scenario", scenario)
        text = (
            f"# Failure narrative for {scenario}\n\n"
            "Claude would explain the chain here. (mocked)"
        )
        return _Message(
            content=[_TextBlock(type="text", text=text)],
            usage=_Usage(input_tokens=100, output_tokens=20),
        )


def _fake_fix_proposal(kwargs: dict[str, Any]) -> _Message:
    """Build a deterministic FixProposal JSON from the request body.

    Targets the first failed resource, setting its `availability_zone` to
    a different AZ. Enough to exercise the Rust re-verify path end-to-end
    without an API key.
    """
    scenario_name = "unknown"
    first_failure_id = "aws_s3_bucket.assets"  # harmless default
    for m in kwargs.get("messages", []):
        content = m.get("content", "")
        if not isinstance(content, str):
            continue
        with contextlib.suppress(_json.JSONDecodeError):
            payload = _json.loads(content)
            chain = payload.get("chain", {}) if isinstance(payload, dict) else {}
            scenario_name = chain.get("scenario", scenario_name)
            failures = chain.get("failures") or []
            if failures:
                first_failure_id = failures[0].get("id", first_failure_id)

    body = {
        "scenario_name": scenario_name,
        "explanation": (
            "Mocked FixProposal -- move the first failed resource to a "
            "different availability zone."
        ),
        "edits": [
            {
                "op": "set_attr",
                "resource_id": first_failure_id,
                "key": "availability_zone",
                "value": "us-east-1b",
            }
        ],
    }
    return _Message(
        content=[_TextBlock(type="text", text=_json.dumps(body))],
        usage=_Usage(input_tokens=100, output_tokens=40),
    )


@dataclass
class MockAnthropic:
    """Ducks the attributes of `anthropic.Anthropic` that `explain()` uses."""

    messages: _Messages = field(default_factory=_Messages)

    def __init__(self, *_: Any, **__: Any) -> None:
        self.messages = _Messages()
