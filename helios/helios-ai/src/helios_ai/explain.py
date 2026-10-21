"""Turn a FailureChain into a human-readable markdown narrative via Claude.

Prompt-caching strategy:
    - System prompt (persona + task framing): cache breakpoint #1.
    - Availability-model glossary: cache breakpoint #2.
    - User turn carries the varying part (the FailureChain JSON).

The two stable text blocks render first, so any request reusing this
shell hits the cache on both. Verify via response.usage.cache_read_input_tokens
on the second call.
"""

from __future__ import annotations

import os
from typing import Any

from .glossary import AVAILABILITY_MODEL_GLOSSARY
from .models import FailureChain

DEFAULT_MODEL = "claude-opus-5-5"
MAX_TOKENS = 16000


def model_id() -> str:
    """The Claude model to call. Model ids expire; `HELIOS_AI_MODEL` overrides the default
    without a code change. Read at call time so a test or a shell can set it late."""
    return os.environ.get("HELIOS_AI_MODEL", DEFAULT_MODEL)

SYSTEM_PERSONA = """\
You are the narration layer of Helios, a deterministic infrastructure
simulator. A pure-Rust + Z3 engine has already proved which AWS
resources fail under a declared scenario; your job is to turn that
proof into a short, concrete report an SRE can act on.

Rules:
- Never contradict the FailureChain. The engine is authoritative.
- Never invent resources or failures not in the FailureChain.
- Do NOT propose fixes here; that is the propose-fix step. Describe only.
- Use the glossary to explain why each resource failed, tracing through
  Contains edges when relevant.
- Lead with the scenario, then the blast radius (# of failures), then
  the failure-by-failure narrative. Finish with a one-line impact
  summary. Plain markdown. No emoji. Under 400 words.
"""


def explain(chain: FailureChain, *, client: Any) -> str:
    """Return a markdown narrative for `chain`.

    `client` is an `anthropic.Anthropic` (or compatible duck-typed)
    instance. Passing it in lets tests inject a fake client.
    """
    response = client.messages.create(
        model=model_id(),
        max_tokens=MAX_TOKENS,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PERSONA,
                "cache_control": {"type": "ephemeral"},
            },
            {
                "type": "text",
                "text": AVAILABILITY_MODEL_GLOSSARY,
                "cache_control": {"type": "ephemeral"},
            },
        ],
        messages=[
            {
                "role": "user",
                "content": chain.model_dump_json(indent=2),
            }
        ],
    )
    for block in response.content:
        if getattr(block, "type", None) == "text":
            return block.text
    raise RuntimeError("Claude returned no text content")
