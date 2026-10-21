"""Propose Terraform attr edits that resolve a FailureChain via Claude.

Prompt-caching strategy (same as explain):
    - System prompt (persona + task framing): cache breakpoint #1.
    - Availability-model + scenario glossary:  cache breakpoint #2.
    - User turn carries the varying part ({chain, attrs_snapshot}).

Output shape is locked to `FixProposal` via `output_config.format.json_schema`
so the engine's re-verify step never has to parse free-text.
"""

from __future__ import annotations

import json
import os
from typing import Any

from pydantic import ValidationError

from .glossary import AVAILABILITY_MODEL_GLOSSARY
from .models import FailureChain, FixProposal

DEFAULT_MODEL = "claude-opus-5-5"
MAX_TOKENS = 16000


def model_id() -> str:
    """The Claude model to call. Model ids expire; `HELIOS_AI_MODEL` overrides the default
    without a code change. Read at call time so a test or a shell can set it late."""
    return os.environ.get("HELIOS_AI_MODEL", DEFAULT_MODEL)

SYSTEM_PERSONA = """\
You are the remediation layer of Helios, a deterministic infrastructure
simulator. A pure-Rust + Z3 engine has already proved which AWS resources
fail under a declared failure scenario; your job is to propose concrete
Terraform attribute edits that resolve the failure chain.

Rules:
- Output ONLY a FixProposal JSON object matching the schema; no prose.
- Use op="set_attr" only. Each edit must target a resource_id that
  appears in attrs_snapshot. Do not invent resource ids.
- Prefer the minimal set of edits. Enabling multi_az on an RDS, widening
  a load balancer's availability_zones, moving a SingleAz resource to a
  different availability_zone, or turning a SingleAz service into its
  multi-AZ equivalent are all valid moves when the glossary supports them.
- `key` is an attribute path. A nested block is a one-element list in
  Terraform JSON: write `scaling_config.desired_size` (or
  `scaling_config[0].desired_size`). A path into an attribute that does
  not exist is rejected.
- You cannot MOVE a resource. Edits to what places it -- subnet_id,
  subnet_ids, subnets, vpc_config, network_configuration, vpc_id, cluster,
  cluster_name, cluster_identifier, db_subnet_group_name,
  subnet_group_name, nat_gateway_id, event_source_arn, redrive_policy --
  are refused: the engine builds its graph from them once. Fix placement
  problems through capacity or failover attributes (desired_count,
  scaling_config.desired_size, num_cache_clusters,
  automatic_failover_enabled, multi_az, availability_zone), or say in the
  explanation that the Terraform itself must change.
- The engine will re-simulate the scenario with your edits applied; only
  verified fixes (those that make the chain empty) count as resolutions.
- If no set_attr edit can plausibly resolve the chain inside the
  attr-only rewrite surface, return an empty edits list and explain why
  in the explanation field — do not fabricate.
"""

FIX_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["scenario_name", "explanation", "edits"],
    "properties": {
        "scenario_name": {"type": "string"},
        "explanation": {"type": "string"},
        "edits": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["op", "resource_id", "key", "value"],
                "properties": {
                    "op": {"type": "string", "enum": ["set_attr"]},
                    "resource_id": {"type": "string"},
                    "key": {"type": "string"},
                    "value": {},
                },
            },
        },
    },
}


def propose_fix(
    chain: FailureChain,
    *,
    attrs_snapshot: dict[str, dict[str, Any]],
    client: Any,
) -> FixProposal:
    """Ask Claude for a FixProposal resolving `chain`, grounded in `attrs_snapshot`.

    `client` is an `anthropic.Anthropic` (or duck-typed compatible) instance.
    `attrs_snapshot` maps resource_id → the current Terraform attrs — Claude
    must only touch ids that appear here.
    """
    user_payload = json.dumps(
        {"chain": chain.model_dump(), "attrs_snapshot": attrs_snapshot},
        indent=2,
    )
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
        output_config={"format": {"type": "json_schema", "schema": FIX_SCHEMA}},
        messages=[{"role": "user", "content": user_payload}],
    )
    for block in response.content:
        if getattr(block, "type", None) == "text":
            # Fail closed: whatever the provider returned is only a FixProposal if it validates.
            try:
                return FixProposal.model_validate_json(block.text)
            except ValidationError as exc:
                raise RuntimeError(f"model output is not a valid FixProposal: {exc}") from exc
    raise RuntimeError("Claude returned no text content")
