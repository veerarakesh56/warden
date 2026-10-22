"""The shape of every MCP tool's result: the `outputSchema` each tool declares (B37).

MCP 2025-06-18 and later: a tool that declares an `outputSchema` MUST return `structuredContent` that
conforms to it, and a client SHOULD validate it (the official SDK's client does, for every result that
is not an error). A declared shape lets another program - often another model - read WARDEN's answer
without guessing, and `tests/test_mcp_output_schema.py` holds every tool's real results to it.

Every successful result has one of two shapes: the tool's own, or `WITHHELD` - what the outbound gate
(`gate.outbound_data`, G5) hands back instead when the data carried a secret. Error results
(`isError: true`) carry text only and are never validated against these.

The shapes are strict (`additionalProperties: false`) where WARDEN builds the object itself, so a new
field is a reviewed change to this file; they stay open only where the content is data WARDEN passes on
(named metrics, a deploy's recorded fields, a finished workflow's result).
"""

from __future__ import annotations

from typing import Any

from .models import BLAST_RADIUS_ORDER, VerdictStatus

_STR_LIST: dict[str, Any] = {"type": "array", "items": {"type": "string"}}
_COUNT: dict[str, Any] = {"type": "integer", "minimum": 0}

# What the outbound gate returns in place of a payload that carried a secret (gate.outbound_data, _ok).
WITHHELD: dict[str, Any] = {
    "type": "object",
    "properties": {"withheld": {"const": True}, "reasons": {**_STR_LIST, "minItems": 1}},
    "required": ["withheld", "reasons"],
    "additionalProperties": False,
}


def _strict(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required or sorted(properties),
            "additionalProperties": False}


def _schema(own: dict[str, Any]) -> dict[str, Any]:
    """A tool's outputSchema: an object root (required on the wire) that is its own shape or WITHHELD."""
    return {"type": "object", "anyOf": [own, WITHHELD]}


_VERDICTS = [v.value for v in VerdictStatus]

VERIFY_REMEDIATION = _strict({
    # Never approved_for_human: a verdict on the caller's claimed evidence is escalated to a person instead.
    "verdict": {"type": "string", "enum": [v for v in _VERDICTS if v != VerdictStatus.approved_for_human.value]},
    "verdict_on_claimed_evidence": {"type": "string", "enum": _VERDICTS},
    "requires_approval": {"type": "boolean"},
    "policies_fired": _STR_LIST,
    "reasons": _STR_LIST,
    "blast_radius_enforced": {"type": "string", "enum": list(BLAST_RADIUS_ORDER)},
    "reversible_by_table": {"type": "boolean"},
    "grounding": {"type": "string"},
    "may_execute": {"const": False},  # no call through this server executes anything
    "note": {"type": "string"},
})

REDACT_TEXT = _strict({"redacted": {"type": "string"}, "identifiers_masked": _COUNT})

GATHER_INCIDENT_CONTEXT = _strict({
    "logs": _STR_LIST,
    "metrics": {"type": "object", "additionalProperties": {"type": "number"}},
    # Every value redacted to text (mcp_server.call_tool): a deploy's fields are the recording's own names.
    "recent_deploys": {"type": "array", "items": {"type": "object", "additionalProperties": {"type": "string"}}},
    "tool_errors": _STR_LIST,
    "identifiers_masked": _COUNT,
})

DESCRIBE_POLICY = _strict({
    "policies": {"type": "object", "minProperties": 1, "additionalProperties": {"type": "string"}},
    "environment_allowlist": {"type": "object", "additionalProperties": _STR_LIST},
    "min_confidence": {"type": "number", "minimum": 0, "maximum": 1},
    "min_evidence": _strict({"log_lines": _COUNT, "metrics": _COUNT}),
})

START_INCIDENT_DIAGNOSIS = _strict(
    {"workflow_id": {"type": "string", "pattern": "^inc-mcp-"}, "note": {"type": "string"},
     "labels_not_followed": _STR_LIST},
    required=["workflow_id"],
)

REQUEST_REMEDIATION = _strict({"workflow_id": {"type": "string", "pattern": "^rem-"}, "next": {"type": "string"}})

WORKFLOW_STATUS = _strict(
    {"workflow_id": {"type": "string"}, "type": {"type": "string"}, "status": {"type": "string"},
     "stage": {"type": "string"},
     "plan": _strict({"entry": {"type": "string"}, "params": {"type": "object"}, "tier": {"type": "string"},
                      "plan_hash": {"type": "string"}, "target": {"type": "string"}, "problems": _STR_LIST}),
     # A finished workflow's result, as the workflow returned it - minus the evidence it read (`context`).
     "result": {"not": {"type": "object", "required": ["context"]}}},
    required=["workflow_id", "type", "status"],
)

OUTPUT_SCHEMAS: dict[str, dict[str, Any]] = {
    "verify_remediation": _schema(VERIFY_REMEDIATION),
    "redact_text": _schema(REDACT_TEXT),
    "gather_incident_context": _schema(GATHER_INCIDENT_CONTEXT),
    "describe_policy": _schema(DESCRIBE_POLICY),
    "start_incident_diagnosis": _schema(START_INCIDENT_DIAGNOSIS),
    "request_remediation": _schema(REQUEST_REMEDIATION),
    "workflow_status": _schema(WORKFLOW_STATUS),
}
