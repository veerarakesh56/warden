"""AEGIS as an MCP server.

Model Context Protocol is the open standard for giving an agent tools. Most MCP servers hand an
agent *more capability*. This one is unusual: the most valuable tool it exposes is
**`verify_remediation`**, which hands an agent a *constraint*.

Any MCP-capable client — Claude Desktop, an IDE agent, another orchestrator — can call AEGIS's
deterministic policy gate and be told, with policy ids, whether the action it was about to take is
allowed in production. **The safety layer becomes reusable by agents that were not written with one.**

Run it:

    aegis-mcp                      # stdio transport, the usual MCP wiring

Built on the official `mcp` Python SDK v2 (2026-07-28 spec, stateless request/response core).
⚠ `mcp.server.fastmcp` does not exist in v2 — it was removed in the rework. This uses the low-level
`Server` with explicit `on_list_tools` / `on_call_tool` callbacks, which is the supported path.
"""

from __future__ import annotations

import json
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from .models import (
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Severity,
)
from .redaction import redact
from .tools import FixtureBackend, gather
from .verifier import ENV_ALLOWED, MIN_CONFIDENCE, verify

SERVER_NAME = "aegis"
SERVER_VERSION = "0.3.0"


def _tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="verify_remediation",
            title="Verify a remediation against AEGIS policy",
            description=(
                "Decide whether a proposed infrastructure remediation is allowed. Returns a verdict "
                "(approved_for_human / escalated / rejected / auto_safe) with the policy ids that "
                "fired. This is a DETERMINISTIC gate - no model is involved in the decision. Call it "
                "before acting on any production system."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "environment": {"type": "string", "enum": ["prod", "staging", "dev"]},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "service": {"type": "string"},
                    "action": {
                        "type": "string",
                        "enum": [a.value for a in ActionKind],
                        "description": "Closed set. Anything outside it is rejected by construction.",
                    },
                    "target": {"type": "string"},
                    "blast_radius": {
                        "type": "string",
                        "enum": ["single_pod", "single_service", "multi_service", "region"],
                    },
                    "reversible": {"type": "boolean"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "has_logs": {"type": "boolean", "default": True},
                    "has_recent_deploy": {"type": "boolean", "default": False},
                    "tool_errors": {"type": "integer", "default": 0},
                },
                "required": [
                    "environment", "severity", "service", "action",
                    "target", "blast_radius", "reversible", "confidence",
                ],
            },
        ),
        types.Tool(
            name="redact_text",
            title="Redact identifiers before sending text to a model",
            description=(
                "Mask emails, IPs, UUIDs, ARNs, JWTs, API keys, AWS account ids and tenant "
                "identifiers. Verifies its own output and fails if any original value survived. Use "
                "before putting logs into any prompt."
            ),
            input_schema={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        ),
        types.Tool(
            name="gather_incident_context",
            title="Gather evidence for an incident",
            description=(
                "Fetch logs, metrics and recent deploys for a known incident id, each under a "
                "wall-clock timeout. Failures are returned as tool_errors rather than hidden, so a "
                "partial picture never looks like a complete one."
            ),
            input_schema={
                "type": "object",
                "properties": {"alert_id": {"type": "string"}},
                "required": ["alert_id"],
            },
        ),
        types.Tool(
            name="describe_policy",
            title="Explain the AEGIS policy set",
            description="Return the eight policies, the per-environment action allow-list and the confidence threshold.",
            input_schema={"type": "object", "properties": {}},
        ),
    ]


def _ok(payload: dict[str, Any]) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, indent=2))],
        structured_content=payload,
    )


def _err(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        is_error=True,
    )


def call_tool(name: str, args: dict[str, Any]) -> types.CallToolResult:
    """Pure dispatch — no transport, no async. Kept separate so it is directly testable."""
    try:
        if name == "verify_remediation":
            alert = Alert(
                alert_id="mcp",
                name="external",
                severity=Severity(args["severity"]),
                service=args["service"],
                environment=args["environment"],
                summary="submitted via MCP",
                started_at="1970-01-01T00:00:00Z",
            )
            context = ContextBundle(
                logs=["evidence present"] if args.get("has_logs", True) else [],
                recent_deploys=[{"sha": "unknown"}] if args.get("has_recent_deploy") else [],
                tool_errors=["upstream tool failed"] * int(args.get("tool_errors", 0)),
            )
            root_cause = RootCause(hypothesis="submitted via MCP", confidence=args["confidence"])
            proposal = RemediationProposal(
                action=ActionKind(args["action"]),
                target=args["target"],
                reasoning="submitted via MCP",
                expected_effect="unknown",
                blast_radius=args["blast_radius"],
                reversible=args["reversible"],
            )
            verdict = verify(alert, context, root_cause, proposal)
            return _ok(
                {
                    "verdict": verdict.status.value,
                    "requires_approval": verdict.requires_approval,
                    "policies_fired": verdict.policy_ids,
                    "reasons": verdict.reasons,
                    "may_execute": False,
                    "note": "AEGIS never executes. A human performs the action.",
                }
            )

        if name == "redact_text":
            result = redact(args["text"])
            return _ok({"redacted": result.text, "identifiers_masked": result.size})

        if name == "gather_incident_context":
            alert = Alert(
                alert_id=args["alert_id"],
                name="lookup",
                severity=Severity.medium,
                service="unknown",
                environment="prod",
                summary="context lookup via MCP",
                started_at="1970-01-01T00:00:00Z",
            )
            ctx = gather(alert, FixtureBackend())
            redacted, mapping = [], {}
            for line in ctx.logs:
                r = redact(line, mapping=mapping)
                mapping = r.mapping
                redacted.append(r.text)
            return _ok(
                {
                    "logs": redacted,
                    "metrics": ctx.metrics,
                    "recent_deploys": ctx.recent_deploys,
                    "tool_errors": ctx.tool_errors,
                    "identifiers_masked": len(mapping),
                }
            )

        if name == "describe_policy":
            return _ok(
                {
                    "policies": {
                        "P1-ENV-ALLOWLIST": "action must be permitted in this environment",
                        "P2-IRREVERSIBLE-IN-PROD": "nothing irreversible in production, at any confidence",
                        "P3-NO-EVIDENCE": "no logs, metrics or deploys gathered means no action",
                        "P4-LOW-CONFIDENCE": f"confidence below {MIN_CONFIDENCE} escalates",
                        "P5-NO-DEPLOY-TO-ROLL-BACK": "cannot roll back a deploy absent from the evidence",
                        "P6-BLAST-RADIUS": "multi_service or region always needs a human",
                        "P7-DISPROPORTIONATE": "heavy actions on low/medium severity escalate",
                        "P8-PARTIAL-CONTEXT": "a failed context tool means incomplete evidence",
                    },
                    "environment_allowlist": {
                        env: sorted(a.value for a in actions) for env, actions in ENV_ALLOWED.items()
                    },
                    "min_confidence": MIN_CONFIDENCE,
                }
            )

        return _err(f"unknown tool: {name}")
    except Exception as exc:  # noqa: BLE001 - an MCP tool must return an error, not crash the server
        return _err(f"{type(exc).__name__}: {exc}")


def build_server() -> Server:
    async def on_list_tools(ctx, params):
        return types.ListToolsResult(tools=_tools())

    async def on_call_tool(ctx, params):
        return call_tool(params.name, dict(params.arguments or {}))

    return Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        instructions=(
            "AEGIS exposes a deterministic safety gate for infrastructure remediation. Call "
            "verify_remediation before acting on any production system; it returns a binding "
            "verdict with policy ids. AEGIS never executes actions itself."
        ),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def main() -> int:
    import anyio

    async def _run() -> None:
        server = build_server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
