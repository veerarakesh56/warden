"""WARDEN as an MCP server.

Model Context Protocol is the open standard for giving an agent tools. Most MCP servers hand an
agent *more capability*. This one is unusual: the most valuable tool it exposes is
**`verify_remediation`**, which hands an agent a *constraint*.

Any MCP-capable client — Claude Desktop, an IDE agent, another orchestrator — can call WARDEN's
deterministic policy gate and be told, with policy ids, whether the action it was about to take is
allowed in production. **The safety layer becomes reusable by agents that were not written with one.**

Run it:

    warden-mcp                      # stdio transport, the usual MCP wiring

Built on the official `mcp` Python SDK v2 (2026-07-28 spec, stateless request/response core).
⚠ `mcp.server.fastmcp` does not exist in v2 — it was removed in the rework. This uses the low-level
`Server` with explicit `on_list_tools` / `on_call_tool` callbacks, which is the supported path.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import catalog, gate, read_scope
from .environments import default_environment_policies
from .models import (
    BLAST_RADIUS_ORDER,
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Severity,
)
from .redaction import redact, redact_many
from .tools import FixtureBackend, gather
from .verifier import MIN_CONFIDENCE, MIN_LOG_LINES, MIN_METRICS, verify

_env_policies = default_environment_policies()

SERVER_NAME = "warden"
SERVER_VERSION = "0.10.0"



def _count(args: dict, key: str, ceiling: int = 1000) -> int:
    """A caller's count, clamped: the schema's bounds are advice to the client, not enforced by the
    dispatcher, and `log_lines: 10**9` would build a billion-item list (2026-09-27 audit)."""
    try:
        return min(max(int(args.get(key, 0)), 0), ceiling)
    except (TypeError, ValueError):
        return 0

def _tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="verify_remediation",
            title="Verify a remediation against WARDEN policy",
            description=(
                "Decide whether a proposed infrastructure remediation is allowed. Returns a verdict "
                "(escalated / rejected / auto_safe) with the policy ids that fired. The evidence counts "
                "are your claim, not read by WARDEN, so a mutating action is at best `escalated`: a "
                "person checks the real evidence. `verdict_on_claimed_evidence` says what the gate "
                "would decide on the claims. This is a DETERMINISTIC gate - no model is involved. Call "
                "it before acting on any production system."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "environment": {
                        "type": "string",
                        "description": (
                            "Configured environments: "
                            + ", ".join(_env_policies.known_environments)
                            + ". Any other value resolves to the restrictive default (fails closed)."
                        ),
                    },
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "service": {"type": "string"},
                    "action": {
                        "type": "string",
                        "enum": [a.value for a in ActionKind],
                        "description": "Closed set. Anything outside it is rejected by construction.",
                    },
                    "target": {"type": "string"},
                    # ⚠ ADVISORY, both. WARDEN decides reversibility from a fixed per-action table
                    # (models.py::ACTION_FACTS) and enforces a per-action blast-radius floor, so a
                    # caller cannot widen its own permissions by claiming an action is reversible or
                    # narrow. Claiming irreversible still sends the proposal to a human (P10).
                    "blast_radius": {
                        "type": "string",
                        "enum": list(BLAST_RADIUS_ORDER),
                        "description": "Your honest estimate. WARDEN enforces a per-action floor; "
                                       "understating this cannot widen what is permitted.",
                    },
                    "reversible": {
                        "type": "boolean",
                        "description": "Advisory only. WARDEN classifies reversibility per action; "
                                       "claiming true does not make an action permitted.",
                    },
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    # Counts, not booleans. Policy P9 weighs how much evidence was actually
                    # gathered, and a boolean cannot express "two vague log lines" versus "a
                    # hundred". An earlier schema used has_logs: boolean and the gate could not
                    # tell the difference.
                    "log_lines": {
                        "type": "integer",
                        "default": 0,
                        "description": "How many log lines were gathered as evidence.",
                    },
                    "metric_count": {
                        "type": "integer",
                        "default": 0,
                        "description": "How many distinct metrics were gathered.",
                    },
                    "has_recent_deploy": {"type": "boolean", "default": False},
                    # Named evidence, so the evidence-aware policies can be evaluated here too: P11
                    # (e.g. oom_killed_containers + pods_ready/pods_total for scale_up,
                    # replica_lag_seconds for failover_replica) and P12 (any counted symptom). Without
                    # it those two policies see no evidence and stay silent.
                    "metrics": {
                        "type": "object",
                        "additionalProperties": {"type": "number"},
                        "description": "Optional named metrics as the backends report them, e.g. "
                                       "replica_lag_seconds, oom_killed_containers, pods_ready, "
                                       "pods_total, crashloop_containers, idle_in_transaction, "
                                       "locks_waiting, long_running_queries, connections_used_pct. "
                                       "P11 and P12 read these; without them they cannot fire. "
                                       "They count toward metric_count.",
                    },
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
                "Mask emails (incl. %40-encoded), IPv4/IPv6, UUIDs, PEM private keys, "
                "connection-string passwords, JWTs/bearer tokens, and cloud credentials across AWS "
                "(ARN, account/secret keys), GCP (AIza, ya29. tokens) and Azure (AccountKey, SAS "
                "sig), plus GitHub/GitLab/Slack/Stripe keys, password=/secret= values and tenant "
                "ids; every copy of a found secret is masked. It cannot see a secret no pattern knows. "
                "Use before putting logs into any prompt."
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
            title="Explain the WARDEN policy set",
            description="Return every gate policy, the per-environment action allow-list and the confidence threshold.",
            input_schema={"type": "object", "properties": {}},
        ),
    ]


# --------------------------------------------------------------------------- workflows
#
# ⛔ An agent may START a diagnosis, REQUEST a remediation and READ a workflow's state. It can never
# approve, sign, reset the kill switch or pass a credential: none of those is a tool, and a test fails
# if one appears. An approval is a person's signature (`warden approve`), made outside this server.

WORKFLOW_TOOLS = ("start_incident_diagnosis", "request_remediation", "workflow_status")
# The client's profile (audit A-B-H4): `read` (the default) may start a diagnosis and read its own workflows;
# `remediate` may also request a remediation. One stdio server serves one client, so the profile is the server's.
PROFILES = {"read": frozenset({"start_incident_diagnosis", "workflow_status"}),
            "remediate": frozenset(WORKFLOW_TOOLS)}


def profile() -> frozenset[str]:
    name = os.environ.get("WARDEN_MCP_PROFILE", "read")
    if name not in PROFILES:
        raise ValueError(f"WARDEN_MCP_PROFILE={name!r}; one of {', '.join(sorted(PROFILES))}")
    return PROFILES[name]


# The workflows THIS server started: `workflow_status` answers for those only (audit A-B-H4: it read any incident's
# report by id). ponytail: in memory, so a restarted server forgets them - its client starts again.
_STARTED: set[str] = set()


def _workflow_tools() -> list[types.Tool]:
    from .catalog import CATALOG

    return [
        types.Tool(
            name="start_incident_diagnosis",
            title="Diagnose an alert as a durable workflow",
            description=(
                "Start the IncidentWorkflow for one alert (workflow id inc-<alert_id>; the same alert "
                "twice is one incident). Read the verdict with workflow_status."
            ),
            input_schema={
                "type": "object",
                "properties": {"alert": {"type": "object", "properties": {
                    "alert_id": {"type": "string"}, "name": {"type": "string"}, "service": {"type": "string"},
                    "environment": {"type": "string"}, "severity": {"type": "string"},
                    "summary": {"type": "string"}, "labels": {"type": "object"}}}},
                "required": ["alert"],
            },
        ),
        types.Tool(
            name="request_remediation",
            title="Request a catalogue remediation (a person must approve it)",
            description=(
                "Start a RemediationWorkflow for one catalogue entry. It plans against live state and "
                "then WAITS for a person's signed approval; this server cannot give one. One open "
                "remediation per resource and environment; the resource's own environment must match."
            ),
            input_schema={
                "type": "object",
                "properties": {"incident_id": {"type": "string"}, "environment": {"type": "string"},
                               "service": {"type": "string"},
                               "entry": {"type": "string", "enum": sorted(CATALOG)},
                               "params": {"type": "object"}},
                "required": ["incident_id", "environment", "service", "entry", "params"],
            },
        ),
        types.Tool(
            name="workflow_status",
            title="Read a workflow's state",
            description="Stage, plan (with its hash) and, once finished, the result of a WARDEN workflow.",
            input_schema={"type": "object", "properties": {"workflow_id": {"type": "string"}},
                          "required": ["workflow_id"]},
        ),
    ]


async def call_workflow_tool(name: str, args: dict[str, Any], client: Any) -> types.CallToolResult:
    from temporalio.client import WorkflowExecutionStatus
    from temporalio.common import WorkflowIDReusePolicy
    from temporalio.exceptions import WorkflowAlreadyStartedError

    from . import runtime
    from .activities import FixRequest
    from .workflows import IncidentWorkflow, RemediationWorkflow

    try:
        if name in WORKFLOW_TOOLS and name not in profile():
            return _err(f"{name} is not allowed for this client (WARDEN_MCP_PROFILE)")
        if name == "start_incident_diagnosis":
            alert = Alert.model_validate(args.get("alert") or {})
            # Only the labels the operator's allowlist names steer a read (audit A-B-H4).
            alert, not_followed = read_scope.restrict(alert, read_scope.load())
            # Its own id space (audit A-B-L11): a caller cannot take the id alert intake will give a real alert.
            wid = f"inc-mcp-{alert.alert_id}"
            _STARTED.add(wid)
            try:
                # One alert is one incident, with one model budget: a completed run is not started again (fifth
                # review, 2026-10-01: each new run got a fresh budget); a FAILED run may be (sixth review).
                await client.start_workflow(IncidentWorkflow.run, alert, id=wid, task_queue=runtime.TASK_QUEUE,
                                            id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY)
            except WorkflowAlreadyStartedError:
                return _ok({"workflow_id": wid, "note": "this alert is already diagnosed or being diagnosed"})
            return _ok({"workflow_id": wid, **({"labels_not_followed": not_followed} if not_followed else {})})
        if name == "request_remediation":
            req = FixRequest.model_validate({k: args.get(k) for k in ("incident_id", "environment", "service",
                                                                     "entry", "params")})
            if req.entry not in catalog.CATALOG:
                return _err(f"{req.entry!r} is not in the catalogue")
            # One open remediation per resource and environment (register C3): keyed on what the fix changes, never
            # on the free-text service name - `orders` in two namespaces, or in dev and prod, are different targets.
            key = catalog.target_key(req.entry, req.params)
            wid = f"rem-{req.environment}-{hashlib.sha256(key.encode()).hexdigest()[:16]}"
            try:
                await client.start_workflow(RemediationWorkflow.run, req, id=wid, task_queue=runtime.TASK_QUEUE)
            except WorkflowAlreadyStartedError:
                return _err(f"a remediation for {key} in {req.environment} is already open ({wid})")
            _STARTED.add(wid)
            return _ok({"workflow_id": wid, "next": "a person reviews it with `warden status` and approves "
                                                    "with `warden approve`; this server cannot"})
        if name == "workflow_status":
            wid = str(args.get("workflow_id", ""))
            if wid not in _STARTED:
                return _err("this server did not start that workflow")
            handle = client.get_workflow_handle(wid)
            desc = await handle.describe()
            out: dict[str, Any] = {"workflow_id": wid, "type": desc.workflow_type, "status": desc.status.name}
            if desc.workflow_type == "RemediationWorkflow":
                stage, plan = await runtime.status(client, wid)
                out["stage"] = stage
                if plan:
                    out["plan"] = plan.model_dump(mode="json", include={"entry", "params", "tier", "plan_hash", "target",
                                                                         "problems"})
            if desc.status == WorkflowExecutionStatus.COMPLETED:
                result = await handle.result()  # an untyped handle decodes to plain JSON already
                out["result"] = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
                if isinstance(out["result"], dict):
                    # The verdict and the proposal, never the evidence read (audit A-B-H4: raw context).
                    out["result"].pop("context", None)
            return _ok(out)
        return _err(f"unknown tool: {name}")
    except Exception as exc:  # noqa: BLE001 - an MCP tool must return an error, not crash the server
        return _err(f"{type(exc).__name__}: {exc}")


def _ok(payload: dict[str, Any], *, scrub_links: bool = True) -> types.CallToolResult:
    # ⛔ Audit A-C-8: an MCP result goes to another program, often another model. Same gate.
    # `scrub_links=False` only for redact_text, whose whole purpose is to hand back the caller's own
    # text with identifiers masked: its links are the caller's data. G5 and control stripping still apply.
    if scrub_links:
        _verdict, payload = gate.outbound_data(payload)
    elif gate.data_leaks(payload):
        payload = {"withheld": True, "reasons": [f"G5: {k}" for k in gate.data_leaks(payload)]}
    else:
        payload = {k: gate.strip_controls(v) if isinstance(v, str) else v for k, v in payload.items()}
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, indent=2))],
        structured_content=payload,
    )


def _err(message: str) -> types.CallToolResult:
    # Checked as it arrived and as it leaves: G3 removing a control or a tag can glue a key back together (ninth
    # review: `unknown tool: x<BEL>AKIA...` went out whole).
    message = gate.for_terminal(message)
    message = gate.for_terminal(gate.sanitise_text(message))  # exception text can quote evidence
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
            named = {str(k): float(v) for k, v in (args.get("metrics") or {}).items()}
            context = ContextBundle(
                logs=["evidence line"] * _count(args, "log_lines"),
                # Named metrics COUNT TOWARD metric_count; only the gap is padded with anonymous zeros.
                # Adding both double-counted the evidence and let P9 pass on half of it.
                metrics={
                    **{f"m{i}": 0.0 for i in range(max(0, _count(args, "metric_count") - len(named)))},
                    **named,
                },
                recent_deploys=[{"sha": "unknown"}] if args.get("has_recent_deploy") else [],
                tool_errors=["upstream tool failed"] * _count(args, "tool_errors"),
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
            # No evidence text reaches this tool, only counts, so there is nothing to ground a claim
            # or resolve a target against: P13/P14 are not evaluated, and the response says so.
            verdict = verify(alert, context, root_cause, proposal, check_grounding=False)
            on_claims = verdict.status.value
            policies, reasons = list(verdict.policy_ids), list(verdict.reasons)
            # ⛔ The evidence here is the CALLER's claim (counts padded into synthetic lines): claiming
            # log_lines=5, metric_count=4 satisfied P9 without WARDEN reading anything. So the verdict
            # that authorises a mutating action is never given on claims - a person checks the real
            # evidence (Phase 0, 2026-09-27). auto_safe covers only inert actions and stays.
            status = on_claims
            if on_claims == "approved_for_human":
                status = "escalated"
                policies.append("MCP-CLAIMED-EVIDENCE")
                reasons.append("The evidence counts were supplied by the caller, not read by WARDEN: "
                               "a person must check the real evidence before approving.")
            return _ok(
                {
                    "verdict": status,
                    "verdict_on_claimed_evidence": on_claims,
                    "requires_approval": verdict.requires_approval,
                    "policies_fired": policies,
                    "reasons": reasons,
                    # What the gate actually enforced, so a caller can see it was overruled rather
                    # than wondering why its "reversible": true was ignored.
                    "blast_radius_enforced": proposal.effective_blast_radius,
                    "reversible_by_table": proposal.table_reversible,
                    "grounding": "not checked: this tool receives evidence counts, not evidence",
                    "may_execute": False,
                    "note": "This MCP server never executes anything. A human performs the action.",
                }
            )

        if name == "redact_text":
            result = redact(args["text"])
            return _ok({"redacted": result.text, "identifiers_masked": result.size}, scrub_links=False)

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
            # ONE text (second review, 2026-09-30): logs, deploys and tool errors share one map, so one
            # host is one placeholder and a secret found anywhere is masked everywhere.
            deploy_keys = [(i, k) for i, d in enumerate(ctx.recent_deploys) for k in d]
            texts = [*ctx.logs, *(str(ctx.recent_deploys[i][k]) for i, k in deploy_keys), *ctx.tool_errors]
            out, mapping = redact_many(texts)
            redacted = out[:len(ctx.logs)]
            redacted_deploys = [{} for _ in ctx.recent_deploys]
            for (i, k), text in zip(deploy_keys, out[len(ctx.logs):len(ctx.logs) + len(deploy_keys)], strict=True):
                redacted_deploys[i][k] = text
            redacted_errors = out[len(ctx.logs) + len(deploy_keys):]
            # recent_deploys must be scrubbed too. This handler reads the bundled fixtures only, whose
            # deploys carry identifiers; a live backend's would carry ECR refs (the host embeds the
            # account id) and role ARNs. This payload goes to the external MCP client/model; returning deploys raw was the same leak
            # the graph path had (fixed there), on a second code path. Tool errors share the map
            # (audit A-C-5); metrics are floats.
            return _ok(
                {
                    "logs": redacted,
                    "metrics": ctx.metrics,
                    "recent_deploys": redacted_deploys,
                    "tool_errors": redacted_errors,
                    "identifiers_masked": len(mapping),
                }
            )

        if name == "describe_policy":
            return _ok(
                {
                    "policies": {
                        "P1-ENV-ALLOWLIST": "action must be permitted in this environment",
                        "P2-IRREVERSIBLE-IN-PROD": (
                            "nothing irreversible in production, at any confidence - reversibility "
                            "comes from WARDEN's per-action table, never from the caller's claim"
                        ),
                        "P3-NO-EVIDENCE": "no logs, metrics or deploys gathered means no action",
                        "P4-LOW-CONFIDENCE": f"confidence below {MIN_CONFIDENCE} escalates",
                        "P5-NO-DEPLOY-TO-ROLL-BACK": "cannot roll back a deploy absent from the evidence",
                        "P6-BLAST-RADIUS": (
                            "multi_service or region always needs a human - measured as the wider "
                            "of WARDEN's per-action floor and the claim, so understating it buys "
                            "nothing"
                        ),
                        "P7-DISPROPORTIONATE": "heavy actions on low/medium severity escalate",
                        "P8-PARTIAL-CONTEXT": "a failed context tool means incomplete evidence",
                        "P9-THIN-EVIDENCE": (
                            "too little evidence was gathered to justify acting, regardless of "
                            "stated confidence - counted by WARDEN, not claimed by the model"
                        ),
                        "P10-CLAIM-CONTRADICTS-TABLE": (
                            "the proposal says the action is irreversible while WARDEN's table "
                            "says it is not; a human reconciles that before anything runs"
                        ),
                        "P11-ACTION-CONTRADICTS-EVIDENCE": (
                            "the action cannot fix what the evidence shows - e.g. scale_up while "
                            "every pod is OOM-killed and failing, restart_pods on an image pull "
                            "error, failover_replica with no replica lag"
                        ),
                        "P12-NO-ACTION-WITH-SYMPTOMS": (
                            "'nothing to do' while WARDEN counts a symptom in the evidence "
                            "escalates; a quiet no_action cannot close a live incident"
                        ),
                        "P13-UNGROUNDED": (
                            "every citation in the diagnosis must name a real evidence id and quote "
                            "it verbatim; none, or any invented one, escalates (not evaluated here: "
                            "this tool receives counts, not evidence)"
                        ),
                        "P16-SUSPECTED-INJECTION": (
                            "a trained injection detector (Meta Llama Prompt Guard 2, run locally) "
                            "flagged an untrusted log line or event, or it was required and could "
                            "not run; escalates (not evaluated here)"
                        ),
                        "P15-CITATIONS-DO-NOT-SUPPORT-ACTION": (
                            "a real action must cite at least one item that bears on it (e.g. a "
                            "rollback cites a deploy, a terminate cites stuck sessions); escalates "
                            "(not evaluated here)"
                        ),
                        "P14-TARGET-NOT-IN-EVIDENCE": (
                            "the target must name a resource WARDEN knows exists (service, alert "
                            "labels, deploys, metric resources); anything else is rejected (not "
                            "evaluated here)"
                        ),
                    },
                    "environment_allowlist": {
                        env: sorted(
                            a.value
                            for a in ActionKind
                            if _env_policies.for_env(env).permits(a)
                        )
                        for env in _env_policies.known_environments
                    },
                    "min_confidence": MIN_CONFIDENCE,
                    "min_evidence": {"log_lines": MIN_LOG_LINES, "metrics": MIN_METRICS},
                }
            )

        return _err(f"unknown tool: {name}")
    except Exception as exc:  # noqa: BLE001 - an MCP tool must return an error, not crash the server
        return _err(f"{type(exc).__name__}: {exc}")


def build_server() -> Server:
    client = None

    async def on_list_tools(ctx, params):
        allowed = profile()
        return types.ListToolsResult(tools=_tools() + [t for t in _workflow_tools() if t.name in allowed])

    async def on_call_tool(ctx, params):
        nonlocal client
        if params.name in WORKFLOW_TOOLS:
            from . import runtime

            try:
                client = client or await runtime.connect()
            except Exception as exc:  # noqa: BLE001
                return _err(f"the workflow service is not reachable: {type(exc).__name__}: {exc}")
            return await call_workflow_tool(params.name, dict(params.arguments or {}), client)
        return call_tool(params.name, dict(params.arguments or {}))

    return Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        instructions=(
            "WARDEN exposes a deterministic safety gate for infrastructure remediation. Call "
            "verify_remediation before acting on any production system; it returns a binding "
            "verdict with policy ids. This server never executes anything; may_execute is always false."
        ),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def main() -> int:
    """The MCP server. An uncaught error - at startup or while serving - is one gated line on stderr,
    never a raw traceback: stdout is the protocol, and the text can quote evidence or a key (fourth
    review, 2026-09-30, A-8). Warnings go through the same gate."""
    import logging

    from .observability import exit_message, install_log_gate

    install_log_gate()  # stderr only: stdout is the protocol; warnings and uncaught errors gated too
    log = logging.getLogger("warden.mcp")
    try:
        return _serve()
    except SystemExit as exc:
        message = exit_message(exc.code)
        if message is not None:
            log.error("error: %s", message)
            return 2
        raise
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # noqa: BLE001 - the last line of defence for what reaches the terminal
        log.error("error: %s: %s", type(exc).__name__, exc)
        return 1


def _serve() -> int:
    import anyio

    from .cli import _load_environment

    _load_environment("mcp")

    async def _run() -> None:
        server = build_server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
