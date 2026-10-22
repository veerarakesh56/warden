"""B37: every MCP tool declares an outputSchema, and what each tool really returns conforms to it.

The SDK's own client validates a successful result against the declared schema and raises on a mismatch, so a
result that drifted from its schema would break every client that calls the tool. These tests call the tools for
real (the gate tools directly and through an in-process client; the workflow tools with a stand-in Temporal client)
and validate every result.
"""

from __future__ import annotations

import asyncio
import types as pytypes

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from mcp.client import Client
from temporalio.client import WorkflowExecutionStatus

from fakes import AWS_ACCESS_KEY_ID
from warden import mcp_schemas, mcp_server
from warden.approvals import Plan
from warden.models import ActionKind

ALL_TOOLS = sorted(mcp_schemas.OUTPUT_SCHEMAS)


def _validate(tool: str, structured: dict) -> None:
    Draft202012Validator(mcp_schemas.OUTPUT_SCHEMAS[tool]).validate(structured)


def _ok(tool: str, result) -> dict:
    assert not result.is_error, result.content[0].text
    _validate(tool, result.structured_content)
    return result.structured_content


def _verify_args(**over):
    args = {"environment": "dev", "severity": "high", "service": "orders", "action": "restart_pods",
            "target": "orders", "blast_radius": "single_service", "reversible": True, "confidence": 0.9,
            "log_lines": 20, "metric_count": 4}
    return args | over


@pytest.fixture(autouse=True)
def _remediate_profile(monkeypatch):
    monkeypatch.setenv("WARDEN_MCP_PROFILE", "remediate")
    monkeypatch.setattr(mcp_server, "_STARTED", set())


def test_every_tool_declares_a_valid_object_schema():
    served = mcp_server._tools() + mcp_server._workflow_tools()
    assert {t.name for t in served} == set(mcp_schemas.OUTPUT_SCHEMAS) == set(mcp_server.ANNOTATIONS)
    for tool in mcp_server.listed_tools():
        assert tool.output_schema == mcp_schemas.OUTPUT_SCHEMAS[tool.name], tool.name
        assert tool.output_schema["type"] == "object"  # an object root, as the wire requires
        Draft202012Validator.check_schema(tool.output_schema)


@pytest.mark.parametrize("over", [
    {},                                                         # escalated: claimed evidence goes to a person
    {"action": "escalate_to_human", "blast_radius": "single_pod"},  # inert: hand-off to a person
    {"action": "scale_down", "environment": "prod"},           # rejected: irreversible in production
    {"confidence": 0.1, "log_lines": 0, "metric_count": 0, "tool_errors": 2, "has_recent_deploy": True,
     "metrics": {"replica_lag_seconds": 0.0}},
])
def test_verify_remediation_results_conform(over):
    out = _ok("verify_remediation", mcp_server.call_tool("verify_remediation", _verify_args(**over)))
    assert out["may_execute"] is False


def test_the_schema_refuses_an_unchecked_approval():
    """The schema states the rule the code keeps: a verdict on claimed evidence is never approved_for_human."""
    out = mcp_server.call_tool("verify_remediation", _verify_args()).structured_content
    assert out["verdict"] == "escalated"
    assert out["verdict_on_claimed_evidence"] == "approved_for_human"
    with pytest.raises(ValidationError):
        _validate("verify_remediation", out | {"verdict": "approved_for_human"})
    with pytest.raises(ValidationError):
        _validate("verify_remediation", out | {"may_execute": True})
    with pytest.raises(ValidationError):  # strict: a new field is a reviewed change to mcp_schemas.py
        _validate("verify_remediation", out | {"extra": 1})


@pytest.mark.parametrize("text", ["", "user a@example.com from 10.0.0.1", f"key {AWS_ACCESS_KEY_ID} here"])
def test_redact_text_results_conform(text):
    _ok("redact_text", mcp_server.call_tool("redact_text", {"text": text}))


@pytest.mark.parametrize("alert_id", [f"inc-00{i}" for i in range(1, 6)] + ["inc-none"])
def test_gather_incident_context_results_conform(alert_id):
    _ok("gather_incident_context", mcp_server.call_tool("gather_incident_context", {"alert_id": alert_id}))


def test_describe_policy_result_conforms():
    out = _ok("describe_policy", mcp_server.call_tool("describe_policy", {}))
    assert set(out["environment_allowlist"])
    assert all(set(v) <= {a.value for a in ActionKind} for v in out["environment_allowlist"].values())


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_a_withheld_result_conforms_to_every_schema(tool):
    """The outbound gate replaces a payload that carried a secret with {withheld, reasons}: still a valid result."""
    withheld = mcp_server._ok({"leak": f"id {AWS_ACCESS_KEY_ID}"}).structured_content
    assert withheld["withheld"] is True
    _validate(tool, withheld)
    with pytest.raises(ValidationError):
        _validate(tool, {"withheld": True, "reasons": []})


class _Handle:
    def __init__(self, workflow_type: str, status: WorkflowExecutionStatus, result=None):
        self._desc = pytypes.SimpleNamespace(workflow_type=workflow_type, status=status)
        self._result = result

    async def describe(self):
        return self._desc

    async def query(self, q):
        if "stage" in getattr(q, "__name__", ""):
            return "awaiting_approval"
        return Plan(workflow_id="rem-dev-x", incident_id="inc-1", entry="k8s_restart", tier="T1",
                    params={"namespace": "shop"}, plan_hash="0" * 64, created_at="2026-10-21T00:00:00Z",
                    target="dev/k8s:shop/orders", problems=[])

    async def result(self):
        return self._result


def _client(handle=None):
    async def start_workflow(*_a, **_kw):
        return None

    return pytypes.SimpleNamespace(start_workflow=start_workflow, get_workflow_handle=lambda _wid: handle)


def test_workflow_tool_results_conform(monkeypatch):
    monkeypatch.delenv("WARDEN_READ_SCOPES", raising=False)
    call = mcp_server.call_workflow_tool
    alert = {"alert_id": "a1", "name": "n", "service": "orders", "environment": "dev", "severity": "high",
             "summary": "s", "labels": {"namespace": "kube-system"}}
    started = _ok("start_incident_diagnosis", asyncio.run(call("start_incident_diagnosis", {"alert": alert},
                                                                _client())))
    assert started["labels_not_followed"] == ["namespace"]
    req = {"incident_id": "inc-1", "environment": "dev", "service": "orders", "entry": "k8s_rollout_undo",
           "params": {"namespace": "shop", "deployment": "orders"}}
    asked = _ok("request_remediation", asyncio.run(call("request_remediation", req, _client())))

    running = _Handle("RemediationWorkflow", WorkflowExecutionStatus.RUNNING)
    status = _ok("workflow_status", asyncio.run(call("workflow_status", {"workflow_id": asked["workflow_id"]},
                                                     _client(running))))
    assert status["stage"] == "awaiting_approval"
    assert len(status["plan"]["plan_hash"]) == 64

    done = _Handle("IncidentWorkflow", WorkflowExecutionStatus.COMPLETED,
                   result={"verdict": {"status": "escalated"}, "context": {"logs": ["read"]}})
    finished = _ok("workflow_status", asyncio.run(call("workflow_status", {"workflow_id": started["workflow_id"]},
                                                       _client(done))))
    assert "context" not in finished["result"]
    with pytest.raises(ValidationError):  # the evidence read never leaves through this tool
        _validate("workflow_status", finished | {"result": {"context": {}}})


def test_an_in_process_client_validates_every_gate_tool_result():
    """The SDK's client checks each result against the listed schema - a mismatch raises there, not here."""
    async def main():
        async with Client(mcp_server.build_server()) as client:
            listed = {t.name: t for t in (await client.list_tools()).tools}
            assert all(listed[n].output_schema == mcp_schemas.OUTPUT_SCHEMAS[n] for n in listed)
            for name, args in [("verify_remediation", _verify_args()), ("redact_text", {"text": "a@example.com"}),
                               ("gather_incident_context", {"alert_id": "inc-001"}), ("describe_policy", {})]:
                result = await client.call_tool(name, args)
                assert not result.is_error
                assert result.structured_content
    asyncio.run(main())


def test_the_client_rejects_a_result_that_breaks_its_schema(monkeypatch):
    """Shows the validation above is live: a declared field the tool never returns is an error at the client."""
    broken = mcp_schemas._schema(mcp_schemas._strict({"redacted": {"type": "string"}, "missing": {"type": "string"}}))
    monkeypatch.setitem(mcp_schemas.OUTPUT_SCHEMAS, "redact_text", broken)

    async def main():
        async with Client(mcp_server.build_server()) as client:
            with pytest.raises(RuntimeError, match="Invalid structured content returned by tool redact_text"):
                await client.call_tool("redact_text", {"text": "hello"})
    asyncio.run(main())
