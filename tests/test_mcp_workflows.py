"""MCP workflow tools: an agent can start, request and read - never approve."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import pathlib
import re
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment

from test_remediation_workflow import REQ, FakePlatform
from warden import audit, codec, mcp_server, runtime
from warden.cli import _alert_from
from warden.llm import LLMClient

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "src" / "warden" / "data" / "mcp_manifest.sha256"
FORBIDDEN_TOOL = re.compile(r"approv|sign|killswitch|kill_switch|reset|apply|execut|shell", re.IGNORECASE)
FORBIDDEN_PARAM = re.compile(r"key|secret|token|passw|credential|signature|approval|nonce", re.IGNORECASE)


def _all_tools():
    return mcp_server._tools() + mcp_server._workflow_tools()


def _param_names(schema):
    for name, sub in (schema.get("properties") or {}).items():
        yield name
        if isinstance(sub, dict):
            yield from _param_names(sub)


def test_no_tool_can_approve_sign_reset_or_execute_and_none_takes_a_credential():
    for tool in _all_tools():
        assert not FORBIDDEN_TOOL.search(tool.name), tool.name
        bad = [p for p in _param_names(tool.input_schema) if FORBIDDEN_PARAM.search(p)]
        assert not bad, (tool.name, bad)


def test_the_tool_manifest_is_pinned():
    """Changing what an agent can do must be a reviewed change: update the hash in the same commit.
    (python -c "from tests.test_mcp_workflows import manifest_hash; print(manifest_hash())")"""
    assert manifest_hash() == MANIFEST.read_text(encoding="utf-8").strip()


def manifest_hash() -> str:
    tools = [{"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in _all_tools()]
    return hashlib.sha256(json.dumps(tools, sort_keys=True).encode()).hexdigest()


def test_start_request_and_read_through_the_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_MCP_PROFILE", "remediate")
    owner = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    from warden import approvals
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T2"])})
    log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, runtime.serving(env.client, log=log, policy=policy, platform=FakePlatform(),
                                       llm_factory=lambda: LLMClient(mock=True)):
            call = mcp_server.call_workflow_tool
            alert = _alert_from("inc-001").model_dump(mode="json")
            started = (await call("start_incident_diagnosis", {"alert": alert}, env.client)).structured_content
            assert started == {"workflow_id": "inc-mcp-inc-001"}
            for _ in range(200):
                raw = await call("workflow_status", {"workflow_id": "inc-mcp-inc-001"}, env.client)
                assert not raw.is_error, raw.content[0].text
                status = raw.structured_content
                if status["status"] == "COMPLETED":
                    break
                await asyncio.sleep(0.05)
            assert status["result"]["verdict"]["status"]
            assert "redaction_map" not in status["result"]
            assert "context" not in status["result"]  # the verdict, never the evidence read (audit A-B-H4)

            req = {k: REQ[k] for k in ("environment", "service", "entry", "params")} | {"incident_id": "inc-inc-001"}
            asked = (await call("request_remediation", req, env.client)).structured_content
            # keyed on the resource and environment, not the service name (register C3)
            wid = "rem-dev-" + hashlib.sha256(b"k8s:shop/orders").hexdigest()[:16]
            assert asked["workflow_id"] == wid and "cannot" in asked["next"]
            again = await call("request_remediation", req, env.client)
            assert again.is_error and "already open" in again.content[0].text
            for _ in range(200):
                status = (await call("workflow_status", {"workflow_id": wid}, env.client)).structured_content
                if status.get("stage") == "awaiting_approval":
                    break
                await asyncio.sleep(0.05)
            assert status["plan"]["entry"] == "k8s_rollout_undo" and len(status["plan"]["plan_hash"]) == 64
            # the only way forward is a person's signature, outside the MCP server:
            await runtime.approve(env.client, wid, plan_hash=status["plan"]["plan_hash"], key=owner,
                                  approver="owner", typed_target=status["plan"]["target"])
            for _ in range(20):  # a handle fetched by id does not auto-skip time; advance it explicitly
                status = (await call("workflow_status", {"workflow_id": wid}, env.client)).structured_content
                if status["status"] == "COMPLETED":
                    return status["result"]
                await env.sleep(timedelta(minutes=5))  # past the verify window and the T+60 re-check (C18a)
            raise AssertionError(status)
    assert asyncio.run(main())["status"] == "recovered"


def test_a_bad_request_is_an_error_not_a_crash(monkeypatch):
    monkeypatch.setenv("WARDEN_MCP_PROFILE", "remediate")
    async def main():
        return await mcp_server.call_workflow_tool("request_remediation", {"entry": "shell"}, client=None)
    result = asyncio.run(main())
    assert result.is_error and "ValidationError" in result.content[0].text


@pytest.mark.parametrize("entry", ["shell", "raw_sql", "put_role_policy", "purge_queue"])
def test_a_complete_request_for_an_excluded_action_is_refused_by_the_catalogue(entry):
    """Audit A-B-VT: the bad-request test above fails for missing fields, whatever the entry - it never showed that
    `shell` is refused. A complete request passes the request model; the catalogue refuses the action itself."""
    from warden import catalog
    from warden.activities import FixRequest

    req = FixRequest(incident_id="inc-1", service="orders", entry=entry, params={"cmd": "rm -rf /"}, environment="dev")
    assert catalog.validate(req.entry, req.params, {}) == [f"{entry!r} is not in the catalogue"]


def test_the_default_client_may_not_request_a_remediation(monkeypatch):
    """Audit A-B-H4: a client's profile decides its tools; the default is read-only."""
    monkeypatch.delenv("WARDEN_MCP_PROFILE", raising=False)

    async def main():
        return await mcp_server.call_workflow_tool("request_remediation", {"entry": "k8s_restart"}, client=None)
    refused = asyncio.run(main())
    assert refused.is_error and "not allowed for this client" in refused.content[0].text
    assert "request_remediation" not in mcp_server.profile() and "workflow_status" in mcp_server.profile()


def test_status_answers_only_for_workflows_this_server_started():
    """Audit A-B-H4: workflow_status read any incident's report by its id."""
    async def main():
        return await mcp_server.call_workflow_tool("workflow_status", {"workflow_id": "inc-someone-elses"}, client=None)
    result = asyncio.run(main())
    assert result.is_error and "did not start" in result.content[0].text


def test_a_caller_cannot_steer_reads_outside_the_allowlist(tmp_path, monkeypatch):
    """Audit A-B-H4: the caller's labels named what WARDEN read. Only values the operator lists are followed."""
    from warden import read_scope
    from warden.models import Alert

    scopes = tmp_path / "scopes.yaml"
    scopes.write_text("orders:\n  namespace: [shop]\n", encoding="utf-8")
    alert = Alert(alert_id="a1", name="n", service="orders", environment="dev", severity="high", summary="s",
                  labels={"namespace": "kube-system", "log_group": "/aws/lambda/prod-payments", "team": "core"})
    kept, dropped = read_scope.restrict(alert, read_scope.load(str(scopes)))
    assert kept.labels == {"team": "core"} and dropped == ["log_group", "namespace"]
    ok = alert.model_copy(update={"labels": {"namespace": "shop"}})
    assert read_scope.restrict(ok, read_scope.load(str(scopes)))[0].labels == {"namespace": "shop"}
    both = alert.model_copy(update={"labels": {"namespace": "shop,kube-system"}})
    assert read_scope.restrict(both, read_scope.load(str(scopes)))[1] == ["namespace"]
    monkeypatch.delenv("WARDEN_READ_SCOPES", raising=False)
    assert read_scope.restrict(ok, read_scope.load())[1] == ["namespace"]  # no allowlist: nothing steers


def test_the_workflow_starts_with_only_the_labels_the_allowlist_names(monkeypatch):
    """Audit A-B-H4: the restriction is applied to the alert the workflow is started with, not only reported."""
    import types

    monkeypatch.delenv("WARDEN_READ_SCOPES", raising=False)
    seen = {}

    async def start_workflow(fn, alert, **kw):
        seen["alert"], seen["id"] = alert, kw["id"]

    alert = {"alert_id": "a9", "name": "n", "service": "orders", "environment": "dev", "severity": "high",
             "summary": "s", "labels": {"namespace": "kube-system", "team": "core"}}
    out = asyncio.run(mcp_server.call_workflow_tool("start_incident_diagnosis", {"alert": alert},
                                                    client=types.SimpleNamespace(start_workflow=start_workflow)))
    assert not out.is_error, out.content[0].text
    assert seen["alert"].labels == {"team": "core"} and seen["id"] == "inc-mcp-a9"
    assert out.structured_content["labels_not_followed"] == ["namespace"]

