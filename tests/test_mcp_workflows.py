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


def test_start_request_and_read_through_the_tools(tmp_path):
    owner = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    from warden import approvals
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T2"])})
    log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, runtime.worker(env.client, log=log, policy=policy, platform=FakePlatform(),
                                       llm_factory=lambda: LLMClient(mock=True)):
            call = mcp_server.call_workflow_tool
            alert = _alert_from("inc-001").model_dump(mode="json")
            started = (await call("start_incident_diagnosis", {"alert": alert}, env.client)).structured_content
            assert started == {"workflow_id": "inc-inc-001"}
            for _ in range(200):
                raw = await call("workflow_status", {"workflow_id": "inc-inc-001"}, env.client)
                assert not raw.is_error, raw.content[0].text
                status = raw.structured_content
                if status["status"] == "COMPLETED":
                    break
                await asyncio.sleep(0.05)
            assert status["result"]["verdict"]["status"]
            assert "redaction_map" not in status["result"]

            req = {k: REQ[k] for k in ("service", "entry", "params")} | {"incident_id": "inc-inc-001"}
            asked = (await call("request_remediation", req, env.client)).structured_content
            assert asked["workflow_id"] == "rem-orders" and "cannot" in asked["next"]
            again = await call("request_remediation", req, env.client)
            assert again.is_error and "already open" in again.content[0].text
            for _ in range(200):
                status = (await call("workflow_status", {"workflow_id": "rem-orders"}, env.client)).structured_content
                if status.get("stage") == "awaiting_approval":
                    break
                await asyncio.sleep(0.05)
            assert status["plan"]["entry"] == "k8s_rollout_undo" and len(status["plan"]["plan_hash"]) == 64
            # the only way forward is a person's signature, outside the MCP server:
            await runtime.approve(env.client, "rem-orders", plan_hash=status["plan"]["plan_hash"], key=owner,
                                  approver="owner")
            for _ in range(20):  # a handle fetched by id does not auto-skip time; advance it explicitly
                status = (await call("workflow_status", {"workflow_id": "rem-orders"}, env.client)).structured_content
                if status["status"] == "COMPLETED":
                    return status["result"]
                await env.sleep(timedelta(minutes=1))
            raise AssertionError(status)
    assert asyncio.run(main())["status"] == "recovered"


def test_a_bad_request_is_an_error_not_a_crash():
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

    req = FixRequest(incident_id="inc-1", service="orders", entry=entry, params={"cmd": "rm -rf /"})
    assert catalog.validate(req.entry, req.params, {}) == [f"{entry!r} is not in the catalogue"]
