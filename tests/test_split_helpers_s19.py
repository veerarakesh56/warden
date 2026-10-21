"""The helpers split out of mcp_server, settings, timeline and tools for SonarCloud (S19): the conditions a plant
check found no local test for (the MCP workflow tools' own tests need a Temporal server)."""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.error
from types import SimpleNamespace

import pytest

from warden import mcp_server, settings
from warden.models import Alert
from warden.timeline import MAX_FILES, CommitReader
from warden.tools import MAX_LINE_CHARS, gather, outcome_of


def test_an_unknown_workflow_tool_is_an_error():
    result = asyncio.run(mcp_server.call_workflow_tool("no_such_tool", {}, client=None))
    assert result.is_error


def test_a_remediation_outside_the_catalogue_is_refused_by_name(monkeypatch):
    monkeypatch.setenv("WARDEN_MCP_PROFILE", "remediate")
    args = {"incident_id": "inc-1", "environment": "dev", "service": "orders", "entry": "not_in_the_catalogue",
            "params": {}}
    result = asyncio.run(mcp_server.call_workflow_tool("request_remediation", args, client=None))
    assert "'not_in_the_catalogue' is not in the catalogue" in result.content[0].text


@pytest.mark.parametrize("module", ["temporalio.client", "temporalio.common", "temporalio.exceptions",
                                    "warden.runtime", "warden.activities", "warden.workflows"])
def test_a_missing_workflow_module_escapes_instead_of_becoming_a_tool_error(module, monkeypatch):
    """As on main: the workflow tools' imports run before the tool's try, so a broken Temporal install is the
    ImportError it is - for every tool name, even one this client may not use - never an `_err` reply."""
    monkeypatch.setitem(sys.modules, module, None)
    call = mcp_server.call_workflow_tool("workflow_status", {"workflow_id": "w"}, client=None)
    with pytest.raises(ImportError):
        asyncio.run(call)


def test_a_missing_name_in_a_workflow_module_escapes_too(monkeypatch):
    """`from .workflows import RemediationWorkflow` failed with an ImportError on main; so does the loader."""
    import warden.workflows

    monkeypatch.delattr(warden.workflows, "RemediationWorkflow")
    call = mcp_server.call_workflow_tool("workflow_status", {"workflow_id": "w"}, client=None)
    with pytest.raises(ImportError, match="RemediationWorkflow"):
        asyncio.run(call)


class _FakeTemporal:
    """Just enough of a Temporal client for the tools: starts nothing, and describes any workflow as running."""

    async def start_workflow(self, *args, **kwargs):
        return None

    def get_workflow_handle(self, wid):
        async def describe():
            return SimpleNamespace(workflow_type="RemediationWorkflow", status=SimpleNamespace(name="RUNNING"))
        return SimpleNamespace(describe=describe)


_REMEDIATION = {"incident_id": "inc-42", "entry": "k8s_rollout_undo", "service": "orders", "environment": "dev",
                "params": {"namespace": "shop", "deployment": "orders", "to_revision": "6"}}


def _status_after_a_remediation(monkeypatch) -> str:
    monkeypatch.setenv("WARDEN_MCP_PROFILE", "remediate")
    monkeypatch.setattr(mcp_server, "_STARTED", set())

    async def no_status(client, wid):
        return "awaiting approval", None
    from warden import runtime
    monkeypatch.setattr(runtime, "status", no_status)
    client = _FakeTemporal()
    started = asyncio.run(mcp_server.call_workflow_tool("request_remediation", _REMEDIATION, client))
    wid = json.loads(started.content[0].text)["workflow_id"]
    return asyncio.run(mcp_server.call_workflow_tool("workflow_status", {"workflow_id": wid}, client)).content[0].text


def test_status_answers_for_a_remediation_this_server_started(monkeypatch):
    """workflow_status answers only for workflows this server started: a remediation it started
    itself is one - checked without Temporal, so a lost `_STARTED.add` is caught locally."""
    assert '"stage": "awaiting approval"' in _status_after_a_remediation(monkeypatch)


def test_a_finished_workflows_result_never_carries_the_evidence_read():
    assert mcp_server._finished_result({"verdict": "AUTO_SAFE", "context": {"logs": ["raw"]}}) == {
        "verdict": "AUTO_SAFE"}


class _Secrets:
    def get_secret_value(self, *, SecretId):
        return {"SecretBinary": b"binary"}


def test_a_secret_with_no_string_is_not_loaded(monkeypatch):
    monkeypatch.delenv("WARDEN_SLACK_WEBHOOK", raising=False)
    names = settings._load_secrets("dev", ["WARDEN_SLACK_WEBHOOK"], _Secrets(), None)
    assert names == []


class _Resp:
    def __init__(self, sha):
        self.sha = sha

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return json.dumps({"sha": self.sha, "commit": {"message": "m"}}).encode()


def _alert():
    return Alert(alert_id="x", name="n", severity="high", service="checkout", environment="dev", summary="s",
                 started_at="2026-10-14T07:00:00+00:00")


def _reader(deploys, opener):
    class Base:
        def deploys(self, alert):
            return deploys

    return CommitReader(Base(), repo="owner/repo", opener=opener)


def test_a_commit_two_deploys_carry_is_read_once():
    asked = []

    def opener(req, timeout):
        asked.append(req.full_url)
        return _Resp("abc1234def")

    _reader([{"sha": "abc1234def"}, {"image": "repo:ABC1234DEF"}], opener).logs(_alert())
    assert asked == ["https://api.github.com/repos/owner/repo/commits/abc1234def"]


def test_at_most_three_commits_are_read():
    shas = [f"abc{i}234def" for i in range(5)]
    lines = _reader([{"sha": s} for s in shas], lambda req, timeout: _Resp("abc0234def")).logs(_alert())
    assert len(lines) == 3


def test_a_commit_that_could_not_be_reached_is_named_partial():
    def opener(req, timeout):
        raise urllib.error.URLError("no route")

    assert _reader([{"sha": "abc1234def"}], opener).logs(_alert()) == [
        "TOOL-PARTIAL github commit abc1234def: URLError - not read"]


class _ManyFiles(_Resp):
    def read(self):
        files = [{"filename": f"f{i}.py", "additions": 1, "deletions": 0} for i in range(MAX_FILES + 5)]
        return json.dumps({"sha": self.sha, "commit": {"message": "m"}, "files": files}).encode()


def test_a_commit_line_names_at_most_max_files_files():
    lines = _reader([{"sha": "abc1234def"}], lambda req, timeout: _ManyFiles("abc1234def")).logs(_alert())
    assert lines[0].count("(+1/-0)") == MAX_FILES


class _DatabaseError(Exception):
    sqlstate = "28000"


def test_a_sqlstate_class_names_the_outcome():
    assert outcome_of(_DatabaseError("login failed")) == "credentials rejected or missing"


class _Backend:
    def __init__(self, logs):
        self._logs = logs

    def logs(self, alert):
        return self._logs

    def metrics(self, alert):
        return {"error_rate": 0.1}

    def deploys(self, alert):
        return []


def test_a_partial_line_that_names_its_tool_is_not_named_twice():
    bundle = gather(_alert(), _Backend(["TOOL-PARTIAL logs: pod a could not be read", "a line"]))
    assert bundle.tool_errors == ["logs: pod a could not be read"]


def test_a_long_log_line_is_cut():
    bundle = gather(_alert(), _Backend(["x" * (MAX_LINE_CHARS + 10)]))
    assert bundle.logs == ["x" * MAX_LINE_CHARS]
