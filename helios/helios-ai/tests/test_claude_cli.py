"""The `claude` CLI provider, against a stubbed subprocess.run (no real CLI is started).

⛔ THE TWO THAT MATTER are `test_every_tool_is_disabled` and `test_it_runs_outside_the_repository`.
Terraform attrs reach the model verbatim and are untrusted input; a model with tools and a cwd in
this repo could act on an injected instruction. Both defences are asserted, because "we passed the
flag" and "the flag survived the next refactor" are different claims.
"""

from __future__ import annotations

import io
import json
import pathlib
import re
import subprocess

import pytest

from helios_ai import _claude_cli, cli
from helios_ai._claude_cli import ClaudeCliClient
from helios_ai.explain import explain
from helios_ai.fix_generator import FIX_SCHEMA, propose_fix
from helios_ai.models import FailedResource, FailureChain

ROOT = pathlib.Path(__file__).resolve().parents[2]

CHAIN = FailureChain(
    scenario="lose-us-east-1a",
    failures=[FailedResource(id="aws_db_instance.db", kind="RdsInstance", reason="single-AZ")],
)
SNAPSHOT = {"aws_db_instance.db": {"multi_az": False}}
VALID = json.dumps({
    "scenario_name": "lose-us-east-1a",
    "explanation": "enable multi_az",
    "edits": [{"op": "set_attr", "resource_id": "aws_db_instance.db", "key": "multi_az",
               "value": True}],
})


class _Recorder:
    """Stands in for subprocess.run and remembers exactly how it was called."""

    def __init__(self, stdout="ok", returncode=0, stderr="", raises=None):
        self.stdout, self.returncode, self.stderr, self.raises = stdout, returncode, stderr, raises
        self.cmd: list[str] = []
        self.kwargs: dict = {}

    def __call__(self, cmd, **kwargs):
        self.cmd, self.kwargs = cmd, kwargs
        if self.raises:
            raise self.raises
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/claude")
    return ClaudeCliClient()


def _call(client, rec, monkeypatch, system="sys", user="usr", **kw):
    monkeypatch.setattr(subprocess, "run", rec)
    return client.messages.create(
        model="opus", max_tokens=10, system=system,
        messages=[{"role": "user", "content": user}], **kw,
    )


def _arg(rec, flag):
    return rec.cmd[rec.cmd.index(flag) + 1]


# --------------------------------------------------------------------------- the untrusted input


def test_every_tool_is_disabled(client, monkeypatch):
    rec = _Recorder()
    _call(client, rec, monkeypatch)
    disallowed = rec.cmd[rec.cmd.index("--disallowed-tools") + 1:]
    for tool in ("Read", "Bash", "Glob", "Grep", "Task", "WebFetch", "Write", "Edit"):
        assert tool in disallowed, f"{tool} is not disabled"


def test_no_tools_mcp_or_operator_settings_reach_the_model(client, monkeypatch):
    """⛔ Measured on Windows: the named --disallowed-tools list alone left 25 callable tools (MCP
    connectors, Skill, Workflow ...) and loaded the operator's CLAUDE.md and hooks."""
    rec = _Recorder()
    _call(client, rec, monkeypatch)
    assert _arg(rec, "--tools") == ""
    assert "--strict-mcp-config" in rec.cmd
    assert _arg(rec, "--setting-sources") == ""


def test_it_runs_outside_the_repository(client, monkeypatch):
    rec = _Recorder()
    _call(client, rec, monkeypatch)
    cwd = pathlib.Path(rec.kwargs["cwd"]).resolve()
    assert ROOT not in cwd.parents and cwd != ROOT, f"the CLI runs at {cwd}, inside the repo"


# --------------------------------------------------------------------------- the mechanics


def test_the_prompt_goes_in_on_stdin_not_as_an_argument(client, monkeypatch):
    rec = _Recorder()
    big = "L" * 40_000
    _call(client, rec, monkeypatch, user=big)
    assert rec.kwargs["input"] == big
    assert not any(big in str(part) for part in rec.cmd), "the prompt was passed as an argument"


def test_the_system_prompt_blocks_and_model_are_passed(client, monkeypatch):
    rec = _Recorder()
    system = [{"type": "text", "text": "persona"}, {"type": "text", "text": "glossary"}]
    _call(client, rec, monkeypatch, system=system)
    assert _arg(rec, "--system-prompt") == "persona\n\nglossary"
    assert _arg(rec, "--model") == "opus"


def test_the_cli_is_spoken_to_in_utf8(client, monkeypatch):
    rec = _Recorder(stdout="a → b — c")
    reply = _call(client, rec, monkeypatch, user="x → y — z")
    assert rec.kwargs["encoding"] == "utf-8"
    assert rec.kwargs["input"].encode("utf-8").decode("utf-8") == "x → y — z"
    assert reply.content[0].text == "a → b — c"


def test_tokens_are_estimated_not_zero(client, monkeypatch):
    reply = _call(client, _Recorder(stdout="x" * 300), monkeypatch)
    assert reply.usage.input_tokens > 0 and reply.usage.output_tokens > 0


def test_the_operators_configuration_is_stripped_but_path_kept(client, monkeypatch):
    for var in ("USERPROFILE", "HOME", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(var, f"/home/operator/{var.lower()}")
    monkeypatch.setenv("PATH", "/usr/bin")
    rec = _Recorder()
    _call(client, rec, monkeypatch)
    env = rec.kwargs["env"]
    for var in ("USERPROFILE", "HOME", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME"):
        assert var not in env, f"{var} survives, so the CLI loads the operator's CLAUDE.md"
    assert env.get("PATH") == "/usr/bin"


# --------------------------------------------------------------------------- failure


def test_a_nonzero_exit_reports_stdout_and_stderr(client, monkeypatch):
    rec = _Recorder(returncode=1, stdout="said on stdout", stderr="said on stderr")
    with pytest.raises(RuntimeError, match=re.escape("exited 1: said on stdout | said on stderr")):
        _call(client, rec, monkeypatch)


def test_a_usage_limit_is_labelled(client, monkeypatch):
    real = "You've hit your session limit · resets 7:40pm (Asia/Kolkata)"
    with pytest.raises(RuntimeError, match="usage limit"):
        _call(client, _Recorder(returncode=1, stdout=real), monkeypatch)


def test_an_unrelated_failure_is_not_labelled_a_usage_limit(client, monkeypatch):
    with pytest.raises(RuntimeError) as info:
        _call(client, _Recorder(returncode=1, stderr="Invalid model name"), monkeypatch)
    assert "usage limit" not in str(info.value)


def test_a_timeout_raises(client, monkeypatch):
    rec = _Recorder(raises=subprocess.TimeoutExpired(cmd="claude", timeout=1))
    with pytest.raises(RuntimeError, match="exceeded"):
        _call(client, rec, monkeypatch)


def test_a_missing_cli_is_refused_at_construction(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: None)
    with pytest.raises(SystemExit, match="needs the `claude` CLI"):
        ClaudeCliClient()


# --------------------------------------------------------------------------- provider selection


@pytest.mark.parametrize("name", ["claude_cli", "claude-cli"])
def test_provider_both_spellings(monkeypatch, name):
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/claude")
    monkeypatch.delenv("HELIOS_AI_MOCK", raising=False)
    monkeypatch.setenv("HELIOS_AI_PROVIDER", name)
    assert isinstance(cli._build_client(), ClaudeCliClient)


def test_provider_defaults_to_anthropic(monkeypatch):
    monkeypatch.delenv("HELIOS_AI_MOCK", raising=False)
    monkeypatch.delenv("HELIOS_AI_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="ANTHROPIC_API_KEY"):
        cli._build_client()


def test_mock_wins_over_provider(monkeypatch):
    monkeypatch.setenv("HELIOS_AI_MOCK", "1")
    monkeypatch.setenv("HELIOS_AI_PROVIDER", "claude_cli")
    assert not isinstance(cli._build_client(), ClaudeCliClient)


def test_unknown_provider_lists_known_values(monkeypatch):
    monkeypatch.delenv("HELIOS_AI_MOCK", raising=False)
    monkeypatch.setenv("HELIOS_AI_PROVIDER", "gpt")
    with pytest.raises(SystemExit, match="anthropic, claude_cli, claude-cli"):
        cli._build_client()


# --------------------------------------------------------------------------- end to end


def test_explain_returns_stdout(client, monkeypatch):
    monkeypatch.setattr(subprocess, "run", _Recorder(stdout="# Narrative"))
    assert explain(CHAIN, client=client) == "# Narrative"


def test_the_schema_is_embedded_in_the_system_prompt(client, monkeypatch):
    rec = _Recorder(stdout=VALID)
    monkeypatch.setattr(subprocess, "run", rec)
    propose_fix(CHAIN, attrs_snapshot=SNAPSHOT, client=client)
    assert json.dumps(FIX_SCHEMA) in _arg(rec, "--system-prompt")


@pytest.mark.parametrize("stdout", [VALID, f"```json\n{VALID}\n```\n", f"```\n{VALID}```"])
def test_propose_fix_accepts_valid_and_fenced_json(client, monkeypatch, stdout):
    monkeypatch.setattr(subprocess, "run", _Recorder(stdout=stdout))
    fix = propose_fix(CHAIN, attrs_snapshot=SNAPSHOT, client=client)
    assert fix.edits[0].key == "multi_az"


def _with(**changes):
    body = json.loads(VALID)
    body.update(changes)
    return json.dumps(body)


@pytest.mark.parametrize("stdout", [
    "Sure! Set multi_az to true.",
    f"Here you go:\n```json\n{VALID}\n```",
    _with(confidence=0.9),
    _with(edits=[{"op": "add_resource", "resource_id": "x", "key": "k", "value": 1}]),
    f"```json\n```json\n{VALID}\n```\n```",
])
def test_propose_fix_fails_closed(client, monkeypatch, stdout):
    monkeypatch.setattr(subprocess, "run", _Recorder(stdout=stdout))
    with pytest.raises(RuntimeError, match="not a valid FixProposal"):
        propose_fix(CHAIN, attrs_snapshot=SNAPSHOT, client=client)


def test_cli_propose_fix_exits_1_with_empty_stdout_on_garbage(monkeypatch, capsys):
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/claude")
    monkeypatch.delenv("HELIOS_AI_MOCK", raising=False)
    monkeypatch.setenv("HELIOS_AI_PROVIDER", "claude_cli")
    monkeypatch.setattr(subprocess, "run", _Recorder(stdout="I cannot help with that."))
    stdin = json.dumps({"chain": CHAIN.model_dump(), "attrs_snapshot": SNAPSHOT})
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    assert cli.main(["propose-fix"]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "not a valid FixProposal" in err


def test_timeout_is_configurable(monkeypatch):
    monkeypatch.setenv("HELIOS_AI_TIMEOUT", "7")
    assert _claude_cli._timeout_s() == 7.0
