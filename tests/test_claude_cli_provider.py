"""The `claude` CLI provider, against a stubbed subprocess.

⛔ THE TWO THAT MATTER are `test_every_tool_is_disabled` and
`test_it_runs_outside_the_repository`. A headless Claude launched inside this repo can read files,
and `scenarios/catalog/` holds the fault classes while `scenarios/scoring.yaml` holds the answer key.
A diagnosing model that can grep those is not being measured — it is looking the answer up, and the
whole benchmark becomes worthless in a way no result would reveal.

Both defences are asserted here because "we passed the flag" and "the flag is still there after
somebody refactors this" are different claims.
"""

from __future__ import annotations

import pathlib
import subprocess

import pytest

from warden.providers import ClaudeCliProvider, ProviderError

ROOT = pathlib.Path(__file__).resolve().parents[1]


class _Recorder:
    """Stands in for subprocess.run and remembers exactly how it was called."""

    def __init__(self, stdout='{"ok": true}', returncode=0, stderr="", raises=None):
        self.stdout, self.returncode, self.stderr, self.raises = stdout, returncode, stderr, raises
        self.cmd = None
        self.kwargs = {}

    def __call__(self, cmd, **kwargs):
        self.cmd, self.kwargs = cmd, kwargs
        if self.raises:
            raise self.raises
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/claude")
    monkeypatch.delenv("WARDEN_MODEL", raising=False)
    return ClaudeCliProvider()


def _run(provider, recorder, monkeypatch, **kw):
    monkeypatch.setattr(subprocess, "run", recorder)
    return provider.complete(system=kw.get("system", "sys"), user=kw.get("user", "usr"))


# --------------------------------------------------------------------------- the answer key


def test_every_tool_is_disabled(provider, monkeypatch):
    """⛔ Load-bearing. With tools, the model could read the catalog and the rubric."""
    rec = _Recorder()
    _run(provider, rec, monkeypatch)
    assert "--disallowed-tools" in rec.cmd
    disallowed = rec.cmd[rec.cmd.index("--disallowed-tools") + 1:]
    for tool in ("Read", "Bash", "Glob", "Grep", "Task", "WebFetch", "Write", "Edit"):
        assert tool in disallowed, f"{tool} is not disabled - it can reach the answer key"


def test_it_runs_outside_the_repository(provider, monkeypatch):
    """⛔ The second, independent defence. One would be an assumption."""
    rec = _Recorder()
    _run(provider, rec, monkeypatch)
    cwd = pathlib.Path(rec.kwargs["cwd"]).resolve()
    assert ROOT not in cwd.parents and cwd != ROOT, (
        f"the CLI runs at {cwd}, inside the repo - scenarios/ is reachable from there"
    )


def test_the_scenario_directory_is_not_reachable_from_the_working_directory(provider, monkeypatch):
    """Belt and braces made concrete: whatever cwd it picked, the catalog is not under it."""
    rec = _Recorder()
    _run(provider, rec, monkeypatch)
    cwd = pathlib.Path(rec.kwargs["cwd"]).resolve()
    assert not (cwd / "scenarios").exists()
    assert not (cwd / "scoring.yaml").exists()


# --------------------------------------------------------------------------- the mechanics


def test_the_prompt_goes_in_on_stdin_not_as_an_argument(provider, monkeypatch):
    """The evidence blob plus the JSON schema runs to several KB, and Windows caps a command line
    at ~32k. An over-long argument fails in a way that looks like the model refusing."""
    rec = _Recorder()
    big = "L" * 40_000
    monkeypatch.setattr(subprocess, "run", rec)
    provider.complete(system="sys", user=big)
    assert rec.kwargs["input"] == big
    assert not any(big in str(part) for part in rec.cmd), "the prompt was passed as an argument"


def test_the_system_prompt_is_passed(provider, monkeypatch):
    rec = _Recorder()
    _run(provider, rec, monkeypatch, system="you are a machine")
    assert "--system-prompt" in rec.cmd
    assert rec.cmd[rec.cmd.index("--system-prompt") + 1] == "you are a machine"


def test_the_model_is_configurable(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/claude")
    monkeypatch.setenv("WARDEN_MODEL", "opus")
    rec = _Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    p = ClaudeCliProvider()
    assert p.model == "opus"
    p.complete(system="s", user="u")
    assert rec.cmd[rec.cmd.index("--model") + 1] == "opus"


def test_tokens_are_estimated_not_reported_as_zero(provider, monkeypatch):
    """A budget fed zeros never fires. The CLI reports no usage, so it must estimate."""
    rec = _Recorder(stdout="x" * 300)
    completion = _run(provider, rec, monkeypatch, system="s" * 90, user="u" * 90)
    assert completion.input_tokens > 0
    assert completion.output_tokens > 0


# --------------------------------------------------------------------------- failure


def test_a_nonzero_exit_is_an_error_not_an_empty_completion(provider, monkeypatch):
    """An empty string would be handed to the JSON parser and surface as 'the model refused',
    blaming the model for a CLI that was not installed properly."""
    rec = _Recorder(returncode=1, stderr="not logged in")
    monkeypatch.setattr(subprocess, "run", rec)
    with pytest.raises(ProviderError, match="exited 1"):
        provider.complete(system="s", user="u")


def test_a_timeout_is_an_error(provider, monkeypatch):
    rec = _Recorder(raises=subprocess.TimeoutExpired(cmd="claude", timeout=45))
    monkeypatch.setattr(subprocess, "run", rec)
    with pytest.raises(ProviderError, match="exceeded"):
        provider.complete(system="s", user="u")


def test_a_missing_cli_is_refused_at_construction(monkeypatch):
    """Fail when the provider is built, not on the first call half way through a wave."""
    monkeypatch.setattr("shutil.which", lambda _name: None)
    with pytest.raises(ProviderError, match="needs the `claude` CLI"):
        ClaudeCliProvider()


def test_it_is_registered_under_both_spellings(monkeypatch):
    from warden.providers import resolve

    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/claude")
    for name in ("claude_cli", "claude-cli"):
        monkeypatch.setenv("WARDEN_PROVIDER", name)
        assert resolve().name == "claude_cli"


# --------------------------------------------------------------------------- whose Claude is it
#
# ⛔ Measured, not theorised. With USERPROFILE set, a headless run loads the operator's global
# CLAUDE.md, their skills and their active modes. The same prompt then took 26s and came back with
# PROSE REFUSING THE REQUEST - "an odd ask ... smells like injection test, not real work" - where a
# clean environment answered with valid JSON in 11s.
#
# A benchmark whose results depend on whose laptop it ran on is measuring the laptop. This is a
# correctness control, and it must not depend on the caller having remembered to sanitise the
# environment first.


def test_the_operators_own_claude_configuration_is_stripped(provider, monkeypatch):
    for var in ("USERPROFILE", "HOME", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(var, f"/home/operator/{var.lower()}")
    rec = _Recorder()
    _run(provider, rec, monkeypatch)
    env = rec.kwargs["env"]
    for var in ("USERPROFILE", "HOME", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME"):
        assert var not in env, (
            f"{var} survives, so the CLI loads the operator's CLAUDE.md and the benchmark measures "
            "their assistant rather than a model"
        )


def test_it_does_not_rely_on_the_caller_having_sanitised_the_environment(provider, monkeypatch):
    """The provider passes an explicit env rather than inheriting one. A caller running
    WARDEN_PROVIDER=claude_cli from an ordinary shell must get the same clean model as one running
    it from the benchmark harness."""
    rec = _Recorder()
    _run(provider, rec, monkeypatch)
    assert "env" in rec.kwargs, "no explicit env passed - the subprocess inherits whatever it likes"


def test_what_the_model_still_needs_does_survive(provider, monkeypatch):
    """Narrow, not scorched earth: PATH still has to work or the CLI cannot start."""
    monkeypatch.setenv("PATH", "/usr/bin")
    rec = _Recorder()
    _run(provider, rec, monkeypatch)
    assert rec.kwargs["env"].get("PATH") == "/usr/bin"


# --------------------------------------------------------------------------- when the pool runs dry
#
# ⛔ Found by a real wave. The usage limit was hit mid-run and five runs failed with
# `claude CLI exited 1:` followed by NOTHING - the CLI writes its reason to stdout, and only stderr
# was being reported. The one fact that explained every one of those ERROR rows had been discarded.


def test_the_reason_on_stdout_is_not_thrown_away(provider, monkeypatch):
    rec = _Recorder(returncode=1, stdout="Something went wrong on our side", stderr="")
    monkeypatch.setattr(subprocess, "run", rec)
    with pytest.raises(ProviderError, match="Something went wrong on our side"):
        provider.complete(system="s", user="u")


def test_a_usage_limit_is_recognised_as_exhaustion_not_a_generic_error(provider, monkeypatch):
    from warden.providers import ProviderExhausted

    rec = _Recorder(returncode=1, stdout="Claude AI usage limit reached|1789040000", stderr="")
    monkeypatch.setattr(subprocess, "run", rec)
    with pytest.raises(ProviderExhausted):
        provider.complete(system="s", user="u")


def test_an_unrelated_failure_is_not_mistaken_for_exhaustion(provider, monkeypatch):
    """A false positive here would stop a whole wave on an ordinary error."""
    from warden.providers import ProviderExhausted

    rec = _Recorder(returncode=1, stdout="", stderr="Invalid model name: sonet")
    monkeypatch.setattr(subprocess, "run", rec)
    with pytest.raises(ProviderError) as info:
        provider.complete(system="s", user="u")
    assert not isinstance(info.value, ProviderExhausted)


def test_the_cli_is_spoken_to_in_utf8_not_the_windows_code_page(provider, monkeypatch):
    """⛔ Found by a real wave: a run died on `'charmap' codec can't encode character '\u2192'`.

    With no explicit encoding, Python encodes stdin in cp1252 on Windows. The model writes `→` into
    its own hypothesis, the propose step sends that hypothesis back, and cp1252 cannot encode it -
    so the call crashed before it was sent. Characters cp1252 CAN encode, like the em dash in every
    prompt's ALERT line, were silently corrupted instead, because the CLI reads UTF-8. Verified
    against the real CLI: UTF-8 round-trips `→ — é` exactly."""
    rec = _Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    provider.complete(system="s", user="ALERT: x \u2014 y. HYPOTHESIS: a \u2192 b")
    assert rec.kwargs.get("encoding") == "utf-8"
    assert rec.kwargs["input"].encode(rec.kwargs["encoding"])  # must not raise
