"""Register M20: a provider and model diagnose only after passing WARDEN's replay set (data/providers.yaml)."""

from __future__ import annotations

import pytest

from warden import providers
from warden.providers import ClaudeCliProvider, ProviderError, qualified, resolve


def _cli(monkeypatch, model="claude-sonnet-5-5"):
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/claude")
    monkeypatch.setenv("WARDEN_MODEL", model)
    monkeypatch.delenv("WARDEN_QUALIFYING", raising=False)
    return ClaudeCliProvider()


def _with(monkeypatch, entries):
    doc = {"bar": {"wrong_and_allowed": 0, "min_correct": 17}, "qualified": entries}
    monkeypatch.setattr(providers, "load_qualified", lambda: doc)


def test_an_unmeasured_model_is_refused(monkeypatch):
    _with(monkeypatch, [])
    with pytest.raises(ProviderError, match="M20"):
        qualified(_cli(monkeypatch))
    with pytest.raises(ProviderError, match="M20"):
        resolve("claude_cli")


def test_only_the_exact_model_that_passed_the_bar_is_admitted(monkeypatch):
    passed = {"provider": "claude_cli", "model": "claude-sonnet-5-5", "correct": 20, "wrong_and_allowed": 0}
    _with(monkeypatch, [passed])
    assert qualified(_cli(monkeypatch)).model == "claude-sonnet-5-5"
    with pytest.raises(ProviderError):
        qualified(_cli(monkeypatch, "claude-opus-5-5"))  # another model is another qualification
    _with(monkeypatch, [{**passed, "wrong_and_allowed": 1}])  # an entry under the bar admits nothing
    with pytest.raises(ProviderError):
        qualified(_cli(monkeypatch))
    _with(monkeypatch, [{**passed, "correct": 16}])
    with pytest.raises(ProviderError):
        qualified(_cli(monkeypatch))


def test_the_shipped_list_loads_and_every_entry_meets_its_bar():
    doc = providers.load_qualified()
    for entry in doc["qualified"]:
        assert entry["wrong_and_allowed"] <= doc["bar"]["wrong_and_allowed"]
        assert entry["correct"] >= doc["bar"]["min_correct"]


def test_the_cli_default_is_a_qualified_model(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/claude")
    monkeypatch.delenv("WARDEN_MODEL", raising=False)
    monkeypatch.delenv("WARDEN_QUALIFYING", raising=False)
    assert qualified(ClaudeCliProvider()).model == "claude-sonnet-5"


def test_reverify_puts_stored_answers_through_todays_gate(tmp_path):
    """--reverify: a gate fix made after a qualification run counts, and no model is called to apply it."""
    import json
    import sys

    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))
    import qualify_provider

    from warden.cli import DEMO_ALERTS
    from warden.graph import run
    from warden.llm import LLMClient
    from warden.models import Alert

    report = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(mock=True))
    stale = json.loads(report.model_dump_json())
    stale["verdict"] = {**stale["verdict"], "status": "auto_safe", "policy_ids": [], "reasons": ["stale"]}
    (tmp_path / "run" / "reports").mkdir(parents=True)
    path = tmp_path / "run" / "reports" / "x.1.json"
    path.write_text(json.dumps(stale), encoding="utf-8")
    assert qualify_provider.reverify(tmp_path) == 1
    assert json.loads(path.read_text(encoding="utf-8"))["verdict"] == report.verdict.model_dump(mode="json")
    assert qualify_provider.reverify(tmp_path) == 0
