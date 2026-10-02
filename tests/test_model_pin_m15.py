"""Register M15: only exact model ids, and the CLI or SDK version is in every diagnosis's provenance."""

from __future__ import annotations

import subprocess
import types

import pytest

from warden.cli import DEMO_ALERTS
from warden.graph import run
from warden.llm import LLMClient
from warden.models import Alert
from warden.providers import ClaudeCliProvider, ProviderError, pinned


@pytest.mark.parametrize("alias", ["sonnet", "opus", "Haiku", "fable", "opus[1m]", "default",
                                   "claude-sonnet-latest", "llama3.1:latest", ""])
def test_an_alias_that_moves_is_refused(alias):
    with pytest.raises(ProviderError):
        pinned(alias)


@pytest.mark.parametrize("exact", ["claude-sonnet-5-5", "claude-haiku-4-5-20251001", "gpt-4o-mini", "llama3.1"])
def test_an_exact_id_is_kept(exact):
    assert pinned(exact) == exact


def test_the_cli_defaults_to_an_exact_id_and_reports_its_version(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/claude")
    monkeypatch.delenv("WARDEN_MODEL", raising=False)
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return types.SimpleNamespace(stdout="2.1.287 (Claude Code)\n", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    provider = ClaudeCliProvider()
    assert pinned(provider.model) == provider.model
    assert provider.version == "claude-cli 2.1.287" and provider.version == "claude-cli 2.1.287"
    assert calls == [["/usr/bin/claude", "--version"]], "read once"


def test_the_version_is_in_the_diagnosis_provenance():
    report = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(mock=True))
    row = next(step for step in report.audit if step.get("node") == "diagnose")
    assert row["provenance"]["version"] == "mock" and row["provenance"]["model"] == "mock"
