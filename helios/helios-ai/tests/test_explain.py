from __future__ import annotations

from pathlib import Path

import pytest

from helios_ai.explain import explain
from helios_ai.models import FailureChain

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("fixture", ["az_outage_chain.json", "region_outage_chain.json"])
def test_explain_matches_snapshot(fake_client, snapshot, fixture: str) -> None:
    chain = FailureChain.model_validate_json((FIXTURES / fixture).read_text())
    narrative = explain(chain, client=fake_client)
    assert narrative == snapshot


def test_explain_sends_cache_markers(fake_client) -> None:
    chain = FailureChain(scenario="dummy", failures=[])
    explain(chain, client=fake_client)
    call = fake_client.messages.calls[0]
    system = call["system"]
    assert isinstance(system, list)
    markers = [b for b in system if b.get("cache_control") == {"type": "ephemeral"}]
    assert len(markers) >= 2, "expected 2 cache breakpoints (system + glossary)"
    assert call["model"] == "claude-opus-5-5"


def test_explain_model_id_comes_from_env(fake_client, monkeypatch) -> None:
    monkeypatch.setenv("HELIOS_AI_MODEL", "claude-test-override")
    explain(FailureChain(scenario="dummy", failures=[]), client=fake_client)
    assert fake_client.messages.calls[0]["model"] == "claude-test-override"


def test_explain_passes_failure_chain_json_on_user_turn(fake_client) -> None:
    chain = FailureChain(scenario="test-xyz", failures=[])
    explain(chain, client=fake_client)
    call = fake_client.messages.calls[0]
    user_content = call["messages"][0]["content"]
    assert '"scenario"' in user_content
    assert '"test-xyz"' in user_content


def test_cli_reads_stdin_writes_stdout(fake_client, capsys, monkeypatch) -> None:
    import io

    from helios_ai import cli

    chain_json = (FIXTURES / "az_outage_chain.json").read_text()
    monkeypatch.setattr(cli, "_build_client", lambda: fake_client)
    monkeypatch.setattr("sys.stdin", io.StringIO(chain_json))

    exit_code = cli.main(["explain"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Failure narrative" in out


def test_cli_mock_env_uses_mock_client(monkeypatch, capsys) -> None:
    import io

    from helios_ai import cli

    monkeypatch.setenv("HELIOS_AI_MOCK", "1")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO('{"scenario":"noop","failures":[]}'))

    exit_code = cli.main(["explain"])
    assert exit_code == 0
    assert "mocked" in capsys.readouterr().out
