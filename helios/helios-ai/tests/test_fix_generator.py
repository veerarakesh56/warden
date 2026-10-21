from __future__ import annotations

import io

from helios_ai.fix_generator import FIX_SCHEMA, propose_fix
from helios_ai.models import FailedResource, FailureChain, FixProposal


def _cache_chain() -> FailureChain:
    return FailureChain(
        scenario="lose-us-east-1a",
        failures=[
            FailedResource(
                id="aws_elasticache_cluster.cache",
                kind="ElasticacheCluster",
                reason="single-AZ in us-east-1a, which is down",
            )
        ],
    )


def test_propose_fix_matches_snapshot(fake_client, snapshot) -> None:
    chain = _cache_chain()
    fix = propose_fix(
        chain,
        attrs_snapshot={
            "aws_elasticache_cluster.cache": {"availability_zone": "us-east-1a"}
        },
        client=fake_client,
    )
    assert fix.model_dump(mode="json") == snapshot


def test_propose_fix_returns_valid_fix_proposal(fake_client) -> None:
    chain = _cache_chain()
    fix = propose_fix(
        chain,
        attrs_snapshot={
            "aws_elasticache_cluster.cache": {"availability_zone": "us-east-1a"}
        },
        client=fake_client,
    )
    assert isinstance(fix, FixProposal)
    assert fix.scenario_name == "lose-us-east-1a"
    assert len(fix.edits) >= 1
    edit = fix.edits[0]
    assert edit.op == "set_attr"
    assert edit.resource_id == "aws_elasticache_cluster.cache"


def test_propose_fix_sends_structured_output_config(fake_client) -> None:
    chain = _cache_chain()
    propose_fix(chain, attrs_snapshot={}, client=fake_client)
    call = fake_client.messages.calls[0]
    assert "output_config" in call
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert call["output_config"]["format"]["schema"] == FIX_SCHEMA


def test_propose_fix_sends_two_cache_breakpoints(fake_client) -> None:
    chain = _cache_chain()
    propose_fix(chain, attrs_snapshot={}, client=fake_client)
    call = fake_client.messages.calls[0]
    markers = [b for b in call["system"] if b.get("cache_control") == {"type": "ephemeral"}]
    assert len(markers) == 2, "expected 2 cache breakpoints (persona + glossary)"
    assert call["model"] == "claude-opus-5-5"


def test_propose_fix_model_id_comes_from_env(fake_client, monkeypatch) -> None:
    monkeypatch.setenv("HELIOS_AI_MODEL", "claude-test-override")
    propose_fix(_cache_chain(), attrs_snapshot={}, client=fake_client)
    assert fake_client.messages.calls[0]["model"] == "claude-test-override"


def test_propose_fix_sends_chain_and_attrs_on_user_turn(fake_client) -> None:
    chain = _cache_chain()
    propose_fix(
        chain,
        attrs_snapshot={"aws_elasticache_cluster.cache": {"availability_zone": "us-east-1a"}},
        client=fake_client,
    )
    call = fake_client.messages.calls[0]
    user_content = call["messages"][0]["content"]
    assert '"chain"' in user_content
    assert '"attrs_snapshot"' in user_content
    assert "aws_elasticache_cluster.cache" in user_content


def test_cli_propose_fix_reads_stdin_writes_stdout(fake_client, capsys, monkeypatch) -> None:
    from helios_ai import cli

    monkeypatch.setattr(cli, "_build_client", lambda: fake_client)
    payload = (
        '{"chain":{"scenario":"lose-us-east-1a","failures":'
        '[{"id":"aws_elasticache_cluster.cache","kind":"ElasticacheCluster",'
        '"reason":"single-AZ in us-east-1a, which is down"}]},'
        '"attrs_snapshot":{"aws_elasticache_cluster.cache":{"availability_zone":"us-east-1a"}}}'
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))

    exit_code = cli.main(["propose-fix"])
    assert exit_code == 0

    import json

    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["scenario_name"] == "lose-us-east-1a"
    assert parsed["edits"][0]["op"] == "set_attr"


def test_cli_propose_fix_mock_env_without_api_key(monkeypatch, capsys) -> None:
    from helios_ai import cli

    monkeypatch.setenv("HELIOS_AI_MOCK", "1")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    payload = (
        '{"chain":{"scenario":"noop","failures":[]},"attrs_snapshot":{}}'
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    exit_code = cli.main(["propose-fix"])
    assert exit_code == 0
    out = capsys.readouterr().out
    import json

    parsed = json.loads(out)
    assert parsed["scenario_name"] == "noop"


def test_the_prompt_names_every_key_the_engine_refuses() -> None:
    """The engine refuses edits that would move a resource (fix.rs PLACEMENT_KEYS). A model not
    told so proposes them -- on WARDEN's Wave 4 stack it proposed moving the NAT."""
    import pathlib
    import re

    from helios_ai.fix_generator import SYSTEM_PERSONA

    src = pathlib.Path(__file__).resolve().parents[2] / "crates/helios-engine/src/fix.rs"
    table = src.read_text(encoding="utf-8").split("PLACEMENT_KEYS: &[&str] = &[")[1].split("];")[0]
    keys = re.findall(r'"([a-z_]+)"', table)
    assert len(keys) >= 12
    assert [k for k in keys if k not in SYSTEM_PERSONA] == []
