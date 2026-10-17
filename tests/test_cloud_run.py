"""scripts/cloud_run.py: paid runs with the cloud runtime's own key, one command each, recorded in providers.yaml."""

from __future__ import annotations

import json
import os
import pathlib
import sys

import pytest
from tests.fakes import ANTHROPIC_KEY_PREFIX

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import cloud_run


class _Secrets:
    def __init__(self, value: str) -> None:
        self.value, self.asked = value, []

    def get_secret_value(self, SecretId: str) -> dict:
        self.asked.append(SecretId)
        return {"SecretString": self.value}


def test_the_key_comes_from_the_runtimes_secret_and_is_never_printed(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    key = ANTHROPIC_KEY_PREFIX + "x" * 20
    secrets = _Secrets(key)
    said = cloud_run.model_key("ops", secrets)
    assert secrets.asked == ["warden/ops/anthropic-api-key"] and os.environ["ANTHROPIC_API_KEY"] == key
    assert key not in said and key not in capsys.readouterr().out
    # Already in the process (the llm zone's task): Secrets Manager is not asked.
    assert "already in this process" in cloud_run.model_key("ops", _Secrets("unused"))
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    with pytest.raises(SystemExit):
        cloud_run.model_key("ops", _Secrets(" "))


def test_a_pass_is_added_under_qualified_and_a_fail_is_a_comment(tmp_path):
    doc = tmp_path / "providers.yaml"
    doc.write_text("bar:\n  min_correct: 17\nqualified:\n  - {\"model\": \"old\"}\n", encoding="utf-8")
    row = {"provider": "anthropic", "model": "m", "correct": 18, "wrong_and_allowed": 0}
    cloud_run.record({**row, "passed": True}, doc)
    import yaml

    assert yaml.safe_load(doc.read_text(encoding="utf-8"))["qualified"][0] == row
    cloud_run.record({**row, "correct": 15, "passed": False, "slo_breaches": ["escalated 29"]}, doc)
    text = doc.read_text(encoding="utf-8")
    assert "# NOT QUALIFIED" in text and "escalated 29" in text
    assert len(yaml.safe_load(text)["qualified"]) == 2  # the failed run admits nothing
    assert json.dumps({**row, "correct": 15}) in text


def test_qualify_runs_the_replay_for_exactly_the_named_model_at_its_own_price(tmp_path, monkeypatch):
    seen = {}

    def fake_main(argv):
        seen.update(argv=argv, provider=os.environ["WARDEN_PROVIDER"], model=os.environ["WARDEN_MODEL"],
                    price=os.environ.get("WARDEN_PRICE_IN"))
        out = pathlib.Path(argv[argv.index("--out") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "qualification.json").write_text(json.dumps({"passed": False}), encoding="utf-8")
        return 1

    import qualify_provider

    monkeypatch.setattr(qualify_provider, "main", fake_main)
    monkeypatch.setenv("WARDEN_PRICE_IN", "99")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "set-by-the-task")
    for name in ("WARDEN_PROVIDER", "WARDEN_MODEL"):
        monkeypatch.delenv(name, raising=False)
    code = cloud_run.main(["qualify", "--model", "claude-opus-5-5", "--budget-usd", "2", "--out", str(tmp_path / "o")])
    assert code == 1 and seen["provider"] == "anthropic" and seen["model"] == "claude-opus-5-5"
    assert seen["price"] is None and "--budget-usd" in seen["argv"] and "2.0" in seen["argv"]
    assert set(cloud_run.JOBS) == {"qualify"}
