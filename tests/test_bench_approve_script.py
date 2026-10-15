"""scripts/bench_approve.py: one bench key, never overwritten, and its approver entry is dev only, T1/T2."""

from __future__ import annotations

import importlib.util
import pathlib

import pytest
import yaml

from warden.approvals import ApproverPolicy

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _script():
    spec = importlib.util.spec_from_file_location("bench_approve", ROOT / "scripts" / "bench_approve.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_entry_is_a_dev_only_t1_t2_approver_and_the_key_is_never_overwritten(tmp_path, monkeypatch):
    mod = _script()
    monkeypatch.setenv("WARDEN_BENCH_KEY", str(tmp_path / "k" / "bench.pem"))
    entry = yaml.safe_load(mod.new_key("dev"))
    policy = ApproverPolicy.model_validate({"approvers": entry})
    bench = policy.approvers["bench"]
    assert (bench.environments, bench.tiers, bench.passkeys) == (["dev"], ["T1", "T2"], [])
    with pytest.raises(SystemExit):
        mod.new_key("dev")
