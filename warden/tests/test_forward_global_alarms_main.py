"""infra/scripts/forward_global_alarms.py main (S3516, one return): a dry run prints the plan and changes nothing; --apply
and --undo hand the plan to apply() and print what it did - each exits 0."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("forward_main", ROOT / "infra" / "scripts" / "forward_global_alarms.py")
forward = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(forward)
ACCOUNT = "0" * 12


@pytest.fixture
def clients(monkeypatch):
    made: list[str] = []

    def client(name, **_kw):
        made.append(name)
        return types.SimpleNamespace(get_caller_identity=lambda: {"Account": ACCOUNT})

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=client))
    return made


def test_a_dry_run_prints_the_plan_and_creates_no_iam_or_events_client(clients, monkeypatch, capsys):
    applied: list = []
    monkeypatch.setattr(forward, "apply", lambda *a, **kw: applied.append(kw) or ["changed"])
    assert forward.main([]) == 0
    out = capsys.readouterr().out
    shown, note = out.rsplit("}\n", 1)
    assert json.loads(shown + "}") == {k: v for k, v in forward.plan(ACCOUNT).items() if k != "tags"}
    assert note == "dry run: nothing was changed (--apply to make it, --undo to remove it)\n"
    assert applied == []
    assert clients == ["sts"]


@pytest.mark.parametrize(("flag", "undo"), [("--apply", False), ("--undo", True)])
def test_apply_and_undo_hand_the_plan_to_apply_and_print_what_it_did(clients, monkeypatch, capsys, flag, undo):
    applied: list = []
    monkeypatch.setattr(forward, "apply", lambda *_clients, undo: applied.append(undo) or ["one", "two"])
    assert forward.main([flag]) == 0
    assert capsys.readouterr().out == "one\ntwo\n"
    assert applied == [undo]
    assert clients == ["sts", "iam", "events"]
