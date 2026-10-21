"""fault-lab/scripts/bench_approve.py main after its split (S3776): which signed step each option posts, what it prints and
its exit code - a record read, a plan shown, denied or approved - with the approval domain faked."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import types

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("bench_approve_flow", ROOT / "fault-lab" / "scripts" / "bench_approve.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)
PLAN = {"workflow_id": "wf-1", "entry": "scale_up", "target": "svc", "tier": "T1", "environment": "dev",
        "plan_hash": "h" * 64}
PLAN_LINE = "plan wf-1: scale_up on svc - tier T1, dev"


@pytest.fixture
def domain(monkeypatch):
    """Every post as (step, body); `answers` is what the domain says to each step."""
    posted: list[tuple[str, dict]] = []
    answers: dict[str, tuple[int, dict]] = {}

    def post(_domain, step, body):
        posted.append((step, body))
        return answers[step]

    ssm = types.SimpleNamespace(get_parameter=lambda Name: {"Parameter": {"Value": "approve.example.test"}})
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda name: ssm))
    monkeypatch.setattr(bench, "load_key", Ed25519PrivateKey.generate)
    monkeypatch.setattr(bench, "_post", post)
    return types.SimpleNamespace(posted=posted, answers=answers)


def test_record_latest_asks_for_no_incident_and_prints_the_records(domain, capsys):
    domain.answers["record"] = (200, {"records": []})
    assert bench.main(["--record", "latest"]) == 0
    assert [(step, body["incident"]) for step, body in domain.posted] == [("record", "")]
    assert json.loads(capsys.readouterr().out) == {"records": []}


def test_a_named_record_that_is_not_there_exits_1(domain, capsys):
    domain.answers["record"] = (404, {"error": "no such incident"})
    assert bench.main(["--record", "inc-9"]) == 1
    assert [(step, body["incident"]) for step, body in domain.posted] == [("record", "inc-9")]
    assert capsys.readouterr().out == "no record (404): no such incident\n"


def test_an_incident_alone_shows_its_plan_and_decides_nothing(domain, capsys):
    domain.answers["plan"] = (200, PLAN)
    assert bench.main(["--incident", "inc-1"]) == 0
    assert [step for step, _ in domain.posted] == ["plan"]
    assert capsys.readouterr().out == PLAN_LINE + "\n"


def test_no_plan_to_approve_exits_1(domain, capsys):
    domain.answers["plan"] = (404, {"error": "nothing waiting"})
    assert bench.main(["--incident", "inc-1", "--approve"]) == 1
    assert [step for step, _ in domain.posted] == ["plan"]
    assert capsys.readouterr().out == "no plan to approve (404): nothing waiting\n"


def test_deny_posts_the_reason_for_the_waiting_plan(domain, capsys):
    domain.answers.update(plan=(200, PLAN), deny=(202, {}))
    assert bench.main(["--incident", "inc-1", "--deny", "not now"]) == 0
    assert [step for step, _ in domain.posted] == ["plan", "deny"]
    deny = domain.posted[1][1]
    assert (deny["workflow_id"], deny["plan_hash"], deny["reason"]) == ("wf-1", PLAN["plan_hash"], "not now")
    assert capsys.readouterr().out == PLAN_LINE + "\ndenied as the bench approver\n"


@pytest.mark.parametrize(("status", "code", "said"), [(202, 0, "approved as the bench approver"),
                                                      (403, 1, "refused (403): not an approver here")])
def test_approve_signs_the_waiting_plan_and_says_whether_it_was_taken(domain, capsys, status, code, said):
    domain.answers.update(plan=(200, PLAN), approve=(status, {"error": "not an approver here"}))
    assert bench.main(["--incident", "inc-1", "--approve"]) == code
    assert [step for step, _ in domain.posted] == ["plan", "approve"]
    approval = domain.posted[1][1]
    assert (approval["workflow_id"], approval["plan_hash"], approval["tier"]) == ("wf-1", PLAN["plan_hash"], "T1")
    assert capsys.readouterr().out == f"{PLAN_LINE}\n{said}\n"
