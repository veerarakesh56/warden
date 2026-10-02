"""A step that keeps failing ends the run on the record, and the breaker counts only failures since its reset
(G2: audit A-B-L10, A-B-L1)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from temporalio.client import WorkflowFailureError

from test_bounds import Clock
from test_remediation_workflow import _approve_with, _run, owner, world  # noqa: F401 - fixtures
from warden import approvals, bounds
from warden.audit import AuditLog
from warden.workflows import QUICK


def _ends(world):  # noqa: F811
    return [e["body"] for e in world["log"].entries(kinds=("workflow.end",))]


def test_every_quick_step_has_a_bounded_number_of_tries():
    policy = QUICK["retry_policy"]
    assert policy.maximum_attempts and 1 < policy.maximum_attempts <= 20


def test_a_step_that_keeps_failing_before_apply_ends_the_run_on_the_record(world):  # noqa: F811
    def unreadable(entry, params):
        raise RuntimeError("the platform cannot be read")
    world["platform"].live = unreadable

    async def nothing(handle):
        pass
    with pytest.raises(WorkflowFailureError):
        _run(world, nothing)
    [end] = _ends(world)
    assert end["status"] == "failed" and not end["checklist"]["applied"]
    assert bounds.killswitch(world["log"]) is None  # nothing was changed: no reason to stop every other fix


def test_a_step_that_keeps_failing_after_apply_trips_the_kill_switch(world, owner):  # noqa: F811
    def broken(service):
        raise RuntimeError("health cannot be read")
    world["platform"].healthy = broken
    with pytest.raises(WorkflowFailureError):
        _run(world, _approve_with(owner))
    [end] = _ends(world)
    assert end["status"] == "failed_after_apply" and end["checklist"]["applied"]
    assert bounds.killswitch(world["log"]) is not None  # a change in an unknown state: a person takes over


def test_the_breaker_counts_only_failures_after_the_last_reset(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    clock, key = Clock(), Ed25519PrivateKey.generate()
    log = AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate(), clock=clock)
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T3"])},
                                      cooling_off_minutes={"T3": 0})
    bounds.record_result(log, "inc-1", service="a", ok=False, now=clock.now)
    bounds.record_result(log, "inc-2", service="a", ok=False, now=clock.now)
    row = bounds.killswitch(log)
    assert row is not None
    signed = approvals.sign(key, approver="owner", workflow_id="killswitch", plan_hash=bounds.trips_hash(log),
                            tier="T3", now=clock.now)
    assert bounds.reset(log, signed, policy=policy, now=clock.now) == []
    clock.advance(minutes=5)
    bounds.record_result(log, "inc-3", service="a", ok=False, now=clock.now)  # one new failure, inside the window
    assert bounds.killswitch(log) is None
    bounds.record_result(log, "inc-4", service="a", ok=False, now=clock.now + timedelta(seconds=1))
    assert bounds.killswitch(log) is not None  # two new ones still trip it
