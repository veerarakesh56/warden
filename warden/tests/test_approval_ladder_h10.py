"""Register H10: nobody approves before the TTL - a person is reminded halfway and told when nothing was done."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from test_remediation_workflow import (  # noqa: F401
    _approve_with,
    _no_approval,
    _run,
    _until_awaiting_approval,
    owner,
    recorded,
    world,
)
from warden import approvals, chatops
from warden.chatops import Notification
from warden.workflows import RemediationWorkflow


class _Sink:
    name = "capture"

    def __init__(self):
        self.texts = []

    def send(self, text, data):
        self.texts.append(text)
        return Notification(sink=self.name, delivered=True, detail="captured")


@pytest.fixture
def sink(monkeypatch):
    import types

    import test_remediation_workflow

    s = _Sink()
    monkeypatch.setattr(chatops, "resolve_sinks", lambda *_a, **_k: [s])
    # A workflow id shaped as production makes them (rem-<env>-<16 hex>): the harness's random UUID is, rightly,
    # withheld by the outbound gate.
    monkeypatch.setattr(test_remediation_workflow, "uuid", types.SimpleNamespace(uuid4=lambda: "dev-6a3fb36ac419b7e0"))
    return s


def test_an_unapproved_plan_is_reminded_halfway_then_reported_expired(world, sink):  # noqa: F811
    out = _run(world, _no_approval)
    assert out.status == "expired"
    assert world["platform"].applied == []
    # The request as the wait opens (sent even with no approval domain: never nothing), the halfway reminder, the
    # expiry.
    assert len(sink.texts) == 3, sink.texts
    assert all("is waiting for an approval" in t for t in sink.texts[:2])
    assert "expired without an approval" in sink.texts[2]
    assert all("audit head" in t and "incident `inc-42`" in t for t in sink.texts)
    whats = [e["body"]["what"] for e in world["log"].entries("inc-42", kinds=("remediation.announce",))]
    assert whats == ["waiting", "waiting", "expired"]


def test_a_plan_approved_in_time_gets_no_reminder_and_its_approvers_are_told_how_it_went(world, owner, sink):  # noqa: F811
    """No waiting or expired message - and, since the owner's first live approvals (2026-10-12, G10-24), the
    people who approved it hear that the fix was verified and that it held."""
    out = _run(world, _approve_with(owner))
    # Nothing in the channel: approved and fixed are on the records page (owner, 2026-10-14), worded as before.
    told = recorded(world["log"])
    assert out.status == "recovered", (sink.texts, told)
    assert len(sink.texts) == 1, (sink.texts, told)
    assert len(told) == 3, (sink.texts, told)
    assert "is waiting for an approval" in sink.texts[0]  # only the request reached the channel
    assert "was approved by `owner` (with their signing key)" in told[0]
    assert "passed its health checks" in told[1]
    assert "held through its re-checks" in told[2]
    assert not any("waiting for an approval" in t or "expired" in t for t in told)


def test_a_plan_approved_after_the_reminder_goes_ahead(world, owner, sink):  # noqa: F811
    async def drive(handle):
        plan = await _until_awaiting_approval(handle)
        for _ in range(3000):  # the reminder fires at half the TTL; time passes only while a result is awaited
            if sink.texts:
                break
            await asyncio.sleep(0.01)
        else:
            # Nothing awaited the result yet: let the server skip to the reminder, then approve.
            await handle.query(RemediationWorkflow.stage)
        await handle.signal(RemediationWorkflow.approve, approvals.sign(
            owner, approver="owner", now=datetime.now(UTC), workflow_id=handle.id, plan_hash=plan.plan_hash,
            tier=plan.tier))

    out = _run(world, drive, approval_ttl_minutes=1)
    assert out.status == "recovered"
    told = recorded(world["log"])
    assert len(sink.texts) == 1, sink.texts
    assert "is waiting for an approval" in sink.texts[0], sink.texts
    assert len(told) == 3
    assert "was approved by `owner`" in told[0]
    assert "passed its health checks" in told[1]
    assert "held through its re-checks" in told[2]
