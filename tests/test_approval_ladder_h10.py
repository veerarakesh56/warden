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
    monkeypatch.setattr(chatops, "resolve_sinks", lambda: [s])
    # A workflow id shaped as production makes them (rem-<env>-<16 hex>): the harness's random UUID is, rightly,
    # withheld by the outbound gate.
    monkeypatch.setattr(test_remediation_workflow, "uuid", types.SimpleNamespace(uuid4=lambda: "dev-6a3fb36ac419b7e0"))
    return s


def test_an_unapproved_plan_is_reminded_halfway_then_reported_expired(world, sink):  # noqa: F811
    out = _run(world, _no_approval)
    assert out.status == "expired" and world["platform"].applied == []
    assert len(sink.texts) == 2, sink.texts
    assert "is waiting for an approval" in sink.texts[0] and "expired without an approval" in sink.texts[1]
    assert all("audit head" in t and "incident `inc-42`" in t for t in sink.texts)
    whats = [e["body"]["what"] for e in world["log"].entries("inc-42", kinds=("remediation.announce",))]
    assert whats == ["waiting", "expired"]


def test_a_plan_approved_in_time_is_not_announced(world, owner, sink):  # noqa: F811
    out = _run(world, _approve_with(owner))
    assert out.status == "recovered" and sink.texts == []


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
    assert len(sink.texts) == 1 and "is waiting for an approval" in sink.texts[0], sink.texts
