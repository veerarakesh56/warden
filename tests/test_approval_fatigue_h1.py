"""Register H1, approval fatigue: hasty approvals are recorded, requests are capped, and T2+ types the target."""

from __future__ import annotations

import asyncio
import types
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_apply_reverifies import _acts
from test_remediation_workflow import REQ
from warden import activities, approvals, runtime
from warden.activities import FixRequest, Plan


def _signed_after(acts, owner, plan, seconds):
    signed = approvals.sign(owner, approver="owner", now=plan.created_at + timedelta(seconds=seconds),
                            workflow_id="rem-1", plan_hash=plan.plan_hash, tier=plan.tier)
    return acts.check_approval(plan, signed, [])


def test_an_approval_signed_seconds_after_the_plan_is_recorded_as_hasty():
    acts, _, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert _signed_after(acts, owner, plan, 3).enough
    [row] = acts.audit.entries(kinds=("approval.accepted",))
    assert row["body"]["hasty"] is True and row["body"]["latency_s"] == 3.0
    acts, _, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    _signed_after(acts, owner, plan, 45)
    assert acts.audit.entries(kinds=("approval.accepted",))[0]["body"]["hasty"] is False


def test_past_the_hourly_cap_the_next_plan_waits():
    acts, _, _ = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert acts.gate(plan, REQ["service"]) == []
    for i in range(activities.MAX_PLANS_PER_HOUR):
        acts.audit.append(f"inc-{i}", "remediation.plan", {"workflow_id": f"rem-other-{i}"})
    assert any(r.startswith("H1:") for r in acts.gate(plan, REQ["service"]))


def _client(plan):
    sent = []

    class _Handle:
        async def query(self, q):
            return {"stage": "awaiting_approval", "plan": plan}[q.__name__]

        async def signal(self, sig, approval):
            sent.append(approval)

    return types.SimpleNamespace(get_workflow_handle=lambda wid: _Handle()), sent


@pytest.mark.parametrize(("tier", "typed", "ok"), [
    ("T2", None, False), ("T2", "dev/k8s:shop/other", False), ("T2", "dev/k8s:shop/orders", True),
    ("T3", None, False), ("T1", None, True)])
def test_a_t2_or_t3_approver_types_the_target(tier, typed, ok):
    acts, _, _ = _acts()
    plan: Plan = acts.resolve_plan(FixRequest(**REQ), "rem-1").model_copy(update={"tier": tier})
    assert plan.target == "dev/k8s:shop/orders"
    client, sent = _client(plan)
    call = runtime.approve(client, "rem-1", plan_hash=plan.plan_hash, key=Ed25519PrivateKey.generate(),
                           approver="owner", typed_target=typed)
    if ok:
        asyncio.run(call)
        assert len(sent) == 1
    else:
        with pytest.raises(ValueError, match="typed exactly"):
            asyncio.run(call)
        assert sent == []
