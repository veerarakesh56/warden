"""Requirement R50: a single approver, stated honestly - in the record of every change, not only in the README."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_remediation_workflow import (  # noqa: F401
    _approve_with,
    _run,
    _until_awaiting_approval,
    owner,
    world,
)
from warden import approvals
from warden.workflows import RemediationWorkflow


def _end(w):
    return w["log"].entries("inc-42", kinds=("workflow.end",))[-1]["body"]


def test_a_change_one_person_approved_says_so(world, owner):  # noqa: F811
    assert _run(world, _approve_with(owner)).status == "recovered"
    end = _end(world)
    assert end["single_approver"] is True and end["approvers"] == ["owner"] and end["required"] == 1
    accepted = world["log"].entries("inc-42", kinds=("approval.accepted",))
    assert [e["body"]["required"] for e in accepted] == [1]


def test_a_change_two_people_approved_is_not_called_single(world, owner):  # noqa: F811
    second = Ed25519PrivateKey.generate()
    pem = second.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = world["policy"]
    world["policy"] = approvals.ApproverPolicy(
        approvers={**policy.approvers, "second": approvals.Approver(public_key=pem, tiers=["T1", "T2"])},
        required={"T1": 2, "T2": 2})

    async def drive(handle):
        plan = await _until_awaiting_approval(handle)
        for name, key in (("owner", owner), ("second", second)):
            await handle.signal(RemediationWorkflow.approve, approvals.sign(
                key, approver=name, now=datetime.now(UTC), workflow_id=handle.id, plan_hash=plan.plan_hash,
                tier=plan.tier))
            await asyncio.sleep(0.2)

    assert _run(world, drive).status == "recovered"
    end = _end(world)
    assert end["single_approver"] is False and end["approvers"] == ["owner", "second"] and end["required"] == 2
