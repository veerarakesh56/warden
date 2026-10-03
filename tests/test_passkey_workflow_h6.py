"""Register H6 through the workflow: a passkey approval of the exact plan lets the fix go ahead, re-verified by the
workflow's own activity; an approval for another plan, with another key, or replayed, is refused and nothing is
applied."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from test_passkeys_h6 import ORIGIN, RP, SoftAuthenticator, _enrol
from test_remediation_workflow import (  # noqa: F401
    _no_approval,
    _run,
    _until_awaiting_approval,
    owner,
    world,
)
from warden import approvals, bounds, passkeys
from warden.workflows import RemediationWorkflow


@pytest.fixture
def phone(world, monkeypatch):  # noqa: F811
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", RP)
    device = SoftAuthenticator()
    cred = _enrol(device)
    pk = approvals.PasskeyCredential(credential_id=cred.credential_id, public_key=cred.public_key,
                                     sign_count=cred.sign_count, device_bound=cred.device_bound)
    owner_entry = world["policy"].approvers["owner"]
    world["policy"] = world["policy"].model_copy(update={"approvers": {
        "owner": owner_entry.model_copy(update={"passkeys": [pk]})}})
    return device, cred


def _assertion(device, cred, plan, workflow_id, *, plan_hash=None):
    options, pending = passkeys.approval_options(rp_id=RP, credentials=[cred], workflow_id=workflow_id,
                                                 plan_hash=plan_hash or plan.plan_hash, tier=plan.tier,
                                                 now=datetime.now(UTC))
    return approvals.PasskeyAssertion(approver="owner", workflow_id=pending.workflow_id, plan_hash=pending.plan_hash,
                                      tier=pending.tier, nonce=pending.nonce, expires_at=pending.expires_at,
                                      challenge=pending.challenge, response=device.assert_(options, origin=ORIGIN))


def _approve_by_passkey(device, cred, **kw):
    async def drive(handle):
        plan = await _until_awaiting_approval(handle)
        await handle.signal(RemediationWorkflow.approve_passkey, _assertion(device, cred, plan, handle.id, **kw))
    return drive


def test_a_passkey_approval_of_the_exact_plan_applies_it(world, phone):  # noqa: F811
    out = _run(world, _approve_by_passkey(*phone))
    assert out.status == "recovered" and len(world["platform"].applied) == 1
    accepted = world["log"].entries("inc-42", kinds=("approval.accepted",))
    assert [(e["body"]["method"], e["body"]["sign_count"]) for e in accepted] == [("passkey", 1)]


def test_a_passkey_approval_of_another_plan_is_refused(world, phone):  # noqa: F811
    async def drive(handle):
        await _approve_by_passkey(*phone, plan_hash="0" * 64)(handle)
        await _no_approval(handle)

    out = _run(world, drive, approval_ttl_minutes=1)
    assert out.status == "expired" and world["platform"].applied == []
    refused = world["log"].entries("inc-42", kinds=("approval.refused",))
    assert any("different plan" in p for p in refused[0]["body"]["problems"])


def test_a_key_the_approver_never_enrolled_is_refused(world, phone):  # noqa: F811
    stranger = SoftAuthenticator()
    stranger_cred = _enrol(stranger)
    async def drive(handle):
        await _approve_by_passkey(stranger, stranger_cred)(handle)
        await _no_approval(handle)

    out = _run(world, drive, approval_ttl_minutes=1)
    assert out.status == "expired" and world["platform"].applied == []
    problems = world["log"].entries("inc-42", kinds=("approval.refused",))[0]["body"]["problems"]
    assert any("not one owner enrolled" in p for p in problems)


def _twice(world, phone, fresh):  # noqa: F811
    device, cred = phone

    async def drive(handle):
        plan = await _until_awaiting_approval(handle)
        first = _assertion(device, cred, plan, handle.id)
        world["policy"].required["T2"] = 2  # so the second is examined, not skipped
        await handle.signal(RemediationWorkflow.approve_passkey, first)
        await asyncio.sleep(0.3)
        second = _assertion(device, cred, plan, handle.id) if fresh else json.loads(first.model_dump_json())
        await handle.signal(RemediationWorkflow.approve_passkey, second)
        await _no_approval(handle)

    out = _run(world, drive, approval_ttl_minutes=1)
    assert out.status == "expired" and world["platform"].applied == []
    return [p for e in world["log"].entries("inc-42", kinds=("approval.refused",)) for p in e["body"]["problems"]]


def test_a_replayed_passkey_approval_is_refused(world, phone):  # noqa: F811
    assert any("already used" in p for p in _twice(world, phone, fresh=False))


def test_one_person_cannot_be_two_approvers_with_two_fresh_passkey_approvals(world, phone):  # noqa: F811
    problems = _twice(world, phone, fresh=True)
    assert any("has already approved this plan" in p for p in problems), problems


def test_a_cloned_passkey_whose_counter_restarted_is_refused_in_a_later_run(world, phone):  # noqa: F811
    device, cred = phone
    world["limits"] = bounds.Limits(cooldown=timedelta(0))  # one target twice; the cool-down has its own test
    assert _run(world, _approve_by_passkey(device, cred)).status == "recovered"  # the counter is now 1, in the audit
    device.count = 0  # a copy of the key, its counter back at the start
    out = _run(world, _approve_by_passkey(device, cred), approval_ttl_minutes=1)
    assert out.status == "expired" and len(world["platform"].applied) == 1
    problems = world["log"].entries("inc-42", kinds=("approval.refused",))[-1]["body"]["problems"]
    assert any("was not greater than current count" in p for p in problems), problems
