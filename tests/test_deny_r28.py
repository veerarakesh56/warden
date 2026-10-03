"""Requirement R28: approve AND deny. On the approval page, after showing the plan, the approver may deny it with a
passkey ceremony over the plan; the workflow then ends the plan "denied" and changes nothing. A denial for another
plan is ignored. A denial can only stop a change - fail-safe by construction."""

from __future__ import annotations

import json

import pytest

import test_approval_page as page_tests
from test_approval_page import PLAN, _ceremony, _show
from warden import approvals
from warden.approvals import Denial


@pytest.fixture
def setup():
    return page_tests.setup.__wrapped__()


def test_the_approver_denies_with_a_passkey_after_seeing_the_plan(setup):
    page, device, sent, _ = setup
    denied = []
    page.deny = lambda wf, d: denied.append((wf, d))
    token = page.new_link("rem-dev-1", "owner")
    assert page.handle("POST", f"/a/{token}/deny-options").status == 403  # not before the plan is shown
    _show(page, device, token)
    response = _ceremony(page, device, token, "deny")
    ok = page.handle("POST", f"/a/{token}/deny", json.dumps({"response": response, "reason": "wrong target"}))
    assert ok.status == 200 and sent == []
    [(wf, d)] = denied
    assert wf == PLAN.workflow_id and d.approver == "owner" and d.plan_hash == PLAN.plan_hash and d.reason == "wrong target"
    assert page.handle("GET", f"/a/{token}").status == 404  # the link is used


def test_a_deny_without_the_passkey_is_refused(setup):
    page, device, _, _ = setup
    denied = []
    page.deny = lambda wf, d: denied.append(d)
    token = page.new_link("rem-dev-1", "owner")
    _show(page, device, token)
    page.handle("POST", f"/a/{token}/deny-options")
    bad = page.handle("POST", f"/a/{token}/deny", json.dumps({"response": {"id": "forged"}}))
    assert bad.status == 403 and denied == []


def test_a_denied_plan_ends_with_nothing_changed(tmp_path):
    from test_remediation_workflow import RemediationWorkflow, _run, _until_awaiting_approval
    from test_remediation_workflow import owner as owner_fixture
    from test_remediation_workflow import world as world_fixture

    world = world_fixture.__wrapped__(tmp_path, owner_fixture.__wrapped__())

    async def deny(handle):
        plan = await _until_awaiting_approval(handle)
        await handle.signal(RemediationWorkflow.deny, Denial(approver="owner", workflow_id=handle.id,
                                                            plan_hash="0" * 64))  # another plan's: ignored
        await handle.signal(RemediationWorkflow.deny, Denial(approver="owner", workflow_id=handle.id,
                                                            plan_hash=plan.plan_hash, reason="not now"))

    out = _run(world, deny)
    assert out.status == "denied" and out.reasons == ["denied by owner: not now"]
    assert world["platform"].applied == [] and not out.checklist["approved"]
    end = [e["body"] for e in world["log"].entries("inc-42", kinds=("workflow.end",))]
    assert end and end[-1].get("status") == "denied"


def test_a_denial_names_a_plain_approver():
    with pytest.raises(ValueError):
        Denial(approver="owner<script>", workflow_id="w", plan_hash="p")
    assert approvals.Denial(approver="owner", workflow_id="w", plan_hash="p").reason == ""
