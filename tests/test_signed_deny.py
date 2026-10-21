"""The bench approver (dev only) may decline too, with the reason a person types in the page's box.
A signed denial of a waiting plan in its environments ends it with nothing changed; a person's approver, another
plan's hash, a forged signature or a stale request denies nothing."""

from __future__ import annotations

import json
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_bench_approver import NOW, _page, _plan
from warden import approvals


def _deny(page, key, plan, reason="the target is wrong", name="bench", at=NOW, plan_hash=None):
    issued = at.isoformat()
    ph = plan_hash or plan.plan_hash
    sig = key.sign(approvals.deny_request(name, plan.workflow_id, ph, reason, issued)).hex()
    return page.handle("POST", "/a/signed/deny", json.dumps({
        "approver": name, "workflow_id": plan.workflow_id, "plan_hash": ph, "reason": reason, "issued_at": issued,
        "signature": sig}))


def test_the_bench_approver_denies_a_waiting_dev_plan_with_its_reason(tmp_path):
    plan = _plan()
    page, bench, _, _ = _page(tmp_path, plan)
    denied = []
    page.deny = lambda wf, d: denied.append((wf, d))
    assert _deny(page, bench, plan).status == 202
    assert denied[0][0] == plan.workflow_id
    assert denied[0][1].reason == "the target is wrong"
    assert denied[0][1].approver == "bench"
    assert denied[0][1].plan_hash == plan.plan_hash


def test_nothing_else_is_denied(tmp_path):
    for plan in (_plan(), _plan(env="prod")):
        page, bench, person, _ = _page(tmp_path / plan.environment, plan) if (tmp_path / plan.environment).mkdir() \
            is None else None
        denied = []
        page.deny = lambda wf, d, denied=denied: denied.append(wf)
        if plan.environment == "prod":
            assert _deny(page, bench, plan).status == 404  # not one of its environments
        else:
            assert _deny(page, person, plan, name="owner").status == 403   # a person's approver: not this path
            assert _deny(page, Ed25519PrivateKey.generate(), plan).status == 403
            assert _deny(page, bench, plan, at=NOW - timedelta(minutes=6)).status == 403
            assert _deny(page, bench, plan, plan_hash="another").status == 404
        assert denied == []
