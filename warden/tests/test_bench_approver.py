"""The bench approver (owner, 2026-10-15): a limited approver - its own key, `dev` only, T1/T2 - asks for an incident's
waiting plan with a signed request and sends a signed approval of it to the approval page, which checks everything
approvals.check checks before it signals; a person's approver (no environment list) never uses this path."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import approvals, audit
from warden.approval_page import ApprovalPage

NOW = datetime(2026, 10, 15, 9, 0, tzinfo=UTC)


def _pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _plan(env="dev", tier="T1"):
    return approvals.Plan(workflow_id=f"rem-{env}-1", incident_id="inc-1", entry="events_enable_rule", tier=tier,
                          params={}, plan_hash="h1", created_at=NOW - timedelta(hours=1), target="rule/tick",
                          environment=env)


def _page(tmp_path, plan, bench_envs=("dev",)):
    bench, person = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    policy = approvals.ApproverPolicy(approvers={
        "bench": approvals.Approver(public_key=_pem(bench), tiers=["T1", "T2"], environments=list(bench_envs)),
        "owner": approvals.Approver(public_key=_pem(person), tiers=["T1", "T2", "T3"])})
    log = audit.AuditLog(tmp_path / "a.db", key=Ed25519PrivateKey.generate())
    log.append("inc-1", "remediation.plan", {"workflow_id": plan.workflow_id, "plan_hash": plan.plan_hash})
    sent = []
    page = ApprovalPage(rp_id="approve.example.test", policy=policy, signal=lambda *a: None, log=log,
                        plan_of=lambda wf: plan if wf == plan.workflow_id else None,
                        signed=lambda wf, a: sent.append((wf, a)), clock=lambda: NOW)
    return page, bench, person, sent


def _ask(page, key, name="bench", incident="inc-1", at=NOW):
    issued = at.isoformat()
    sig = key.sign(approvals.plan_request(name, incident, issued)).hex()
    return page.handle("POST", "/a/signed/plan", json.dumps({"approver": name, "incident": incident,
                                                            "issued_at": issued, "signature": sig}))


def _approve(page, key, plan, name="bench"):
    a = approvals.sign(key, approver=name, workflow_id=plan.workflow_id, plan_hash=plan.plan_hash, tier=plan.tier,
                       now=NOW)
    return page.handle("POST", "/a/signed/approve", a.model_dump_json())


def test_the_bench_approver_is_shown_its_plan_and_its_signed_approval_is_sent(tmp_path):
    plan = _plan()
    page, bench, _, sent = _page(tmp_path, plan)
    shown = _ask(page, bench)
    assert shown.status == 200
    assert json.loads(shown.body) == {
        "workflow_id": "rem-dev-1", "plan_hash": "h1", "tier": "T1", "environment": "dev",
        "entry": "events_enable_rule", "target": "rule/tick"}
    assert _approve(page, bench, plan).status == 202
    assert [wf for wf, _ in sent] == ["rem-dev-1"]


def test_a_plan_outside_its_environments_or_tiers_is_neither_shown_nor_approved(tmp_path):
    for plan in (_plan(env="prod"), _plan(tier="T3")):
        (tmp_path / plan.environment / plan.tier).mkdir(parents=True)
        page, bench, _, sent = _page(tmp_path / plan.environment / plan.tier, plan)
        assert _ask(page, bench).status == 404
        assert _approve(page, bench, plan).status == 403
        assert not sent


def test_a_person_a_forged_signature_a_stale_request_and_a_reused_approval_are_refused(tmp_path):
    plan = _plan()
    page, bench, person, sent = _page(tmp_path, plan)
    assert _ask(page, person, name="owner").status == 403          # a person's approver never uses this path
    assert _approve(page, person, plan, name="owner").status == 403
    assert _ask(page, Ed25519PrivateKey.generate()).status == 403   # not the bench approver's key
    assert _ask(page, bench, at=NOW - timedelta(minutes=6)).status == 403
    a = approvals.sign(bench, approver="bench", workflow_id=plan.workflow_id, plan_hash=plan.plan_hash, tier="T1",
                       now=NOW)
    page.log.append("inc-1", "approval.accepted", {"nonce": a.nonce})
    assert page.handle("POST", "/a/signed/approve", a.model_dump_json()).status == 403
    assert not sent
