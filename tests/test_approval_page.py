"""The approval page (decision D14; registers H6, R28, R58): a link reveals nothing until the approver's passkey says
who they are; approving needs the target typed (T2+) and a second passkey ceremony over the plan; the workflow gets
the assertion to re-verify; the link works once and for 15 minutes; every response is locked down."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_passkeys_h6 import RP, SoftAuthenticator, _enrol
from warden import approvals, passkeys
from warden.activities import Plan
from warden.approval_page import ApprovalPage

T0 = datetime(2026, 10, 3, 9, 0, tzinfo=UTC)
PLAN = Plan(workflow_id="rem-dev-1", incident_id="inc-9", entry="k8s_rollout_restart", tier="T2",
            params={"namespace": "shop", "deployment": "orders"}, plan_hash="p" * 64, created_at=T0,
            target="dev/k8s/shop/orders", environment="dev")


class _Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


@pytest.fixture
def setup():
    device = SoftAuthenticator()
    cred = _enrol(device)
    pem = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(
        public_key=pem, tiers=["T1", "T2"], passkeys=[approvals.PasskeyCredential(
            credential_id=cred.credential_id, public_key=cred.public_key, sign_count=0, device_bound=True)])})
    sent, clock = [], _Clock()
    page = ApprovalPage(rp_id=RP, policy=policy, plan_of=lambda wf: PLAN if wf == PLAN.workflow_id else None,
                        signal=lambda wf, a: sent.append((wf, a)), clock=clock)
    return page, device, sent, clock


def _ceremony(page, device, token, step):
    r = page.handle("POST", f"/a/{token}/{step}-options")
    assert r.status == 200, r.body
    return device.assert_(json.dumps(json.loads(r.body)["options"]))


def _show(page, device, token):
    return page.handle("POST", f"/a/{token}/login", json.dumps({"response": _ceremony(page, device, token, "login")}))


def test_the_link_shows_nothing_until_a_passkey_says_who_is_looking(setup):
    page, device, _, _ = setup
    token = page.new_link("rem-dev-1", "owner")
    shell = page.handle("GET", f"/a/{token}")
    assert shell.status == 200 and "orders" not in shell.body and "p" * 64 not in shell.body
    assert page.handle("POST", f"/a/{token}/approve-options").status == 403  # no plan before who-are-you
    shown = _show(page, device, token)
    plan = json.loads(shown.body)["plan"]
    assert shown.status == 200 and plan["target"] == PLAN.target and plan["type_the_target"] is True
    assert plan["made"].startswith("2026-10-03 09:00:00Z")  # UTC first, then the display zone (R4)


def test_an_approval_with_the_target_typed_reaches_the_workflow_once(setup):
    page, device, sent, _ = setup
    token = page.new_link("rem-dev-1", "owner")
    _show(page, device, token)
    response = _ceremony(page, device, token, "approve")
    ok = page.handle("POST", f"/a/{token}/approve", json.dumps({"response": response, "typed_target": PLAN.target}))
    assert ok.status == 200 and len(sent) == 1
    wf, assertion = sent[0]
    assert wf == "rem-dev-1" and assertion.plan_hash == PLAN.plan_hash and assertion.tier == "T2"
    # What the workflow will re-verify does verify: the challenge is the plan's own, signed by the enrolled key.
    pending = passkeys.Pending(wf, assertion.plan_hash, assertion.tier, assertion.nonce, assertion.expires_at,
                               assertion.challenge)
    cred = page._credentials("owner")[0]
    approval, problems = passkeys.verify_approval(assertion.response, pending=pending, credential=cred, rp_id=RP,
                                                  origin=page.origin, now=T0, used_nonces=set())
    assert problems == [] and approval.plan_hash == PLAN.plan_hash
    assert page.handle("GET", f"/a/{token}").status == 404  # used once


def test_a_mistyped_target_sends_nothing(setup):
    page, device, sent, _ = setup
    token = page.new_link("rem-dev-1", "owner")
    _show(page, device, token)
    response = _ceremony(page, device, token, "approve")
    r = page.handle("POST", f"/a/{token}/approve", json.dumps({"response": response, "typed_target": "dev/k8s/shop"}))
    assert r.status == 400 and sent == []


def test_someone_elses_passkey_sees_nothing(setup):
    page, _, sent, _ = setup
    token = page.new_link("rem-dev-1", "owner")
    stranger = SoftAuthenticator()
    _enrol(stranger)
    r = page.handle("POST", f"/a/{token}/login",
                    json.dumps({"response": _ceremony(page, stranger, token, "login")}))
    assert r.status == 403 and "orders" not in r.body and sent == []


def test_an_expired_or_unknown_link_answers_the_same(setup):
    page, _, _, clock = setup
    token = page.new_link("rem-dev-1", "owner")
    clock.now = T0 + timedelta(minutes=15)
    expired, unknown = page.handle("GET", f"/a/{token}"), page.handle("GET", "/a/" + "x" * 43)
    assert expired.status == unknown.status == 404 and expired.body == unknown.body


def test_every_response_is_locked_down(setup):
    page, _, _, _ = setup
    token = page.new_link("rem-dev-1", "owner")
    for r in (page.handle("GET", f"/a/{token}"), page.handle("GET", "/a/nope")):
        csp = r.headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp
        assert r.headers["Strict-Transport-Security"].startswith("max-age=") and r.headers["Cache-Control"] == "no-store"
        assert r.headers["Referrer-Policy"] == "no-referrer"
    shell = page.handle("GET", f"/a/{token}").body
    assert "<script src" not in shell and "http://" not in shell and "https://" not in shell
    nonce = page.handle("GET", f"/a/{token}").headers["Content-Security-Policy"].split("'nonce-")[1].split("'")[0]
    assert len(nonce) >= 16
