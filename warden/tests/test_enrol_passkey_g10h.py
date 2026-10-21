"""Enrolling a passkey on the approval page (decision D14, register H6; the owner's first live enrolment, 2026-10-12).

The link is signed by the approver's own Ed25519 key, lasts 15 minutes and works once. The page runs the ceremony and
hands back the approver list with the new passkey in it - and trusts nothing of it: the passkey approves only after a
person saves that list where WARDEN reads it."""

from __future__ import annotations

import dataclasses
import json
import pathlib
import re
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from webauthn.helpers import bytes_to_base64url

from test_approval_page import PLAN, T0, _Clock, _show
from test_passkeys_h6 import RP, SoftAuthenticator
from warden import approvals, audit, cli
from warden.approval_page import LINK_TTL, ApprovalPage, AuditLinkStore, invite

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@pytest.fixture
def setup():
    key, clock = Ed25519PrivateKey.generate(), _Clock()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=_pem(key), tiers=["T1", "T2"])})
    page = ApprovalPage(rp_id=RP, policy=policy, plan_of=lambda wf: PLAN if wf == PLAN.workflow_id else None,
                        signal=lambda wf, a: None, clock=clock)
    return page, key, clock


def _options(page, token):
    r = page.handle("POST", f"/e/{token}/options")
    assert r.status == 200, r.body
    return json.dumps(json.loads(r.body)["options"])


def _finish(page, token, response):
    return page.handle("POST", f"/e/{token}/finish", json.dumps({"response": response}))


def test_the_approvers_own_key_enrols_a_passkey_and_only_the_saved_list_makes_it_count(setup):
    page, key, _ = setup
    device, token = SoftAuthenticator(), invite(key, "owner", now=T0)
    shell = page.handle("GET", f"/e/{token}")
    assert shell.status == 200
    assert "frame-ancestors 'none'" in shell.headers["Content-Security-Policy"]
    assert "owner" not in shell.body
    assert token not in shell.body
    done = _finish(page, token, device.register(_options(page, token)))
    assert done.status == 200, done.body
    said = json.loads(done.body)
    listed = approvals.ApproverPolicy.loads(said["approvers"])
    assert said["approver"] == "owner"
    assert said["device_bound"] is True
    assert [c.credential_id for c in listed.approvers["owner"].passkeys] == [bytes_to_base64url(device.credential_id)]
    # Everything else in the list is as it was: the same break-glass key, tiers and rules.
    assert listed.model_copy(update={"approvers": page.policy.approvers}) == page.policy
    assert listed.approvers["owner"].public_key == page.policy.approvers["owner"].public_key
    # The page trusts nothing of it: its own list is unchanged, and the passkey shows no plan yet.
    assert page.policy.approvers["owner"].passkeys == []
    link = page.new_link(PLAN.workflow_id, "owner")
    assert page.handle("POST", f"/a/{link}/login-options").status == 200
    assert page.handle("POST", f"/a/{link}/login", json.dumps({"response": {"id": "x"}})).status == 403
    # Saved where WARDEN reads it, the same passkey shows the plan.
    saved = dataclasses.replace(page, policy=listed)
    assert _show(saved, device, saved.new_link(PLAN.workflow_id, "owner")).status == 200


def test_a_synced_passkey_is_listed_as_not_device_bound(setup):
    page, key, _ = setup
    token = invite(key, "owner", now=T0)
    said = json.loads(_finish(page, token, SoftAuthenticator(synced=True).register(_options(page, token))).body)
    assert said["device_bound"] is False
    assert approvals.ApproverPolicy.loads(said["approvers"]).approvers["owner"].passkeys[0].device_bound is False


@pytest.mark.parametrize("case", ["another key", "unknown approver", "expired", "made to last", "not a link",
                                  "changed after signing"])
def test_a_link_nobody_entitled_signed_for_now_invites_nobody(setup, case):
    page, key, clock = setup
    token = invite(key, "owner", now=T0)
    if case == "another key":
        token = invite(Ed25519PrivateKey.generate(), "owner", now=T0)
    elif case == "unknown approver":
        token = invite(key, "someone", now=T0)
    elif case == "expired":
        clock.now = T0 + LINK_TTL
    elif case == "made to last":
        token = invite(key, "owner", now=T0 + timedelta(hours=1))
    elif case == "not a link":
        token = "x" * 43
    else:
        signature = token.split(".")[1]
        token = bytes_to_base64url(json.dumps({"approver": "owner", "expires_at": (T0 + LINK_TTL).isoformat(),
                                               "nonce": "n"}).encode()) + "." + signature
    for r in (page.handle("GET", f"/e/{token}"), page.handle("POST", f"/e/{token}/options"),
              page.handle("POST", f"/e/{token}/finish", "{}")):
        assert r.status == 404
        assert json.loads(r.body) == {"error": "this enrolment link is not valid"}


def test_a_ceremony_that_does_not_verify_enrols_nothing_and_a_link_works_once(setup):
    page, key, _ = setup
    token = invite(key, "owner", now=T0)
    elsewhere = SoftAuthenticator().register(_options(page, token), origin="https://evil.example.test")
    assert _finish(page, token, elsewhere).status == 403
    assert _finish(page, token, SoftAuthenticator(uv=False).register(_options(page, token))).status == 403
    _options(page, token)
    assert page.handle("POST", f"/e/{token}/finish", "not json").status == 403
    device = SoftAuthenticator()
    answer = device.register(_options(page, token))
    assert _finish(page, token, answer).status == 200
    assert _finish(page, token, answer).status == 404
    assert page.handle("GET", f"/e/{token}").status == 404


def test_an_answer_needs_its_own_challenge_and_an_enrolled_passkey_is_not_listed_twice(setup):
    page, key, _ = setup
    device, token = SoftAuthenticator(), invite(key, "owner", now=T0)
    answer = device.register(_options(page, token))
    assert page.handle("POST", f"/e/{invite(key, 'owner', now=T0)}/finish",
                       json.dumps({"response": answer})).status == 403  # another link's challenge
    listed = approvals.ApproverPolicy.loads(json.loads(_finish(page, token, answer).body)["approvers"])
    saved, again = dataclasses.replace(page, policy=listed), invite(key, "owner", now=T0)
    assert _finish(saved, again, device.register(_options(saved, again))).status == 409


def test_the_lambdas_store_keeps_a_used_link_used_and_never_the_link(setup, tmp_path):
    page, key, clock = setup
    log = audit.AuditLog(tmp_path / "a.db")

    def invocation():  # each request is its own Lambda invocation: nothing but the audit carries over
        return dataclasses.replace(page, store=AuditLinkStore(log, clock=clock))

    token = invite(key, "owner", now=T0)
    answer = SoftAuthenticator().register(_options(invocation(), token))
    assert _finish(invocation(), token, answer).status == 200
    assert invocation().handle("GET", f"/e/{token}").status == 404
    assert token not in json.dumps([e["body"] for e in log.entries()])


def test_the_command_signs_a_link_the_page_accepts_and_opens_it_without_printing_it(setup, tmp_path, monkeypatch,
                                                                                    capsys):
    page, key, clock = setup
    pem = tmp_path / "owner.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    monkeypatch.delenv("WARDEN_APPROVER_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("WARDEN_APPROVAL_RP_ID", raising=False)
    import webbrowser

    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)
    assert cli.main(["enrol", "--approver", "owner", "--key", str(pem)]) == 1  # no domain, no link
    assert not opened
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", RP)
    assert cli.main(["enrol", "--approver", "owner", "--key", str(pem)]) == 0
    (link,) = opened
    printed = capsys.readouterr()
    assert link.startswith(f"https://{RP}/e/")
    assert link.split("/e/")[1] not in printed.out + printed.err
    clock.now = cli.datetime.now(cli.UTC)
    assert page.handle("GET", link.removeprefix(f"https://{RP}")).status == 200


def test_the_api_routes_the_enrolment_steps_the_page_serves():
    tf = (ROOT / "infra" / "terraform" / "modules" / "warden-runtime" / "frontdoor.tf").read_text(encoding="utf-8")
    assert '"GET /e/{token}", "POST /e/{token}/{step}"' in tf
    src = (ROOT / "warden" / "src" / "warden" / "approval_page.py").read_text(encoding="utf-8")
    assert set(re.findall(r'post\("([a-z]+)"', src.split("_ENROL = ")[1].split("_PAGE = ")[0])) == {"options", "finish"}
    assert '("POST", "options")' in src
    assert '("POST", "finish")' in src


def test_the_enrolment_page_can_be_cleared_and_says_what_the_list_and_its_risk_levels_are():
    """Owner, 2026-10-12: after copying the list "there should be something to close it or say done", or the list
    stays on the page for whoever sees the tab or its history later - and "what does all this T1 T2 T3 mean"."""
    from warden import approvals
    from warden.approval_page import _ENROL

    page = " ".join(_ENROL.split())
    assert '<button id="clear" type="button" hidden>Done: clear this page</button>' in page
    # Cleared by the button, and when the page is left: nothing comes back with the browser's Back button.
    assert 'const wipe = () => { $("list").value = "";' in page
    assert 'window.addEventListener("pagehide", wipe)' in page
    assert '$("clear").addEventListener("click", () => { wipe();' in page
    assert "public half only: the key itself never leaves your device" in page
    for tier, meaning in approvals.TIER_MEANS.items():  # the page's words are the ones every message uses
        assert f"{tier} {meaning.split(' risk: ')[0]} ({meaning.split(' risk: ')[1]})" in page
