"""The kill switch is reset where the audit is (register G10-30; the first live trip, 2026-10-12).

The switch tripped in the cloud runtime and could not be reset: the only reset was a command that opens the audit
database, which no laptop reaches there. Now an approver opens a link their own key signed (`warden killswitch link`),
the approval page shows every trip since the last reset, and their passkey resets it - under the riskiest tier's
rules: an approver of T3, a device-bound passkey, exactly the trips shown, and the wait after the latest trip."""

from __future__ import annotations

import json
import pathlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_passkeys_h6 import RP, SoftAuthenticator, _enrol
from warden import approvals, audit, bounds, cli
from warden.approval_page import RESET_INVITE, ApprovalPage, AuditLinkStore, invite

ROOT = pathlib.Path(__file__).resolve().parents[1]
WAIT = timedelta(minutes=10)  # the example policy's T3 cooling-off


class World:
    def __init__(self, tmp_path, *, tiers=("T1", "T2", "T3"), synced=False, ahead=WAIT + timedelta(minutes=1)):
        self.key, self.device = Ed25519PrivateKey.generate(), SoftAuthenticator(synced=synced)
        cred = _enrol(self.device)
        pem = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(
            public_key=pem, tiers=list(tiers), passkeys=[approvals.PasskeyCredential(
                credential_id=cred.credential_id, public_key=cred.public_key, sign_count=0,
                device_bound=cred.device_bound)])})
        self.log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        bounds.trip(self.log, "inc-1", "rem-dev-1 ended rollback_failed: orders did not recover, and the undo failed")
        self.ahead = ahead
        self.page = ApprovalPage(rp_id=RP, policy=self.policy, plan_of=lambda wf: None, signal=lambda wf, a: None,
                                 store=AuditLinkStore(self.log, clock=self.now), log=self.log, clock=self.now)

    def now(self):
        return datetime.now(UTC) + self.ahead

    def link(self, purpose=RESET_INVITE):
        return invite(self.key, "owner", now=self.now(), purpose=purpose)

    def reset(self, token):
        shown = self.page.handle("POST", f"/k/{token}/trips")
        assert shown.status == 200, shown.body
        answer = self.device.assert_(json.dumps(json.loads(shown.body)["options"]))
        return json.loads(shown.body), self.page.handle("POST", f"/k/{token}/reset", json.dumps({"response": answer}))


def test_an_approvers_passkey_resets_the_switch_after_showing_every_trip(tmp_path):
    w = World(tmp_path)
    bounds.trip(w.log, "inc-2", "rem-dev-2 ended apply_failed: half-made")
    w.ahead += timedelta(seconds=5)
    token = w.link()
    shell = w.page.handle("GET", f"/k/{token}")
    assert shell.status == 200
    assert "rollback_failed" not in shell.body  # the reasons come with the first step
    shown, done = w.reset(token)
    assert shown["on"] is True
    assert shown["wait"] == ""
    assert [t["reason"][:9] for t in shown["trips"]] == ["rem-dev-1", "rem-dev-2"]
    assert done.status == 200
    assert json.loads(done.body) == {"reset": True}
    assert bounds.killswitch(w.log) is None
    [row] = [e["body"] for e in w.log.entries(kinds=(bounds.RESET,))]
    assert row["approver"] == "owner"
    assert row["method"] == "passkey"
    assert len(row["trips"]) == 2
    assert w.page.handle("GET", f"/k/{token}").status == 404  # used once
    assert audit.verify(tmp_path / "audit.db", w.log.key.public_key()).unsigned_tail == 0
    again = w.link()
    assert json.loads(w.page.handle("POST", f"/k/{again}/trips").body) == {"on": False}  # nothing left to reset


@pytest.mark.parametrize("over, needle", [
    ({"ahead": timedelta(0)}, "T3 needs the latest trip to be 0:10:00 old"),
    ({"synced": True}, "T3 needs a device-bound passkey"),
    ({"tiers": ("T1", "T2")}, "owner may not approve T3"),
])
def test_a_reset_keeps_the_riskiest_tiers_rules(tmp_path, over, needle):
    w = World(tmp_path, **over)
    shown, done = w.reset(w.link())
    assert done.status == 403, done.body
    assert any(needle in p for p in json.loads(done.body)["problems"]), done.body
    assert bounds.killswitch(w.log) is not None
    assert bool(shown["wait"]) is ("ahead" in over)  # the page says from when it can be reset


def test_a_trip_added_after_the_reasons_were_shown_is_not_reset_unseen(tmp_path):
    w = World(tmp_path)
    token = w.link()
    shown = json.loads(w.page.handle("POST", f"/k/{token}/trips").body)
    bounds.trip(w.log, "inc-3", "rem-dev-3 ended apply_failed")
    w.ahead += WAIT + timedelta(minutes=1)  # past the new trip's own wait, and still:
    done = w.page.handle("POST", f"/k/{token}/reset",
                         json.dumps({"response": w.device.assert_(json.dumps(shown["options"]))}))
    assert done.status == 403
    assert bounds.killswitch(w.log) is not None


def test_a_link_opens_only_what_it_was_signed_for_and_a_page_without_the_audit_resets_nothing(tmp_path):
    import dataclasses

    from warden.approval_page import INVITE

    w = World(tmp_path)
    enrol, reset = w.link(INVITE), w.link()
    assert w.page.handle("GET", f"/k/{enrol}").status == 404
    assert w.page.handle("GET", f"/e/{reset}").status == 404
    assert w.page.handle("GET", f"/e/{enrol}").status == 200
    assert w.page.handle("GET", f"/k/{reset}").status == 200
    other = invite(Ed25519PrivateKey.generate(), "owner", now=w.now(), purpose=RESET_INVITE)
    assert w.page.handle("POST", f"/k/{other}/trips").status == 404
    assert dataclasses.replace(w.page, log=None).handle("GET", f"/k/{reset}").status == 404
    # Someone else's passkey, or no challenge: nothing is reset.
    token = w.link()
    shown = json.loads(w.page.handle("POST", f"/k/{token}/trips").body)
    stranger = SoftAuthenticator().assert_(json.dumps(shown["options"]))
    assert w.page.handle("POST", f"/k/{token}/reset", json.dumps({"response": stranger})).status == 403
    assert w.page.handle("POST", f"/k/{w.link()}/reset", "{}").status == 403
    assert bounds.killswitch(w.log) is not None


def test_the_command_opens_a_signed_link_without_printing_it_or_opening_the_audit(tmp_path, monkeypatch, capsys):
    import webbrowser

    w = World(tmp_path)
    pem = tmp_path / "owner.pem"
    pem.write_bytes(w.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    for name in ("WARDEN_ENV", "WARDEN_APPROVER_KEY_PASSPHRASE", "WARDEN_AUDIT_DB", "WARDEN_AUDIT_DSN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", RP)
    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)
    assert cli.main(["killswitch", "link", "--approver", "owner", "--key", str(pem)]) == 0
    (url,) = opened
    printed = capsys.readouterr()
    assert url.startswith(f"https://{RP}/k/")
    assert url.split("/k/")[1] not in printed.out + printed.err
    assert w.page.handle("GET", url.removeprefix(f"https://{RP}")).status == 200


def test_the_api_routes_the_reset_and_the_message_names_the_way_to_it():
    tf = (ROOT / "terraform" / "modules" / "warden-runtime" / "frontdoor.tf").read_text(encoding="utf-8")
    assert '"GET /k/{token}", "POST /k/{token}/{step}"' in tf
    acts = (ROOT / "src" / "warden" / "activities.py").read_text(encoding="utf-8")
    assert "`warden killswitch " in acts
    assert "link --approver YOU --key YOUR.pem` opens the page" in acts
    lambdas = (ROOT / "src" / "warden" / "lambdas.py").read_text(encoding="utf-8")
    assert "store=AuditLinkStore(log), log=log" in lambdas  # the Lambda's page is given the audit
