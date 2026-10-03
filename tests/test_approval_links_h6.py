"""Registers H6 and R28: approving from chat. As a plan's wait for an approval opens, each approver who may approve its
tier and has a passkey gets a link to the approval page - minted by WARDEN, recorded in the audit by its hash only,
and delivered beside the gated text, because the gate removes every URL a model or an alert could have written.
Only a link of the exact shape https://<the approval domain>/a/<token> gets through."""

from __future__ import annotations

import pytest

from warden import approvals, chatops
from warden.reporting import Report

RP = "approve.example.test"
TOKEN = "A" * 43


@pytest.fixture
def rp(monkeypatch):
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", RP)


def test_only_an_approval_link_of_the_exact_shape_gets_through(rp):
    good = ("Approve as owner", f"https://{RP}/a/{TOKEN}")
    bad = [("Approve as owner", f"https://evil.example/a/{TOKEN}"), ("Approve as owner", f"https://{RP}/a/{TOKEN}/x"),
           ("Approve as owner", f"http://{RP}/a/{TOKEN}"), ("Approve as owner", f"https://{RP}.evil.example/a/{TOKEN}"),
           ("Click <here>", f"https://{RP}/a/{TOKEN}"), ("Approve as owner", f"https://{RP}/a/{TOKEN[:-1]}")]
    assert chatops.approval_links((good, *bad)) == [f"Approve as owner: https://{RP}/a/{TOKEN}"]


def test_no_link_leaves_without_an_approval_domain(monkeypatch):
    monkeypatch.delenv("WARDEN_APPROVAL_RP_ID", raising=False)
    assert chatops.approval_links((("Approve as owner", f"https://{RP}/a/{TOKEN}"),)) == []


class _Sink:
    name = "test"

    def __init__(self):
        self.sent = []

    def send(self, text, data):
        self.sent.append(text)
        return chatops.Notification(sink=self.name, delivered=True, detail="")


def test_the_links_go_beside_the_gated_text(rp):
    sink = _Sink()
    report = Report(markdown=f"A plan waits. See https://{RP}/a/{TOKEN} or https://evil.example/x", data={"alert": {"id": "inc-1"}},
                    promotion=(), actions=(("Approve as owner", f"https://{RP}/a/{TOKEN}"),))
    chatops.notify(report, sinks=[sink])
    [text] = sink.sent
    body, links = text.rsplit("\n\n", 1)
    assert "https://" not in body  # the gate removed both URLs the text carried
    assert links == f"Approve as owner: https://{RP}/a/{TOKEN}"


def _policy(with_passkeys=("owner",), tiers=("T1", "T2")):
    key = "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n"
    cred = approvals.PasskeyCredential(credential_id="c", public_key="p", sign_count=0, device_bound=True)
    return approvals.ApproverPolicy(approvers={
        "owner": approvals.Approver(public_key=key, tiers=list(tiers), passkeys=[cred] if "owner" in with_passkeys else []),
        "second": approvals.Approver(public_key=key, tiers=["T1"], passkeys=[cred]),
        "nokey": approvals.Approver(public_key=key, tiers=list(tiers))})


def test_a_link_for_each_approver_who_may_approve_the_tier_and_has_a_passkey(rp, tmp_path):
    import json

    from test_approval_page import PLAN
    from warden import audit
    from warden.activities import RemediationActivities
    from warden.approval_page import AuditLinkStore

    log = audit.AuditLog(tmp_path / "a.db")
    acts = RemediationActivities(audit=log, policy=_policy(), platform=None)
    links = acts._approval_links(PLAN)  # a T2 plan: "second" may approve T1 only, "nokey" has no passkey
    assert [label for label, _ in links] == ["Approve as owner"]
    token = links[0][1].rsplit("/", 1)[1]
    assert chatops.approval_links(links) and AuditLinkStore(log).link(token).approver == "owner"
    assert token not in json.dumps([e["body"] for e in log.entries()])


def test_without_an_approval_domain_no_link_is_minted(monkeypatch, tmp_path):
    from test_approval_page import PLAN
    from warden import audit
    from warden.activities import RemediationActivities

    monkeypatch.delenv("WARDEN_APPROVAL_RP_ID", raising=False)
    log = audit.AuditLog(tmp_path / "a.db")
    assert RemediationActivities(audit=log, policy=_policy(), platform=None)._approval_links(PLAN) == ()
    assert log.entries() == []


def test_the_wait_opens_with_the_links_and_without_a_domain_says_nothing_new(rp, monkeypatch, tmp_path):
    from test_remediation_workflow import _no_approval, _run
    from test_remediation_workflow import owner as owner_fixture
    from test_remediation_workflow import world as world_fixture

    sent = []
    monkeypatch.setattr(chatops, "resolve_sinks", lambda threads=None: [_Sink()])
    real_notify = chatops.notify
    monkeypatch.setattr(chatops, "notify", lambda report, sinks=None, threads=None: sent.append(report) or real_notify(
        report, sinks, threads))
    world = world_fixture.__wrapped__(tmp_path, owner_fixture.__wrapped__())
    world["policy"] = _policy()
    _run(world, _no_approval)
    with_links = [r for r in sent if r.actions]
    # As the wait opens, and again at the halfway reminder: two messages carry links, each its own fresh one.
    assert len(with_links) == 2 and all(r.actions[0][0] == "Approve as owner" for r in with_links)
    assert with_links[0].actions[0][1] != with_links[1].actions[0][1]
    kinds = [e["kind"] for e in world["log"].entries("inc-42")]
    assert kinds.index("remediation.announce") < kinds.index("workflow.end")

    monkeypatch.delenv("WARDEN_APPROVAL_RP_ID")
    sent.clear()
    (tmp_path / "b").mkdir()
    world2 = world_fixture.__wrapped__(tmp_path / "b", owner_fixture.__wrapped__())
    world2["policy"] = _policy()
    _run(world2, _no_approval)
    assert not any(r.actions for r in sent)
