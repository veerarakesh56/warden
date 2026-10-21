"""The people asked to approve a plan are told how it went (register G10-24; the owner's first live approvals,
2026-10-12). One approved fix was refused by AWS, one was applied and verified, one plan was never opened because an
earlier one on the same resource was still being watched - and after "waiting for an approval" Slack said nothing.

Now: a verified fix and every end of a run are said, from the run's own signed end row; a report that held a fix for
approval is followed by "no plan was opened, and why" when there is none; and a tier is said in words."""

from __future__ import annotations

import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from test_approval_page import PLAN, _show
from test_remediation_workflow import _approve_with, _no_approval, _run, recorded
from warden import approvals, audit, bounds, codec
from warden.activities import (
    OUTCOME,
    PERSON_TAKES_OVER,
    Diagnosed,
    EvidencePack,
    IncidentActivities,
    Plan,
    RemediationActivities,
    Verified,
    _run_id,
)
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import Alert, Verdict, VerdictStatus
from warden.workflows import END_STAGES, TOLD, IncidentWorkflow, RemediationWorkflow


def _whats(world):
    return [e["body"]["what"] for e in world["log"].entries("inc-42", kinds=("remediation.announce",))]


def test_a_fix_that_did_not_work_and_was_undone_is_said_with_its_reason(world, owner, sink):
    world["platform"].healthy_after = None
    out = _run(world, _approve_with(owner))
    assert out.status == "rolled_back"
    assert _whats(world) == ["waiting", "approved", "rolled_back"]
    assert "Approved by `owner` (with their signing key)." in sink.texts[-1]
    assert "did not work, so WARDEN undid it" in sink.texts[-1]
    assert "Why: orders did not recover within" in sink.texts[-1]
    assert "audit head" in sink.texts[-1]
    assert "kill switch" not in sink.texts[-1]
    assert audit.verify(world["db"], world["log"].key.public_key()).unsigned_tail == 0  # the record still ends signed


def test_an_approved_plan_the_platform_refused_is_said_as_nothing_changed(world, owner, sink):
    from warden.platforms.k8s import KubernetesPlatformRefused

    def refuse(entry, params):
        raise KubernetesPlatformRefused("deployment/orders no longer has 3 replica(s); nothing was changed")

    world["platform"].apply = refuse
    out = _run(world, _approve_with(owner))
    assert out.status == "refused_at_apply"
    assert _whats(world) == ["waiting", "approved", "refused_at_apply"]
    assert "did not apply the approved plan `k8s_rollout_undo`" in sink.texts[-1]
    assert "nothing was changed" in sink.texts[-1]
    assert "no longer has 3 replica(s)" in sink.texts[-1]


def test_an_end_that_leaves_the_target_unknown_says_every_fix_is_stopped(world, owner, sink):
    world["platform"].healthy_after = None
    world["platform"].rollback_error = "422 the count moved"
    out = _run(world, _approve_with(owner))
    assert out.status == "rollback_failed"
    assert bounds.killswitch(world["log"]) is not None
    assert "undoing it FAILED" in sink.texts[-1]
    assert "`warden killswitch link --approver YOU --key YOUR.pem` opens the page" in sink.texts[-1]


def test_an_expired_plan_is_said_once_and_the_tier_is_said_in_words(world, sink):
    out = _run(world, _no_approval)
    # The request, its halfway reminder, the expiry - not a further "ended" message.
    assert out.status == "expired"
    assert _whats(world) == ["waiting", "waiting", "expired"]
    assert f"(T2 - {approvals.TIER_MEANS['T2']}) is waiting for an approval" in sink.texts[0]
    # A request names nobody (owner, 2026-10-12): who decided is said when they have.
    assert ("Only an enrolled approver of this risk level can approve it: the link opens for nobody else, and who "
            "decided is said here when they have.") in sink.texts[0]
    assert "owner" not in sink.texts[0].split("---")[0]
    assert "Approved by" not in sink.texts[1]  # nobody did


def test_every_end_a_person_is_told_of_has_its_own_words_and_the_unknown_ones_name_the_switch():
    assert TOLD == END_STAGES - {"expired", "cancelled", "cancelled_after_apply", "failed", "failed_after_apply"}
    assert TOLD <= set(OUTCOME)
    assert "verified" in OUTCOME
    assert PERSON_TAKES_OVER & TOLD == {"rollback_failed", "apply_failed"}
    assert set(approvals.TIER_MEANS) == set(approvals.TIERS)
    for text in OUTCOME.values():
        assert "{entry}" in text
        assert "{target}" in text


def test_the_message_is_read_from_the_runs_own_end_row_never_from_the_caller(world):
    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    plan = Plan(workflow_id="rem-dev-1", incident_id="inc-42", entry="k8s_rollout_undo", tier="T2", params={},
                created_at=PLAN.created_at, target="dev/k8s/shop/orders", environment="dev")
    assert acts.announce(plan, "ended") == []  # no end row: nothing to say, whatever the caller meant
    world["log"].append("inc-42", "workflow.end", {"workflow_id": "rem-dev-9", "run_id": "", "status": "recovered"})
    assert acts.announce(plan, "ended") == []  # another workflow's end is not this plan's
    assert world["log"].entries("inc-42", kinds=("remediation.announce",)) == []


def test_the_approval_page_says_the_risk_in_words(page_setup):
    page, device, _, _ = page_setup
    plan = json.loads(_show(page, device, page.new_link("rem-dev-1", "owner")).body)["plan"]
    assert plan["tier"] == "T2"
    assert plan["risk"] == approvals.TIER_MEANS["T2"]


# ------------------------------------------------------------------ the incident's side: no plan to approve

REQUEST = {"entry": "events_enable_rule", "params": {"rule": "warden-dev-nightly"}, "service": "warden-dev-nightly",
           "environment": "dev", "incident_id": "inc-002", "workflow_id": "rem-dev-test"}
WHY = "no single known-good to_version was read (WARDEN does not choose one)"


def _incidents(tmp_path, answers):
    """Run one incident per answer of plan_fix (a request, or "" for "no plan" with WHY on the record)."""
    class _Acts(IncidentActivities):
        @activity.defn(name="verify")
        def verify(self, pack: EvidencePack, diagnosed: Diagnosed) -> Verified:
            return Verified(verdict=Verdict(status=VerdictStatus.approved_for_human, reasons=["test"]))

        @activity.defn(name="plan_fix")
        def plan_fix(self, alert: Alert, diagnosed: Diagnosed, verified: Verified) -> dict:
            answer = answers.pop(0)
            if not answer:
                self.audit.append(alert.alert_id, "incident.plan_fix", {"run_id": _run_id(), "planned": False,
                                                                        "why": WHY})
            return dict(answer or {})

    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = _Acts(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="noplan", workflows=[IncidentWorkflow, RemediationWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify, acts.second_opinion, acts.plan_fix, acts.no_plan,
                                           acts.notify],
                               activity_executor=ThreadPoolExecutor(2)):
            for n in range(len(answers)):
                handle = await env.client.start_workflow(IncidentWorkflow.run, Alert(**DEMO_ALERTS["inc-002"]),
                                                         id=f"inc-noplan-{n}", task_queue="noplan")
                await asyncio.wait_for(handle.result(), 120)
        return [e["body"] for e in log.entries("inc-002", kinds=("incident.no_plan",))]

    return asyncio.run(main())


def test_a_report_that_held_a_fix_for_approval_is_followed_by_why_there_is_no_plan(tmp_path, sink):
    """One message per incident (G10-46): the report's summary says why no plan was opened - no second message."""
    rows = _incidents(tmp_path, [""])
    assert rows == [], sink.texts
    assert len(sink.texts) == 1, sink.texts
    [said] = sink.texts
    assert f"**No fix plan:** {WHY}" in said
    assert "nothing to approve" in said
    assert "## Summary" in said
    assert "## What WARDEN read" not in said  # the rest is on the record page
    assert "incident `inc-002`" in said
    assert "audit head" in said
    # With no plan, the on-call line says so - not "approve or deny ... with the button in this message" (fs-07, live).
    assert "with the button in this message" not in said
    assert "no fix plan could be opened (why below)" in said


def test_a_plan_that_opened_is_not_followed_by_one_and_a_second_on_the_same_resource_says_the_first_is_open(
        tmp_path, sink):
    rows = _incidents(tmp_path, [dict(REQUEST), dict(REQUEST)])
    assert len(rows) == 1, rows  # the first opened its plan; the second met it still open (one per resource, C3)
    assert "an earlier plan for the same resource (`rem-dev-test`) is still open" in rows[0]["why"]
    assert "records page" in rows[0]["why"]
    assert "warden status" not in rows[0]["why"]
    assert "opened no fix plan" in sink.texts[-1]
    assert "rem-dev-test" in sink.texts[-1]


def test_no_plan_says_nothing_when_a_plan_was_opened_or_nothing_is_on_the_record(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db")
    acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True))
    assert acts.no_plan("inc-7") == []
    log.append("inc-7", "incident.plan_fix", {"run_id": "", "planned": True, "why": "", "entry": "k8s_restart"})
    assert acts.no_plan("inc-7") == []
    assert log.entries("inc-7", kinds=("incident.no_plan",)) == []


@pytest.mark.parametrize("status", sorted(TOLD))
def test_each_told_end_is_a_sentence_a_person_can_act_on(status):
    said = OUTCOME[status].format(entry="e", target="t")
    assert said.endswith(".")
    assert "`e`" in said
    assert "`t`" in said


def test_the_page_tells_someone_it_was_not_made_for_that_they_cannot_approve(page_setup):
    """Owner, 2026-10-12: "anyone who has access to that Slack can do that, right?" - no, and the page now says so."""
    page, _, _, _ = page_setup
    token = page.new_link("rem-dev-1", "owner")
    shell = page.handle("GET", f"/a/{token}").body
    assert "Only that person can open it, with their own passkey" in shell
    assert "If this link was not made for you, you cannot approve this plan." in shell
    # And it is not only words: an answer from a passkey the approver did not enrol is refused.
    assert page.handle("POST", f"/a/{token}/login-options").status == 200
    stranger = page.handle("POST", f"/a/{token}/login", json.dumps({"response": {"id": "someone-elses"}}))
    assert stranger.status == 403
    assert "plan" not in json.loads(stranger.body)


def test_who_approved_is_read_from_the_record_and_nothing_is_claimed_without_one(world):
    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    plan = Plan(workflow_id="rem-dev-1", incident_id="inc-42", entry="k8s_rollout_undo", tier="T2", params={},
                created_at=PLAN.created_at, target="dev/k8s/shop/orders", environment="dev", plan_hash="h" * 64)
    assert acts.announce(plan, "approved") == []  # no accepted approval on the record
    world["log"].append("inc-42", "approval.accepted", {"workflow_id": "rem-dev-1", "run_id": "", "approver": "mallory",
                                                        "plan_hash": "another plan"})
    assert acts.announce(plan, "approved") == []  # another plan's approval is not this one's


def test_a_confirmed_approver_is_shown_by_name_and_who_saw_the_plan_is_on_the_record(page_setup, tmp_path):
    """Owner, 2026-10-12: once the passkey has said who it is, the page should give the name - and who looked at,
    approved or denied a plan should be on the record."""
    import dataclasses

    from warden.approval_page import AuditLinkStore

    page, device, _, _ = page_setup
    assert json.loads(_show(page, device, page.new_link("rem-dev-1", "owner")).body)["approver"] == "owner"
    named = page.policy.model_copy(deep=True)
    named.approvers["owner"].name = "Asha Rao"
    log = audit.AuditLog(tmp_path / "a.db")
    page = dataclasses.replace(page, policy=named, store=AuditLinkStore(log, clock=page.clock))
    shell = page.handle("GET", f"/a/{(token := page.new_link('rem-dev-1', 'owner'))}").body
    assert "Asha" not in shell  # nothing of who the link is for before the passkey
    assert json.loads(_show(page, device, token).body)["approver"] == "Asha Rao"  # the name, not the list's id
    [seen] = [e["body"] for e in log.entries(kinds=("approval.link_viewed",))]
    assert seen["approver"] == "owner"
    assert seen["workflow_id"] == "rem-dev-1"
    assert "you are " in shell
    assert "Approval sent" in shell
    assert 'sent("Denied"' in shell
    assert named.shown("owner") == "Asha Rao"
    assert named.shown("nobody") == "nobody"
    assert approvals.ApproverPolicy.loads(__import__("yaml").safe_dump(named.model_dump())).approvers["owner"].name == "Asha Rao"


def test_an_undo_wardens_own_check_refuses_is_not_a_failed_rollback_and_the_switch_stays_off(world, owner, sink):
    """The first live rollback (2026-10-12): the fix was applied, the rule was switched off again by someone else,
    and WARDEN's undo found nothing to undo - it said "undoing it FAILED: the target's state is unknown" and stopped
    every automatic fix. The state was known. Only a call that AWS refuses, or one that may be half-made, is that."""
    class Moved(RuntimeError):
        nothing_changed = True
        own_check = True

    def refuse(entry, params, snapshot):
        raise Moved("rule warden-dev-lab-tick is already disabled; nothing was changed")

    world["platform"].healthy_after = None
    world["platform"].rollback = refuse
    out = _run(world, _approve_with(owner))
    assert out.status == "not_recovered", out
    assert bounds.killswitch(world["log"]) is None, out
    assert out.reasons[1] == "not rolled back: rule warden-dev-lab-tick is already disabled; nothing was changed"
    assert "did not work, and WARDEN did not undo it" in sink.texts[-1]
    assert "already disabled" in sink.texts[-1]
    assert "FAILED" not in sink.texts[-1]
    assert "kill switch" not in sink.texts[-1]
    assert not world["log"].entries("inc-42", kinds=("remediation.rollback_failed",))


def test_an_undo_aws_itself_refuses_is_still_a_failed_rollback(world, owner, sink):
    class Denied(RuntimeError):
        nothing_changed = True  # never written - and WARDEN's change is still in place, not undone

    def refuse(entry, params, snapshot):
        raise Denied("AWS refused events_enable_rule (AccessDenied); nothing was changed")

    world["platform"].healthy_after = None
    world["platform"].rollback = refuse
    out = _run(world, _approve_with(owner))
    assert out.status == "rollback_failed"
    assert bounds.killswitch(world["log"]) is not None


def test_the_aws_platform_marks_its_own_refusal_of_an_undo_and_not_awss():
    from test_aws_platform_g6 import FN, WHO
    from test_aws_platform_g6 import Fake as AwsFake
    from warden.platforms.aws import AwsPlatform, AwsPlatformRefused

    f = AwsFake()
    p = AwsPlatform(reader=lambda service: f, actor=f.actor, clock=lambda: PLAN.created_at, sleep=lambda s: None)
    live = p.live("lambda_enable_esm", {"function": FN, "mapping": "u-1"})
    with pytest.raises(AwsPlatformRefused, match="is already disabled") as own:  # never enabled: nothing to undo
        p.rollback("lambda_enable_esm", {"function": FN, "mapping": "u-1"}, live["state"], who=WHO)
    assert own.value.own_check is True
    assert own.value.nothing_changed is True
    assert not hasattr(AwsPlatformRefused("AWS refused x; nothing was changed"), "own_check")


def test_a_message_mentions_the_people_it_names_only_from_the_approver_list(world, owner, sink, monkeypatch):
    """2026-10-12: a message names the approver with an @-mention, so people can see in Slack who that person is."""
    from warden import chatops

    member = "U" + "0" * 3 + "ABCDEFG"  # a placeholder id, built from parts
    world["policy"].approvers["owner"].name, world["policy"].approvers["owner"].team = "Asha Rao", "Platform"
    world["policy"].approvers["owner"].slack = member
    seen = []
    real = chatops.notify
    monkeypatch.setattr(chatops, "notify", lambda report, **kw: seen.append(report) or real(report, **kw))
    out = _run(world, _approve_with(owner))
    row = ("owner", member, "Asha Rao (Platform)")
    assert out.status == "recovered", [r.people for r in seen]
    assert all(r.people == (row,) for r in seen), [r.people for r in seen]
    # A reader outside Slack gets the person's name where the sentence names them - never the list's id for them
    # (owner, 2026-10-12: "don't use owner at all anywhere ... it feels unprofessional").
    # Approved and fixed are kept for the records page (G10-46), named the same way as any reader but Slack.
    told = recorded(world["log"])
    assert len(sink.texts) == 1
    assert "approved by `Asha Rao (Platform)` (with their signing key)" in told[0]
    assert "owner" not in sink.texts[0].split("---")[0]  # the request names nobody
    assert "@@" not in "".join(told)
    assert not any("owner" in t for t in told)
    assert world["policy"].shown("owner") == "Asha Rao (Platform)"
    assert world["policy"].said("owner") == "@@owner@@"
    world["policy"].approvers["owner"].name = ""
    assert world["policy"].shown("owner") == "owner"  # only where the list gives no name is its id all there is
    world["policy"].approvers["owner"].name = "Asha Rao"
    # In Slack the mark becomes Slack's own mention, in the sentence - and only an id of exactly Slack's shape does.
    said = "was approved by @@owner@@ (with their passkey); @@nobody@@ and @@other@@ were not asked"
    people = [row, ("other", "<!channel>", "Someone `else`")]
    assert chatops.name_people(said, people, slack=True) == (
        f"was approved by <@{member}> (with their passkey); `nobody` and `Someone else` were not asked")
    assert chatops.name_people(said, people, slack=False).startswith("was approved by `Asha Rao (Platform)` (with")
    assert chatops.to_slack_mrkdwn(f"<@{member}>") == f"&lt;@{member}&gt;"  # one typed into a message is only text
    assert chatops.to_slack_mrkdwn("by @@owner@@") == "by @@owner@@"         # the mark reaches the sink whole
    with pytest.raises(ValueError):
        approvals.Approver(public_key="k", slack="<!channel>")
    assert world["policy"].people() == (row,)


def test_the_slack_sinks_name_the_approver_where_the_sentence_does_and_nowhere_else(monkeypatch):
    """Owner, 2026-10-12, reading a live message: it said "approved by owner" and the mention stood alone under the
    footer - "name owner things are not right in place"."""
    from warden import chatops

    member, posted = "W" + "A1B2C3D4", []
    monkeypatch.setattr(chatops, "_post_json", lambda url, payload, name: posted.append(payload) or chatops.Notification(
        sink=name, delivered=True, detail="ok"))
    sink_ = chatops.SlackWebhookSink("https://hooks.example.test/x", live=True)
    sink_.send("**Approved** by @@owner@@ <b>\n\n---\nfooter", {"people": [["owner", member, "Asha Rao"]]})
    sink_.send("no one named, and @@asha@@ is nobody here", {})
    assert f"by <@{member}> &lt;b&gt;" in posted[0]["text"]
    assert posted[0]["text"].endswith("footer")
    assert posted[0]["text"].count("<@") == 1
    assert "owner" not in posted[0]["text"]
    assert "<@" not in posted[1]["text"]
    assert "`asha` is nobody here" in posted[1]["text"]

    class Plain:
        name = "plain"

        def send(self, text, data):
            posted.append(text)
            return chatops.Notification(sink=self.name, delivered=True, detail="ok")

    from warden.reporting import Report

    chatops.notify(Report(markdown="approved by @@owner@@", data={}, promotion=(),
                          people=(("owner", member, "Asha Rao"), ("second", member, "Not Named Here"))), sinks=[Plain()])
    assert posted[-1] == "approved by `Asha Rao`"  # another reader than Slack: the name - no mark, no mention syntax


@pytest.mark.parametrize("typed", ["not now", ""])
def test_a_denial_says_who_denied_how_and_when_as_an_approval_does(world, sink, typed):
    """2026-10-14: a denial must say who denied, how and when, as an approval does. The message read
    "was denied: nothing was changed. Why: denied by owner"."""
    import re

    from test_remediation_workflow import RemediationWorkflow, _until_awaiting_approval
    from warden import history
    from warden.approvals import Denial

    world["policy"].approvers["owner"].name = "Asha Rao"

    async def deny(handle):
        plan = await _until_awaiting_approval(handle)
        await handle.signal(RemediationWorkflow.deny, Denial(approver="owner", workflow_id=handle.id,
                                                            plan_hash=plan.plan_hash, reason=typed))

    out = _run(world, deny)
    assert out.status == "denied"
    assert _whats(world) == ["waiting", "denied"]
    said = recorded(world["log"])[-1]
    assert not any("was denied" in t for t in sink.texts)  # on the records page, not in the channel
    assert re.search(r"was denied by `Asha Rao` \(with their passkey\) at \d{4}-\d\d-\d\d \d\d:\d\d:\d\dZ", said)
    assert ": nothing was changed." in said
    assert "Why:" not in said
    assert "owner" not in said
    assert ("Their reason: `not now`" in said) == bool(typed)
    assert ("Their reason" in said) == bool(typed)
    # ...and the resource's record says who, where it said only "was denied".
    [row] = [r for r in history.plans(world["log"]) if r["status"] == "denied"]
    assert row["denied_by"] == "owner"
    assert history._line(row).endswith("· was denied · by @@owner@@")
    assert history._denier({"status": "denied", "reasons": ["denied by x; rm -rf"]}) == ""  # only an approver's id
    assert history._denier({"status": "expired", "reasons": ["denied by owner"]}) == ""
