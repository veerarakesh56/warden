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

from test_approval_ladder_h10 import sink  # noqa: F401
from test_approval_page import PLAN, _show
from test_approval_page import setup as page_setup  # noqa: F401
from test_remediation_workflow import (  # noqa: F401
    _approve_with,
    _no_approval,
    _run,
    owner,
    world,
)
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


def _whats(world):  # noqa: F811
    return [e["body"]["what"] for e in world["log"].entries("inc-42", kinds=("remediation.announce",))]


def test_a_fix_that_did_not_work_and_was_undone_is_said_with_its_reason(world, owner, sink):  # noqa: F811
    world["platform"].healthy_after = None
    out = _run(world, _approve_with(owner))
    assert out.status == "rolled_back" and _whats(world) == ["rolled_back"]
    assert "did not work, so WARDEN undid it" in sink.texts[-1] and "Why: orders did not recover within" in sink.texts[-1]
    assert "audit head" in sink.texts[-1] and "kill switch" not in sink.texts[-1]
    assert audit.verify(world["db"], world["log"].key.public_key()).unsigned_tail == 0  # the record still ends signed


def test_an_approved_plan_the_platform_refused_is_said_as_nothing_changed(world, owner, sink):  # noqa: F811
    from warden.platforms.k8s import KubernetesPlatformRefused

    def refuse(entry, params):
        raise KubernetesPlatformRefused("deployment/orders no longer has 3 replica(s); nothing was changed")

    world["platform"].apply = refuse
    out = _run(world, _approve_with(owner))
    assert out.status == "refused_at_apply" and _whats(world) == ["refused_at_apply"]
    assert "did not apply the approved plan `k8s_rollout_undo`" in sink.texts[-1]
    assert "nothing was changed" in sink.texts[-1] and "no longer has 3 replica(s)" in sink.texts[-1]


def test_an_end_that_leaves_the_target_unknown_says_every_fix_is_stopped(world, owner, sink):  # noqa: F811
    world["platform"].healthy_after = None
    world["platform"].rollback_error = "422 the count moved"
    out = _run(world, _approve_with(owner))
    assert out.status == "rollback_failed" and bounds.killswitch(world["log"]) is not None
    assert "undoing it FAILED" in sink.texts[-1] and "`warden killswitch reset`" in sink.texts[-1]


def test_an_expired_plan_is_said_once_and_the_tier_is_said_in_words(world, sink):  # noqa: F811
    out = _run(world, _no_approval)
    assert out.status == "expired" and _whats(world) == ["waiting", "expired"]  # not a third "ended" message
    assert f"(T2 - {approvals.TIER_MEANS['T2']}) is waiting for an approval" in sink.texts[0]


def test_every_end_a_person_is_told_of_has_its_own_words_and_the_unknown_ones_name_the_switch():
    assert TOLD == END_STAGES - {"expired", "cancelled", "cancelled_after_apply", "failed", "failed_after_apply"}
    assert TOLD <= set(OUTCOME) and "verified" in OUTCOME
    assert PERSON_TAKES_OVER & TOLD == {"rollback_failed", "apply_failed"}
    assert set(approvals.TIER_MEANS) == set(approvals.TIERS)
    for text in OUTCOME.values():
        assert "{entry}" in text and "{target}" in text


def test_the_message_is_read_from_the_runs_own_end_row_never_from_the_caller(world):  # noqa: F811
    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    plan = Plan(workflow_id="rem-dev-1", incident_id="inc-42", entry="k8s_rollout_undo", tier="T2", params={},
                created_at=PLAN.created_at, target="dev/k8s/shop/orders", environment="dev")
    assert acts.announce(plan, "ended") == []  # no end row: nothing to say, whatever the caller meant
    world["log"].append("inc-42", "workflow.end", {"workflow_id": "rem-dev-9", "run_id": "", "status": "recovered"})
    assert acts.announce(plan, "ended") == []  # another workflow's end is not this plan's
    assert world["log"].entries("inc-42", kinds=("remediation.announce",)) == []


def test_the_approval_page_says_the_risk_in_words(page_setup):  # noqa: F811
    page, device, _, _ = page_setup
    plan = json.loads(_show(page, device, page.new_link("rem-dev-1", "owner")).body)["plan"]
    assert plan["tier"] == "T2" and plan["risk"] == approvals.TIER_MEANS["T2"]


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
                               activities=[acts.prepare, acts.diagnose, acts.verify, acts.plan_fix, acts.no_plan],
                               activity_executor=ThreadPoolExecutor(2)):
            for n in range(len(answers)):
                handle = await env.client.start_workflow(IncidentWorkflow.run, Alert(**DEMO_ALERTS["inc-002"]),
                                                         id=f"inc-noplan-{n}", task_queue="noplan")
                await asyncio.wait_for(handle.result(), 120)
        return [e["body"] for e in log.entries("inc-002", kinds=("incident.no_plan",))]

    return asyncio.run(main())


def test_a_report_that_held_a_fix_for_approval_is_followed_by_why_there_is_no_plan(tmp_path, sink):  # noqa: F811
    rows = _incidents(tmp_path, [""])
    assert [r["why"] for r in rows] == [WHY] and rows[0]["delivered"] == ["capture"]
    assert f"opened no fix plan for this incident: {WHY}" in sink.texts[-1] and "nothing to approve" in sink.texts[-1]
    assert "incident `inc-002`" in sink.texts[-1] and "audit head" in sink.texts[-1]


def test_a_plan_that_opened_is_not_followed_by_one_and_a_second_on_the_same_resource_says_the_first_is_open(
        tmp_path, sink):  # noqa: F811
    rows = _incidents(tmp_path, [dict(REQUEST), dict(REQUEST)])
    assert len(rows) == 1, rows  # the first opened its plan; the second met it still open (one per resource, C3)
    assert "an earlier plan for the same resource is still open (`warden status rem-dev-test`)" in rows[0]["why"]
    assert "opened no fix plan" in sink.texts[-1] and "rem-dev-test" in sink.texts[-1]


def test_no_plan_says_nothing_when_a_plan_was_opened_or_nothing_is_on_the_record(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db")
    acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True))
    assert acts.no_plan("inc-7") == []
    log.append("inc-7", "incident.plan_fix", {"run_id": "", "planned": True, "why": "", "entry": "k8s_restart"})
    assert acts.no_plan("inc-7") == [] and log.entries("inc-7", kinds=("incident.no_plan",)) == []


@pytest.mark.parametrize("status", sorted(TOLD))
def test_each_told_end_is_a_sentence_a_person_can_act_on(status):
    said = OUTCOME[status].format(entry="e", target="t")
    assert said.endswith(".") and "`e`" in said and "`t`" in said
