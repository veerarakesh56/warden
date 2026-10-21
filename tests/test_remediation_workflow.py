"""RemediationWorkflow on Temporal's time-skipping test server, with a fake platform.

Every path is checked end to end: through the real workflow, the real activities, the real audit log
and real signatures. Only the platform being changed is fake.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from warden import approvals, audit, bounds, codec
from warden.activities import FixRequest, RemediationActivities
from warden.workflows import STEPS, RemediationWorkflow

QUEUE = "remediation-test"
CONVERTER = codec.data_converter(os.urandom(32))


class FakePlatform:
    def __init__(self, healthy_after=1):
        self.state = {"revision": "7", "image": "orders:bad"}
        self.applied, self.rolled_back = [], []
        self.checks = 0
        self.healthy_after = healthy_after  # None: never recovers
        self.drift_on_second_read = False
        self.reads = 0
        self.apply_error = None

    def live(self, entry, params):
        self.reads += 1
        if self.drift_on_second_read and self.reads == 2:
            self.state = {**self.state, "revision": "8"}
        return {"namespace": {"shop"}, "deployment": {"orders"}, "to_revision": {"6"}, "environment": "dev",
                "state": dict(self.state)}

    def apply(self, entry, params):
        if self.apply_error:
            raise RuntimeError(self.apply_error)
        self.applied.append((entry, params))
        return "rolled back to revision 6"

    def healthy(self, service):
        self.checks += 1
        return self.healthy_after is not None and self.checks >= self.healthy_after

    def rollback(self, entry, params, snapshot):
        if getattr(self, "rollback_error", None):
            raise RuntimeError(self.rollback_error)
        if getattr(self, "nothing_to_undo", False):
            return "nothing to roll back: a restart replaced the pods, and the old ones cannot come back"
        self.rolled_back.append(snapshot)
        return f"restored revision {snapshot['revision']}"


@pytest.fixture
def owner():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def world(tmp_path, owner):
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"])})
    log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
    return {"log": log, "policy": policy, "platform": FakePlatform(), "db": tmp_path / "audit.db"}


REQ = {"incident_id": "inc-42", "entry": "k8s_rollout_undo", "service": "orders", "environment": "dev",
       "params": {"namespace": "shop", "deployment": "orders", "to_revision": "6"}}


def recorded(log, incident="inc-42"):
    """The messages WARDEN keeps for its records page instead of posting them (activities.RECORDED_ONLY): approved,
    denied, fixed - each written as before and through the same gate, in order."""
    return [e["body"]["said"] for e in log.entries(incident, kinds=("remediation.announce",))
            if e["body"].get("recorded_only")]


def _run(world, drive, **req):
    """Start the workflow, let `drive(handle, sign)` interact with it, return the outcome."""
    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=CONVERTER)
        acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"],
                                     limits=world.get("limits", bounds.DEFAULT_LIMITS), changes=world.get("changes"))
        methods = [acts.resolve_plan, acts.gate, acts.announce, acts.check_approval, acts.check_passkey, acts.precheck,
                   acts.apply, acts.check_success, acts.record_result, acts.rollback, acts.finish, acts.again_alert, acts.side_effects,
                   acts.approval_extension]
        async with env, Worker(env.client, task_queue=QUEUE, workflows=[RemediationWorkflow], activities=methods,
                               activity_executor=ThreadPoolExecutor(4)):
            handle = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**{**REQ, **req}),
                                                     id=f"rem-{uuid.uuid4()}", task_queue=QUEUE)
            await drive(handle)
            outcome = await handle.result()
            world["history"] = await handle.fetch_history()
            world["namespace"] = env.client.namespace
            return outcome
    return asyncio.run(main())


async def _until_awaiting_approval(handle):
    from temporalio.service import RPCError

    for _ in range(200):
        try:
            if await handle.query(RemediationWorkflow.stage) == "awaiting_approval":
                return await handle.query(RemediationWorkflow.plan)
        except RPCError:
            # A run that is handing over to its next one (continue-as-new, G10-44) can leave a query unanswered until
            # its deadline (CI, 2026-10-14: "query deadline exceeded", about one run in six): not there yet.
            pass
        await asyncio.sleep(0.05)
    raise AssertionError("never reached awaiting_approval")


def _approve_with(key, approver="owner", tweak=None):
    async def drive(handle):
        plan = await _until_awaiting_approval(handle)
        fields = {"workflow_id": handle.id, "plan_hash": plan.plan_hash, "tier": plan.tier, **(tweak or {})}
        await handle.signal(RemediationWorkflow.approve,
                            approvals.sign(key, approver=approver, now=datetime.now(UTC), **fields))
    return drive


async def _no_approval(handle):
    pass


def test_an_approved_fix_is_applied_once_verified_and_fully_audited(world, owner):
    out = _run(world, _approve_with(owner))
    assert out.status == "recovered" and out.checklist == dict.fromkeys(STEPS, True)
    assert world["platform"].applied == [("k8s_rollout_undo", REQ["params"])]
    kinds = [e["kind"] for e in world["log"].entries("inc-42")]
    assert "remediation.check" in kinds  # every real health check is on the record (fourth review)
    assert [k for k in kinds if k != "remediation.check"] == [
        "remediation.plan", "remediation.gate", "remediation.announce", "approval.accepted", "remediation.announce",
        "remediation.precheck",
        "lock.taken", "remediation.intent", bounds.APPLIED, bounds.RESULT, "remediation.announce", "workflow.end",
        "remediation.announce"]  # the approvers are told it is verified, and how it ended (G10-24)
    assert audit.verify(world["db"], world["log"].key.public_key()).unsigned_tail == 0


def test_without_an_approval_nothing_happens_and_it_expires(world):
    out = _run(world, _no_approval)
    assert out.status == "expired" and not out.checklist["approved"]
    assert world["platform"].applied == []


def test_a_forged_approval_is_refused_and_a_real_one_still_works(world, owner):
    async def drive(handle):
        await _approve_with(Ed25519PrivateKey.generate())(handle)  # someone else's key
        await _approve_with(owner)(handle)
    out = _run(world, drive)
    assert out.status == "recovered"
    refused = world["log"].entries("inc-42", kinds=("approval.refused",))
    assert refused[0]["body"]["problems"] == ["the signature is not owner's"]


def test_an_approval_of_a_different_plan_does_not_count(world, owner):
    out = _run(world, _approve_with(owner, tweak={"plan_hash": "0" * 64}))
    assert out.status == "expired"
    assert "approval is for a different plan (the plan changed after it was approved)" in out.reasons
    assert world["platform"].applied == []


def test_a_target_warden_did_not_read_is_refused_before_anything_else(world, owner):
    out = _run(world, _no_approval, params={**REQ["params"], "deployment": "payments; rm -rf /"})
    assert out.status == "refused" and not out.checklist["planned"]
    assert world["platform"].applied == []


def test_the_kill_switch_blocks_it(world, owner):
    bounds.trip(world["log"], "inc-0", "manual stop")
    out = _run(world, _no_approval)
    assert out.status == "blocked" and out.reasons == ["the kill switch is on: manual stop"]


def _ends(world):
    return [(e["body"]["status"], e["body"]["reasons"]) for e in world["log"].entries("inc-42", kinds=("workflow.end",))]


def test_a_target_that_changed_after_approval_is_not_touched_and_the_plan_is_made_again(world, owner):
    """Decision D7: never applied unseen - made again from what WARDEN reads now, and put to the approvers again."""
    world["platform"].drift_on_second_read = True
    out = _run(world, _approve_with(owner))
    assert world["platform"].applied == [] and out.status == "expired"  # the new plan waited; nobody approved it
    (first, why), (last, _) = _ends(world)
    assert first == "drifted" and why == [
        "the target changed after the plan was made; it needs a new plan",
        "WARDEN makes the plan again from what it reads now and asks for an approval once more (1 of 2)"]
    assert last == "expired"


def test_the_plan_made_again_is_applied_once_it_is_approved_in_its_turn(world, owner):
    world["platform"].drift_on_second_read = True

    async def twice(handle):
        await _approve_with(owner)(handle)
        # The next run of the same workflow makes its own plan: wait for it on WARDEN's record, not by querying a run
        # that is handing over (that query can hang until its deadline), then approve it in its turn. Up to 60 s of
        # wall time: 20 s ran out once under the gate's four parallel workers (2026-10-14) and approved too early.
        for _ in range(1200):
            made = world["log"].entries("inc-42", kinds=("remediation.plan",))
            if [s for s, _ in _ends(world)] == ["drifted"] and len(made) == 2:
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("the plan made again never reached the record")
        await _approve_with(owner)(handle)

    out = _run(world, twice)
    assert out.status == "recovered" and len(world["platform"].applied) == 1
    assert [s for s, _ in _ends(world)] == ["drifted", "recovered"]
    plans = [e["body"]["plan_hash"] for e in world["log"].entries("inc-42", kinds=("remediation.plan",))]
    assert len(plans) == 2 and plans[0] != plans[1]  # a new plan, with its own approval


def test_a_target_that_keeps_changing_is_planned_again_at_most_twice_then_goes_to_a_person(world, owner):
    from warden.workflows import REPLAN_MAX

    out = _run(world, _no_approval, replans=REPLAN_MAX)  # already planned again twice
    assert out.status == "expired"  # nothing changed: the cap is on the next drift, tested below
    world2 = world
    world2["platform"].drift_on_second_read = True
    world2["platform"].reads = 0
    out = _run(world2, _approve_with(owner), replans=REPLAN_MAX)
    assert out.status == "drifted" and out.reasons == ["the target changed after the plan was made; it needs a new plan"]
    with pytest.raises(ValueError):
        FixRequest(**{**REQ, "replans": REPLAN_MAX + 1})


def test_a_fix_that_does_not_recover_is_rolled_back(world, owner):
    world["platform"].healthy_after = None
    out = _run(world, _approve_with(owner))
    assert out.status == "rolled_back" and out.checklist["applied"] and not out.checklist["verified"]
    assert world["platform"].rolled_back == [{"revision": "7", "image": "orders:bad"}]
    assert world["log"].entries("inc-42", kinds=(bounds.RESULT,))[0]["body"]["ok"] is False


def test_a_failed_apply_is_not_retried_or_rolled_back_blindly(world, owner):
    world["platform"].apply_error = "API timeout"
    out = _run(world, _approve_with(owner))
    assert out.status == "apply_failed" and not out.checklist["applied"]
    assert world["platform"].rolled_back == []
    intents = world["log"].entries("inc-42", kinds=("remediation.intent",))
    assert len(intents) == 1  # maximum_attempts=1: tried once
    assert "API timeout" not in str(world["history"].to_json_dict())  # failure text is encrypted too


def test_an_approver_limited_to_t1_cannot_approve_a_t2_fix(world, owner):
    world["policy"].approvers["owner"].tiers = ["T1"]
    out = _run(world, _approve_with(owner))
    assert out.status == "expired" and "owner may not approve T2" in out.reasons


def test_the_checklist_cannot_be_given_as_input():
    # `replans` can only lower how often WARDEN plans again (D7); a caller setting it skips nothing. `soak_minutes` can
    # only lengthen the watch (at least 60, item 11).
    assert set(FixRequest.model_fields) == {"incident_id", "entry", "params", "service", "environment",
                                            "approval_ttl_minutes", "recover_within_minutes", "replans", "soak_minutes"}


def test_the_ttl_is_honoured(world, owner):
    async def late(handle):
        await _until_awaiting_approval(handle)
    out = _run(world, late, approval_ttl_minutes=1)
    assert out.status == "expired"
    assert (world["log"].entries("inc-42", kinds=("workflow.end",))[0]["at"]
            - world["log"].entries("inc-42", kinds=("remediation.plan",))[0]["at"]) < timedelta(minutes=5)


def test_a_recorded_history_replays_deterministically(world, owner):
    """The workflow code must make the same decisions when Temporal replays it after a worker restart."""
    _run(world, _approve_with(owner))
    # Payloads are bound to their namespace and workflow (codec.py), so a replay names the namespace
    # the history was recorded in.
    asyncio.run(Replayer(workflows=[RemediationWorkflow], data_converter=CONVERTER, namespace=world["namespace"])
                .replay_workflow(world["history"]))


def test_a_failed_rollback_still_ends_signed_and_trips_the_kill_switch(world, owner):
    """Sixth review (2026-10-01): a rollback that failed - an HPA moved the count, the API was down - crashed the
    workflow with no end row and no checkpoint. It ends `rollback_failed`, on the record, and no further fix runs
    until a person resets the kill switch: WARDEN's change may still be in place."""
    world["platform"].healthy_after = None
    world["platform"].rollback_error = "422 the count moved"
    out = _run(world, _approve_with(owner))
    assert out.status == "rollback_failed" and out.checklist["applied"] and not out.checklist["verified"]
    kinds = [e["kind"] for e in world["log"].entries("inc-42")]
    assert "remediation.rollback_failed" in kinds and kinds[-2:] == ["workflow.end", "remediation.announce"]
    assert bounds.killswitch(world["log"]) is not None
    assert audit.verify(world["db"], world["log"].key.public_key()).unsigned_tail == 0


def test_a_rollback_row_names_its_run_and_plan(world, owner):
    world["platform"].healthy_after = None
    _run(world, _approve_with(owner))
    row = world["log"].entries("inc-42", kinds=("remediation.rollback",))[0]["body"]
    assert row["run_id"] and row["plan_hash"] and row["workflow_id"]


def test_a_fix_with_nothing_to_undo_is_not_called_rolled_back(world, owner):
    """Sixth review (2026-10-01): a restart that did not help was recorded `rolled_back`, though nothing was undone
    and the new pods stayed. It ends `not_recovered`, saying why."""
    world["platform"].healthy_after = None
    world["platform"].nothing_to_undo = True
    out = _run(world, _approve_with(owner))
    assert out.status == "not_recovered" and out.checklist["applied"] and not out.checklist["verified"]
    assert any("nothing to roll back" in r for r in out.reasons), out.reasons


def test_a_fix_filed_under_another_service_is_refused(world):
    """Sixth review (2026-10-01): a scale of `payments` filed under service `orders` was judged healthy by `orders`
    and never rolled back. The service must name what the fix changes."""
    class Both(FakePlatform):
        def live(self, entry, params):
            return {**super().live(entry, params), "deployment": {"orders", "payments"}}

    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=Both())
    plan = acts.resolve_plan(FixRequest(**{**REQ, "params": {**REQ["params"], "deployment": "payments"}}), "rem-x")
    assert any("deployment 'payments', not the service 'orders'" in p for p in plan.problems), plan.problems
    same = acts.resolve_plan(FixRequest(**REQ), "rem-y")
    assert same.problems == []


def test_health_is_asked_only_of_the_platform_that_made_the_change():
    """Sixth review: a database named like a Deployment decided the Deployment's verdict."""
    from warden.platforms import RoutedPlatform

    class Says:
        def __init__(self, ok):
            self.ok, self.asked = ok, 0

        def knows(self, service):
            return True

        def healthy(self, service):
            self.asked += 1
            return self.ok

    k8s, db = Says(True), Says(False)
    routed = RoutedPlatform(k8s=k8s, db=db)
    assert routed.healthy_for("k8s_scale", "orders") is True and db.asked == 0
    assert routed.healthy_for("db_terminate_idle_in_tx", "orders") is False
    assert RoutedPlatform(db=db).healthy_for("k8s_scale", "orders") is False  # none connected: not healthy


def test_a_platform_that_refuses_before_writing_reports_nothing_changed(world, owner):
    """Sixth review (2026-10-01): a platform's own refusal - the count moved, a bound re-checked - was reported
    `apply_failed`, "may be half-made", though nothing was written."""
    from warden.platforms.k8s import KubernetesPlatformRefused

    def refuse(entry, params):
        raise KubernetesPlatformRefused("deployment/orders no longer has 3 replica(s); nothing was changed")

    world["platform"].apply = refuse
    out = _run(world, _approve_with(owner))
    assert out.status == "refused_at_apply" and not out.checklist["applied"], out
    assert world["log"].entries("inc-42", kinds=("remediation.refused",))


@pytest.mark.parametrize("status", ["rollback_failed", "apply_failed"])
def test_an_end_that_leaves_the_target_unknown_trips_the_kill_switch(world, status):
    """Seventh review (2026-10-01): only the rollback activity's own failure tripped the switch - a rollback past
    its timeout, or on a worker that died, ended rollback_failed with it off, and later fixes ran. The end row
    trips it, whatever ended the run."""
    from warden import bounds
    from warden.activities import FixOutcome

    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    assert bounds.killswitch(world["log"]) is None
    acts.finish("inc-42", "rem-x", FixOutcome(status=status, reasons=["Timeout"], checklist={}))
    tripped = bounds.killswitch(world["log"])
    assert tripped is not None and status in str(tripped), tripped


def test_an_ordinary_end_leaves_the_kill_switch_alone(world):
    from warden import bounds
    from warden.activities import FixOutcome

    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    for status in ("recovered", "rolled_back", "not_recovered", "refused", "refused_at_apply", "expired", "drifted"):
        acts.finish("inc-42", "rem-x", FixOutcome(status=status, checklist={}))
    assert bounds.killswitch(world["log"]) is None


def test_a_run_cancelled_after_apply_ends_on_the_record_and_trips_the_kill_switch(world, owner):
    """Eighth review (2026-10-01): cancelled while verifying an applied fix, a run left no end row and the kill
    switch off - the next fix on the same service was let through."""
    from warden import bounds

    approve = _approve_with(owner)

    async def drive(handle):
        await approve(handle)
        for _ in range(400):
            if await handle.query(RemediationWorkflow.stage) == "verifying":
                break
            await asyncio.sleep(0.05)
        await handle.cancel()

    with pytest.raises(Exception):  # noqa: B017 - the run ends cancelled, as asked
        _run(world, drive)
    ends = [e["body"] for e in world["log"].entries("inc-42", kinds=("workflow.end",))]
    assert [e["status"] for e in ends] == ["cancelled_after_apply"], ends
    assert bounds.killswitch(world["log"]) is not None


def test_every_unknown_end_is_its_own_trip_and_a_reset_names_the_latest(world):
    """Eighth review: a switch already on swallowed a second unknown end, and one reset signed for the first trip
    cleared both."""
    from warden import bounds
    from warden.activities import FixOutcome

    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    acts.finish("inc-42", "rem-a", FixOutcome(status="rollback_failed", reasons=["A"], checklist={}))
    first = bounds.trips_hash(world["log"])
    acts.finish("inc-43", "rem-b", FixOutcome(status="apply_failed", reasons=["B"], checklist={}))
    assert [r["body"]["reason"] for r in bounds.trips(world["log"])] == ["rem-a ended rollback_failed: A",
                                                                        "rem-b ended apply_failed: B"]
    assert bounds.trips_hash(world["log"]) != first  # an approval of the first trip alone resets nothing


def test_a_retried_finish_writes_one_end_row(world, monkeypatch):
    """Eighth review: Temporal retries `finish` when a step after its end row fails - a second end row was written."""
    from warden import activities as acts_module
    from warden.activities import FixOutcome

    monkeypatch.setattr(acts_module, "_run_id", lambda: "run-1")
    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    for _ in range(2):
        acts.finish("inc-42", "rem-a", FixOutcome(status="recovered", checklist={}))
    assert len(world["log"].entries("inc-42", kinds=("workflow.end",))) == 1


def _blocking(world, method):
    """Make the fake platform's `method` block (in its activity thread) until released; return (started, release)."""
    import threading

    started, release = threading.Event(), threading.Event()
    real = getattr(world["platform"], method)

    def blocked(*a, **k):
        started.set()
        release.wait(5)
        return real(*a, **k)

    setattr(world["platform"], method, blocked)
    return started, release


def _cancel_once(world, owner, started, release):
    approve = _approve_with(owner)

    async def drive(handle):
        await approve(handle)
        for _ in range(400):
            if started.is_set():
                break
            await asyncio.sleep(0.05)
        await handle.cancel()
        await asyncio.sleep(0.5)
        release.set()

    with pytest.raises(Exception):  # noqa: B017 - the run ends cancelled, as asked
        _run(world, drive)
    return [e["body"]["status"] for e in world["log"].entries("inc-42", kinds=("workflow.end",))]


def test_a_cancel_during_apply_ends_on_the_record_and_trips(world, owner):
    """Ninth review (2026-10-01): a cancel landing while an activity ran arrives as an ActivityError, not a
    CancelledError, so the run left no end row and the switch off; and a cancel during apply read as "cancelled",
    though apply may have acted."""
    started, release = _blocking(world, "apply")
    assert _cancel_once(world, owner, started, release) == ["cancelled_after_apply"]
    assert bounds.killswitch(world["log"]) is not None


def test_a_cancel_before_apply_ends_on_the_record_without_a_trip(world):
    """Cancelled while it waits for approval - nothing sent to the target - the run ends `cancelled`, no trip. (Blocking
    precheck in a thread instead raced the cancel on CI's Linux runners and hung, 2f577cd.)"""
    async def drive(handle):
        await _until_awaiting_approval(handle)
        await handle.cancel()

    with pytest.raises(Exception):  # noqa: B017 - the run ends cancelled, as asked
        _run(world, drive)
    statuses = [e["body"]["status"] for e in world["log"].entries("inc-42", kinds=("workflow.end",))]
    assert statuses == ["cancelled"], statuses
    assert bounds.killswitch(world["log"]) is None


def test_a_retried_finish_signs_an_end_row_its_first_try_left_unsigned(world, monkeypatch, tmp_path):
    """Register R9-O4: the try that wrote the end row failed before its checkpoint; the retry found the row and
    returned, and the end of the run stayed unsigned."""
    from warden import activities as acts_module
    from warden.activities import FixOutcome

    monkeypatch.setattr(acts_module, "_run_id", lambda: "run-1")
    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    real = world["log"].checkpoint
    monkeypatch.setattr(world["log"], "checkpoint", lambda: (_ for _ in ()).throw(RuntimeError("worker died")))
    with pytest.raises(RuntimeError, match="worker died"):
        acts.finish("inc-42", "rem-a", FixOutcome(status="recovered", checklist={}))
    monkeypatch.setattr(world["log"], "checkpoint", real)
    acts.finish("inc-42", "rem-a", FixOutcome(status="recovered", checklist={}))
    assert len(world["log"].entries("inc-42", kinds=("workflow.end",))) == 1
    pub = world["log"].key.public_key()
    assert audit.verify(world["db"], pub).unsigned_tail == 0


def test_how_a_plan_ended_is_on_the_workers_log_with_no_typed_reason(world, caplog):
    """Live, 2026-10-12: the owner denied a plan and the worker's log said nothing - only the audit could tell.
    The status and the approvers' ids are logged; a denial's typed reason is not."""
    import logging

    from warden.activities import FixOutcome

    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    with caplog.at_level(logging.INFO, logger="warden.incident"):
        acts.finish("inc-42", "rem-x", FixOutcome(status="denied", reasons=["denied by owner: typed words"], checklist={}))
    assert [r.getMessage() for r in caplog.records] == ["inc-42 fix plan rem-x ended denied approvers=-"]


# ------------------------------------------------------------------ U3-8: an approver extends the wait


SLACK_ID = "U" + "0" * 3 + "APPROV1"


def _extended_run(world, owner, *, ask, approve_after):
    """A plan that waits an hour; `ask(plan)` may record an extension while it waits; the clock is moved past the
    hour; then, if `approve_after`, the owner approves it."""
    world["policy"].approvers["owner"].slack = SLACK_ID

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=CONVERTER)
        acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
        methods = [acts.resolve_plan, acts.gate, acts.announce, acts.check_approval, acts.check_passkey, acts.precheck,
                   acts.apply, acts.check_success, acts.record_result, acts.rollback, acts.finish, acts.again_alert,
                   acts.side_effects, acts.approval_extension]
        async with env, Worker(env.client, task_queue=QUEUE, workflows=[RemediationWorkflow], activities=methods,
                               activity_executor=ThreadPoolExecutor(4)):
            handle = await env.client.start_workflow(RemediationWorkflow.run,
                                                     FixRequest(**REQ, approval_ttl_minutes=60),
                                                     id=f"rem-{uuid.uuid4()}", task_queue=QUEUE)
            plan = await _until_awaiting_approval(handle)
            ask(plan)
            await env.sleep(timedelta(minutes=90))  # past the plan's own hour
            still = await handle.query(RemediationWorkflow.stage)
            later = await handle.query(RemediationWorkflow.plan)
            if approve_after and still == "awaiting_approval":
                await _approve_with(owner)(handle)
            outcome = await handle.result()
            world["history"] = await handle.fetch_history()
            world["namespace"] = env.client.namespace
            return still, later, outcome
    return asyncio.run(main())


def _extend(world, hours=24):
    from warden import extend

    def ask(plan):
        got = extend.request(world["log"], world["policy"], incident="inc-42", user=SLACK_ID, hours=hours,
                             now=datetime.now(UTC))
        assert not got.get("why"), got
    return ask


def test_an_approvers_extension_keeps_the_plan_waiting_past_its_time_and_it_is_still_checked_before_apply(world,
                                                                                                         owner):
    still, later, out = _extended_run(world, owner, ask=_extend(world), approve_after=True)
    assert still == "awaiting_approval"
    assert later.approval_ttl_minutes > 60 * 24  # it says its new time
    assert out.status == "recovered"
    assert out.checklist["prechecked"]  # the precheck still ran before apply
    kinds = [e["kind"] for e in world["log"].entries("inc-42")]
    assert kinds.index("approval.extended") < kinds.index("approval.accepted") < kinds.index("remediation.precheck")
    # The plan said its new time with fresh links when its first hour ran out: the request, the halfway reminder and
    # then that one (CodeRabbit, PR 150: two were there without it).
    assert _waiting(world) == 3
    asyncio.run(Replayer(workflows=[RemediationWorkflow], data_converter=CONVERTER, namespace=world["namespace"])
                .replay_workflow(world["history"]))


def _waiting(world):
    return sum(1 for e in world["log"].entries("inc-42", kinds=("remediation.announce",))
               if e["body"].get("what") == "waiting")


def test_without_an_extension_the_plan_expires_at_its_time(world, owner):
    still, _, out = _extended_run(world, owner, ask=lambda plan: None, approve_after=True)
    assert still == "expired"
    assert out.status == "expired"
    assert world["platform"].applied == []
    assert _waiting(world) == 2  # the request and the halfway reminder only


def test_an_extension_of_another_plan_does_not_keep_this_one(world, owner):
    def ask(plan):
        world["log"].append("inc-42", "approval.extended", {"workflow_id": plan.workflow_id, "plan_hash": "other",
                                                            "until": (datetime.now(UTC) + timedelta(days=2)).isoformat()})
    still, _, out = _extended_run(world, owner, ask=ask, approve_after=True)
    assert still == "expired"
    assert out.status == "expired"
    assert world["platform"].applied == []
