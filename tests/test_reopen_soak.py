"""Item 11 (owner, 2026-10-16): a fix that was verified and then did not hold.

The fix is watched through its soak (WARDEN_SOAK_MINUTES, 60 by default: re-checks at +15 and +60, and at the soak's
end when it is longer). When the same alarm - or one on a resource the fix changed - comes back inside it, intake
reopens the SAME incident (its record carries the whole story), marks the fix as not holding, and tells the fix's
run, which ends `relapsed`. From then on WARDEN does not offer that fix for that target again on its own."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from temporalio.common import WorkflowIDReusePolicy

from test_false_recovery_c18a import _Sequence
from test_incident_note import ALERT, _diag, _Plans
from test_intake import _Client, _ev, _log
from test_remediation_workflow import _approve_with, _run, owner, world  # noqa: F401 - fixtures
from warden import bounds, catalog, history, intake, records, resolver, workflows
from warden.activities import FixRequest, IncidentActivities, Verified
from warden.audit import AuditLog
from warden.models import Verdict, VerdictStatus


class _Reusing(_Client):
    async def start_workflow(self, fn, *, args, id, task_queue, id_reuse_policy):
        self.calls.append(("start", id, args[0].alert_id, id_reuse_policy))


def _fixed(log, incident, *, at, soak=60, ended="", service=None, env="prod", wid="rem-prod-1", run="r1"):
    """A fix plan of `incident` whose run passed its checks at `at` - still watched unless `ended`."""
    log.append(incident, "remediation.plan", {"workflow_id": wid, "run_id": run, "entry": "k8s_rollout_undo",
                                              "environment": env, "service": service or "checkout",
                                              "target": f"{env}/deployment:checkout", "soak_minutes": soak})
    log.append(incident, bounds.RESULT, {"workflow_id": wid, "run_id": run, "ok": True, "service": "x"})
    if ended:
        log.append(incident, "workflow.end", {"workflow_id": wid, "run_id": run, "status": ended})
    # The record's own times are the clock's: the test moves "now" instead.
    return log.entries(incident, kinds=(bounds.RESULT,))[-1]["at"]


def test_the_same_alarm_inside_the_soak_reopens_the_same_incident():
    log = _log()
    ev = _ev(at=datetime.now(UTC))
    incident = f"{intake.fingerprint(ev)}-20261016T010000Z"
    _fixed(log, incident, at=None, service="not-named-by-the-alarm")  # matched by its fingerprint alone
    client = _Reusing()
    d = asyncio.run(intake.submit(client, ev, log))
    assert (d.action, d.workflow_id) == ("reopen", f"inc-{incident}") and "did not hold" in d.reason
    start = [c for c in client.calls if c[0] == "start"]
    assert start == [("start", f"inc-{incident}", incident, WorkflowIDReusePolicy.ALLOW_DUPLICATE)]
    assert ("signal", "rem-prod-1", "alarm") in [c[:3] for c in client.calls]  # its run ends relapsed
    [mark] = [e["body"] for e in log.entries(incident, kinds=(history.DID_NOT_HOLD,))]
    assert (mark["entry"], mark["target"], mark["workflow_id"]) == ("k8s_rollout_undo", "prod/deployment:checkout",
                                                                     "rem-prod-1")
    assert log.entries(incident, kinds=("incident.reopened",))
    # The record says it in words.
    shown = records.record(log, incident)
    assert any(records.STEP.get(e["kind"]) == "Reopened: the alarm came back while the fix was being watched"
               for e in shown.rows)
    # A repeat of the alarm while the reopened run goes joins it: no second reopen, no new incident.
    again = asyncio.run(intake.submit(_Reusing(running={f"inc-{incident}"}), _ev(at=datetime.now(UTC)
                                                                                + timedelta(minutes=1)), log))
    assert (again.action, again.workflow_id) == ("signal_incident", f"inc-{incident}")


def test_an_alarm_on_the_fixed_resource_reopens_too_and_after_the_soak_it_is_a_new_incident(monkeypatch):
    log = _log()
    ev = _ev(at=datetime.now(UTC))
    _fixed(log, "other-20261016T010000Z", at=None, service=ev.alert.service, env=ev.alert.environment)
    assert intake.held_fix(ev, log, datetime.now(UTC))["incident"] == "other-20261016T010000Z"
    later = datetime.now(UTC) + timedelta(minutes=60) + intake.SOAK_GRACE + timedelta(seconds=5)
    assert intake.held_fix(ev, log, later) is None


def test_a_fix_that_ended_or_was_never_verified_reopens_nothing():
    log = _log()
    ev = _ev(at=datetime.now(UTC))
    fp = intake.fingerprint(ev)
    _fixed(log, f"{fp}-a", at=None, ended="recovered")
    log.append(f"{fp}-b", "remediation.plan", {"workflow_id": "rem-2", "run_id": "r", "environment": "prod",
                                               "service": "checkout", "soak_minutes": 60})
    log.append(f"{fp}-b", bounds.RESULT, {"workflow_id": "rem-2", "run_id": "r", "ok": False})
    assert intake.held_fix(ev, log, datetime.now(UTC)) is None
    assert asyncio.run(intake.submit(_Client(), ev, log)).action == "start"


def test_another_environment_or_an_mcp_request_reopens_nothing():
    log = _log()
    ev = _ev(at=datetime.now(UTC))
    _fixed(log, f"{intake.fingerprint(ev)}-x", at=None, env="dev")
    assert intake.held_fix(ev, log, datetime.now(UTC)) is None
    held = {"incident": "i", "entry": "e", "verified_at": "2026-10-16T01:00:00+00:00"}
    mcp = intake.decide(_ev(source="mcp"), recent=[], open_incidents={}, verifying={}, open_count=0, held=held)
    assert mcp.action == "start"


def test_an_expected_shutdown_is_not_a_fix_that_did_not_hold():
    held = {"incident": "i", "entry": "e", "verified_at": "2026-10-16T01:00:00+00:00"}
    d = intake.decide(_ev(), recent=[], open_incidents={}, verifying={}, open_count=0, held=held,
                      expected=("nightly stop", None))
    assert d.action == "expected"


# ------------------------------------------------------------------ the same fix is not offered again

def test_a_fix_that_did_not_hold_is_not_offered_again_for_that_target(tmp_path):
    passed = Verified(verdict=Verdict(status=VerdictStatus.approved_for_human))
    log = AuditLog(tmp_path / "a.db", key=None)
    acts = IncidentActivities(audit=log, platform=_Plans())
    first = acts.plan_fix(ALERT, _diag(), passed)
    assert first["entry"] == "dynamodb_restore_capacity"
    target = f"dev/{catalog.target_key(first['entry'], first['params'])}"
    log.append("inc-0", history.DID_NOT_HOLD, {"entry": first["entry"], "target": target, "workflow_id": "rem-0"})
    assert acts.plan_fix(ALERT, _diag(), passed) == {}
    row = log.entries(ALERT.alert_id, kinds=("incident.plan_fix",))[-1]["body"]
    assert row["not_again"] == "inc-0" and "did not hold" in row["why"] and "a person decides" in row["why"]
    # Another target, or another fix, is still offered.
    assert history.did_not_hold(log, first["entry"], "dev/table:another") == ("", "")
    assert history.did_not_hold(log, "dynamodb_raise_capacity", target) == ("", "")


def test_a_fix_that_relapsed_at_a_re_check_is_not_offered_again_either(tmp_path):
    log = AuditLog(tmp_path / "a.db", key=None)
    log.append("inc-9", "remediation.plan", {"workflow_id": "w", "run_id": "r", "entry": "e", "target": "dev/t"})
    log.append("inc-9", "workflow.end", {"workflow_id": "w", "run_id": "r", "status": "relapsed"})
    assert history.did_not_hold(log, "e", "dev/t")[0] == "inc-9"
    log.append("inc-8", "remediation.plan", {"workflow_id": "w2", "run_id": "r", "entry": "e", "target": "dev/u"})
    log.append("inc-8", "workflow.end", {"workflow_id": "w2", "run_id": "r", "status": "recovered"})
    assert history.did_not_hold(log, "e", "dev/u") == ("", "")


def test_the_reopened_incidents_own_earlier_fix_is_its_history():
    log = _log()
    alert = ALERT.model_copy(update={"alert_id": "inc-r"})
    log.append("inc-r", "remediation.plan", {"workflow_id": "w", "run_id": "r", "entry": "e", "target": "dev/t",
                                             "environment": "dev", "service": alert.service})
    log.append("inc-r", "workflow.end", {"workflow_id": "w", "run_id": "r", "status": "relapsed"})
    assert [r["incident"] for r in history.past(alert, log)] == ["inc-r"]
    assert "Again:" in history.again(history.past(alert, log))


# ------------------------------------------------------------------ the soak setting and the watch

def test_the_soak_is_a_setting_bounded_by_the_request(monkeypatch):
    monkeypatch.delenv("WARDEN_SOAK_MINUTES", raising=False)
    assert resolver.soak_minutes() == 60
    for raw, want in (("120", 120), ("5", 60), ("99999", 1440), ("soon", 60)):
        monkeypatch.setenv("WARDEN_SOAK_MINUTES", raw)
        assert resolver.soak_minutes() == want
    base = {"incident_id": "i", "entry": "k8s_rollout_undo", "params": {}, "environment": "dev", "service": "s"}
    assert workflows.rechecks(FixRequest(**base)) == workflows.RECHECK_AFTER  # histories from before replay as ran
    assert workflows.rechecks(FixRequest(**base, soak_minutes=120))[-1] == timedelta(minutes=120)


def test_a_longer_soak_re_checks_at_its_end_and_a_relapse_there_is_said(world, owner):  # noqa: F811
    world["platform"] = _Sequence([True, True, True, True, True, False])  # the streak, +15, +60, then fails
    out = _run(world, _approve_with(owner), soak_minutes=120)
    assert out.status == "relapsed" and "120-minute re-check" in out.reasons[0]
    assert world["platform"].checks == 3 + 3


def test_the_plan_row_carries_its_soak_for_intake(world, owner):  # noqa: F811
    world["platform"] = _Sequence([True])
    assert _run(world, _approve_with(owner), soak_minutes=90).status == "recovered"
    [plan] = [e["body"] for e in world["log"].entries(kinds=("remediation.plan",))]
    assert plan["soak_minutes"] == 90
