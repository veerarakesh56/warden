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


def LATER():
    """An alarm that transitioned after the fix passed its checks (the record stamps those with the clock)."""
    return datetime.now(UTC) + timedelta(seconds=2)


class _Reusing(_Client):
    async def start_workflow(self, fn, *, args, id, task_queue, id_reuse_policy):
        self.calls.append(("start", id, args[0].alert_id, id_reuse_policy))
        self.escalated = args[1]


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
    ev = _ev(at=LATER())
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
    ev = _ev(at=LATER())
    _fixed(log, "other-20261016T010000Z", at=None, service=ev.alert.service, env=ev.alert.environment)
    assert intake.held_fix(ev, log, datetime.now(UTC))["incident"] == "other-20261016T010000Z"
    later = datetime.now(UTC) + timedelta(minutes=60) + intake.SOAK_GRACE + timedelta(seconds=5)
    assert intake.held_fix(ev, log, later) is None


def test_a_fix_that_ended_or_was_never_verified_reopens_nothing():
    log = _log()
    ev = _ev(at=LATER())
    fp = intake.fingerprint(ev)
    _fixed(log, f"{fp}-a", at=None, ended="recovered")
    log.append(f"{fp}-b", "remediation.plan", {"workflow_id": "rem-2", "run_id": "r", "environment": "prod",
                                               "service": "checkout", "soak_minutes": 60})
    log.append(f"{fp}-b", bounds.RESULT, {"workflow_id": "rem-2", "run_id": "r", "ok": False})
    assert intake.held_fix(ev, log, datetime.now(UTC)) is None
    assert asyncio.run(intake.submit(_Client(), ev, log)).action == "start"


def test_another_environment_or_an_mcp_request_reopens_nothing():
    log = _log()
    ev = _ev(at=LATER())
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


# ------------------------------------------------------------------ PR 43 review (CodeRabbit)

def test_an_alarm_that_transitioned_before_the_fix_was_verified_reopens_nothing():
    log = _log()
    before = datetime.now(UTC) - timedelta(minutes=1)  # delivered late, from before the fix passed its checks
    ev = _ev(at=before)
    _fixed(log, f"{intake.fingerprint(ev)}-x", at=None)
    assert intake.held_fix(ev, log, datetime.now(UTC)) is None
    assert intake.held_fix(_ev(at=LATER()), log, datetime.now(UTC)) is not None


def test_a_reopened_incident_keeps_the_alarms_reason_to_go_to_a_person():
    held = {"incident": "i", "entry": "e", "verified_at": "2026-10-16T01:00:00+00:00"}
    flapping = intake.decide(_ev(), recent=[{}] * (intake.FLAP_FLIPS - 1), open_incidents={}, verifying={},
                             open_count=0, held=held)
    assert flapping.action == "reopen" and "flapping" in flapping.escalate
    health = _ev().model_copy(update={"escalate": "AWS Health reports an issue"})
    assert intake.decide(health, recent=[], open_incidents={}, verifying={}, open_count=0,
                         held=held).escalate == "AWS Health reports an issue"
    log = _log()
    ev = _ev(at=LATER()).model_copy(update={"escalate": "AWS Health reports an issue"})
    _fixed(log, f"{intake.fingerprint(ev)}-x", at=None)
    client = _Reusing()
    assert asyncio.run(intake.submit(client, ev, log)).action == "reopen"
    assert client.escalated == "AWS Health reports an issue"  # the reopened run is escalate-only


class _FailsOnce(_Reusing):
    def __init__(self):
        super().__init__()
        self.failed = False

    async def start_workflow(self, fn, **kw):
        if not self.failed:
            self.failed = True
            raise RuntimeError("Temporal is unreachable for a moment")
        await super().start_workflow(fn, **kw)


def test_a_reopen_whose_start_failed_is_honoured_when_the_alarm_is_retried_after_the_fix_ended():
    log = _log()
    ev = _ev(at=LATER())
    incident = f"{intake.fingerprint(ev)}-20261016T010000Z"
    _fixed(log, incident, at=None)
    client = _FailsOnce()
    try:
        asyncio.run(intake.submit(client, ev, log))
        raise AssertionError("the failed start must fail the delivery, so EventBridge retries it")
    except RuntimeError:
        pass
    assert not [c for c in client.calls if c[0] == "signal"]  # the fix is told only once the incident has started
    log.append(incident, "workflow.end", {"workflow_id": "rem-prod-1", "run_id": "r1", "status": "recovered"})
    assert intake.held_fix(ev, log, datetime.now(UTC)) is None  # the soak is over for any other alarm...
    d = asyncio.run(intake.submit(client, ev, log))  # ...but the same transition, retried, still reopens
    assert (d.action, d.workflow_id) == ("reopen", f"inc-{incident}")
    assert [c[:2] for c in client.calls if c[0] == "start"] == [("start", f"inc-{incident}")]
    assert len(log.entries(incident, kinds=(history.DID_NOT_HOLD,))) == 1  # recorded once
    assert log.entries(incident, kinds=(intake.REOPEN_STARTED,))
    assert intake.reopen_pending(ev, log, datetime.now(UTC)) is None  # honoured: nothing pending now


def test_a_failure_to_hold_blocks_the_fix_until_an_approver_signs_otherwise(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from warden import approvals

    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={
        "owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"]),
        "bench": approvals.Approver(public_key=pem, tiers=["T1", "T2"], environments=["prod"])})
    clock = [datetime.now(UTC) - timedelta(days=40)]
    log = AuditLog(tmp_path / "a.db", key=None, clock=lambda: clock[0])
    early = approvals.sign(key, approver="owner", workflow_id=history.OFFER_AGAIN_WORKFLOW, plan_hash="x", tier="T2",
                           now=clock[0] - timedelta(minutes=1))
    log.append("inc-old", history.DID_NOT_HOLD, {"entry": "e", "target": "dev/t"})  # 40 days ago
    clock[0] = datetime.now(UTC)
    [(failed_at, _)] = history.failures(log, "e", "dev/t")
    # Durable: no time limit (a 30-day window let it be offered again with nobody deciding).
    assert history.did_not_hold(log, "e", "dev/t")[0] == "inc-old"
    right = history.offer_again_hash("e", "dev/t", failed_at)
    signed_before = early.model_copy(update={"plan_hash": right})
    assert history.offer_again(log, signed_before, policy=policy, entry="e", target="dev/t")  # not its signature
    for who in ("bench",):  # an approver limited to prod may not clear a dev fix
        other = approvals.sign(key, approver=who, workflow_id=history.OFFER_AGAIN_WORKFLOW, plan_hash=right, tier="T2")
        assert history.offer_again(log, other, policy=policy, entry="e", target="dev/t")
    assert history.did_not_hold(log, "e", "dev/t")[0] == "inc-old"
    ok = approvals.sign(key, approver="owner", workflow_id=history.OFFER_AGAIN_WORKFLOW, plan_hash=right, tier="T2")
    assert history.offer_again(log, ok, policy=policy, entry="e", target="dev/t") == []
    assert history.did_not_hold(log, "e", "dev/t") == ("", "")
    assert history.offer_again(log, ok, policy=policy, entry="e", target="dev/t")  # used once
    # It fails to hold again: blocked again, the earlier clearance does not carry over.
    log.append("inc-new", history.DID_NOT_HOLD, {"entry": "e", "target": "dev/t"})
    assert history.did_not_hold(log, "e", "dev/t")[0] == "inc-new"


def test_the_own_fix_that_did_not_hold_is_history_while_its_run_is_still_ending():
    log = _log()
    alert = ALERT.model_copy(update={"alert_id": "inc-r"})
    log.append("inc-r", "remediation.plan", {"workflow_id": "w", "run_id": "r", "entry": "e", "target": "dev/t",
                                             "environment": "dev", "service": alert.service})
    assert history.past(alert, log) == []  # its own fix, still open, before anything said it did not hold
    log.append("inc-r", history.DID_NOT_HOLD, {"workflow_id": "w", "entry": "e", "target": "dev/t"})
    assert [r["incident"] for r in history.past(alert, log)] == ["inc-r"]


def test_the_own_fix_that_did_not_hold_is_beside_the_reopened_diagnosis(tmp_path):
    log = AuditLog(tmp_path / "a.db", key=None)
    started = datetime.now(UTC) + timedelta(minutes=1)
    alert = ALERT.model_copy(update={"alert_id": "inc-r", "started_at": started.isoformat()})
    log.append("inc-r", bounds.APPLIED, {"workflow_id": "w", "run_id": "r", "service": f"dev/table:{alert.service}",
                                         "action_class": "dynamodb_restore_capacity"})
    acts = IncidentActivities(audit=log, platform=_Plans())
    assert acts._own_fixes(alert) == []
    log.append("inc-r", history.DID_NOT_HOLD, {"workflow_id": "w", "entry": "e", "target": "dev/t"})
    [(_, link)] = acts._own_fixes(alert)
    assert link["workflow_id"] == "w" and link["incident"] == "inc-r"


def test_the_offer_again_command_clears_a_fix_with_the_approvers_own_key(tmp_path, monkeypatch, capsys):
    import pathlib

    import yaml
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from warden import audit
    from warden.cli import main

    signer = Ed25519PrivateKey.generate()
    key_file = tmp_path / "owner.pem"
    key_file.write_bytes(signer.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    pem = signer.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    audit.generate_key(tmp_path / "audit.pem", tmp_path / "audit.pub")
    (tmp_path / "approvers.yaml").write_text(yaml.safe_dump(
        {"approvers": {"owner": {"public_key": pem, "tiers": ["T1", "T2"]}}}), encoding="utf-8")
    for name, value in {"WARDEN_APPROVERS": "approvers.yaml", "WARDEN_AUDIT_DB": "audit.db",
                        "WARDEN_AUDIT_KEY": "audit.pem"}.items():
        monkeypatch.setenv(name, str(tmp_path / value))
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    args = ["offer-again", "inc-9", "--approver", "owner", "--key", str(key_file)]
    assert main(args) == 1 and "nothing to clear" in capsys.readouterr().err
    log = audit.AuditLog(pathlib.Path(tmp_path / "audit.db"))
    log.append("inc-9", history.DID_NOT_HOLD, {"entry": "e", "target": "dev/t", "workflow_id": "w"})
    assert history.did_not_hold(log, "e", "dev/t")[0] == "inc-9"
    assert main(args) == 0 and "may be offered again" in capsys.readouterr().out
    assert history.did_not_hold(audit.AuditLog(pathlib.Path(tmp_path / "audit.db")), "e", "dev/t") == ("", "")
