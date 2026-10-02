"""Registers C1, C2, C20, C21: alarms come in through intake, which starts, groups, escalates or ignores them."""

from __future__ import annotations

import asyncio
import contextlib
import os
import tempfile
import types
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.client import WorkflowExecutionStatus
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from test_remediation_workflow import FakePlatform, _approve_with, _run
from warden import audit, codec, intake
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import Alert
from warden.workflows import IncidentWorkflow, RemediationWorkflow

T0 = datetime(2026, 10, 3, 1, 0, tzinfo=UTC)


def _ev(state="ALARM", at=T0, source="alarm", service=None):
    alert = Alert(**DEMO_ALERTS["inc-001"])
    if service:
        alert = alert.model_copy(update={"service": service})
    return intake.AlarmEvent(source=source, rule="HighErrorRate", state=state, transitioned_at=at, alert=alert)


def _decide(ev, recent=(), open_incidents=None, verifying=None, open_count=0):
    return intake.decide(ev, recent=list(recent), open_incidents=open_incidents or {}, verifying=verifying or {},
                         open_count=open_count)


def test_only_an_alarm_state_starts_an_incident_and_its_id_is_the_transition():
    """C20: OK and INSUFFICIENT_DATA start nothing; one transition is one id, the next transition another."""
    assert _decide(_ev("OK")).action == "ignore" and _decide(_ev("INSUFFICIENT_DATA")).action == "ignore"
    first = _decide(_ev())
    assert first.action == "start" and first.workflow_id == f"inc-{first.fingerprint}-20261003T010000Z"
    assert _decide(_ev()).workflow_id == first.workflow_id
    assert _decide(_ev(at=T0 + timedelta(hours=2))).workflow_id != first.workflow_id


def test_a_flapping_alarm_goes_to_a_person_without_the_model():
    """C21: the fourth change inside the window is an escalate-only incident."""
    assert _decide(_ev(), recent=[{}] * (intake.FLAP_FLIPS - 2)).action == "start"
    flapping = _decide(_ev(), recent=[{}] * (intake.FLAP_FLIPS - 1))
    assert flapping.action == "escalate_only" and "flapping" in flapping.reason


def test_a_repeat_signals_the_open_incident_and_a_storm_is_capped():
    """C2: the same fingerprint joins its open incident; past the cap, a new alarm is escalate-only."""
    fp = intake.fingerprint(_ev())
    joined = _decide(_ev(), open_incidents={fp: "inc-open"})
    assert (joined.action, joined.workflow_id) == ("signal_incident", "inc-open")
    assert _decide(_ev(), open_count=intake.MAX_OPEN).action == "escalate_only"
    assert _decide(_ev(), open_count=intake.MAX_OPEN - 1).action == "start"


def test_an_alarm_on_a_service_wardens_fix_is_verifying_goes_to_that_fix():
    """C1: not a new incident that would act on WARDEN's own change again - a signal to the remediation."""
    ev = _ev()
    fp = intake.fingerprint(ev)
    d = _decide(ev, open_incidents={fp: "inc-open"}, verifying={(ev.alert.environment, ev.alert.service): "rem-1"})
    assert (d.action, d.workflow_id) == ("signal_remediation", "rem-1")


def test_a_caller_of_the_mcp_server_cannot_take_a_real_alarms_id():
    assert intake.fingerprint(_ev(source="mcp")) != intake.fingerprint(_ev())


class _Handle:
    def __init__(self, client, wid):
        self.client, self.id = client, wid

    async def describe(self):
        status = WorkflowExecutionStatus.RUNNING if self.id in self.client.running else WorkflowExecutionStatus.COMPLETED
        return types.SimpleNamespace(status=status)

    async def query(self, _q):
        return self.client.stages.get(self.id, "")

    async def signal(self, sig, at):
        self.client.calls.append(("signal", self.id, sig.__name__, at))


class _Client:
    def __init__(self, running=(), stages=None):
        self.running, self.stages, self.calls = set(running), stages or {}, []

    def get_workflow_handle(self, wid):
        return _Handle(self, wid)

    async def start_workflow(self, fn, *, args, id, task_queue, id_reuse_policy):
        self.calls.append(("start", id, args[1]))


def _log():
    return audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())


def test_submit_reads_the_open_incidents_and_remediations_from_the_record():
    log, now = _log(), datetime.now(UTC)
    first = asyncio.run(intake.submit(_Client(), _ev(at=now), log))
    assert first.action == "start"
    again = asyncio.run(intake.submit(client := _Client(running={first.workflow_id}), _ev(at=now + timedelta(minutes=5)),
                                      log))
    assert (again.action, again.workflow_id) == ("signal_incident", first.workflow_id)
    assert client.calls[-1][:3] == ("signal", first.workflow_id, "repeat")
    log.append("inc-x", "remediation.plan", {"workflow_id": "rem-9", "environment": "prod", "service": "checkout"})
    c1 = asyncio.run(intake.submit(client := _Client(running={first.workflow_id}, stages={"rem-9": "verifying"}),
                                   _ev(at=now + timedelta(minutes=6)), log))
    assert (c1.action, c1.workflow_id) == ("signal_remediation", "rem-9")
    assert client.calls[-1][:3] == ("signal", "rem-9", "alarm")
    assert [e["body"]["action"] for e in log.entries(kinds=("intake.decision",))] == [
        "start", "signal_incident", "signal_remediation"]


def test_submit_counts_ok_transitions_toward_flapping_and_starts_escalate_only():
    log, now, client = _log(), datetime.now(UTC), _Client()
    for i, state in enumerate(("ALARM", "OK", "ALARM")):
        asyncio.run(intake.submit(client, _ev(state=state, at=now + timedelta(minutes=i)), log))
    d = asyncio.run(intake.submit(client, _ev(state="OK", at=now + timedelta(minutes=3)), log))
    assert d.action == "ignore"
    d = asyncio.run(intake.submit(client, _ev(at=now + timedelta(minutes=4)), log))
    assert d.action == "escalate_only" and client.calls[-1] == ("start", d.workflow_id, d.reason)


def test_an_alarm_during_the_verify_window_rolls_the_fix_back():
    """C1, end to end: without the alarm this run recovers at its first check; with it, it rolls back."""
    world = {"log": _log(), "platform": FakePlatform(healthy_after=1)}
    from test_remediation_workflow import approvals, serialization

    owner = Ed25519PrivateKey.generate()
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    world["policy"] = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"])})

    async def drive(handle):
        await _approve_with(owner)(handle)
        for _ in range(400):
            if await handle.query(RemediationWorkflow.stage) == "verifying":
                await handle.signal(RemediationWorkflow.alarm, "2026-10-03T01:05:00+00:00")
                return
            await asyncio.sleep(0.05)
        raise AssertionError("never reached verifying")

    out = _run(world, drive)
    assert out.status == "rolled_back" and "alarm fired again" in out.reasons[0], out
    assert world["platform"].rolled_back


def test_an_escalate_only_incident_asks_no_model_and_ends_on_the_record():
    class _Counting:
        name, model, calls = "fake", "fake", 0

        def complete(self, **kw):
            _Counting.calls += 1
            raise AssertionError("the model was asked")

    async def main():
        log = _log()
        acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(provider=_Counting(), mock=False))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        alert = Alert(**DEMO_ALERTS["inc-001"])
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            h = await env.client.start_workflow(IncidentWorkflow.run, args=[alert, "the alarm is flapping"],
                                                id="inc-flap", task_queue="q")
            with contextlib.suppress(Exception):
                await h.result()
            return (await h.describe()).status.name, log.entries(alert.alert_id, kinds=("incident.verify",))

    status, verified = asyncio.run(main())
    assert _Counting.calls == 0 and status == "FAILED"
    assert verified[0]["body"]["status"] == "escalated" and "P0-MODEL-UNAVAILABLE" in verified[0]["body"]["policies"]
