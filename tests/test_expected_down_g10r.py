"""An alarm on something a person declared down, or not in use, is not an incident (register G10-39).

Owner, 2026-10-12: non-production environments are shut down at night - "that is expected state, not an incident" -
and "not only night shutdown, even sometimes on holidays and weekends and some other times when not needed, and
maybe even complete or temporary not using those environments or AWS services or application services".

While a declaration covers an alarm no incident starts. When the cover ends the alarm is looked at again: a
shutdown that did not come back is an incident then, dated then."""

from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from test_alarm_reader_g9 import _alarm, _backend
from test_intake import _Client, _decide, _ev, _log
from warden import audit, codec, expected, intake, settings
from warden.activities import EvidencePack, IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import Alert, Severity
from warden.workflows import ZONES, IncidentWorkflow

IST = timedelta(hours=5, minutes=30)
DECLARED = """
- name: staging nights
  environments: [staging, qa-staging]
  zone: Asia/Kolkata
  hours: "20:00-08:00"
- name: staging weekends
  environments: [staging, qa-staging]
  zone: Asia/Kolkata
  days: [sat, sun]
- name: Diwali
  environments: [staging]
  zone: Asia/Kolkata
  dates: ["2026-11-09"]
- name: reports parked
  services: [reports]
  zone: Asia/Kolkata
  until: "2026-11-01T09:00"
- name: old search cluster
  resources: [search-v1]
- name: one team's test table, in dev only
  environments: [dev]
  resources: [scratch-orders]
  zone: UTC
  from: "2026-10-01T00:00"
"""


def _alert(environment="staging", service="checkout", **labels):
    return Alert(alert_id="a1", name="n", service=service, environment=environment, severity=Severity.high,
                 summary="", started_at="2026-10-12T00:00:00+00:00", labels=labels)


def _ist(day, hour, minute=0, month=10):
    return datetime(2026, month, day, hour, minute, tzinfo=UTC) - IST


def _covers(at, text=DECLARED, **alert):
    return expected.covering(_alert(**alert), at, text)


# ------------------------------------------------------------------ what a declaration covers


def test_a_night_a_weekend_and_a_holiday_are_expected_and_the_working_day_is_not():
    assert _covers(_ist(13, 21)) == ("staging nights", _ist(14, 8))       # Tuesday 21:00: until 08:00 tomorrow
    assert _covers(_ist(14, 7, 59)) == ("staging nights", _ist(14, 8))    # crosses midnight
    assert _covers(_ist(14, 8)) is None and _covers(_ist(14, 19, 59)) is None
    # Friday night runs into the weekend and Sunday night: one cover, ending Monday 08:00.
    assert _covers(_ist(16, 21)) == ("staging nights", _ist(19, 8))
    assert _covers(_ist(17, 12)) == ("staging weekends", _ist(19, 8))
    assert _covers(_ist(9, 12, month=11)) == ("Diwali", _ist(10, 8, month=11))  # a Monday holiday, then its night
    assert _covers(_ist(13, 21), environment="prod") is None              # no declaration names prod
    assert _covers(_ist(13, 21), environment="qa-staging") is not None


def test_a_service_or_a_resource_not_in_use_is_expected_until_its_declaration_ends_or_is_removed():
    assert _covers(_ist(13, 12), environment="prod", service="reports") == ("reports parked", _ist(1, 9, month=11))
    assert _covers(_ist(1, 9, month=11), environment="prod", service="reports") is None
    # Nothing ends this one: expected for as long as it is declared.
    assert _covers(_ist(13, 12), environment="prod", elasticsearch="search-v1") == ("old search cluster", None)
    assert _covers(_ist(13, 12), environment="prod", elasticsearch="search-v2") is None
    # Every part of the WHAT must match: the table in dev, not the same name in prod; and not before `from`.
    assert _covers(_ist(13, 12), environment="dev", dynamodb_table="scratch-orders")[0].startswith("one team")
    assert _covers(_ist(13, 12), environment="prod", dynamodb_table="scratch-orders") is None
    assert _covers(datetime(2026, 9, 30, 12, tzinfo=UTC), environment="dev", dynamodb_table="scratch-orders") is None


@pytest.mark.parametrize("broken", [
    "- {name: x, environments: staging}",                                  # a word, not a list
    "- {name: x, zone: Asia/Kolkata, hours: '20:00-08:00'}",                # names nothing
    "- {name: x, environments: [staging], hours: '25:00-08:00'}",
    "- {name: x, environments: [staging], hours: '20:00'}",
    "- {name: x, environments: [staging], days: [someday]}",
    "- {name: x, environments: [staging], zone: Mars/Olympus}",
    "- {name: x, environments: [staging], untill: '2026-11-01T09:00'}",     # a mistyped key is not ignored
    "- {name: x, environments: [staging], dates: [tomorrow]}",
    "{environments: [staging]}", "- [staging]", "environments: [", "just words",
])
def test_a_declaration_that_cannot_be_read_covers_nothing_so_a_mistake_never_hides_an_alarm(broken):
    assert _covers(_ist(13, 21), text=broken) is None
    # ...and the readable one beside it still applies.
    both = broken + "\n- {name: ok, environments: [staging]}" if broken.startswith("- ") else broken
    assert (_covers(_ist(13, 21), text=both) == ("ok", None)) == broken.startswith("- ")


def test_nothing_is_expected_where_nothing_is_declared(monkeypatch):
    monkeypatch.delenv("WARDEN_EXPECTED_DOWN", raising=False)
    assert expected.covering(_alert(), _ist(13, 21)) is None and expected.declarations("") == []
    monkeypatch.setenv("WARDEN_EXPECTED_DOWN", DECLARED)
    assert expected.covering(_alert(), _ist(13, 21))[0] == "staging nights"
    assert "WARDEN_EXPECTED_DOWN" in settings.LOADABLE - settings.SECRETS  # plain configuration, from Parameter Store


# ------------------------------------------------------------------ intake holds it


def test_a_covered_alarm_starts_no_incident_now_and_a_person_who_asks_still_gets_a_diagnosis():
    until = _ist(14, 8)
    held = intake.decide(_ev(), recent=[], open_incidents={}, verifying={}, open_count=0,
                         expected=("staging nights", until))
    assert held.action == "expected" and held.workflow_id == f"inc-{held.fingerprint}-20261014T023000Z"
    assert held.reason == "expected down ('staging nights') until 2026-10-14 02:30 UTC: looked at again then"
    forever = intake.decide(_ev(), recent=[], open_incidents={}, verifying={}, open_count=0,
                            expected=("old search cluster", None))
    assert forever.action == "expected" and forever.workflow_id == "" and "nothing is looked at again" in forever.reason
    for source in ("mcp", "cli"):
        asked = intake.decide(_ev(source=source), recent=[], open_incidents={}, verifying={}, open_count=0,
                              expected=("staging nights", until))
        assert asked.action == "start"
    # An OK transition is still only counted, and a fix being verified is still told.
    assert intake.decide(_ev(state="OK"), recent=[], open_incidents={}, verifying={}, open_count=0,
                         expected=("staging nights", until)).action == "ignore"
    assert _decide(_ev()).action == "start"  # nothing declared: as before


class _Holding(_Client):
    async def start_workflow(self, fn, *, args, id, task_queue, id_reuse_policy, start_delay=None):
        self.calls.append(("start", id, args, start_delay))


def test_the_held_alarm_is_started_now_to_run_when_its_cover_ends_once(monkeypatch):
    now = datetime.now(UTC)
    zone_now = now + IST
    # Covered for the next two hours, whatever the time of day the test runs at.
    monkeypatch.setenv("WARDEN_EXPECTED_DOWN", f"""
- name: tonight
  environments: [{DEMO_ALERTS['inc-001']['environment']}]
  zone: Asia/Kolkata
  from: "{zone_now - timedelta(hours=1):%Y-%m-%dT%H:%M}"
  until: "{zone_now + timedelta(hours=2):%Y-%m-%dT%H:%M}"
""")
    log, client = _log(), _Holding()
    first = asyncio.run(intake.submit(client, _ev(at=now), log))
    again = asyncio.run(intake.submit(client, _ev(at=now + timedelta(minutes=5)), log))
    assert first.action == again.action == "expected" and first.workflow_id == again.workflow_id  # one hold per cover
    (_, wid, args, delay), _ = client.calls
    assert wid == first.workflow_id and args[1] == "" and args[2] == first.reason
    assert args[0].alert_id == wid.removeprefix("inc-")
    assert timedelta(minutes=118) <= delay <= timedelta(hours=2)
    rows = [e["body"] for e in log.entries(kinds=("intake.decision",))]
    assert [r["action"] for r in rows] == ["expected", "expected"] and "expected down ('tonight')" in rows[0]["reason"]
    # A held alarm is no part of an alarm storm: the next, unrelated alarm is a plain new incident.
    monkeypatch.delenv("WARDEN_EXPECTED_DOWN")
    assert asyncio.run(intake.submit(_Holding(running={wid}), _ev(at=now, service="other"), log)).action == "start"


# ------------------------------------------------------------------ when the cover ends


def test_the_alarms_own_state_says_whether_it_still_fires_and_the_record_says_where_no_alarm_can_be_read(tmp_path):
    held = _alert(alarm="warden-dev-q-depth")
    assert _backend(_alarm())[0].alarm_firing(held) is True
    backend, cw, _ = _backend(_alarm(StateValue="OK"))
    assert backend.alarm_firing(held) is False
    assert cw.calls == [("describe_alarms", {"AlarmNames": ["warden-dev-q-depth"],
                                             "AlarmTypes": ["MetricAlarm", "CompositeAlarm"]})]
    assert _backend(None)[0].alarm_firing(held) is None and _backend(_alarm())[0].alarm_firing(_alert()) is None

    class Backend:
        def __init__(self, answer):
            self.answer = answer

        def alarm_firing(self, alert):
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer

    log = audit.AuditLog(tmp_path / "a.db", key=None)
    alert = held.model_copy(update={"alert_id": "fp1-20261014T023000Z"})
    said = lambda backend: IncidentActivities(audit=log, backend=backend).after_hold(alert, "why")
    assert said(Backend(True)) is True and said(Backend(False)) is False
    # No alarm to read (another monitoring system, a fixture), or a read that failed: unknown - until intake's own
    # record of this alarm's last transition says.
    assert said(Backend(None)) is None and said(Backend(RuntimeError("denied"))) is None and said(None) is None
    log.append("intake-fp1", "intake.event", {"fingerprint": "fp1", "state": "ALARM"})
    assert said(Backend(None)) is True
    log.append("intake-fp1", "intake.event", {"fingerprint": "fp1", "state": "OK"})
    assert said(Backend(None)) is False and said(Backend(True)) is True  # the alarm itself outranks the record
    rows = [e["body"] for e in log.entries(alert.alert_id, kinds=("incident.after_hold",))]
    assert rows[0]["held"] == "why" and [r["firing"] for r in rows][:2] == [True, False]
    assert "after_hold" in ZONES["read"]


def _run(tmp_path, firing):
    """The workflow for a held alarm whose cover has ended; what it read, and what it returned."""
    seen: dict = {"prepared": []}

    class _Acts(IncidentActivities):
        @activity.defn(name="after_hold")
        def after_hold(self, alert: Alert, held: str) -> bool | None:
            if firing == "unreadable":
                raise RuntimeError("the read zone is down")
            return firing

        @activity.defn(name="prepare")
        def prepare(self, alert: Alert) -> EvidencePack:
            seen["prepared"].append(alert.started_at)
            return super().prepare(alert)

    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = _Acts(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="held-test", workflows=[IncidentWorkflow],
                               activities=[acts.after_hold, acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            old = Alert(**DEMO_ALERTS["inc-002"]).model_copy(update={"started_at": "2026-10-09T15:00:00+00:00"})
            handle = await env.client.start_workflow(IncidentWorkflow.run, args=[old, "", "expected down ('nights')"],
                                                     id=f"inc-held-{firing}", task_queue="held-test")
            seen["report"] = await asyncio.wait_for(handle.result(), 120)

    asyncio.run(main())
    return seen


def test_an_alarm_that_cleared_while_held_is_no_incident_and_nothing_is_read_or_asked(tmp_path):
    seen = _run(tmp_path, False)
    assert seen["prepared"] == [] and seen["report"].root_cause is None and seen["report"].verdict is None
    assert seen["report"].halted_reason == ("the alarm had cleared when its hold ended (expected down ('nights')): "
                                           "no incident")


@pytest.mark.parametrize("firing", [True, None, "unreadable"])
def test_an_alarm_still_firing_or_unreadable_when_its_cover_ends_is_an_incident_dated_then(tmp_path, firing):
    seen = _run(tmp_path, firing)
    [started] = seen["prepared"]
    assert started != "2026-10-09T15:00:00+00:00" and datetime.fromisoformat(started).year >= 2026
    assert datetime.fromisoformat(started) > datetime(2026, 10, 10, tzinfo=UTC)  # around now, not the shutdown
    assert seen["report"].verdict is not None
