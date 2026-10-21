"""Owner item U3-4, post-deploy watch: an alarm on a service inside the watch after a deploy of it is reported as any
alarm is, with the deploy named under the title as a suspect - never the cause - and on the incident's record. It
decides nothing: only the message and the record read it."""

from __future__ import annotations

import pathlib
import re
from datetime import UTC, datetime, timedelta

import pytest

from warden import audit, deploy_watch
from warden.models import Alert, ContextBundle, Severity

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIRED = datetime(2026, 10, 21, 10, 0, tzinfo=UTC)
HOUR = timedelta(minutes=60)
ALERT = Alert(alert_id="w-1", name="Errors", severity=Severity.high, service="warden-dev-checkout",
              environment="dev", summary="", started_at=FIRED.isoformat())


def _deploy(minutes_before: float, **extra) -> dict:
    return {"kind": "ecs", "service": "warden-dev-checkout", "version": "checkout:14", "previous": "checkout:13",
            "at": (FIRED - timedelta(minutes=minutes_before)).isoformat().replace("+00:00", "Z"), **extra}


def _ctx(*deploys, logs=()) -> ContextBundle:
    return ContextBundle(logs=list(logs), metrics={}, recent_deploys=list(deploys))


def _appconfig(completed: str) -> str:
    return (f"CONFIG appconfig checkout/dev-flags monitors this alarm: deployment=7 state=COMPLETE version=3 "
            f"completed={completed}")


@pytest.mark.parametrize(("raw", "minutes"), [
    ("", 60), ("90", 90), (" 45 ", 45), ("1", 5), ("-5", 5), ("100000", 360), ("abc", 60), ("1.5", 60)])
def test_the_watch_is_configurable_and_bounded(raw, minutes):
    assert deploy_watch.watch(raw) == timedelta(minutes=minutes)


def test_the_watch_reads_its_setting_from_the_environment(monkeypatch):
    monkeypatch.setenv("WARDEN_DEPLOY_WATCH_MIN", "30")
    assert deploy_watch.watch() == timedelta(minutes=30)
    monkeypatch.delenv("WARDEN_DEPLOY_WATCH_MIN")
    assert deploy_watch.watch() == timedelta(minutes=deploy_watch.DEFAULT_MINUTES)


def test_the_watch_is_never_longer_than_the_deploy_reads_look_back():
    from warden.aws_backend import RECENT_DEPLOY_WINDOW

    assert timedelta(minutes=deploy_watch.MAX_MINUTES) <= RECENT_DEPLOY_WINDOW


def test_an_alarm_inside_the_watch_names_the_deploy_and_how_long_before():
    [got] = deploy_watch.suspects(ALERT, _ctx(_deploy(12)), window=HOUR)
    assert (got["kind"], got["service"], got["version"], got["minutes"]) == ("ecs", "warden-dev-checkout",
                                                                            "checkout:14", 12)
    assert got["at"] == FIRED - timedelta(minutes=12)


@pytest.mark.parametrize(("minutes_before", "inside"), [(0, True), (60, True), (61, False), (-1, False), (300, False)])
def test_the_watch_runs_from_the_deploy_for_its_window_and_never_before_it(minutes_before, inside):
    """A deploy at D watches D..D+WATCH: one after the alarm fired is no suspect of it, one longer ago is past."""
    assert bool(deploy_watch.suspects(ALERT, _ctx(_deploy(minutes_before)), window=HOUR)) is inside


def test_a_secret_rotation_is_not_a_deploy_and_an_unknown_kind_is_named_plainly():
    rotated = _deploy(5, kind="secret")
    odd = _deploy(6, kind="<b>evil</b>")
    assert [d["kind"] for d in deploy_watch.suspects(ALERT, _ctx(rotated, odd), window=HOUR)] == ["deploy"]


def test_each_kind_warden_reads_is_watched():
    deploys = [_deploy(5, kind="lambda", service="warden-dev-fn", version="7"),
               _deploy(10, kind="k8s", service="shop-web", version="", revision="4"),
               _deploy(15, kind="config")]
    got = deploy_watch.suspects(ALERT, _ctx(*deploys, logs=[_appconfig("2026-10-21T09:40:00Z")]), window=HOUR)
    assert [(d["kind"], d["version"]) for d in got] == [("lambda", "7"), ("k8s", "4"), ("config", "checkout:14")]
    # MOST at a time, newest first: the AppConfig one (20 min before) is the fourth.
    assert len(got) == deploy_watch.MOST


def test_an_appconfig_deployment_is_watched_and_one_still_deploying_is_a_suspect_now():
    [done] = deploy_watch.suspects(ALERT, _ctx(logs=[_appconfig("2026-10-21T09:40:00Z")]), window=HOUR)
    assert (done["kind"], done["service"], done["version"], done["minutes"], done["deploying"]) == (
        "appconfig", "checkout/dev-flags", "3", 20, False)
    [going] = deploy_watch.suspects(ALERT, _ctx(logs=[_appconfig("not yet")]), window=HOUR)
    assert going["deploying"] is True and going["minutes"] == 0
    assert deploy_watch.suspects(ALERT, _ctx(logs=[_appconfig("2026-10-21T07:00:00Z")]), window=HOUR) == []
    assert deploy_watch.suspects(ALERT, _ctx(logs=["CONFIG appconfig x monitors this alarm: junk"]), window=HOUR) == []


def test_an_alarm_with_no_start_time_cannot_be_placed():
    """Never measured from now instead: a late or replayed incident would name whatever was deployed lately."""
    just_now = {**_deploy(0), "at": (datetime.now(UTC) - timedelta(minutes=5)).isoformat()}
    for started in ("", "not a time"):
        unplaced = ALERT.model_copy(update={"started_at": started})
        assert deploy_watch.suspects(unplaced, _ctx(just_now), window=HOUR) == []


def test_an_image_address_is_never_named():
    """An image's address names the registry's account: the version is shown, never the image."""
    image = "registry.example/checkout:" + "a1b2c3d"
    found = deploy_watch.suspects(ALERT, _ctx(_deploy(5, version="", image=image)), window=HOUR)
    assert found[0]["version"] == ""
    assert "registry.example" not in deploy_watch.banner(found, HOUR)


def test_the_banner_names_the_deploy_as_a_suspect_never_the_cause():
    found = deploy_watch.suspects(ALERT, _ctx(_deploy(12)), window=HOUR)
    text = deploy_watch.banner(found, HOUR)
    assert text.startswith("**After a deploy:** this alarm fired inside WARDEN's 60-min watch after a deploy: ")
    assert "`warden-dev-checkout` version `checkout:14` (ecs), deployed 2026-10-21 09:48Z" in text
    assert "12 min before it fired" in text
    assert text.endswith("The deploy is a suspect, not the cause: the diagnosis below decides from the evidence, "
                         "and nothing is rolled back for the timing alone.")
    assert not re.search(r"\bcaused\b|\bbecause of\b|root cause", text)
    assert deploy_watch.banner([], HOUR) == ""


def test_a_deploy_still_going_says_so_and_names_no_time():
    found = deploy_watch.suspects(ALERT, _ctx(logs=[_appconfig("not yet")]), window=HOUR)
    assert "`checkout/dev-flags` version `3` (appconfig), still deploying when WARDEN read it" in \
        deploy_watch.banner(found, HOUR)


def test_names_in_the_banner_are_inert_text():
    """A service or version name is text WARDEN did not write: it never becomes markup or a mention."""
    found = deploy_watch.suspects(ALERT, _ctx(_deploy(5, service="x`<!channel>`", version="**1**")), window=HOUR)
    text = deploy_watch.banner(found, HOUR)
    assert "<!channel>" not in text and "xˋ‹!channel›ˋ" in text


def test_the_report_carries_the_banner_under_its_title_and_the_record_its_row(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DEPLOY_WATCH_MIN", "60")
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    report = "# Incident title\n\nbody"
    out = deploy_watch.mark(log, "w-1", ALERT, _ctx(_deploy(12)), report, run_id="r1")
    title, blank, line, rest = out.split("\n", 3)
    assert (title, blank, rest) == ("# Incident title", "", "\nbody") and line.startswith("**After a deploy:**")
    [row] = [e["body"] for e in log.entries("w-1", kinds=(deploy_watch.KIND,))]
    assert row["run_id"] == "r1" and row["role"] == "suspect" and row["watch_minutes"] == 60
    assert [(d["kind"], d["version"], d["minutes"], d["at"]) for d in row["deploys"]] == [
        ("ecs", "checkout:14", 12, "2026-10-21T09:48:00+00:00")]


def test_no_deploy_in_the_watch_leaves_the_report_and_the_record_as_they_were(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    assert deploy_watch.mark(log, "w-1", ALERT, _ctx(_deploy(90)), "# T\n\nbody") == "# T\n\nbody"
    assert log.entries("w-1", kinds=(deploy_watch.KIND,)) == []


def test_the_record_page_names_the_step():
    from warden.records import STEP

    assert "suspect, not the cause" in STEP[deploy_watch.KIND]


def test_only_the_message_reads_the_watch():
    """The watch decides nothing: no prompt, policy, plan, verifier or intake reads it - only the incident's message
    (activities.notify) does."""
    readers = sorted(p.name for p in (ROOT / "src" / "warden").rglob("*.py")
                     if p.name != "deploy_watch.py" and "deploy_watch" in p.read_text(encoding="utf-8"))
    assert readers == ["activities.py"]
    text = (ROOT / "src" / "warden" / "activities.py").read_text(encoding="utf-8")
    notify = text[text.index("    def notify(self"):text.index("    @activity.defn", text.index("    def notify(self"))]
    assert text.count("deploy_watch.mark(") == 1 and "deploy_watch.mark(" in notify


def test_an_incident_after_a_deploy_says_so_in_its_message(tmp_path, monkeypatch):
    """End to end on the bundled incident inc-001: its alarm fired four minutes after a deploy of checkout."""
    from warden import chatops
    from warden.activities import IncidentActivities
    from warden.cli import DEMO_ALERTS
    from warden.llm import LLMClient

    sent = []
    monkeypatch.setattr(chatops, "notify", lambda report, sinks=None, threads=None: sent.append(report.markdown) or [])
    monkeypatch.delenv("WARDEN_DEPLOY_WATCH_MIN", raising=False)
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True))
    pack = acts.prepare(Alert(**DEMO_ALERTS["inc-001"]))
    diagnosed = acts.diagnose(pack)
    acts.notify(pack, diagnosed, acts.verify(pack, diagnosed), mode="none")
    lines = sent[-1].split("\n")
    assert lines[0].startswith("# ") and lines[2].startswith("**After a deploy:** this alarm fired inside WARDEN's "
                                                             "60-min watch after a deploy: ")
    assert "4 min before it fired" in lines[2] and "a suspect, not the cause" in lines[2]
    [row] = [e["body"] for e in log.entries(pack.alert.alert_id, kinds=(deploy_watch.KIND,))]
    assert row["deploys"][0]["minutes"] == 4
    # The recorded report (the record page's) carries it too.
    [report] = [e["body"]["markdown"] for e in log.entries(pack.alert.alert_id, kinds=("incident.report",))]
    assert "**After a deploy:**" in report
