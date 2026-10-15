"""Owner, 2026-10-15: "in real time the fixes might break things or cause even bigger other problems". An alarm in
the same environment within the hour after one of WARDEN's own applied fixes gets that fix beside its evidence, as a
change - like a person's deploy - so the diagnosis weighs it: cites it as the cause, or finds another. Nothing is
assumed. Both records keep the link."""

from __future__ import annotations

from datetime import UTC, datetime

from warden import audit, bounds
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import Alert


def _fix(log, incident, env, *, on="warden-dev-order-processor", wid="rem-dev-180000b1cc263177"):
    log.append(incident, "remediation.plan", {"workflow_id": wid, "run_id": "r1", "entry": "lambda_enable_esm",
                                              "service": on, "environment": env, "plan_hash": "h1"})
    bounds.record_applied(log, incident, service=f"{env}/lambda:m-1", action_class="lambda_enable_esm",
                          plan_hash="h1", workflow_id=wid, run_id="r1")


def _alert():
    return Alert(**{**DEMO_ALERTS["inc-002"], "started_at": datetime.now(UTC).isoformat()})


def test_a_recent_warden_fix_in_the_environment_is_a_change_beside_the_new_alarm(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    env = _alert().environment
    _fix(log, "inc-earlier", env)
    _fix(log, "inc-elsewhere", "staging" if env != "staging" else "dev", wid="rem-other-1")
    alert = _alert()  # the alarm starts after the fix was applied
    pack = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True)).prepare(alert)
    lines = [ln for ln in pack.prompt.splitlines() if "by WARDEN (its own fix" in ln]
    assert len(lines) == 1, lines  # its own environment's fix only
    assert "lambda_enable_esm on warden-dev-order-processor" in lines[0]
    assert "applied 0 min before this alarm started, on a different resource from this alarm's" in lines[0]
    assert {s["node"] for s in pack.steps} >= {"own_fixes"}
    # The earlier fix's record names the alarm looked at beside it.
    later = log.entries("inc-earlier", kinds=("incident.later_alarm",))
    assert [e["body"]["incident"] for e in later] == [alert.alert_id]


def test_no_recent_fix_adds_nothing_and_an_incidents_own_fix_is_not_its_own_suspect(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    alert = _alert()
    _fix(log, alert.alert_id, alert.environment)
    alert = alert.model_copy(update={"started_at": datetime.now(UTC).isoformat()})
    pack = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True)).prepare(alert)
    assert "by WARDEN (its own fix" not in pack.prompt
    assert "own_fixes" not in {s["node"] for s in pack.steps}
