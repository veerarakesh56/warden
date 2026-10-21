"""Research 2026-10-15, item 12: a fix succeeds when the symptom is gone, not only when the change landed - the
CloudWatch alarm that opened the incident, read live, must not still be in ALARM. Unknown never blocks: a good fix
is not rolled back for want of a reading."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import approvals, audit
from warden.activities import Plan, RemediationActivities


class _Platform:
    def __init__(self, state, healthy=True):
        self.state, self.ok, self.asked = state, healthy, []

    def healthy(self, service):
        return self.ok

    def alarm_state(self, alarm, environment=None):
        self.asked.append((alarm, environment))
        if isinstance(self.state, Exception):
            raise self.state
        return self.state


def _check(tmp_path, state, *, via="cloudwatch", healthy=True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    log = audit.AuditLog(tmp_path / "a.db", key=Ed25519PrivateKey.generate())
    log.append("inc-1", "incident.alert", {"alert": {"name": "warden-dev-orders-errors",
                                                     "labels": {"alarm": "warden-dev-orders-errors", "via": via}}})
    platform = _Platform(state, healthy)
    acts = RemediationActivities(audit=log, policy=approvals.ApproverPolicy(approvers={}), platform=platform)
    plan = Plan(workflow_id="rem-dev-1", incident_id="inc-1", entry="lambda_move_alias", tier="T2", params={},
                plan_hash="h", created_at=datetime.now(UTC), target="lambda/warden-dev-orders", environment="dev")
    ok = acts.check_success(plan, "warden-dev-orders")
    row = log.entries("inc-1", kinds=("remediation.check",))[-1]["body"]
    return ok, row, platform.asked


@pytest.mark.parametrize(("state", "ok"), [("ALARM", False), ("OK", True), ("INSUFFICIENT_DATA", True), (None, True),
                                           (RuntimeError("throttled"), True)])
def test_the_opening_alarm_still_in_alarm_is_not_a_recovery_and_unknown_never_blocks(tmp_path, state, ok):
    got, row, asked = _check(tmp_path, state)
    assert got is ok
    assert row["healthy"] is ok
    assert asked == [("warden-dev-orders-errors", "dev")]
    assert row["alarm"] == "warden-dev-orders-errors"
    assert row["alarm_state"] == (state if isinstance(state, str) else None)


def test_the_alarm_is_read_only_after_the_fixs_own_check_passed_and_only_for_cloudwatch(tmp_path):
    got, row, asked = _check(tmp_path / "a", "OK", healthy=False)
    assert got is False
    assert asked == []
    got, row, asked = _check(tmp_path / "b", "ALARM", via="datadog")
    assert got is True
    assert asked == []
    assert "alarm" not in row
