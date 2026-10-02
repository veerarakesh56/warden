"""Bounds, kill switch and circuit breaker, read from the audit log."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import approvals, bounds
from warden.audit import AuditLog


class Clock:
    def __init__(self):
        self.now = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def log(tmp_path, clock):
    return AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate(), clock=clock)


@pytest.fixture
def owner():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def policy(owner):
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T3"])},
                                    cooling_off_minutes={"T3": 0})


def _apply(log, service="orders-api", action_class="k8s_restart", n=1):
    for _ in range(n):
        bounds.record_applied(log, "inc-1", service=service, action_class=action_class)


def test_nothing_blocks_a_first_change(log, clock):
    assert bounds.blocked(log, service="orders-api", action_class="k8s_restart", now=clock.now) == []


def test_a_service_gets_three_changes_an_hour_then_waits(log, clock):
    _apply(log, n=3)
    assert bounds.blocked(log, service="orders-api", action_class="other", now=clock.now) == [
        "orders-api already had 3 changes in the last hour"]
    assert bounds.blocked(log, service="checkout", action_class="other", now=clock.now) == []
    clock.advance(minutes=61)
    assert bounds.blocked(log, service="orders-api", action_class="other", now=clock.now) == []


def test_an_action_class_gets_ten_runs_a_day(log, clock):
    for i in range(10):
        _apply(log, service=f"svc-{i}")
    assert bounds.blocked(log, service="svc-new", action_class="k8s_restart", now=clock.now) == [
        "k8s_restart already ran 10 times in the last day"]
    clock.advance(hours=25)
    assert bounds.blocked(log, service="svc-new", action_class="k8s_restart", now=clock.now) == []


def test_two_failed_success_checks_in_an_hour_trip_the_kill_switch(log, clock):
    bounds.record_result(log, "inc-1", service="a", ok=False, now=clock.now)
    assert bounds.killswitch(log) is None
    clock.advance(minutes=30)
    bounds.record_result(log, "inc-2", service="b", ok=False, now=clock.now)
    reasons = bounds.blocked(log, service="c", action_class="x", now=clock.now)
    assert reasons and reasons[0].startswith("the kill switch is on: 2 remediations failed")


def test_failures_far_apart_do_not_trip_it(log, clock):
    bounds.record_result(log, "inc-1", service="a", ok=False, now=clock.now)
    clock.advance(hours=2)
    bounds.record_result(log, "inc-2", service="a", ok=False, now=clock.now)
    bounds.record_result(log, "inc-3", service="a", ok=True, now=clock.now)
    assert bounds.killswitch(log) is None


def test_only_a_signed_approval_of_this_trip_resets_it_and_only_once(log, clock, owner, policy):
    bounds.trip(log, "inc-1", "manual stop")
    wrong = approvals.sign(owner, approver="owner", workflow_id="killswitch", plan_hash="killswitch-trip-999",
                           tier="T3", now=clock.now)
    assert "approval is for a different plan (the plan changed after it was approved)" in \
        bounds.reset(log, wrong, policy=policy, now=clock.now)
    right = approvals.sign(owner, approver="owner", workflow_id="killswitch", plan_hash=bounds.trips_hash(log),
                           tier="T3", now=clock.now)
    assert bounds.reset(log, right, policy=policy, now=clock.now) == []
    assert bounds.killswitch(log) is None

    bounds.trip(log, "inc-2", "again")
    assert "approval is for a different plan (the plan changed after it was approved)" in \
        bounds.reset(log, right, policy=policy, now=clock.now)  # the old approval does not clear a new trip


def test_a_forged_reset_is_refused(log, clock, policy):
    bounds.trip(log, "inc-1", "manual stop")
    forged = approvals.sign(Ed25519PrivateKey.generate(), approver="owner", workflow_id="killswitch",
                            plan_hash=bounds.trips_hash(log), tier="T3", now=clock.now)
    assert bounds.reset(log, forged, policy=policy, now=clock.now) == ["the signature is not owner's"]
    assert bounds.killswitch(log) is not None


def test_the_switch_state_is_in_the_signed_audit(log, clock, tmp_path):
    from warden import audit

    bounds.trip(log, "inc-1", "manual stop")
    result = audit.verify(tmp_path / "audit.db", log.key.public_key())
    assert result.ok and result.unsigned_tail == 0


def test_a_reset_signs_every_trip_it_was_shown_and_no_later_one(log, clock, owner, policy):
    """Register R9-O4: a reset signed for the latest trip cleared earlier ones its approver never saw."""
    bounds.trip(log, "inc-1", "first")
    shown = bounds.trips_hash(log)
    signed = approvals.sign(owner, approver="owner", workflow_id="killswitch", plan_hash=shown, tier="T3",
                            now=clock.now)
    bounds.trip(log, "inc-2", "second, after the approval")
    assert bounds.reset(log, signed, policy=policy, now=clock.now) != []
    assert bounds.killswitch(log) is not None
    import hashlib  # an approver shown only the latest trip: that signature clears nothing either
    latest = str(bounds.trips(log)[-1]["seq"])
    only_latest = approvals.sign(owner, approver="owner", workflow_id="killswitch", tier="T3", now=clock.now,
                                 plan_hash="killswitch-trips-" + hashlib.sha256(latest.encode()).hexdigest())
    assert bounds.reset(log, only_latest, policy=policy, now=clock.now) != []
    both = approvals.sign(owner, approver="owner", workflow_id="killswitch", plan_hash=bounds.trips_hash(log),
                          tier="T3", now=clock.now)
    assert bounds.reset(log, both, policy=policy, now=clock.now) == []
    assert log.entries(kinds=(bounds.RESET,))[-1]["body"]["trips"] == [r["seq"] for r in
                                                                        log.entries(kinds=(bounds.TRIPPED,))]
