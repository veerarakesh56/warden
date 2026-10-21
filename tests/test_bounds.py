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
    hourly = bounds.Limits(cooldown=timedelta(0))  # the hourly count alone; the cool-down has its own test
    _apply(log, n=3)
    assert bounds.blocked(log, service="orders-api", action_class="other", now=clock.now, limits=hourly) == [
        "orders-api already had 3 changes in the last hour"]
    assert bounds.blocked(log, service="checkout", action_class="other", now=clock.now, limits=hourly) == []
    clock.advance(minutes=61)
    assert bounds.blocked(log, service="orders-api", action_class="other", now=clock.now, limits=hourly) == []


def test_a_target_wardens_changed_waits_out_the_cool_down(log, clock):
    """Register C8, oscillation: a fix on a fix, or a rollback of a rollback, waits until the first change held."""
    _apply(log, n=1)
    first = bounds.blocked(log, service="orders-api", action_class="other", now=clock.now)
    assert len(first) == 1
    assert first[0].startswith("C8: WARDEN changed orders-api")
    assert "30 min" in first[0]
    assert bounds.blocked(log, service="checkout", action_class="other", now=clock.now) == []
    clock.advance(minutes=29)
    assert bounds.blocked(log, service="orders-api", action_class="other", now=clock.now)
    clock.advance(minutes=2)
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
    assert reasons
    assert reasons[0].startswith("the kill switch is on: 2 remediations failed")


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
    assert result.ok
    assert result.unsigned_tail == 0


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


# Mutation testing (lane U, mutmut 3.8.0 on bounds.py) found rules the tests above never pinned. Each test below
# names one of them.


def _passkey(approver="owner", *, plan_hash, nonce="nonce-1", workflow_id="killswitch", tier="T3"):
    from warden.passkeys import PasskeyApproval

    return PasskeyApproval(approver=approver, workflow_id=workflow_id, plan_hash=plan_hash, tier=tier, nonce=nonce,
                           credential_id="cred-1", new_sign_count=1, approved_at=datetime(2026, 9, 28, tzinfo=UTC))


def _no_wait(policy, minutes=None):
    """The fixture's policy with the T3 cooling-off set to `minutes`, or with no T3 entry at all for None."""
    return policy.model_copy(update={"cooling_off_minutes": {} if minutes is None else {"T3": minutes}})


def test_the_reset_hash_is_sha256_of_the_trip_numbers_joined_by_commas(log):
    """What an approver signs must not drift between releases: an approval signed on one version is checked by the
    next during a rollout, and the audit keeps the hash it was for."""
    bounds.trip(log, "inc-1", "first")
    bounds.trip(log, "inc-2", "second")
    assert bounds.trips_hash(log) == ("killswitch-trips-"
                                      "17f8af97ad4a7f7639a4c9171d5185cbafb85462877a4746c21bdb0a4f940ca0")


def test_a_reset_with_the_switch_off_says_the_switch_is_not_on(log, clock, owner, policy):
    signed = approvals.sign(owner, approver="owner", workflow_id="killswitch", plan_hash=bounds.trips_hash(log),
                            tier="T3", now=clock.now)
    assert bounds.reset(log, signed, policy=policy, now=clock.now) == ["the kill switch is not on"]


def test_a_reset_row_names_its_approver_its_nonce_and_the_trips_it_cleared(log, clock, owner, policy):
    bounds.trip(log, "inc-1", "manual stop")
    signed = approvals.sign(owner, approver="owner", workflow_id="killswitch", plan_hash=bounds.trips_hash(log),
                            tier="T3", now=clock.now)
    bounds.reset(log, signed, policy=policy, now=clock.now)
    assert log.entries(kinds=(bounds.RESET,))[-1]["body"] == {"approver": "owner", "nonce": signed.nonce, "trips": [1]}


def test_a_passkey_reset_with_the_switch_off_says_the_switch_is_not_on(log, clock, policy):
    verified = _passkey(plan_hash=bounds.trips_hash(log))
    assert bounds.reset_by_passkey(log, verified, policy=policy, now=clock.now) == ["the kill switch is not on"]


def test_a_passkey_reset_row_names_the_approver_the_nonce_the_trips_and_the_credential(log, clock, policy):
    bounds.trip(log, "inc-1", "manual stop")
    bounds.reset_by_passkey(log, _passkey(plan_hash=bounds.trips_hash(log)), policy=policy, now=clock.now)
    assert log.entries(kinds=(bounds.RESET,))[-1]["body"] == {
        "approver": "owner", "nonce": "nonce-1", "trips": [1], "method": "passkey", "credential_id": "cred-1"}


def test_a_passkey_approval_of_fewer_trips_than_the_record_says_a_trip_was_added(log, clock, policy):
    bounds.trip(log, "inc-1", "first")
    seen = bounds.trips_hash(log)
    bounds.trip(log, "inc-2", "second, after the approver looked")
    assert bounds.reset_by_passkey(log, _passkey(plan_hash=seen), policy=policy, now=clock.now) == [
        "the approval is not of the trips now on the record (a trip was added since)"]


def test_a_passkey_approval_is_used_once_even_for_a_later_trip(log, clock, policy):
    """The approval page checks the challenge with no used nonces (approval_page.py): this is the replay guard."""
    bounds.trip(log, "inc-1", "first")
    bounds.reset_by_passkey(log, _passkey(plan_hash=bounds.trips_hash(log)), policy=policy, now=clock.now)
    bounds.trip(log, "inc-2", "second")
    replayed = _passkey(plan_hash=bounds.trips_hash(log))
    assert bounds.reset_by_passkey(log, replayed, policy=policy, now=clock.now) == ["the approval was already used"]


def test_a_fresh_passkey_approval_resets_a_switch_that_was_reset_before(log, clock, policy):
    bounds.trip(log, "inc-1", "first")
    bounds.reset_by_passkey(log, _passkey(plan_hash=bounds.trips_hash(log)), policy=policy, now=clock.now)
    bounds.trip(log, "inc-2", "second")
    fresh = _passkey(plan_hash=bounds.trips_hash(log), nonce="nonce-2")
    assert bounds.reset_by_passkey(log, fresh, policy=policy, now=clock.now) == []


def test_a_policy_without_a_t3_wait_lets_a_passkey_reset_at_once(log, clock, policy):
    bounds.trip(log, "inc-1", "manual stop")
    verified = _passkey(plan_hash=bounds.trips_hash(log))
    assert bounds.reset_by_passkey(log, verified, policy=_no_wait(policy), now=clock.now) == []


def test_a_passkey_reset_is_allowed_the_moment_the_t3_wait_ends(log, clock, policy):
    """The same edge as approvals.check: a plan exactly as old as the cooling-off has waited it out."""
    bounds.trip(log, "inc-1", "manual stop")
    verified = _passkey(plan_hash=bounds.trips_hash(log))
    ends = clock.now + timedelta(minutes=10)
    assert bounds.reset_by_passkey(log, verified, policy=_no_wait(policy, 10), now=ends) == []


def test_a_passkey_reset_a_moment_before_the_t3_wait_ends_is_refused(log, clock, policy):
    bounds.trip(log, "inc-1", "manual stop")
    verified = _passkey(plan_hash=bounds.trips_hash(log))
    early = clock.now + timedelta(minutes=10) - timedelta(microseconds=1)
    assert bounds.reset_by_passkey(log, verified, policy=_no_wait(policy, 10), now=early) == [
        "T3 needs the latest trip to be 0:10:00 old before it is reset"]


def test_a_success_check_result_does_not_start_the_cool_down(log, clock):
    bounds.record_result(log, "inc-1", service="orders-api", ok=True, now=clock.now)
    assert bounds.blocked(log, service="orders-api", action_class="k8s_restart", now=clock.now) == []


def test_success_check_results_do_not_count_as_a_services_changes(log, clock):
    hourly = bounds.Limits(cooldown=timedelta(0))
    for i in range(3):
        bounds.record_result(log, f"inc-{i}", service="orders-api", ok=True, now=clock.now)
    assert bounds.blocked(log, service="orders-api", action_class="k8s_restart", now=clock.now, limits=hourly) == []


def test_rows_that_name_an_action_class_but_are_not_changes_do_not_count_toward_its_day(log, clock):
    daily = bounds.Limits(cooldown=timedelta(0))
    for i in range(10):
        bounds.record_result(log, f"inc-{i}", service=f"svc-{i}", ok=True, now=clock.now, action_class="k8s_restart")
    assert bounds.blocked(log, service="svc-new", action_class="k8s_restart", now=clock.now, limits=daily) == []


def test_a_result_row_names_its_service_and_whether_the_check_passed(log, clock):
    bounds.record_result(log, "inc-1", service="orders-api", ok=False, now=clock.now, workflow_id="rem-1")
    assert log.entries(kinds=(bounds.RESULT,))[-1]["body"] == {"service": "orders-api", "ok": False,
                                                               "workflow_id": "rem-1"}
