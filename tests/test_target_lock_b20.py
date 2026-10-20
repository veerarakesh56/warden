"""B20: one writer per target - a lock in the audit, taken as a fix applies, held until its run ends, the same for every
worker (a check-and-set inside the audit's own write lock), and every take and refusal on the record."""

from __future__ import annotations

import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from temporalio.exceptions import ApplicationError

from test_apply_reverifies import _acts, _approve
from test_remediation_workflow import REQ
from warden import audit, bounds, locks
from warden.activities import FixRequest

KEY = "dev/k8s:shop/orders"
NOW = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)


def _log(path=None, clock=None):
    return audit.AuditLog(path or Path(tempfile.mkdtemp()) / "audit.db", clock=clock)


def _take(log, run, now=NOW, wid=None):
    return locks.take(log, f"inc-{run}", KEY, workflow_id=wid or f"rem-{run}", run_id=run, plan_hash="h", now=now)


def test_the_first_run_holds_the_target_and_the_second_is_refused_on_the_record():
    log = _log(clock=lambda: NOW)
    assert _take(log, "a") == ""
    why = _take(log, "b")
    assert why.startswith("B20 TARGET-LOCKED: dev/k8s:shop/orders is held by fix run rem-a of incident inc-a")
    [taken] = log.entries(kinds=(locks.TAKEN,))
    [refused] = log.entries(kinds=(locks.REFUSED,))
    assert taken["body"]["workflow_id"] == "rem-a"
    assert refused["body"]["why"] == why
    assert _take(log, "a") == ""
    assert len(log.entries(kinds=(locks.TAKEN,))) == 1  # already held: no second row


def test_another_target_is_not_held():
    log = _log(clock=lambda: NOW)
    assert _take(log, "a") == ""
    assert locks.take(log, "inc-b", "dev/k8s:other/orders", workflow_id="rem-b", run_id="b", plan_hash="h",
                      now=NOW) == ""


def test_the_lock_ends_with_its_runs_end_row_or_its_ttl():
    log = _log(clock=lambda: NOW)
    assert _take(log, "a") == ""
    log.append("inc-a", "workflow.end", {"workflow_id": "rem-a", "run_id": "other-run"})  # another run's end
    assert _take(log, "b") != ""
    log.append("inc-a", "workflow.end", {"workflow_id": "rem-a", "run_id": "a"})
    assert _take(log, "b") == ""
    assert _take(log, "c", now=NOW + locks.TTL + timedelta(minutes=1)) == ""  # b's run never ended: its TTL did


def test_two_workers_on_one_audit_never_both_take_the_target():
    """The check and the take are one step under the audit's write lock: while worker A has read "free" and not yet
    written, worker B (its own connection to the same audit) waits, then reads A's take and is refused."""
    path = Path(tempfile.mkdtemp()) / "audit.db"
    a, b = _log(path, clock=lambda: NOW), _log(path, clock=lambda: NOW)
    real, got, first = locks.holder, {}, threading.Event()

    def slow_holder(log, key, now):
        found = real(log, key, now)
        if log is a and not first.is_set():
            first.set()
            other = threading.Thread(target=lambda: got.setdefault("b", _take(b, "b")))
            other.start()
            time.sleep(0.5)  # B runs now, if anything lets it in between A's read and A's write
            got["b_done_while_a_held"] = not other.is_alive()
            got["thread"] = other
        return found

    locks.holder = slow_holder
    try:
        got["a"] = _take(a, "a")
    finally:
        locks.holder = real
    got["thread"].join(10)
    assert got["a"] == ""
    assert got["b"].startswith("B20 TARGET-LOCKED")
    assert got["b_done_while_a_held"] is False
    assert len(a.entries(kinds=(locks.TAKEN,))) == 1


def _approved(acts, owner, wid):
    plan = acts.resolve_plan(FixRequest(**REQ), wid)
    assert _approve(acts, owner, plan, wid).enough
    assert acts.precheck(plan) == []
    return plan


def _no_cooldown(acts):
    acts.limits = bounds.Limits(cooldown=timedelta(0), per_service_per_hour=10)


def test_a_second_fix_of_a_held_target_is_refused_at_apply_and_changes_nothing():
    acts, platform, owner = _acts()
    _no_cooldown(acts)  # the bounds' cool-down would stop it too: the lock is what is tested
    first, second = _approved(acts, owner, "rem-1"), _approved(acts, owner, "rem-2")
    acts.apply(first, REQ["service"])
    with pytest.raises(ApplicationError, match="B20 TARGET-LOCKED") as err:
        acts.apply(second, REQ["service"])
    assert err.value.type == "ApplyRefused"
    assert len(platform.applied) == 1
    [taken] = acts.audit.entries(kinds=(locks.TAKEN,))
    assert taken["body"]["key"] == first.target == "dev/k8s:shop/orders"


def test_a_target_is_free_again_once_the_run_holding_it_ends():
    acts, platform, owner = _acts()
    _no_cooldown(acts)
    first, second = _approved(acts, owner, "rem-1"), _approved(acts, owner, "rem-2")
    acts.apply(first, REQ["service"])
    acts.audit.append(REQ["incident_id"], "workflow.end", {"workflow_id": "rem-1", "run_id": ""})
    acts.apply(second, REQ["service"])
    assert len(platform.applied) == 2


def test_an_undo_while_another_run_holds_the_target_is_not_sent():
    acts, platform, owner = _acts()
    plan = _approved(acts, owner, "rem-1")
    acts.apply(plan, REQ["service"])
    # This run's hold lapsed and another run took the target: undoing now could undo that run's change.
    acts.audit.append("inc-9", locks.TAKEN, {"key": plan.target, "workflow_id": "rem-9", "run_id": "r9"})
    detail = acts.rollback(plan)
    assert detail.startswith("not rolled back: fix run rem-9 holds dev/k8s:shop/orders")
    assert platform.rolled_back == []
    assert bounds.killswitch(acts.audit) is None  # a known state: nothing was half-made


def test_the_run_holding_the_target_undoes_its_own_fix():
    acts, platform, owner = _acts()
    plan = _approved(acts, owner, "rem-1")
    acts.apply(plan, REQ["service"])
    assert not acts.rollback(plan).startswith("not rolled back")
    assert len(platform.rolled_back) == 1
