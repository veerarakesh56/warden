"""Bounds, the kill switch and the circuit breaker - all read from the audit log.

`blocked()` lists every reason an apply must not happen. It runs at the gate, before the approval wait,
AND again inside `apply` itself - a kill switch tripped during the wait used to be missed (third review,
2026-09-30):
- the kill switch is on;
- this service already had `per_service_per_hour` applies in the last hour;
- this action class already had `per_class_per_day` applies in the last day.

After each apply, `record_result()` writes whether the workflow's OWN success check passed. When
`breaker_failures` of them failed within `breaker_window`, it trips the kill switch: something is
going wrong repeatedly, and the right move is to stop and get a person.

The kill switch is turned off only by `reset()` with a valid signed approval whose plan hash is the
hash of the trip row itself - an approval for one trip cannot clear another.

The state lives in the audit log, so it is as tamper-evident as the rest of the record, and there is
no second store to fall out of step with it.

ponytail: counts are read by scanning the audit rows in the window; an index on (kind, at) when the
log gets large.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta

from . import approvals
from .audit import AuditLog

APPLIED, RESULT, TRIPPED, RESET = "remediation.applied", "remediation.result", "killswitch.on", "killswitch.off"


@dataclass(frozen=True)
class Limits:
    per_service_per_hour: int = 3
    per_class_per_day: int = 10
    breaker_failures: int = 2
    breaker_window: timedelta = timedelta(hours=1)


DEFAULT_LIMITS = Limits()


def killswitch(log: AuditLog) -> dict | None:
    """The trip row while the kill switch is on, else None."""
    last = log.entries(kinds=(TRIPPED, RESET))
    return last[-1] if last and last[-1]["kind"] == TRIPPED else None


def trip(log: AuditLog, correlation_id: str, reason: str, **run: str) -> None:
    """Every trip is a row, the switch on or not: a second run ending in an unknown state while it was on left no
    row, and one reset - signed for the first trip, its reason the only one the approver saw - cleared both (eighth
    review, 2026-10-01). A reset names the latest trip."""
    log.append(correlation_id, TRIPPED, {"reason": reason, **run})
    log.checkpoint()


def trips(log: AuditLog) -> list[dict]:
    """Every trip since the last reset, oldest first: what an approver must see before resetting."""
    rows = log.entries(kinds=(TRIPPED, RESET))
    since = max((i for i, r in enumerate(rows) if r["kind"] == RESET), default=-1)
    return [r for r in rows[since + 1:] if r["kind"] == TRIPPED]


def trips_hash(log: AuditLog) -> str:
    """What a reset signs: every trip since the last reset, by sequence number. Signing only the latest let a reset
    clear trips its approver was never shown (register R9-O4); a trip added after the approval changes the hash."""
    seqs = ",".join(str(r["seq"]) for r in trips(log))
    return "killswitch-trips-" + hashlib.sha256(seqs.encode()).hexdigest()


def reset(log: AuditLog, approval: approvals.SignedApproval, *, policy: approvals.ApproverPolicy,
          now: datetime) -> list[str]:
    """Turn the kill switch off. Needs a T3 approval of exactly the trips since the last reset."""
    rows = trips(log)
    if killswitch(log) is None or not rows:
        return ["the kill switch is not on"]
    used = {e["body"]["nonce"] for e in log.entries(kinds=(RESET,))}
    problems = approvals.check(approval, policy=policy, workflow_id="killswitch", plan_hash=trips_hash(log),
                               tier="T3", plan_created_at=rows[-1]["at"], used_nonces=used, now=now)
    if not problems:
        log.append(rows[-1]["correlation_id"], RESET, {"approver": approval.approver, "nonce": approval.nonce,
                                                       "trips": [r["seq"] for r in rows]})
        log.checkpoint()
    return problems


def blocked(log: AuditLog, *, service: str, action_class: str, now: datetime,
            limits: Limits = DEFAULT_LIMITS) -> list[str]:
    reasons = []
    if (row := killswitch(log)) is not None:
        reasons.append(f"the kill switch is on: {row['body']['reason']}")
    hour = [e for e in log.entries(kinds=(APPLIED,), since=now - timedelta(hours=1))
            if e["body"].get("service") == service]
    if len(hour) >= limits.per_service_per_hour:
        reasons.append(f"{service} already had {len(hour)} changes in the last hour")
    day = [e for e in log.entries(kinds=(APPLIED,), since=now - timedelta(days=1))
           if e["body"].get("action_class") == action_class]
    if len(day) >= limits.per_class_per_day:
        reasons.append(f"{action_class} already ran {len(day)} times in the last day")
    return reasons


def record_applied(log: AuditLog, correlation_id: str, *, service: str, action_class: str, **detail) -> None:
    log.append(correlation_id, APPLIED, {"service": service, "action_class": action_class, **detail})


def record_result(log: AuditLog, correlation_id: str, *, service: str, ok: bool, now: datetime,
                  limits: Limits = DEFAULT_LIMITS, **detail) -> None:
    log.append(correlation_id, RESULT, {"service": service, "ok": ok, **detail})
    # Only failures since the last reset (audit A-B-L1): a person who reset the switch has seen those, and one new
    # failure must not re-trip it on the strength of the failures the reset was for.
    resets = log.entries(kinds=(RESET,))
    after = resets[-1]["seq"] if resets else 0
    failures = [e for e in log.entries(kinds=(RESULT,), since=now - limits.breaker_window)
                if not e["body"]["ok"] and e["seq"] > after]
    if len(failures) >= limits.breaker_failures:
        trip(log, correlation_id, f"{len(failures)} remediations failed their success check within "
                                  f"{limits.breaker_window}")
