"""Bounds, the kill switch and the circuit breaker - all read from the audit log.

Before any apply, `blocked()` lists every reason it must not happen:
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


def trip(log: AuditLog, correlation_id: str, reason: str) -> None:
    if killswitch(log) is None:
        log.append(correlation_id, TRIPPED, {"reason": reason})
        log.checkpoint()


def trip_hash(row: dict) -> str:
    return f"killswitch-trip-{row['seq']}"


def reset(log: AuditLog, approval: approvals.SignedApproval, *, policy: approvals.ApproverPolicy,
          now: datetime) -> list[str]:
    """Turn the kill switch off. Needs a T3 approval of exactly the current trip."""
    row = killswitch(log)
    if row is None:
        return ["the kill switch is not on"]
    used = {e["body"]["nonce"] for e in log.entries(kinds=(RESET,))}
    problems = approvals.check(approval, policy=policy, workflow_id="killswitch", plan_hash=trip_hash(row),
                               tier="T3", plan_created_at=row["at"], used_nonces=used, now=now)
    if not problems:
        log.append(row["correlation_id"], RESET, {"approver": approval.approver, "nonce": approval.nonce})
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
                  limits: Limits = DEFAULT_LIMITS) -> None:
    log.append(correlation_id, RESULT, {"service": service, "ok": ok})
    failures = [e for e in log.entries(kinds=(RESULT,), since=now - limits.breaker_window) if not e["body"]["ok"]]
    if len(failures) >= limits.breaker_failures:
        trip(log, correlation_id, f"{len(failures)} remediations failed their success check within "
                                  f"{limits.breaker_window}")
