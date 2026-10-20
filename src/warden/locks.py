"""B20: one writer per target - a lock in the audit, durable across workers, and on the record.

Before this, two fixes of one resource were kept apart by the workflow id (`rem-<env>-<target hash>`: one open run per
id) and by the bounds' cool-down, which reads the applied rows and then writes its own: two workers could both read
"nothing applied" and both apply. Now a run takes the target's lock as it applies (activities.apply), with a
check-and-set inside the audit's own write lock (AuditLog.append_unless), so of two runs only one holds it - whichever
worker, process or starter runs them - and the other is refused before anything is changed.

The key is the plan's target, `<environment>/<platform>:<resource>` (catalog.target_key), the key the bounds use.
A lock is held until its run ends (that run's `workflow.end` row - every end, recovered or not, writes one), or until
TTL passes: a run whose end row was never written does not hold its target for ever. The TTL is
longer than the longest run holding one: the verify window (at most 2 h), its re-checks and a day's soak.
Each take and each refusal is a row: who held the target, from when, and who was turned away.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from .audit import AuditLog

TAKEN, REFUSED = "lock.taken", "lock.refused"
TTL = timedelta(hours=48)


def _ended(log: AuditLog, row: dict[str, Any]) -> bool:
    b = row["body"]
    return any(e["body"].get("workflow_id") == b.get("workflow_id") and e["body"].get("run_id") == b.get("run_id")
               for e in log.entries(row["correlation_id"], kinds=("workflow.end",)) if e["seq"] > row["seq"])


def holder(log: AuditLog, key: str, now: datetime) -> dict[str, Any] | None:
    """The `lock.taken` row of the run holding `key` now, or None."""
    for row in reversed(log.entries(kinds=(TAKEN,), since=now - TTL)):
        if row["body"].get("key") == key and not _ended(log, row):
            return row
    return None


def same_run(row: dict[str, Any], workflow_id: str, run_id: str) -> bool:
    return row["body"].get("workflow_id") == workflow_id and row["body"].get("run_id") == run_id


def take(log: AuditLog, correlation_id: str, key: str, *, workflow_id: str, run_id: str, plan_hash: str,
         now: datetime) -> str:
    """Take `key` for this run: "" when it holds it (taken now, or already), else why not - and the refusal is a row."""
    if not key or not workflow_id:
        return "the target's lock needs a target and a workflow to hold it"

    def held_by_another() -> str:
        row = holder(log, key, now)
        if row is None or same_run(row, workflow_id, run_id):
            return "" if row is None else "held"
        b = row["body"]
        return (f"B20 TARGET-LOCKED: {key} is held by fix run {b.get('workflow_id')} of incident "
                f"{row['correlation_id']} since {row['at']:%Y-%m-%d %H:%M}Z; one writer per target, so this run "
                "changes nothing until that one ends")

    _, why = log.append_unless(correlation_id, TAKEN, {"key": key, "workflow_id": workflow_id, "run_id": run_id,
                                                       "plan_hash": plan_hash, "ttl_hours": TTL.total_seconds() / 3600},
                               held_by_another)
    if why == "held":
        return ""
    if why:
        log.append(correlation_id, REFUSED, {"key": key, "workflow_id": workflow_id, "run_id": run_id,
                                             "plan_hash": plan_hash, "why": why})
    return why
