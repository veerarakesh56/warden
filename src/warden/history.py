"""What WARDEN's own record says was done to this resource before (owner, 2026-10-12: "is there memory - what was
done, what went wrong, what worked - so it helps to make right decisions later?").

Facts from the signed audit and nothing else: which fix, on what, how it ended, who approved. Never a past
diagnosis's prose - a model that is shown its own old opinions repeats them with growing confidence (register N9).

For the people: a section of the incident's report, and one sentence in the approval request when the same fix on
the same target ended badly in the last day. The model does not read it: its prompt is pinned to the run that
qualified it, and history joins it only after a measured run says it helps.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .environments import both_times

LOOKBACK = timedelta(days=30)
MOST = 5
RECENT = timedelta(hours=24)
# How a run ended, in the words a person reads; an end not listed is shown as recorded.
ENDED = {"recovered": "worked", "relapsed": "worked, then failed again", "rolled_back": "did not work and was undone",
         "not_recovered": "did not work", "rollback_failed": "did not work, and its undo failed",
         "apply_failed": "failed part-way", "refused_at_apply": "was not applied", "drifted": "was not applied",
         "expired": "was not approved in time", "denied": "was denied", "mitigated": "held the harm, not fixed"}
WENT_BADLY = frozenset({"relapsed", "rolled_back", "not_recovered", "rollback_failed", "apply_failed"})


def plans(log: Any, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Every fix plan on the record in LOOKBACK, with how its run ended (`open` while it runs), newest first."""
    since = (now or datetime.now(UTC)) - LOOKBACK
    ends = {(e["body"].get("workflow_id"), e["body"].get("run_id")): e
            for e in log.entries(kinds=("workflow.end",), since=since)}
    rows = []
    for e in log.entries(kinds=("remediation.plan",), since=since):
        b = e["body"]
        end = ends.get((b.get("workflow_id"), b.get("run_id")))
        rows.append({"at": (end or e)["at"], "entry": str(b.get("entry", "")), "target": str(b.get("target", "")),
                     "environment": b.get("environment"), "service": b.get("service"),
                     "plan_hash": b.get("plan_hash"), "incident": e["correlation_id"],
                     "status": str(end["body"].get("status")) if end else "open",
                     "approvers": [str(a) for a in (end["body"].get("approvers") or [])] if end else []})
    return sorted(rows, key=lambda r: r["at"], reverse=True)


def past(alert: Any, log: Any, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """The earlier fix plans for a resource this alert names, at most MOST. This incident's own plan is not history."""
    from .resolver import named_resources

    names = named_resources(alert)
    return [r for r in plans(log, now=now) if r["incident"] != alert.alert_id
            and r["environment"] == alert.environment and r["service"] in names][:MOST]


def _line(row: dict[str, Any]) -> str:
    how = "is still open" if row["status"] == "open" else ENDED.get(row["status"], f"ended {row['status']}")
    # Each approver as their mark: a reader gets the person (chatops.name_people), never the list's id for them.
    who = f" · approved by {', '.join(f'@@{a}@@' for a in row['approvers'])}" if row["approvers"] else ""
    return f"{both_times(row['at'], seconds=False)} · `{row['entry']}` on `{row['target']}` · {how}{who}"


def section(rows: list[dict[str, Any]]) -> str:
    """The report's section: WARDEN's record of this resource, as facts."""
    if not rows:
        return ""
    return "\n".join(["", "### This resource before - WARDEN's own record", "", *(f"- {_line(r)}" for r in rows)])


def warning(rows: list[dict[str, Any]], *, entry: str, target: str, plan_hash: str,
            now: datetime | None = None) -> str:
    """One sentence for the approval request when this same fix on this same target ended badly in the last day."""
    now = now or datetime.now(UTC)
    again = [r for r in rows if r["entry"] == entry and r["target"] == target and r["plan_hash"] != plan_hash
             and r["status"] in WENT_BADLY and now - r["at"] <= RECENT]
    if not again:
        return ""
    # The latest one's own ending, and how many did not last - not "applied at" its ending's time, nor every one
    # counted as the latest's kind (live, 2026-10-12: "worked, then failed again - 4 times", of which one had).
    latest = f"most recently it {ENDED[again[0]['status']]} ({both_times(again[0]['at'], seconds=False)})"
    if len(again) == 1:
        return f" Before you decide: this same fix was tried in the last day and did not last - {latest}."
    return f" Before you decide: this same fix was tried {len(again)} times in the last day and none lasted - {latest}."
