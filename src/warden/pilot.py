"""Pilot metrics (`warden report pilot`, the records page's `/r/pilot`): the numbers a client sees each week, read
ONLY from WARDEN's signed audit.

Every row is checked first, the way `warden audit verify` checks the whole log (audit.verify): its hash must be its
own content's, it must link to the row before it, and a checkpoint whose Ed25519 signature verifies must cover it
through an unbroken chain. A row that fails is not counted and is reported as such; a row after the last checkpoint is
not signed yet, and is not counted either (as `AuditLog.intact` treats it). A checkpoint whose signature does not
verify, or that was signed over a different history, is reported too, as `audit.verify` reports it.

What each number means (docs/OPERATIONS.md, "Pilot metrics", says the same):

- **Incident**: an incident id (not a discussion's `discuss-...`) whose first `incident.ingest` or
  `incident.after_hold` row - the rows the records page lists incidents by - is at or after `since` (UTC).
- **Plan**: one run of a fix plan - a `remediation.plan` row's (`workflow_id`, `run_id`) - of a counted incident. Its
  outcome is read from that run's own `workflow.end` row; a plan with no end row yet is *open*. The four outcomes are
  counted over ENDED plans (a rate's denominator), and one plan can be two of them (approved, then changed under it
  and planned again):
  - *approved*: the end row's `checklist.approved` is true (the tier's quorum, as `finish` records it);
  - *denied*: the end status is `denied`;
  - *re-planned*: the end status is `drifted` or `refused_at_apply` and a later run of the same workflow made a new
    plan, or an approver's "new plan" (`discuss.replan` with `started`) came after it and before the next plan;
  - *escalated*: the end status hands the target to a person (`PERSON_TAKES_OVER`: the undo or the apply failed, or
    the run was cancelled or failed after applying).
- **Escalation rate**: incidents WARDEN declined to decide, over incidents: the last `incident.verify` row says
  `escalated`, or an `incident.second_opinion` row says the two diagnoses disagree.
- **Alarm time**: the `started_at` of the incident's first `incident.alert` row (when the alarm fired, as its source
  said). **Alarm to plan**: to the incident's first `remediation.plan` row. **Alarm to fixed**: to the first
  `remediation.result` row with `ok` true of a plan run that ended `recovered` or `verified` (its end row's time if it
  has no such row). An incident with no such run - open, or ended otherwise - is not in the fixed times. A negative
  time (an alarm source's clock ahead) is left out and counted.
- **Median**: the middle value, the mean of the two middle ones for an even count (statistics.median). **p90**: the
  nearest rank - the smallest value at least 90% of the values are at or below: sorted[ceil(0.9 * n) - 1].
- **Model calls**: the `calls` of every `incident.llm_spend` row of the incident and of its discussion
  (`discuss-<id>`), plus one per `eldane.call` row. **Spend ledger**: the `usd` of the same rows. Eldane's
  calls record tokens, not US dollars: they are not in that ledger.
- **Cost per incident**: the `cost` (US dollars) of the `llm.call` rows of the incident and its discussion, over
  incidents. A call row with no cost is NOT RECORDED for that call (counted and said, never estimated); with no
  `llm.call` or `llm.fallback` row anywhere in the verified audit, cost and fallbacks are NOT RECORDED, never 0.
- **Fallbacks**: `llm.fallback` rows of the incident and its discussion, by `reason` (rules_only, model_refused,
  budget_cap, provider_unavailable; any other reason is counted as "other", its text never printed). Per incident:
  fallbacks / incidents. Per model request: fallbacks / `llm.call` rows.
- **Model requests**: `llm.call` rows, one per request sent - retries, unanswered requests and Eldane's trials
  included. NOT the same count as model calls (the spend ledger's), so the two are named apart and never compared.
- **Undo count**: `remediation.rollback` rows with `undone` true, one per plan run; `remediation.rollback_failed`
  rows are counted beside it.
- A rate with nothing to divide by is "n/a". All times are UTC.
"""

from __future__ import annotations

import json
import math
import pathlib
import sqlite3
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature

from . import audit, records

STARTS = ("incident.ingest", "incident.after_hold")  # records.incident_ids lists incidents by these
FIXED = frozenset({"recovered", "verified"})
REPLANNED_ENDS = frozenset({"drifted", "refused_at_apply"})
# activities.PERSON_TAKES_OVER, kept here so the records page does not import the worker (tests assert they agree).
PERSON_TAKES_OVER = frozenset(
    {"rollback_failed", "apply_failed", "cancelled_after_apply", "failed_after_apply"}
)
DISCUSS = "discuss-"
ALERT, PLAN_ROW, END, SPEND = (
    "incident.alert",
    "remediation.plan",
    "workflow.end",
    "incident.llm_spend",
)
OUTCOMES = (
    "approved",
    "denied",
    "re-planned",
    "escalated",
)  # of a plan, in the order the report says them
NA = "n/a"
NOT_RECORDED = "not recorded"
# One row per model request (retries, unanswered requests and Eldane's trials included), with `cost` (US dollars), `latency_ms`, `prompt_tokens` and `completion_tokens`; one row per
# fall-back from the model, with its `reason` (lane FDE-F, 2026-10-21). An audit with neither row was written before
# they existed: its cost and fallbacks are NOT RECORDED, never 0.
LLM_CALL, FALLBACK = "llm.call", "llm.fallback"
SCOPED = (
    "every row was verified before counting; the whole record's integrity counts are shown only to readers of "
    "every environment"
)
FALLBACK_REASONS = ("rules_only", "model_refused", "budget_cap", "provider_unavailable")
MODEL_REQUESTS = "Model requests (llm.call rows)"
REQUESTS_ARE = "every request sent, retries, unanswered ones and Eldane's trials included"


# ------------------------------------------------------------------ the rows, checked


@dataclass
class Checked:
    """The audit's rows that verified (each: seq, at, correlation_id, kind, body), the ones that did not and why, how
    many are not signed yet, and the checkpoints that did not verify and why (as audit.verify reports them)."""

    rows: list[dict[str, Any]] = field(default_factory=list)
    failed: list[tuple[int, str]] = field(default_factory=list)
    unsigned: int = 0
    total: int = 0
    bad_checkpoints: list[tuple[int, str]] = field(default_factory=list)

    @property
    def intact(self) -> bool:
        """No row and no checkpoint failed verification: what `warden audit verify` would call intact."""
        return not (self.failed or self.bad_checkpoints)


def _valid_heads(
    checkpoints: list[Any], hashes: dict[int, str], public_key: Any, bad: list[tuple[int, str]]
) -> set[int]:
    """The checkpoints whose signature verifies with `public_key` and whose head is the stored row's hash; each other
    one is added to `bad` with audit.verify's reason (`_check_checkpoints`)."""
    good = set()
    for seq, head, signature in checkpoints:
        try:
            public_key.verify(bytes.fromhex(signature), audit._signed_message(seq, head))
        except (InvalidSignature, ValueError, TypeError):
            bad.append((seq, "has an invalid signature"))
            continue
        if hashes.get(seq) != head:
            bad.append((seq, "was signed over a different history"))
            continue
        good.add(seq)
    return good


def _own_problems(rows: list[Any]) -> tuple[dict[int, str], set[int]]:
    """Per row: why its own content does not check out; and the rows that do not link to the row before them (or
    follow a missing one)."""
    changed: dict[int, str] = {}
    unlinked: set[int] = set()
    prev, expected = audit.GENESIS, 1
    for seq, at, cid, kind, body, stored_prev, stored_hash in rows:
        if seq != expected or stored_prev != prev:
            unlinked.add(seq)
        if audit._hash(stored_prev, seq, at, cid, kind, body) != stored_hash:
            changed[seq] = "changed after it was written"
        prev, expected = stored_hash, seq + 1
    return changed, unlinked


def check(rows: list[Any], checkpoints: list[Any], public_key: Any) -> Checked:
    """Each row's verdict. `rows`: (seq, at, correlation_id, kind, body, prev, hash) in seq order; `checkpoints`:
    (seq, hash, signature). A row counts only when its own hash holds, it links to the row before it, and a validly
    signed checkpoint reaches it through rows that all link."""
    out = Checked(total=len(rows))
    valid = _valid_heads(checkpoints, {r[0]: r[6] for r in rows}, public_key, out.bad_checkpoints)
    last_checkpoint = max((c[0] for c in checkpoints), default=0)
    changed, unlinked = _own_problems(rows)
    covered = False
    kept: list[dict[str, Any]] = []
    for seq, at, cid, kind, body, _prev, _hash in reversed(rows):
        covered = covered or seq in valid
        why = changed.get(seq) or ("does not link to the row before it" if seq in unlinked else "")
        if why:
            out.failed.append((seq, why))
        elif covered:
            kept.append(_row(seq, at, cid, kind, body, out))
        elif seq > last_checkpoint:
            out.unsigned += 1  # the tail no checkpoint has reached yet
        else:
            out.failed.append((seq, "no valid signature covers it"))
        if seq in unlinked or seq in changed:
            # A broken link, or a row whose own hash fails (its `prev` is then unproven, CodeRabbit PR 175): no
            # checkpoint above it reaches the rows before it.
            covered = False
    out.rows = [r for r in reversed(kept) if r]
    out.failed.sort()
    return out


def _row(seq: int, at: str, cid: str, kind: str, body: str, out: Checked) -> dict[str, Any]:
    try:
        when, data = datetime.fromisoformat(at), json.loads(body)
    except (ValueError, TypeError):
        when, data = None, None
    if when is None or when.tzinfo is None or not isinstance(data, dict):
        out.failed.append(
            (seq, "cannot be read")
        )  # verified, yet not a row WARDEN writes: said, never counted
        return {}
    return {
        "seq": seq,
        "at": when.astimezone(UTC),
        "correlation_id": cid,
        "kind": kind,
        "body": data,
    }


ROWS_SQL = "SELECT seq, at, correlation_id, kind, body, prev, hash FROM entries ORDER BY seq"
CHECKPOINTS_SQL = "SELECT seq, hash, signature FROM checkpoints ORDER BY seq"


def read(log: Any, public_key: Any) -> Checked:
    """Every row of `log` (an AuditLog already open - the records page's own), checked against `public_key`. SELECT
    only.
    ponytail: reads the whole log on every call - the chain is only checkable from its start; a cached verified
    prefix when the audit holds millions of rows."""
    rows = log.store.run(ROWS_SQL).fetchall()
    checkpoints = log.store.run(CHECKPOINTS_SQL).fetchall()
    return check([tuple(r) for r in rows], [tuple(c) for c in checkpoints], public_key)


class Unreadable(Exception):
    """The audit could not be read (missing, empty, unreachable): said, never a crash and never a verification
    failure."""


def _pg_rows(dsn: str) -> tuple[list[Any], list[Any]]:
    try:
        import psycopg
    except ImportError:
        raise Unreadable("psycopg is not installed here") from None
    try:
        with audit._pg_connect(dsn) as db:
            # Autocommit, so the SET is its own statement and every SELECT after it starts a READ ONLY transaction
            # (CodeRabbit, PR 175) - whatever the connection factory's default.
            db.autocommit = True
            db.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            return db.execute(ROWS_SQL).fetchall(), db.execute(CHECKPOINTS_SQL).fetchall()
    except psycopg.Error as e:
        # A database's error text can name its host or user: the kind of error only.
        raise Unreadable(type(e).__name__) from None


def _sqlite_rows(path: pathlib.Path) -> tuple[list[Any], list[Any]]:
    if not path.is_file():
        raise Unreadable(f"no audit file at {path}")
    try:
        db = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
        try:
            return db.execute(ROWS_SQL).fetchall(), db.execute(CHECKPOINTS_SQL).fetchall()
        finally:
            db.close()
    except sqlite3.Error as e:
        raise Unreadable(f"{type(e).__name__}: {e}") from None


def read_only(target: Any, public_key: Any) -> Checked:
    """Every row of the audit at `target`, opened READ-ONLY, checked against `public_key`: a SQLite file through a
    `mode=ro` URI (missing: Unreadable - never created), or a PostgreSQL DSN whose session is set READ ONLY before the
    first query. SELECT only; nothing is created or written (an AuditLog would create the tables on an empty file).
    Unreadable when the audit cannot be read; a verification problem is never that."""
    if audit._is_postgres(target):
        rows, checkpoints = _pg_rows(str(target))
    else:
        rows, checkpoints = _sqlite_rows(pathlib.Path(target))
    return check([tuple(r) for r in rows], [tuple(c) for c in checkpoints], public_key)


# ------------------------------------------------------------------ since


def parse_since(text: str, now: datetime | None = None) -> datetime:
    """`--since`: a day (YYYY-MM-DD, its start in UTC) or a time with its zone (Z or an offset), as UTC. ValueError for
    anything else, a time with no zone (local or UTC? hours apart), or a time still to come."""
    raw = (text or "").strip()
    now = now or datetime.now(UTC)
    try:
        if len(raw) == 10:
            when = datetime.combine(date.fromisoformat(raw), datetime.min.time(), UTC)
        else:
            when = datetime.fromisoformat(raw)
    except ValueError:
        raise ValueError(
            f"--since must be a day (YYYY-MM-DD) or a time with its zone, got {raw!r}"
        ) from None
    if when.tzinfo is None:
        raise ValueError(
            "--since needs a zone: end it with Z or an offset such as +05:30, or give a day"
        )
    if when > now:
        raise ValueError("--since is in the future: nothing has happened since then")
    return when.astimezone(UTC)


# ------------------------------------------------------------------ the numbers


@dataclass
class Plan:
    workflow_id: str
    run_id: str
    seq: int
    at: datetime
    end: dict[str, Any] | None = None
    ended_at: datetime | None = None
    replanned: bool = False


@dataclass
class Incident:
    id: str
    first: datetime
    environment: str = ""
    alarm: datetime | None = None
    plans: list[Plan] = field(default_factory=list)
    escalated: bool = False
    fixed: datetime | None = None
    calls: int = 0
    usd: float = 0.0
    critic_calls: int = 0
    llm_calls: int = 0
    llm_cost: float = 0.0
    uncosted: int = 0  # llm.call rows with no cost
    fallbacks: Counter = field(default_factory=Counter)
    undone: int = 0
    undo_failed: int = 0


@dataclass
class Report:
    since: datetime
    until: datetime
    checked: Checked
    incidents: list[Incident] = field(default_factory=list)
    negative_times: int = 0
    llm_recorded: bool = False  # any llm.call or llm.fallback row in the verified audit
    scoped: bool = (
        False  # a reader limited to some environments: no audit-wide count is shown to them
    )

    @property
    def plans(self) -> list[Plan]:
        return [p for i in self.incidents for p in i.plans]

    @property
    def ended(self) -> list[Plan]:
        return [p for p in self.plans if p.end is not None]

    def outcome(self, name: str) -> int:
        """How many ended plans had this outcome (one of OUTCOMES)."""
        tests = dict(
            zip(
                OUTCOMES,
                (
                    lambda p: (p.end.get("checklist") or {}).get(OUTCOMES[0]) is True,
                    lambda p: _status(p) == OUTCOMES[1],
                    lambda p: p.replanned,
                    lambda p: _status(p) in PERSON_TAKES_OVER,
                ),
                strict=True,
            )
        )
        return sum(1 for p in self.ended if tests[name](p))

    def times(self, to: str) -> list[float]:
        """Seconds from each incident's alarm to its first plan (`plan`) or its fix (`fixed`); negatives left out."""
        out = []
        for i in self.incidents:
            end = i.fixed
            if to == "plan":
                end = i.plans[0].at if i.plans else None
            if i.alarm is not None and end is not None and end >= i.alarm:
                out.append((end - i.alarm).total_seconds())
        return out


def _status(p: Plan) -> str:
    return str((p.end or {}).get("status") or "")


def _run(e: dict[str, Any]) -> tuple[str, str]:
    """The fix run a row belongs to: (workflow_id, run_id)."""
    return str(e["body"].get("workflow_id") or ""), str(e["body"].get("run_id") or "")


def _alert(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The alarm as the incident's first `incident.alert` row recorded it ({} when none)."""
    for e in rows:
        if e["kind"] == ALERT and isinstance(e["body"].get("alert"), dict):
            return e["body"]["alert"]
    return {}


def _alarm_time(alert: dict[str, Any]) -> datetime | None:
    try:
        when = datetime.fromisoformat(str(alert.get("started_at") or ""))
    except ValueError:
        return None
    return when.astimezone(UTC) if when.tzinfo is not None else None


def _plans(rows: list[dict[str, Any]]) -> list[Plan]:
    plans: dict[tuple[str, str], Plan] = {}
    ends: dict[tuple[str, str], dict[str, Any]] = {}
    for e in rows:
        key = _run(e)
        if e["kind"] == PLAN_ROW and key not in plans:
            plans[key] = Plan(*key, seq=e["seq"], at=e["at"])
        elif e["kind"] == END and key not in ends:
            ends[key] = e
    out = sorted(plans.values(), key=lambda p: p.seq)
    for p in out:
        end = ends.get((p.workflow_id, p.run_id))
        p.end, p.ended_at = (end["body"], end["at"]) if end else (None, None)
        p.replanned = _status(p) in REPLANNED_ENDS and any(
            q.workflow_id == p.workflow_id and q.seq > p.seq for q in out
        )
    return out


def _new_plan_asked(plans: list[Plan], discussed: list[dict[str, Any]]) -> None:
    """An approver's "new plan" re-plans the latest plan made before it."""
    for e in discussed:
        if e["kind"] == "discuss.replan" and e["body"].get("started"):
            before = [p for p in plans if p.seq < e["seq"]]
            if before:
                before[-1].replanned = True


def _fixed_at(rows: list[dict[str, Any]], plans: list[Plan]) -> datetime | None:
    """When the first plan run that ended fixed was first found healthy (its end row's time if never said)."""
    for p in plans:
        if _status(p) in FIXED:
            ok = [
                e["at"]
                for e in rows
                if e["kind"] == "remediation.result"
                and e["body"].get("ok") is True
                and _run(e) == (p.workflow_id, p.run_id)
            ]
            return ok[0] if ok else p.ended_at
    return None


def _escalated(rows: list[dict[str, Any]]) -> bool:
    verdicts = [e["body"].get("status") for e in rows if e["kind"] == "incident.verify"]
    disagreed = any(
        e["body"].get("agree") is False for e in rows if e["kind"] == "incident.second_opinion"
    )
    return bool(verdicts and verdicts[-1] == OUTCOMES[3]) or disagreed


def _spend(i: Incident, rows: list[dict[str, Any]]) -> None:
    for e in rows:
        if e["kind"] == SPEND:
            i.calls += int(e["body"].get("calls") or 0)
            i.usd += float(e["body"].get("usd") or 0.0)
        elif e["kind"] == "eldane.call":
            i.critic_calls += 1
        elif e["kind"] == LLM_CALL:
            _call(i, e["body"])
        elif e["kind"] == FALLBACK:
            i.fallbacks[str(e["body"].get("reason") or "unstated")] += 1


def _call(i: Incident, body: dict[str, Any]) -> None:
    i.llm_calls += 1
    cost = body.get("cost")
    if (
        isinstance(cost, int | float)
        and not isinstance(cost, bool)
        and math.isfinite(cost)
        and cost >= 0
    ):
        i.llm_cost += float(cost)
    else:
        i.uncosted += 1  # never estimated: this row's cost is not recorded


def _undo(i: Incident, rows: list[dict[str, Any]]) -> None:
    i.undone = len(
        {
            _run(e)
            for e in rows
            if e["kind"] == "remediation.rollback" and e["body"].get("undone") is True
        }
    )
    i.undo_failed = len({_run(e) for e in rows if e["kind"] == "remediation.rollback_failed"})


def _incident(cid: str, rows: list[dict[str, Any]], discussed: list[dict[str, Any]]) -> Incident:
    alert = _alert(rows)
    i = Incident(
        id=cid,
        first=min(e["at"] for e in rows if e["kind"] in STARTS),
        # The records' own rule, so a reader is counted the incidents the records show them.
        environment=records.environment_of(rows),
        alarm=_alarm_time(alert),
    )
    i.plans = _plans(rows)
    _new_plan_asked(i.plans, discussed)
    i.fixed, i.escalated = _fixed_at(rows, i.plans), _escalated(rows)
    _spend(i, rows + [e for e in discussed if e["kind"] in (SPEND, LLM_CALL, FALLBACK)])
    _undo(i, rows)
    return i


def report(
    checked: Checked,
    since: datetime,
    *,
    allowed: set[str] | None = None,
    now: datetime | None = None,
) -> Report:
    """The pilot numbers for the incidents first seen at or after `since`, from `checked` rows only. `allowed`: the
    environments the reader may read (None: every one) - the records page's own rule."""
    by: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in checked.rows:
        by[str(e["correlation_id"])].append(e)
    out = Report(
        since=since.astimezone(UTC),
        until=(now or datetime.now(UTC)).astimezone(UTC),
        checked=checked,
    )
    for cid, rows in by.items():
        if cid.startswith(DISCUSS) or not any(e["kind"] in STARTS for e in rows):
            continue
        i = _incident(cid, rows, by.get(DISCUSS + cid, []))
        if i.first >= out.since and (allowed is None or i.environment in allowed):
            out.incidents.append(i)
    out.incidents.sort(key=lambda i: i.first)
    out.llm_recorded = any(e["kind"] in (LLM_CALL, FALLBACK) for e in checked.rows)
    out.scoped = allowed is not None
    plan_times = sum(1 for i in out.incidents if i.alarm and i.plans and i.plans[0].at < i.alarm)
    fixed_times = sum(1 for i in out.incidents if i.alarm and i.fixed and i.fixed < i.alarm)
    out.negative_times = plan_times + fixed_times
    return out


# ------------------------------------------------------------------ in words


def rate(part: int, whole: int) -> str:
    """`part` of `whole` as a percentage to one place; "n/a" when there is nothing to divide by."""
    return f"{100 * part / whole:.1f}%" if whole else NA


def p90(values: list[float]) -> float | None:
    """Nearest rank: the smallest value with at least 90% of the values at or below it."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[math.ceil(0.9 * len(ordered)) - 1]


def median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def minutes(seconds: float | None) -> str:
    return NA if seconds is None else f"{seconds / 60:.1f} min"


def lines(r: Report, *, detail: bool = True) -> list[tuple[str, str]]:
    """The report as (name, value) pairs, the same on the command line and the page. `detail`: name each row that
    failed verification (the command line); the page says how many."""
    c, n, ended = r.checked, len(r.incidents), len(r.ended)
    failed = f"{len(c.failed)} failed verification and are NOT counted"
    if detail and c.failed:
        failed += (
            ": "
            + "; ".join(f"row {s} {why}" for s, why in c.failed[:20])
            + (" ..." if len(c.failed) > 20 else "")
        )
    audit_rows = (
        f"{c.total} read; {len(c.rows)} verified and counted; {failed}; "
        f"{c.unsigned} not signed yet (not counted)"
    )
    if c.bad_checkpoints:
        audit_rows += f"; {len(c.bad_checkpoints)} checkpoint(s) failed verification"
        if detail:
            audit_rows += ": " + "; ".join(
                f"checkpoint {s} {why}" for s, why in c.bad_checkpoints[:20]
            )
    if r.scoped:
        audit_rows = SCOPED
    out = [
        (
            "Window",
            f"incidents first seen from {r.since:%Y-%m-%d %H:%M} UTC to {r.until:%Y-%m-%d %H:%M} UTC",
        ),
        ("Audit rows", audit_rows),
        ("Incidents", str(n)),
        ("Plans", f"{len(r.plans)} ({ended} ended, {len(r.plans) - ended} open)"),
    ]
    for name in OUTCOMES:
        k = r.outcome(name)
        out.append((f"Plans {name}", f"{k} of {ended} ended ({rate(k, ended)})"))
    for name, to in (("Alarm to plan", "plan"), ("Alarm to fixed", "fixed")):
        t = r.times(to)
        out.append(
            (name, f"median {minutes(median(t))}, p90 {minutes(p90(t))} ({len(t)} incident(s))")
        )
    out.append(
        ("Not fixed (open or ended otherwise)", str(sum(1 for i in r.incidents if i.fixed is None)))
    )
    if r.negative_times:
        out.append(
            (
                "Times left out",
                f"{r.negative_times}: the alarm's time was after the plan or the fix",
            )
        )
    esc = sum(1 for i in r.incidents if i.escalated)
    out.append(("Escalation rate", f"{esc} of {n} incidents ({rate(esc, n)})"))
    out += _model_lines(r, n)
    undone, undo_failed = (
        sum(i.undone for i in r.incidents),
        sum(i.undo_failed for i in r.incidents),
    )
    out.append(("Undo count", f"{undone} (undo failed: {undo_failed})"))
    return out


def _model_lines(r: Report, n: int) -> list[tuple[str, str]]:
    """Model calls, cost and fallbacks. Cost and fallbacks come only from llm.call and llm.fallback rows: with none in
    the audit they are "not recorded"; a call row without a cost is not recorded for that call, never estimated."""
    calls = sum(i.calls + i.critic_calls for i in r.incidents)
    critic = sum(i.critic_calls for i in r.incidents)
    ledger = sum(i.usd for i in r.incidents)
    out = [
        (
            "Model calls per incident",
            (f"{calls / n:.2f}" if n else NA)
            + f" ({calls} in all from incident.llm_spend and eldane.call, {critic} of them Eldane's)",
        ),
        (
            "Spend ledger (incident.llm_spend)",
            f"US${ledger:.4f} in all (the budget ledger; Eldane's calls are not in it)",
        ),
    ]
    if not r.llm_recorded:
        why = f"{NOT_RECORDED} (no {LLM_CALL} or {FALLBACK} rows in the audit)"
        return [*out, ("Cost per incident", why), ("Fallbacks", why)]
    rows = sum(i.llm_calls for i in r.incidents)
    uncosted = sum(i.uncosted for i in r.incidents)
    cost = sum(i.llm_cost for i in r.incidents)
    said = f"US${cost / n:.4f}" if n else NA
    said += f" (US${cost:.4f} in all over {rows - uncosted} {LLM_CALL} row(s) with a cost"
    said += f"; {uncosted} row(s) without one: {NOT_RECORDED} for those)" if uncosted else ")"
    out.append(("Cost per incident", said))
    seen: Counter = Counter()
    for i in r.incidents:
        seen.update(i.fallbacks)
    total = sum(seen.values())
    # The closed set by name; any other reason only counted, never printed (its text is the writer's, not ours).
    other = sum(v for k, v in seen.items() if k not in FALLBACK_REASONS)
    per_incident = f"{total / n:.2f} ({total} / {n} incidents)" if n else f"{NA} (0 incidents)"
    # The llm.call rows count every request sent (retries, unanswered requests and Eldane's trials included), so they
    # are not the "Model calls" above (the spend ledger's count): named apart, never put side by side as one count.
    out.extend(
        [
            ("Fallbacks", f"{total}; per incident {per_incident}"),
            (MODEL_REQUESTS, f"{rows} ({LLM_CALL} rows: {REQUESTS_ARE})"),
            (
                "Fallbacks per model request",
                f"{rate(total, rows)} ({total} / {rows} {LLM_CALL} rows: {REQUESTS_ARE})",
            ),
            (
                "Fallbacks by reason",
                ", ".join(f"{k} {seen[k]}" for k in FALLBACK_REASONS) + f", other {other}",
            ),
        ]
    )
    return out


def default_since(now: datetime | None = None, days: int = 7) -> datetime:
    """The page's default: the start (UTC) of the day `days` days ago."""
    day = (now or datetime.now(UTC)).astimezone(UTC).date() - timedelta(days=days)
    return datetime.combine(day, datetime.min.time(), UTC)
