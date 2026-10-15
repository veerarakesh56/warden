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
        rows.append({"seqs": [e["seq"], *([end["seq"]] if end else [])],
                     "at": (end or e)["at"], "entry": str(b.get("entry", "")), "target": str(b.get("target", "")),
                     "environment": b.get("environment"), "service": b.get("service"),
                     "plan_hash": b.get("plan_hash"), "incident": e["correlation_id"],
                     "status": str(end["body"].get("status")) if end else "open",
                     "approvers": [str(a) for a in (end["body"].get("approvers") or [])] if end else [],
                     "denied_by": _denier(end["body"]) if end else "",
                     "why": str((end["body"].get("reasons") or [""])[0]) if end else ""})
    return sorted(rows, key=lambda r: r["at"], reverse=True)


def _denier(end: dict[str, Any]) -> str:
    """Who denied the plan, from its end row's own reason (`denied by <approver>`, workflows.py) - or ""."""
    first = str((end.get("reasons") or [""])[0])
    name = first.removeprefix("denied by ").split(":")[0].strip()
    ok = end.get("status") == "denied" and first.startswith("denied by ") and name.replace(".", "").replace(
        "_", "").replace("-", "").isalnum()
    return name if ok else ""


def _iso_said(text: str) -> str:
    """Every machine timestamp in WARDEN's own reason, as times are written everywhere else."""
    import re

    def said(m: re.Match[str]) -> str:
        try:
            return both_times(datetime.fromisoformat(m.group(0)), seconds=False)
        except ValueError:
            return m.group(0)
    return re.sub(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+[+][0-9]{2}:[0-9]{2}", said, text)


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
    if row.get("denied_by"):
        who = f" · by @@{row['denied_by']}@@"  # "was denied · by <the person>"
    # Why a fix did not last or was not applied - "worked, then failed again" alone said nothing of what happened
    # (owner, 2026-10-14). WARDEN's own reason, cut short and inert; a denial's is the person's words and is not
    # repeated here.
    why = str(row.get("why") or "")
    if why and row["status"] not in ("denied", "recovered", "open"):
        from .reporting import untrusted_inline

        who += f" · why: {untrusted_inline(_iso_said(why), limit=160)}"
    return f"{both_times(row['at'], seconds=False)} · `{row['entry']}` on `{row['target']}` · {how}{who}"


# The earlier fixes that make this incident a failure AGAIN: one that worked (or worked and failed again) on this
# resource in LOOKBACK. Owner, 2026-10-15: when something breaks again after a fix, Slack must say so, not only the
# record page.
FIXED_BEFORE = frozenset({"recovered", "relapsed", "mitigated"})


def again(rows: list[dict[str, Any]]) -> str:
    """The Slack message's line for an incident on a resource WARDEN fixed before - its newest such fix - or ""."""
    fixed = [r for r in rows if r["status"] in FIXED_BEFORE]
    if not fixed:
        return ""
    more = f" ({len(fixed) - 1} more earlier, on the full record)" if len(fixed) > 1 else ""
    return (f"**Again:** WARDEN fixed this resource before - {_line(fixed[0])}{more}. It is failing again: whether that "
            "fix is related is for the diagnosis and a person to judge.")


# Similar incidents (owner, 2026-10-15): "compare using previous similar or common issues - what was done then, how
# was the result, did it fail or succeed, later double-checked, is it stable, and what should we do now - with
# timestamps and record links ... and troubleshooting if anything is suspicious and repetitive". From WARDEN's own
# signed record only: the incidents, their fix plans and how each run ended - never a past diagnosis's prose.
SIMILAR_SCAN, SIMILAR_MOST, PATTERN_WINDOW = 300, 5, timedelta(days=7)


def similar(log: Any, incident: str, *, now: datetime | None = None, link: Any = None) -> dict[str, Any]:
    """The incidents like `incident` in LOOKBACK - the same alarm, or the same service, in the same environment -
    newest first, each with what was done and how it ended, whether it stayed stable (no like incident after it), and
    the pattern they make. `link(incident)` gives a record's address, when there is one."""
    from . import records

    now = now or datetime.now(UTC)
    here = records.record(log, incident, light=True)
    if here is None:
        return {"current": None, "rows": [], "pattern": []}
    fixes = {}
    for p in plans(log, now=now):  # newest first: each incident's latest plan
        fixes.setdefault(p["incident"], p)
    alike = []
    for other in records.incident_ids(log)[:SIMILAR_SCAN]:
        if other == incident:
            continue
        r = records.record(log, other, light=True)
        if r is None or r.environment != here.environment or now - r.first > LOOKBACK:
            continue
        why = [w for w, same in (("same alarm", bool(here.alarm) and r.alarm == here.alarm),
                                 ("same service", bool(here.service) and r.service == here.service)) if same]
        if why:
            alike.append((r, why))
    alike.sort(key=lambda x: x[0].first, reverse=True)
    rows = []
    for r, why in alike:
        fix = fixes.get(r.id)
        after = [o for o, _ in alike if o.first > r.first] + ([here] if here.first > r.first else [])
        nxt = min(after, key=lambda o: o.first) if after else None
        rows.append({"incident": r.id, "at": r.first, "why": why, "status": r.status, "verdict": r.verdict,
                     "action": r.action, "target": r.target, "fix": fix,
                     "stable": nxt is None, "next": nxt.id if nxt else "", "next_at": nxt.first if nxt else None,
                     "link": link(r.id) if link else ""})
    return {"current": here, "rows": rows, "pattern": _pattern(here, rows, now)}


def _pattern(here: Any, rows: list[dict[str, Any]], now: datetime) -> list[str]:
    """What repeats: the same alarm or service again and again, the same action proposed each time, a fix that did not
    hold. Counts, from the record - a person judges what they mean."""
    out = []
    week = [r for r in rows if now - r["at"] <= PATTERN_WINDOW]
    if len(week) >= 2:
        out.append(f"{len(week) + 1} incidents like this one in the last 7 days (this one included): it keeps "
                   "coming back - look for the cause, not only the symptom")
    actions = [r["action"] for r in rows if r["action"]]
    if here.action and actions.count(here.action) >= 2:
        out.append(f"`{here.action}` was proposed {actions.count(here.action)} times before for incidents like this")
    held = [r for r in rows if r["fix"] and r["fix"]["status"] == "recovered" and not r["stable"]]
    if held:
        out.append(f"{len(held)} earlier fix(es) worked and then an incident like this came back: the fix treated "
                   "the symptom")
    bad = [r for r in rows if r["fix"] and r["fix"]["status"] in WENT_BADLY]
    if bad:
        out.append(f"{len(bad)} earlier fix(es) of incidents like this did not work, or failed again")
    return out


def similar_text(found: dict[str, Any], *, title: str = "Seen before - WARDEN's own record") -> str:
    """The facts as Slack text: this incident at a glance, the similar ones with their record links, the pattern."""
    here, rows = found.get("current"), found.get("rows") or []
    if here is None:
        return ""
    lines = [f"*WARDEN's record of `{here.id}`*: alarm `{here.alarm or '-'}`, opened "
             f"{both_times(here.first, seconds=False)} · {here.status}"
             + (f" · proposed `{here.action}` on `{here.target}`" if here.action else "")
             + (f" · gate: {here.verdict}" if here.verdict else "")]
    if not rows:
        lines.append(f"*{title}*: nothing like it in the last {LOOKBACK.days} days.")
    else:
        lines.append(f"*{title}*: {len(rows)} like it in the last {LOOKBACK.days} days.")
        for r in rows[:SIMILAR_MOST]:
            fix = r["fix"]
            done = (f"`{fix['entry']}` on `{fix['target']}` {ENDED.get(fix['status'], fix['status'])}"
                    + (f" · approved by {', '.join(f'@@{a}@@' for a in fix['approvers'])}" if fix["approvers"] else "")
                    if fix else (f"proposed `{r['action']}`, {r['status'].lower()}" if r["action"] else r["status"]))
            stable = ("no incident like it since" if r["stable"]
                      else f"came back {both_times(r['next_at'], seconds=False)} (`{r['next']}`)")
            ref = f"<{r['link']}|{r['incident']}>" if r["link"] else f"`{r['incident']}`"
            lines.append(f"- {both_times(r['at'], seconds=False)} · {ref} · {' and '.join(r['why'])} · {done} · "
                         f"{stable}")
    for p in found.get("pattern") or []:
        lines.append(f"*Pattern:* {p}.")
    return "\n".join(lines)


def section(rows: list[dict[str, Any]]) -> str:
    """The report's section: WARDEN's record of this resource, as facts."""
    if not rows:
        return ""
    return "\n".join(["", "### This resource before - WARDEN's own record", "", *(f"- {_line(r)}" for r in rows)])


def warning(rows: list[dict[str, Any]], *, entry: str, target: str, plan_hash: str,
            now: datetime | None = None) -> str:
    """One sentence for the approval request when this same fix on this same target ended badly in the last day."""
    now = now or datetime.now(UTC)
    same = [r for r in rows if r["entry"] == entry and r["target"] == target and r["plan_hash"] != plan_hash
            and now - r["at"] <= RECENT]
    again = [r for r in same if r["status"] in WENT_BADLY]
    if not again:
        return ""
    # The latest one's own ending, and how many did not last - not "applied at" its ending's time, nor every one
    # counted as the latest's kind (live, 2026-10-12: "worked, then failed again - 4 times", of which one had).
    latest = f"most recently it {ENDED[again[0]['status']]} ({both_times(again[0]['at'], seconds=False)})"
    times = "once" if len(again) == 1 else f"{len(again)} times"
    # ...and what did hold is said too: "none lasted" stood beside a run of the same fix that had worked an hour
    # before (live, 2026-10-12).
    held = [r for r in same if r["status"] == "recovered"]
    also = (f" It held {'once' if len(held) == 1 else f'{len(held)} times'} in that day, most recently "
            f"{both_times(held[0]['at'], seconds=False)}." if held else "")
    return f" Before you decide: in the last day this same fix did not last {times} - {latest}.{also}"


_TARGET = __import__("re").compile(r"[A-Za-z0-9:/._@+=,-]{1,200}")
# What the model may be shown of a past run: a fix that ran to an end. Not one still open, and not a denial - a
# person's "no" is not a fact about the resource (research 2026-10-15).
_SHOWN = frozenset(ENDED) - {"denied"}


def for_prompt(rows: list[dict[str, Any]], log: Any) -> list[dict[str, Any]]:
    """The past runs a diagnosis may be shown, with the research's safeguards (2026-10-15): only rows the signed
    record vouches for (AuditLog.intact), only today's catalogue entries on a target of a resource's shape, only runs
    that ended - so a forged, altered or half-written row, or a fix since removed, never reaches the model."""
    from .catalog import CATALOG

    seqs = [s for r in rows for s in r.get("seqs", ())]
    good = log.intact(seqs) if seqs else set()
    return [r for r in rows if r.get("seqs") and set(r["seqs"]) <= good and r["entry"] in CATALOG
            and _TARGET.fullmatch(r["target"]) and r["status"] in _SHOWN]


def prompt_facts(rows: list[dict[str, Any]]) -> str:
    """Past fix plans on this resource for the model (owner, 2026-10-14: show past incidents to the model; off unless
    WARDEN_HISTORY_IN_PROMPT=1, measured live first). Facts in a fixed vocabulary from the signed record only: when,
    the catalogue entry, the target, how its run ended - never a reason, a note, a name or a past diagnosis's words
    (registers N9, G10-48), so nothing a person or a model wrote reaches a later diagnosis."""
    if not rows:
        return ""
    lines = [f"- {r['at'].astimezone(UTC).isoformat(timespec='minutes')} `{r['entry']}` on `{r['target']}`: "
             f"{ENDED.get(r['status'], 'still open' if r['status'] == 'open' else 'ended')}" for r in rows]
    return ("PAST FIX PLANS ON THIS RESOURCE (WARDEN's signed record of earlier incidents - not evidence of this one;"
            " cite only this incident's evidence ids, and judge this incident on its own evidence):\n" + "\n".join(lines))
