"""Investigation cards and learned notes on an incident's record page (B37).

The INVESTIGATION CARD is the investigation at a glance: what WARDEN read, what it cited, what it asked to read
more of, what it proposed, what the rules decided and how it ended - each line from the incident's own signed rows
(incident.gather, incident.investigate, incident.diagnose, incident.verify, the end), as counts, ids and words from
WARDEN's own tables. A step that is not on the record says so; nothing is inferred.

The LEARNED NOTES are what the record already knows about incidents like this one: for each record it is linked to
(a person's signed link) or that WARDEN found (links.found: the same alarm, the same resource, a fix's aftermath), how
that one ended and with which fix - and one line that adds them up. They are WARDEN's reading of its own record for a
person to weigh, never advice it acts on; the proven fix (links.proven_fix, shown by records.linked) stays the only
fix the record vouches for.

Nothing here reads the vault or any value outside the audit record, and every free text passes the redaction a
model's input does (redaction.redact) before it is escaped onto the page.
"""

from __future__ import annotations

from typing import Any

MOST_NOTES = 6  # related records read for the notes, at most: each is one more read of the record
INERT = {"no_action": "nothing to change", "escalate_to_human": "hand it to a person"}
HELD = {"Fixed and held", "Fixed"}
PLANNED = "Cleared while expected down"


def _scrub(text: Any) -> str:
    from .redaction import redact

    return redact(str(text)).text


def _last(r: Any, kind: str) -> dict[str, Any] | None:
    rows = [e["body"] for e in r.rows if e["kind"] == kind]
    return rows[-1] if rows else None


def _count(n: Any, one: str, many: str) -> str:
    n = int(n) if isinstance(n, int | float) else 0
    return f"{n} {one if n == 1 else many}"


def card_rows(r: Any) -> list[tuple[str, str]]:
    """The card's lines, plain text (the page escapes them): what the incident's own rows say, step by step."""
    from .records import PLAIN

    out: list[tuple[str, str]] = []
    g = _last(r, "incident.gather")
    if g is None:
        out.append(("Read", "No evidence read is on the record"))
    else:
        read = ", ".join((_count(g.get("logs"), "log line", "log lines"), _count(g.get("metrics"), "metric", "metrics"),
                          _count(g.get("deploys"), "recent deploy", "recent deploys")))
        failed = g.get("tool_errors") or 0
        out.append(("Read", read + (f"; {_count(failed, 'read', 'reads')} FAILED - unknown, not healthy" if failed
                                    else "; no read failed")))
    more = sum(1 for e in r.rows if e["kind"] == "incident.investigate")
    if more:
        out.append(("Read more", f"{_count(more, 'more read', 'more reads')} of what the alarm names"))
    d = _last(r, "incident.diagnose")
    if d is None:
        out.append(("Diagnosis", "None on the record"))
    else:
        cited = [str(c) for c in d.get("cited") or []]
        out.append(("Cited", f"{_count(len(cited), 'evidence item', 'evidence items')}"
                    + (f": {', '.join(cited[:12])}" if cited else " - nothing the rules could check")))
        if d.get("need_evidence"):
            out.append(("Asked for", _count(len(d["need_evidence"]), "more resource to read", "more resources to read")))
        action = str(d.get("action") or "")
        target = _scrub(d.get("target") or "")
        out.append(("Proposed", INERT.get(action) or (f"{action.replace('_', ' ')} on {target}" if action
                                                       else "No proposal")))
    v = _last(r, "incident.verify")
    if v is not None:
        status = str(v.get("status") or "")
        policies = [str(p) for p in v.get("policies") or []]
        out.append(("Rules", PLAIN.get(status, status.replace("_", " ")) + (f" ({', '.join(policies)})" if policies
                                                                            else " - no policy fired")))
    out.append(("Ended", r.status))
    return out


def learned(log: Any, r: Any) -> list[dict[str, Any]]:
    """For each related record - a person's signed links first, then the ones WARDEN found - how it ended and with
    which fix. One environment only: links.py holds both kinds of link to it, and a record of another environment is
    left out here too. A record that cannot be read is left out, never guessed at."""
    from .links import WORDS
    from .records import record

    seen: dict[str, str] = {}
    for k in r.links:
        seen.setdefault(str(k["with"]), WORDS.get(k.get("side"), "is linked to"))
    for k in r.found:
        seen.setdefault(str(k["with"]), str(k.get("words") or "is related to"))
    notes = []
    for other, how in [(o, w) for o, w in seen.items() if o != r.id][:MOST_NOTES]:
        try:
            o = record(log, other, light=True)
        except (ValueError, KeyError, TypeError):
            continue
        if o is None or o.environment != r.environment:  # links.py holds both kinds to one; held here again
            continue
        notes.append({"with": other, "how": how, "first": o.first, "status": o.status, "kind": o.kind,
                      "fix": str(o.plan.get("entry") or "") if o.plan else "", "action": o.action})
    return notes


def lesson(notes: list[dict[str, Any]]) -> str:
    """The notes added up in one line: how incidents like this one have ended."""
    if not notes:
        return ""
    held = [n for n in notes if n["status"] in HELD]
    bad = [n for n in notes if n["kind"] == "bad"]
    planned = [n for n in notes if n["status"] == PLANNED]
    handed = [n for n in notes if n["action"] == "escalate_to_human" and n not in held + bad + planned]
    fixes = sorted({n["fix"] for n in held if n["fix"]})
    parts = [f"{len(held)} fixed" + (f" (by {', '.join(fixes)})" if fixes else "") if held else "",
             f"{len(bad)} where the fix did not work" if bad else "",
             f"{len(planned)} cleared during a planned shutdown" if planned else "",
             f"{len(handed)} handed to a person" if handed else ""]
    said = "; ".join(p for p in parts if p)
    return f"Of {_count(len(notes), 'related record', 'related records')}: {said or 'none has ended yet'}."


def section(r: Any) -> str:
    """The card and the notes as the incident page shows them; every text escaped. Nothing breaks the page: a row
    of an unexpected shape leaves the card saying it could not be drawn."""
    from .records import Query, _e, _facts, _when

    try:
        card = _facts([(k, _e(v)) for k, v in card_rows(r)])
    except (ValueError, KeyError, TypeError, AttributeError):
        card = '<p class="quiet">The investigation card could not be drawn from this record; every step is below.</p>'
    out = f'<h2>Investigation card</h2><p class="lede">The investigation at a glance, from its signed rows.</p>{card}'
    notes = getattr(r, "learned", None) or []
    if notes:
        items = "".join(
            f'<li>This incident {_e(n["how"])} <a href="{_e(Query().href(incident=n["with"]))}"><span class="mono">'
            f'{_e(n["with"])}</span></a> (<time>{_e(_when(n["first"]))}</time>): {_e(n["status"])}'
            + (f' - fix <span class="mono">{_e(n["fix"])}</span>' if n["fix"] else "") + "</li>" for n in notes)
        out += ('<h2>Learned from related records</h2><p class="lede">How incidents like this one ended, from WARDEN\'s '
                f'own record - for a person to weigh; WARDEN acts on none of it.</p><p class="pad">{_e(lesson(notes))}'
                f'</p><ul class="flags">{items}</ul>')
    return out
