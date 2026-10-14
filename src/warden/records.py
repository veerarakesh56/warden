"""WARDEN's records, as web pages (owner, 2026-10-14): every incident, its plan, who approved or denied it with their
note, anything that tried to steer WARDEN, and how it ended - stored, kept up to date, and readable at any time,
instead of a stream of Slack messages. The list shows each incident's summary, its details unfold beneath it, and
each incident has a page of its own with the whole report and every step WARDEN recorded, in UTC and local time.

Everything here is read from WARDEN's signed audit record; nothing is written. Every value on a page is escaped: the
alert's text, a person's note and the model's words are data on these pages, never markup. The pages carry no
script but one (a quiet refresh of the list) and no style or image from anywhere else (approval_page._headers).
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

LOOKBACK = timedelta(days=30)
REFRESH_S = 60

# A fix run's end, in words, and how it reads at a glance: the kind is said in words too, never by colour alone.
ENDED = {
    "verified": ("Fixed", "ok"), "recovered": ("Fixed and held", "ok"), "relapsed": ("Fixed, then failed again", "bad"),
    "rolled_back": ("Did not work - undone", "bad"), "not_recovered": ("Did not work", "bad"),
    "rollback_failed": ("Undo failed - state unknown", "bad"), "refused_at_apply": ("Not applied", "warn"),
    "apply_failed": ("Apply failed - state unknown", "bad"), "drifted": ("Target changed - not applied", "warn"),
    "denied": ("Denied", "warn"), "expired": ("Expired - nothing changed", "warn"),
    "cancelled_after_apply": ("Stopped after applying", "bad"), "failed_after_apply": ("Failed after applying", "bad"),
}

# Each step on the record, in plain words, for an incident's page.
STEP = {
    "intake.decision": "The alarm came in", "incident.alert": "The alarm was recorded",
    "incident.ingest": "WARDEN started reading", "incident.gather": "Evidence read",
    "incident.redact": "Secrets removed from the evidence", "incident.tripwire": "Injection check on the evidence",
    "incident.diagnose": "Diagnosis", "incident.investigate": "Read more of what the alarm names",
    "incident.verify": "Safety policies checked", "incident.changes": "Recent changes looked up",
    "incident.report": "Report written", "incident.notify": "Report sent", "incident.plan_fix": "Fix plan looked for",
    "incident.no_plan": "No fix plan", "incident.after_hold": "Looked at again after expected down",
    "incident.evidence": "Evidence kept for questions",
    "remediation.plan": "Fix plan made", "remediation.gate": "Fix plan checked", "remediation.announce": "Asked for approval",
    "approval.link_viewed": "Approval page opened", "approval.slack_verified": "Signed in with Slack",
    "approval.accepted": "Approved", "approval.refused": "An approval was refused",
    "remediation.precheck": "Target checked before applying", "remediation.intent": "About to apply",
    "remediation.check": "Health checked after the fix", "remediation.rollback": "Fix undone",
    "remediation.rollback_failed": "Undoing the fix failed", "remediation.refused": "Apply refused",
    "workflow.end": "Fix run ended", "change.recorded": "Change recorded", "discuss.turn": "Asked about in the discussion",
    "discuss.answer": "WARDEN answered in the discussion", "discuss.reply": "Answer posted",
}
_QUIET = {"incident.llm_spend", "incident.llm_reserve", "approval.challenge", "approval.challenge_taken",
          "approval.link", "approval.link_used", "chatops.thread", "discuss.reply"}


@dataclass
class Record:
    """One incident as its record says it is."""

    id: str
    first: datetime
    last: datetime
    alarm: str = ""
    environment: str = ""
    service: str = ""
    severity: str = ""
    summary: str = ""
    status: str = "In progress"
    kind: str = "info"
    hypothesis: str = ""
    confidence: float | None = None
    action: str = ""
    target: str = ""
    verdict: str = ""
    policies: list[str] = field(default_factory=list)
    plan: dict[str, Any] = field(default_factory=dict)
    no_plan: str = ""
    decisions: list[dict[str, Any]] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    asked: int = 0
    report: str = ""
    evidence: str = ""  # what the model was shown, as kept with the incident (incident.evidence)
    rows: list[dict[str, Any]] = field(default_factory=list)
    shown: Any = None  # approver id -> the name a reader sees; never the list's id


def incident_ids(log: Any, *, now: datetime | None = None) -> list[str]:
    """Every incident on the record in the last LOOKBACK, newest first. A discussion's own reading of an incident
    (`discuss-...`) is part of that incident, not one of its own."""
    since = (now or datetime.now(UTC)) - LOOKBACK
    seen: dict[str, datetime] = {}
    for e in log.entries(kinds=("incident.ingest", "incident.after_hold"), since=since):
        cid = str(e["correlation_id"])
        if not cid.startswith("discuss-"):
            seen[cid] = max(seen.get(cid, e["at"]), e["at"])
    return sorted(seen, key=lambda c: seen[c], reverse=True)


def record(log: Any, incident: str, policy: Any = None) -> Record | None:
    """One incident from its rows; None when the record holds nothing for it."""
    from . import approvals

    rows = log.entries(incident)
    if not rows:
        return None
    r = Record(id=incident, first=rows[0]["at"], last=rows[-1]["at"], rows=rows)

    def shown(approver: str) -> str:
        if policy is not None and approver in getattr(policy, "approvers", {}):
            return policy.shown(approver)
        return "an approver"  # never the list's id

    r.shown = shown

    for e in rows:
        kind, b = e["kind"], e["body"]
        if kind == "incident.alert":
            a = b.get("alert") or {}
            r.alarm = str((a.get("labels") or {}).get("alarm") or a.get("name") or "")
            r.environment, r.service = str(a.get("environment") or ""), str(a.get("service") or "")
            r.severity, r.summary = str(a.get("severity") or ""), str(a.get("summary") or "")
        elif kind == "incident.ingest" and not r.environment:
            r.environment = str(b.get("env") or "")
        elif kind == "incident.diagnose":
            r.hypothesis, r.action, r.target = str(b.get("hypothesis") or ""), str(b.get("action") or ""), str(
                b.get("target") or "")
            r.confidence = b.get("confidence") if isinstance(b.get("confidence"), int | float) else None
            if b.get("degraded"):
                r.hypothesis = r.hypothesis or f"No diagnosis: {b['degraded']}"
        elif kind == "incident.verify":
            r.verdict, r.policies = str(b.get("status") or ""), [str(p) for p in b.get("policies") or []]
        elif kind == "incident.tripwire":
            if b.get("flagged"):
                r.flags.append("The injection check flagged evidence that tried to instruct WARDEN: "
                               + ", ".join(str(f) for f in b["flagged"][:8]) + ". It was held away from any decision.")
            elif str(b.get("status") or "ran") not in ("ran", "off"):
                r.flags.append(f"The injection check did not finish ({b.get('status')}): the incident went to a person.")
        elif kind == "incident.report":
            r.report = str(b.get("markdown") or "")
        elif kind == "incident.evidence":
            r.evidence = str(b.get("prompt") or "")
        elif kind in ("incident.no_plan",) or (kind == "incident.plan_fix" and not b.get("planned") and b.get("why")):
            r.no_plan = str(b.get("why") or r.no_plan)
        elif kind == "remediation.plan":
            r.plan = {"entry": b.get("entry"), "target": b.get("target"), "tier": b.get("tier"),
                      "plan_hash": b.get("plan_hash"), "made": e["at"], "workflow_id": b.get("workflow_id")}
        elif kind == "approval.accepted":
            note = str(b.get("note") or "")
            r.decisions.append({"what": "Approved", "who": shown(str(b.get("approver"))), "at": e["at"],
                                "how": "passkey" if b.get("method") == "passkey" else "signing key", "note": note,
                                "hasty": bool(b.get("hasty")), "latency": b.get("latency_s")})
            r.flags += [f"A note from {shown(str(b.get('approver')))} held {t}." for t in approvals.note_tries(note)]
        elif kind == "approval.refused":
            r.flags.append("An approval was refused: " + "; ".join(str(p) for p in (b.get("problems") or [])[:3]))
        elif kind == "discuss.turn":
            r.asked += 1
        elif kind == "discuss.answer" and b.get("asks_for_change") and not b.get("approver"):
            r.flags.append("Someone who is not an approver asked WARDEN for a change in the discussion; WARDEN changes "
                           "nothing from there.")
        elif kind == "workflow.end":
            status = str(b.get("status") or "")
            for why in b.get("reasons") or []:
                why = str(why)
                if why.startswith("denied by "):
                    who, _, reason = why.removeprefix("denied by ").partition(": ")
                    r.decisions.append({"what": "Denied", "who": shown(who), "at": e["at"], "how": "passkey",
                                        "note": reason, "hasty": False, "latency": None})
                    r.flags += [f"A reason from {shown(who)} held {t}." for t in approvals.note_tries(reason)]
            if status in ENDED:
                r.status, r.kind = ENDED[status]
            elif status:
                r.status, r.kind = status.replace("_", " ").capitalize(), "info"
    if r.status == "In progress":
        if any(d["what"] == "Approved" for d in r.decisions):
            r.status, r.kind = "Approved - being applied", "info"
        elif r.plan:
            r.status, r.kind = "Waiting for approval", "warn"
        elif r.no_plan:
            r.status, r.kind = "No fix plan", "info"
        elif any(e["kind"] == "incident.after_hold" and e["body"].get("firing") is False for e in rows):
            r.status, r.kind = "Cleared while expected down", "ok"
        elif r.verdict:
            r.status, r.kind = "Diagnosed", "info"
    return r


# ------------------------------------------------------------------ pages


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _when(t: datetime | None) -> str:
    from .environments import both_times

    return both_times(t, seconds=False) if t else "-"


def _badge(r: Record) -> str:
    return f'<span class="badge {r.kind}">{_e(r.status)}</span>'


def _facts(pairs: list[tuple[str, str]]) -> str:
    return '<dl class="facts">' + "".join(f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in pairs if v) + "</dl>"


def _decisions(r: Record) -> str:
    if not r.decisions:
        return '<p class="quiet">No decision on the record.</p>'
    out = []
    for d in r.decisions:
        lat = f" after {d['latency']:.0f} s" if isinstance(d.get("latency"), int | float) else ""
        hasty = ' <span class="badge warn">Quick decision</span>' if d.get("hasty") else ""
        note = (f'<blockquote class="note">{_e(d["note"])}</blockquote>' if d.get("note")
                else '<p class="quiet">No note.</p>')
        out.append(f'<li><p><strong>{_e(d["what"])}</strong> by {_e(d["who"])} with their {_e(d["how"])} at '
                   f'<time>{_e(_when(d["at"]))}</time>{_e(lat)}{hasty}</p>{note}</li>')
    return '<ul class="decisions">' + "".join(out) + "</ul>"


def _flags(r: Record) -> str:
    if not r.flags:
        return '<p class="quiet">Nothing on the record tried to steer WARDEN.</p>'
    return '<ul class="flags">' + "".join(f"<li>{_e(f)}</li>" for f in r.flags) + "</ul>"


def _summary_facts(r: Record) -> list[tuple[str, str]]:
    conf = f" (confidence {r.confidence:.2f})" if r.confidence is not None else ""
    plan = (f'<span class="mono">{_e(r.plan.get("entry"))}</span> on <span class="mono">{_e(r.plan.get("target"))}'
            f'</span> - risk {_e(r.plan.get("tier"))}' if r.plan else "")
    return [("Alarm", _e(r.alarm)), ("Where", _e(" / ".join(x for x in (r.environment, r.service) if x))),
            ("Severity", _e(r.severity)), ("Alert says", _e(r.summary)), ("First seen", _e(_when(r.first))),
            ("Last step", _e(_when(r.last))), ("WARDEN thinks", _e(r.hypothesis + conf) if r.hypothesis else ""),
            ("Safety check", _e(r.verdict.replace("_", " ") + (f" ({', '.join(r.policies)})" if r.policies else ""))
             if r.verdict else ""),
            ("Fix plan", plan or (_e("None: " + r.no_plan) if r.no_plan else "")),
            ("Discussion", _e(f"{r.asked} question(s) in the discussion channel") if r.asked else "")]


def list_page(records: list[Record]) -> str:
    """The list: one row per incident, its summary in view, its details folded beneath it."""
    if not records:
        body = '<p class="quiet pad">No incident in the last 30 days.</p>'
    else:
        items = []
        for r in records:
            title = r.alarm or r.id
            items.append(
                f'<details class="row"><summary><span class="when"><time>{_e(_when(r.first))}</time></span>'
                f'<span class="what"><strong>{_e(title)}</strong><span class="sub">{_e(r.environment)}'
                f'{" / " + _e(r.service) if r.service else ""}</span></span>{_badge(r)}'
                f'{"<span class=" + chr(34) + "badge bad" + chr(34) + ">Flagged</span>" if r.flags else ""}</summary>'
                f'<div class="more">{_facts(_summary_facts(r))}'
                f'<h3>Decisions</h3>{_decisions(r)}<h3>Anything that tried to steer WARDEN</h3>{_flags(r)}'
                f'<p><a class="open" href="/r/{_e(r.id)}">Open the full record</a></p></div></details>')
        body = '<div class="rows">' + "".join(items) + "</div>"
    return _shell("WARDEN records", "Records", "<h1>Incidents</h1><p class=\"lede\">The last 30 days, newest first. "
                  "Open a row for its details, or its full record for everything WARDEN read and did.</p>" + body,
                  refresh=True)


def incident_page(r: Record) -> str:
    """One incident: its summary, decisions and flags, the report as WARDEN wrote it, and every step on the record."""
    steps = []
    for e in r.rows:
        if e["kind"] in _QUIET:
            continue
        said = STEP.get(e["kind"], e["kind"])
        steps.append(f'<tr><td><time>{_e(_when(e["at"]))}</time></td><td>{_e(said)}</td>'
                     f'<td class="mono small">{_e(_brief(e, r.shown))}</td></tr>')
    report = ""
    if r.report:
        report = ('<h2>Complete findings</h2><p class="lede">Everything WARDEN found and proposed, as its report says '
                  'it. Open a section, or <button type="button" class="link" id="all">open all</button>.</p>'
                  + findings(r.report))
    if r.evidence:
        report += ('<details class="block"><summary>The evidence WARDEN read, exactly as its model was shown it'
                   f'</summary><pre class="report">{_e(r.evidence)}</pre></details>')
    main = (f'<p class="back"><a href="/r">All incidents</a></p><h1>{_e(r.alarm or r.id)}</h1>'
            f'<p class="lede">{_badge(r)} Incident <span class="mono">{_e(r.id)}</span></p>'
            f'<h2>Summary</h2>{_facts(_summary_facts(r))}'
            f'<h2>Decisions</h2>{_decisions(r)}'
            f'<h2>Anything that tried to steer WARDEN</h2>{_flags(r)}{report}'
            f'<details class="block"><summary>Every step on the record</summary><div class="scroll"><table>'
            f'<thead><tr><th scope="col">When</th><th scope="col">Step</th><th scope="col">Details</th></tr></thead>'
            f'<tbody>{"".join(steps)}</tbody></table></div></details>')
    return _shell(f"WARDEN - {r.alarm or r.id}", "Record", main, script=_OPEN_ALL_JS if r.report else "")


_FENCE = "```"
_INLINE = (
    (re.compile(r"`([^`\n]+)`"), r"<code>\1</code>"),
    (re.compile(r"\*\*([^*\n]+)\*\*"), r"<strong>\1</strong>"),
)


def _inline(text: str) -> str:
    """One line of the report as HTML: escaped first, then only code spans and bold - nothing else becomes markup."""
    out = _e(text)
    for pattern, tag in _INLINE:
        out = pattern.sub(tag, out)
    if len(text) > 2 and text.startswith("_") and text.endswith("_"):
        out = f"<em>{out[1:-1]}</em>"
    return out


def _section(lines: list[str]) -> str:
    """A report section's lines as paragraphs, lists (one level of nesting) and code blocks."""
    html_out, in_code, code, open_list = [], False, [], False
    for line in lines:
        if line.strip().startswith(_FENCE):
            if in_code:
                html_out.append(f'<pre class="code">{_e(chr(10).join(code))}</pre>')
                code, in_code = [], False
            else:
                if open_list:
                    html_out.append("</ul>")
                    open_list = False
                in_code = True
            continue
        if in_code:
            code.append(line)
            continue
        item = line.lstrip()
        if item.startswith("- "):
            if not open_list:
                html_out.append("<ul>")
                open_list = True
            nested = ' class="sub"' if line.startswith("  ") else ""
            html_out.append(f"<li{nested}>{_inline(item[2:])}</li>")
            continue
        if open_list and line.startswith("  ") and item:  # a list item's own second line
            html_out.append(f'<li class="more-line">{_inline(item)}</li>')
            continue
        if open_list:
            html_out.append("</ul>")
            open_list = False
        if item:
            html_out.append(f"<p>{_inline(item)}</p>")
    if in_code and code:
        html_out.append(f'<pre class="code">{_e(chr(10).join(code))}</pre>')
    if open_list:
        html_out.append("</ul>")
    return "".join(html_out)


def findings(markdown: str) -> str:
    """The report WARDEN wrote, section by section, each its own panel that unfolds - the whole of it, in-depth,
    laid out as a page rather than as a message (owner, 2026-10-14: "complete findings on page to refer if needed")."""
    head, *parts = re.split(r"(?m)^## ", markdown)
    intro = [ln for ln in head.splitlines() if ln.strip() and not ln.startswith("# ")]
    out = [f'<div class="intro">{_section(intro)}</div>'] if intro else []
    for part in parts:
        title, _, body = part.partition("\n")
        if title.strip().startswith("Summary"):
            continue  # its facts are at the top of the page
        out.append(f'<details class="block finding"><summary>{_inline(title.strip())}</summary>'
                   f'<div class="body">{_section(body.splitlines())}</div></details>')
    return "".join(out)


# "Open all" for the findings: a reader who wants everything gets it in one press; nothing is hidden from the page.
_OPEN_ALL_JS = """
const all = document.getElementById("all");
if (all) all.addEventListener("click", () => {
  const panels = [...document.querySelectorAll("details.finding")];
  const open = panels.some(d => !d.open);
  panels.forEach(d => { d.open = open; });
  all.textContent = open ? "close all" : "open all";
});
"""


_DENIED = re.compile(r"^denied by ([A-Za-z0-9._-]{1,64})(?:: .*)?$", re.DOTALL)


def _brief(e: dict[str, Any], shown: Any = None) -> str:
    """A step's own facts, short: the fields a reader looks for. A person by their name, never the list's id, and
    never their whole note (that is in Decisions, above)."""
    b = e["body"]
    keep = ("status", "action", "target", "entry", "tier", "planned", "why", "flagged", "delivered", "verdict",
            "policies", "healthy", "found", "firing", "problems", "reasons", "hasty")
    parts = []
    for k in keep:
        if k in b and b[k] not in (None, "", [], {}):
            v = b[k]
            if k == "reasons":
                v = [f"denied by {shown(m.group(1)) if shown else 'an approver'}" if (m := _DENIED.match(str(w)))
                     else str(w) for w in v]
            parts.append(f"{k}: {', '.join(map(str, v)) if isinstance(v, list) else v}")
    return "; ".join(parts)[:400]


def signed_out_page(go: str) -> str:
    return _shell("WARDEN records", "Records", f'<h1>Sign in to read the records</h1><p class="lede">WARDEN\'s '
                  f'records are for the people on its approver and viewer lists.</p><p class="pad"><a class="primary '
                  f'slack" href="{_e(go)}">Sign in with Slack</a></p>')


def missing_page() -> str:
    return _shell("WARDEN records", "Records", "<h1>No such incident</h1><p class=\"lede\">WARDEN's record holds "
                  "nothing under that id. <a href=\"/r\">See every incident</a>.</p>")


def refused_page() -> str:
    return _shell("WARDEN records", "Records", '<h1>Not on the list</h1><p class="lede">This Slack account is not on '
                  "WARDEN's approver or viewer list, so its records are not shown. Ask an approver to add you.</p>")


_RECORDS_STYLE = """
.page.wide{max-width:64rem}
.sheet h1{margin-top:1.375rem}
h2{font-size:1.0625rem;margin:1.75rem 1.25rem .5rem}
h3{font-size:.9375rem;margin:1.25rem 0 .5rem}
.quiet{color:var(--muted)}
.pad{padding:0 1.25rem 1.25rem}
.small{font-size:.8125rem}
.badge{display:inline-block;font-size:.75rem;font-weight:600;padding:.1875rem .5rem;border-radius:999px;
border:1px solid currentColor;white-space:nowrap;margin-left:.375rem}
.badge.ok{color:var(--ok)}.badge.warn{color:var(--warn)}.badge.bad{color:var(--bad)}.badge.info{color:var(--muted)}
.rows{border-top:1px solid var(--line)}
.row{border-bottom:1px solid var(--line)}
.row>summary{display:grid;grid-template-columns:minmax(9rem,13rem) 1fr auto;gap:.5rem 1rem;align-items:center;
padding:.875rem 1.25rem;cursor:pointer;list-style:none}
.row>summary::-webkit-details-marker{display:none}
.row>summary:hover{background:var(--well)}
.row[open]>summary{background:var(--well)}
.when{color:var(--muted);font-size:.8125rem}
.what{display:flex;flex-direction:column;min-width:0;overflow-wrap:anywhere}
.sub{color:var(--muted);font-size:.8125rem}
.more{padding:.25rem 1.25rem 1.25rem;background:var(--well);box-shadow:var(--in)}
.more .facts{margin:0}
.decisions,.flags{margin:0;padding-left:1.125rem}
.decisions li,.flags li{margin:.375rem 0}
.sheet>.decisions,.sheet>.flags,.sheet>.quiet{margin:0 1.25rem}
.note{margin:.375rem 0 .75rem;padding:.625rem .875rem;border-radius:.625rem;background:var(--sheet);
border:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere}
a{color:var(--accent)}
a.open{font-weight:600}
.back{margin:1rem 1.25rem 0;font-size:.875rem}
.block{margin:1.5rem 1.25rem 0;border:1px solid var(--line);border-radius:.75rem;overflow:hidden}
.block>summary{padding:.75rem 1rem;font-weight:600;cursor:pointer;background:var(--well)}
.block:last-child{margin-bottom:1.25rem}
.report{margin:0;padding:1rem;white-space:pre-wrap;overflow-wrap:anywhere;font:.8125rem/1.5 ui-monospace,SFMono-Regular,
Menlo,Consolas,monospace}
.scroll{overflow-x:auto}
.intro{margin:0 1.25rem}
.finding .body{padding:.25rem 1rem 1rem}
.finding .body p{margin:.5rem 0}
.finding .body ul{margin:.375rem 0;padding-left:1.25rem}
.finding .body li{margin:.25rem 0}
.finding .body li.sub{margin-left:1.25rem;list-style:circle}
.finding .body li.more-line{list-style:none;color:var(--muted)}
.finding code,.intro code{font:.8125rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:.0625rem .3125rem;
border-radius:.3125rem;background:var(--well);overflow-wrap:anywhere}
pre.code{margin:.5rem 0;padding:.75rem .875rem;border-radius:.625rem;background:var(--well);box-shadow:var(--in);
overflow-x:auto;font:.8125rem/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
button.link{width:auto;display:inline;padding:0;border:0;background:none;color:var(--accent);font-weight:600;
text-decoration:underline;cursor:pointer}
table{width:100%;border-collapse:collapse;font-size:.875rem}
th,td{text-align:left;vertical-align:top;padding:.5rem .75rem;border-top:1px solid var(--line)}
th{font-size:.75rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);border-top:0}
td:first-child{white-space:nowrap;color:var(--muted)}
@media (max-width:40rem){.row>summary{grid-template-columns:1fr auto}.when{grid-column:1/-1}
td:first-child{white-space:normal}}
"""

# A quiet refresh of the list (owner: "should be updated every time"), never while a row is open or the reader is
# reading below the top - so nothing jumps under them.
_REFRESH_JS = """
setTimeout(function again() {
  if (document.querySelector("details[open]") || window.scrollY > 40 || document.hidden) {
    setTimeout(again, 15000); return; }
  location.reload();
}, REFRESH_MS);
""".replace("REFRESH_MS", str(REFRESH_S * 1000))


def _shell(title: str, where: str, main: str, *, refresh: bool = False, script: str = "") -> str:
    from .approval_page import _SHELL, _STYLE

    return (_SHELL.replace('<div class="page">', '<div class="page wide">').replace("{{TITLE}}", _e(title))
            .replace("{{WHERE}}", _e(where)).replace("{{MAIN}}", main)
            .replace("{{FOOT}}", "Read from WARDEN's signed record. Times in UTC, local time in brackets.")
            .replace("{{STYLE}}", _STYLE + _RECORDS_STYLE).replace("{{JS}}", "")
            .replace("{{SCRIPT}}", (_REFRESH_JS if refresh else "") + script).replace("{{SLACK}}", "0"))
