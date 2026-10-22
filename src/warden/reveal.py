"""The reveal: a person reads the real values behind an incident's placeholders (owner, 2026-10-20).

`/r/<incident>/masked` on the records site (the approval page's Lambda, approval_page._records):

- **Who.** A reader Slack named in this browser who may read the incident's records (the records page's own rule;
  nobody else learns that the incident exists) AND is an approver for its environment. A viewer
  (WARDEN_RECORD_VIEWERS) reads the record but never reveals (owner-safe default, review 2026-10-21); a passkey
  step-up for each reveal is an open owner decision.
- **What they see first.** The incident's masked values as the signed audit holds them: placeholder, kind and the
  stable pseudonym (vault.py) - enough to recognise and correlate, without a reveal.
- **The reveal.** The reader picks the values, gives a reason, and POSTs the form to the same address: the reason
  and the choice travel in the body, never in an address, a history or a proxy's log. The signed audit records it
  FIRST (`incident.reveal`: who, which values, why, the sealed row's hash) - no row, no value. Then the sealed map is
  opened with the vault key, which only this Lambda's role may use (kms:Decrypt, purpose=vault; CloudTrail records
  it too), and only the chosen values are shown, once, never cached (no-store), never in an address, never in Slack.
- **Forgery and abuse.** The form carries a token derived from the reader's own sign-in cookie, which no script and
  no other site can read: a page elsewhere cannot make a reader's browser reveal anything. A refused attempt (a
  forged or stale form, no value chosen, no reason, not an approver) is recorded too (`incident.reveal_attempt_refused`:
  who and why, never the token). At most MAX_PER_HOUR reveals and refused attempts per reader. The reason is redacted
  - whole, before it is cut to MAX_REASON - before it is recorded: a pasted secret is not kept.

No AI zone has a path here: no Temporal activity, MCP tool or command calls it, and no zone but this Lambda's can
open the key (tests/test_reveal.py, tests/test_vault.py).
"""

from __future__ import annotations

import hashlib
import hmac
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import Any

from . import vault

REVEAL = "incident.reveal"
REFUSED = "incident.reveal_refused"  # the vault would not open: nothing was shown
ATTEMPT_REFUSED = "incident.reveal_attempt_refused"  # a reveal asked and refused before anything was opened
MAX_PER_HOUR = 20
MIN_REASON, MAX_REASON = 10, 300


def latest_index(log: Any, incident: str) -> dict[str, Any] | None:
    """The incident's latest sealed index (the evidence its model was last shown), or None."""
    rows = log.entries(incident, kinds=(vault.INDEX,))
    return rows[-1]["body"] if rows else None


def token(cookie: str, incident: str) -> str:
    """The form's anti-forgery token: bound to this reader's own sign-in cookie (HttpOnly, this site only) and the
    incident."""
    return hmac.new(cookie.encode(), f"reveal:{incident}".encode(), hashlib.sha256).hexdigest()[:32]


def _same(sent: str, expected: str) -> bool:
    """The token check, in constant time; bytes, so a token with any character is refused, never an error."""
    return hmac.compare_digest(sent.encode("utf-8", "replace"), expected.encode("utf-8", "replace"))


def link(log: Any, incident: str) -> str:
    """The record page's way to its masked values, when it has any."""
    from .records import _e

    index = latest_index(log, incident)
    if not index or not index.get("entries"):
        return ""
    n = len(index["entries"])
    return (f'<p class="pad"><a class="button" href="/r/{_e(urllib.parse.quote(incident, safe=""))}/masked">'
            f'Masked values ({n})</a><span class="hint">Recognise them by their ids; reveal one with a reason - '
            'every reveal is on the record.</span></p>')


def _table(entries: list[dict[str, str]], values: dict[str, str] | None = None, *, pick: bool = False) -> str:
    from .records import _e

    head = "<th scope=\"col\">Reveal</th>" if pick else ""
    rows = []
    for e in entries:
        p = str(e.get("placeholder", ""))
        box = (f'<td><input type="checkbox" name="p" value="{_e(p)}" aria-label="reveal {_e(p)}"></td>'
               if pick else "")
        shown = f'<td class="mono">{_e(values[p])}</td>' if values is not None and p in values else ""
        rows.append(f'<tr>{box}<td class="mono">{_e(p)}</td><td>{_e(e.get("kind", ""))}</td>'
                    f'<td class="mono">{_e(e.get("pseudonym", "-"))}</td>{shown}</tr>')
    extra = '<th scope="col">Value</th>' if values is not None else ""
    return ('<div class="scroll"><table><thead><tr>' + head + '<th scope="col">Placeholder</th><th scope="col">Kind'
            f'</th><th scope="col">Id</th>{extra}</tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")


def _page(incident: str, main: str) -> str:
    from .records import _e, _shell

    back = f'<p class="pad"><a href="/r/{_e(urllib.parse.quote(incident, safe=""))}">Back to the record</a></p>'
    return _shell(f"WARDEN - masked values of {incident}", "Masked values", back + main)


def form_page(incident: str, index: dict[str, Any], cookie: str, note: str = "") -> str:
    from .records import _e

    action = f'/r/{_e(urllib.parse.quote(incident, safe=""))}/masked'
    said = f'<p class="note" role="alert">{_e(note)}</p>' if note else ""
    return _page(incident, (
        f'<h1>Masked values</h1><p class="lede">What WARDEN masked in incident <span class="mono">{_e(incident)}'
        "</span> before any model saw it. The id is the same for the same value in every incident, so you can "
        "recognise it without revealing it. No AI can read these values.</p>" + said
        + f'<form method="post" action="{action}"><input type="hidden" name="reveal" value="1">'
        f'<input type="hidden" name="t" value="{_e(token(cookie, incident))}">'
        + _table(index["entries"], pick=True)
        + f'<p><label for="why">Why you need to see them (on the record, {MIN_REASON}+ characters)</label>'
        f'<input id="why" name="why" required minlength="{MIN_REASON}" maxlength="{MAX_REASON}" autocomplete="off">'
        '</p><p><button class="primary" type="submit">Reveal the chosen values</button></p></form>'))


def revealed_page(incident: str, index: dict[str, Any], values: dict[str, str]) -> str:
    chosen = [e for e in index["entries"] if e.get("placeholder") in values]
    return _page(incident, (
        "<h1>Masked values - revealed</h1><p class=\"lede\">Shown to you once; this reveal is on the incident's "
        "record. Do not paste these values into Slack or a ticket.</p>" + _table(chosen, values)))


def message_page(incident: str, text: str) -> str:
    from .records import _e

    return _page(incident, f'<h1>Masked values</h1><p class="note" role="alert">{_e(text)}</p>')


# The form's fixed fields (reveal, t, why); each value it offers adds one `p`.
FIXED_FIELDS = 3


def asked(form: str, offered: int) -> dict[str, Any]:
    """The reveal's form, as POSTed (application/x-www-form-urlencoded). `offered`: how many values the page offers
    to pick - a body with more fields than the page's own form can send raises ValueError."""
    q = urllib.parse.parse_qs(form, keep_blank_values=True, max_num_fields=offered + FIXED_FIELDS)
    return {"reveal": q.get("reveal", [""])[0] == "1", "t": q.get("t", [""])[0], "why": q.get("why", [""])[0],
            "p": q.get("p", [])}


def _problem(sent: str, expected: str, chosen: list[str], why: str) -> str:
    """What is wrong with a reveal asked: the form not opened here, no value chosen, or no reason given. "" for
    nothing."""
    if not _same(sent, expected):
        return "this form was not opened here; open the masked values again"
    if not chosen:
        return "choose at least one value"
    if len(why) < MIN_REASON:
        return f"say why, in at least {MIN_REASON} characters"
    return ""


def _recent(log: Any, member: str, now: datetime) -> int:
    """This reader's reveals and refused attempts in the hour before `now`."""
    rows = log.entries(kinds=(REVEAL, ATTEMPT_REFUSED), since=now - timedelta(hours=1))
    return sum(1 for e in rows if e["body"].get("member") == member)


def _refuse(log: Any, incident: str, member: str, problem: str, chosen: list[str]) -> None:
    """A refused attempt on the record: who, which values, why refused - never the token, never the reason."""
    log.append(incident, ATTEMPT_REFUSED, {"member": member, "problem": problem, "placeholders": chosen})


_TOO_MANY = f"At most {MAX_PER_HOUR} reveals an hour; try again later."


def _limited(log: Any, member: str, now: datetime) -> bool:
    """This reader has reached MAX_PER_HOUR reveals and refused attempts in the hour before `now`."""
    return _recent(log, member, now) >= MAX_PER_HOUR


def _not_an_approver(log: Any, incident: str, member: str, form: str | None, now: datetime) -> tuple[int, str]:
    """A reader who may not reveal: a POST is recorded as a refused attempt - until the hourly limit, after which
    nothing more is written (review, PR 119)."""
    if form is not None:
        if _limited(log, member, now):
            return 429, message_page(incident, _TOO_MANY)
        _refuse(log, incident, member, "not an approver", [])
    return 403, message_page(incident, "Only an approver for this environment may see or reveal masked values.")


def _oversize(log: Any, incident: str, index: dict[str, Any], cookie: str, member: str,
              now: datetime) -> tuple[int, str]:
    """A POST with more fields than the page's form can send: refused and recorded, counted against the hourly limit
    as every refused attempt is; nothing is opened."""
    if _limited(log, member, now):
        return 429, message_page(incident, _TOO_MANY)
    problem = "this form holds more fields than the page offers; open the masked values again"
    _refuse(log, incident, member, problem, [])
    return 400, form_page(incident, index, cookie, problem)


def _open_for(log: Any, incident: str, index: dict[str, Any], opener: Any, now: datetime,
              asked_for: dict[str, Any]) -> tuple[int, str]:
    """A checked reveal: the sealed row, still within its retention by `now`; its `incident.reveal` row on the record
    FIRST (no row, no value); then the vault opened and only the chosen values shown. `asked_for`: member, chosen,
    why, environment."""
    member, chosen = asked_for["member"], asked_for["chosen"]
    row = vault.sealed_row(log, incident, str(index.get("sha256", "")), now=now)  # expiry judged at the same now
    if row is None:
        return 410, message_page(incident, "These values are no longer kept (their retention ended, or they were "
                                           "erased). Their ids above still identify them.")
    opener = opener or vault.Vault.from_environment()
    if opener is None:
        return 503, message_page(incident, "The vault is not configured here.")
    log.append(incident, REVEAL, {"member": member, "placeholders": chosen, "why": asked_for["why"],
                                  "sha256": row["sha256"], "environment": asked_for["environment"],
                                  "at": now.isoformat(timespec="seconds")})
    try:
        opened = opener.open(row)
    except vault._SEAL_ERRORS as exc:  # KMS refusing, the database, a tag that does not verify (InvalidTag)
        log.append(incident, REFUSED, {"member": member, "error": type(exc).__name__})
        return 503, message_page(incident, "The vault could not be opened; nothing was shown.")
    return 200, revealed_page(incident, index, {p: opened[p] for p in chosen if p in opened})


def reveal(log: Any, incident: str, *, member: str, cookie: str, form: str | None, environment: str = "",
           approver: bool = False, opener: Any = None, now: datetime | None = None) -> tuple[int, str]:
    """The masked-values page for `member`, who may read this incident's records: (status, html). `form`: the
    reveal's POSTed body (None for a GET, which only shows the form). `approver`: whether this reader may reveal.
    `opener`: the vault (vault.Vault.from_environment by default)."""
    from .redaction import redact

    now = (now or datetime.now(UTC)).astimezone(UTC)
    if not approver:
        return _not_an_approver(log, incident, member, form, now)
    index = latest_index(log, incident)
    if not index or not index.get("entries"):
        return 404, message_page(incident, "WARDEN masked nothing it kept in this incident.")
    if form is None:
        return 200, form_page(incident, index, cookie)
    try:
        a = asked(form, len(index["entries"]))
    except ValueError:  # more fields than this page's form holds: a refusal on the record, never an error (review)
        return _oversize(log, incident, index, cookie, member, now)
    if not a["reveal"]:
        return 200, form_page(incident, index, cookie)
    if _limited(log, member, now):
        return 429, message_page(incident, _TOO_MANY)
    known = {str(e.get("placeholder")) for e in index["entries"]}
    chosen = sorted({p for p in a["p"] if p in known})
    why = " ".join(redact(a["why"]).text.split())[:MAX_REASON]  # redacted whole, then cut: no secret's tail is kept
    problem = _problem(a["t"], token(cookie, incident), chosen, why)
    if problem:
        _refuse(log, incident, member, problem, chosen)
        return 400, form_page(incident, index, cookie, problem)
    return _open_for(log, incident, index, opener, now,
                     {"member": member, "chosen": chosen, "why": why, "environment": environment})
