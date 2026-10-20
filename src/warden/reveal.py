"""The reveal: a person reads the real values behind an incident's placeholders (owner, 2026-10-20).

`/r/<incident>/masked` on the records site (the approval page's Lambda, approval_page._records):

- **Who.** A reader Slack named in this browser who may read the incident's records - an approver, or someone on the
  viewer list (WARDEN_RECORD_VIEWERS), limited to their environments - exactly the records page's own rule. Nobody
  else learns that the incident exists.
- **What they see first.** The incident's masked values as the signed audit holds them: placeholder, kind and the
  stable pseudonym (vault.py) - enough to recognise and correlate, without a reveal.
- **The reveal.** The reader picks the values, gives a reason, and sends the form. The signed audit records it
  FIRST (`incident.reveal`: who, which values, why, the sealed row's hash) - no row, no value. Then the sealed map is
  opened with the vault key, which only this Lambda's role may use (kms:Decrypt, purpose=vault; CloudTrail records
  it too), and only the chosen values are shown, once, never cached (no-store), never in an address, never in Slack.
- **Forgery and abuse.** The form carries a token derived from the reader's own sign-in cookie, which no script and
  no other site can read: a link elsewhere cannot make a reader's browser reveal (and record) anything. At most
  MAX_PER_HOUR reveals per reader. The reason is redacted before it is recorded: a pasted secret is not kept.

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
REFUSED = "incident.reveal_refused"
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
        + f'<form method="get" action="{action}"><input type="hidden" name="reveal" value="1">'
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


def asked(query: str) -> dict[str, Any]:
    q = urllib.parse.parse_qs(query, keep_blank_values=True)
    return {"reveal": q.get("reveal", [""])[0] == "1", "t": q.get("t", [""])[0], "why": q.get("why", [""])[0],
            "p": q.get("p", [])}


def reveal(log: Any, incident: str, *, member: str, cookie: str, query: str, environment: str = "",
           opener: Any = None, now: datetime | None = None) -> tuple[int, str]:
    """The masked-values page for `member`, who may read this incident's records: (status, html). With a reveal
    asked, checked and recorded, the chosen values. `opener`: the vault (vault.Vault.from_environment by default)."""
    from .redaction import redact

    index = latest_index(log, incident)
    if not index or not index.get("entries"):
        return 404, message_page(incident, "WARDEN masked nothing it kept in this incident.")
    a = asked(query)
    if not a["reveal"]:
        return 200, form_page(incident, index, cookie)
    known = {str(e.get("placeholder")) for e in index["entries"]}
    chosen = sorted({p for p in a["p"] if p in known})
    why = " ".join(redact(a["why"][:MAX_REASON]).text.split())
    problem = ("this form was not opened here; open the masked values again" if not hmac.compare_digest(
        a["t"], token(cookie, incident)) else
               "choose at least one value" if not chosen else
               f"say why, in at least {MIN_REASON} characters" if len(why) < MIN_REASON else "")
    if problem:
        return 400, form_page(incident, index, cookie, problem)
    now = (now or datetime.now(UTC)).astimezone(UTC)
    recent = [e for e in log.entries(kinds=(REVEAL,), since=now - timedelta(hours=1))
              if e["body"].get("member") == member]
    if len(recent) >= MAX_PER_HOUR:
        return 429, message_page(incident, f"At most {MAX_PER_HOUR} reveals an hour; try again later.")
    row = vault.sealed_row(log, incident, str(index.get("sha256", "")))
    if row is None:
        return 410, message_page(incident, "These values are no longer kept (their retention ended, or they were "
                                           "erased). Their ids above still identify them.")
    opener = opener or vault.Vault.from_environment()
    if opener is None:
        return 503, message_page(incident, "The vault is not configured here.")
    # On the record FIRST: no row, no value.
    log.append(incident, REVEAL, {"member": member, "placeholders": chosen, "why": why, "sha256": row["sha256"],
                                  "environment": environment, "at": now.isoformat(timespec="seconds")})
    try:
        opened = opener.open(row)
    except vault._SEAL_ERRORS as exc:
        log.append(incident, REFUSED, {"member": member, "error": type(exc).__name__})
        return 503, message_page(incident, "The vault could not be opened; nothing was shown.")
    return 200, revealed_page(incident, index, {p: opened[p] for p in chosen if p in opened})
