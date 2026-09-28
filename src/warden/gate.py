"""The outbound gate: the last check on what WARDEN says before it leaves the process.

v0 (Phase 0 of the v2 re-architecture, 2026-09-27). Two of the planned rules:

- **G3, untrusted text.** Outside code blocks, markdown images, raw HTML, markdown links and bare
  URLs are removed. The model's hypothesis and reasoning are rendered as markdown, and they can
  repeat text an attacker planted in a log line - an image or a link whose URL carries data out.
  The report's own templates contain no URLs, so nothing legitimate is lost. Inside code blocks the
  text is shown verbatim and nothing is followed. Since G1 (audit A-C-9), G3 also:
  - removes protocol-relative `//host` links and link reference definitions;
  - catches `<img/src=...>`;
  - defangs bare domains (`evil[.]com`);
  - strips terminal and text-direction control characters;
  - tracks fences the CommonMark way, so an indented or `~~~` line cannot switch sanitising off;
  - sanitises what follows a fence that is never closed.
- **G5, leaks.** If the final text still contains anything the redactor classes as secret (every
  kind except the identifiers an operator may choose to show), the message is BLOCKED and a stub
  goes out instead: a person reads the full report locally.

- **G2, unverifiable claims** (`hedge`, Phase 1). The model may write "no customer impact", "no data
  was lost" or "the issue is resolved". WARDEN verifies none of these: it reads no impact data, and
  it checks no outcome (that is Phase 2's success check). Each such claim in model-written text is
  marked `[unverified: ...]` where it stands. "The root cause is" is not marked: the report already
  heads the model's text as its hypothesis, with its confidence.

Every way out uses this module (audit A-C-8):
- chat sinks: `enforce`, with G5 also over the text as built, before notify re-redacts it;
- stdout: `for_terminal`;
- MCP results and generic webhooks: `outbound_data`.

Verdicts: PASS (unchanged), REWRITE (G3 removed something), BLOCK (G5). G1 (every claim grounded) is
P13 in the verifier; the report says when it fired. G4 (commands only from an approved plan) is Phase 2.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .redaction import redact

# Identifier kinds an operator may choose to show (reporting.REVEALABLE). Anything else found in an
# outgoing message is a leak.
_SHOWABLE = frozenset({"EMAIL", "TENANT", "IPV4", "IPV6"})

_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
# Any inline link, whatever its target: `//host/...` (protocol-relative) carries data out as well as
# `https://` does (audit A-C-9). A reference definition `[x]: target` likewise.
_MDLINK = re.compile(r"\[([^\]]*)\]\(\s*[^)\s]+[^)]*\)")
_REFDEF = re.compile(r"^ {0,3}\[[^\]]+\]:\s*\S+.*$")
_URL = re.compile(r"(?:\b(?:https?|ftp|file|data|javascript):|(?<![\w:/])//[\w-]+\.)[^\s)>\]'\"]+", re.IGNORECASE)
# A tag, not a `<TENANT_1>` placeholder (placeholders carry `_`, which a tag name never does here).
# `<img/src=...>` is a tag too: a `/` may separate the name from its attributes (audit A-C-9).
_HTML = re.compile(r"</?[a-zA-Z][a-zA-Z0-9-]*(?:[\s/][^<>]*)?>")
# Bare domains are defanged (`evil[.]com`) so a chat client does not turn them into links - data can
# ride in a subdomain or a path (audit A-C-9). Unfurling is off as well (chatops.py).
_TLDS = ("com|net|org|io|co|dev|app|ai|xyz|info|biz|me|us|uk|in|cn|ru|de|fr|jp|br|au|ca|eu|nl|se|ch|"
         "cloud|site|online|top|tk|ml|ga|cf|gq|link|click|ly|to|gg|tv|cc|ws|pw|page|tech|"
         "store|live|world|space|website|fun|icu|buzz|lol|ninja|rocks|xn--[a-z0-9-]+")
_DOMAIN = re.compile(rf"(?<![\w@.\[/-])((?:[a-z0-9-]+\.)+)({_TLDS})(?![\w-])", re.IGNORECASE)
# CommonMark fences: at most 3 spaces of indent, ``` or ~~~, closed by the same character at least as
# long. `lstrip().startswith("```")` let a 4-space-indented or ~~~ line flip the state and leave the
# rest of the message unsanitised (audit A-C-9).
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
# Terminal and text-direction control characters: an ESC sequence can rewrite what a terminal shows
# (or make a hyperlink); bidi overrides reorder what a reader sees.
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


@dataclass
class GateResult:
    verdict: str                      # PASS | REWRITE | BLOCK
    text: str
    reasons: list[str] = field(default_factory=list)


def strip_controls(text: str) -> str:
    return _CONTROL.sub("", text)


def _clean_line(line: str) -> str:
    line = strip_controls(line)
    if _REFDEF.match(line):
        return "[link definition removed]"
    line = _IMAGE.sub("[image removed]", line)
    line = _MDLINK.sub(r"\1 [link removed]", line)
    line = _URL.sub("[link removed]", line)
    line = _HTML.sub("", line)
    return _DOMAIN.sub(lambda m: f"{m.group(1)[:-1]}[.]{m.group(2)}", line)


def sanitise_text(text: str) -> str:
    """G3 over markdown: every line outside a fenced code block (CommonMark fence rules)."""
    lines = text.split("\n")
    out, fence, opened = [], None, -1
    for i, line in enumerate(lines):
        m = _FENCE.match(line)
        if fence is None:
            # A backtick fence's info string cannot contain a backtick; then it is not a fence.
            if m and not (m.group(1)[0] == "`" and "`" in line[m.end():]):
                fence, opened = m.group(1), i
                out.append(strip_controls(line))
            else:
                out.append(_clean_line(line))
        else:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not line[m.end():].strip():
                fence = None
            out.append(strip_controls(line))
    if fence is not None:
        # Never closed. CommonMark runs it to the end; Slack shows the fence as text and renders what
        # follows. Sanitise what follows, so neither reading leaves an active link.
        out[opened + 1:] = [_clean_line(line) for line in lines[opened + 1:]]
    return "\n".join(out)


def sanitise_data(value: Any) -> Any:
    """G3 over structured data (a generic webhook sends it as JSON): every string, recursively."""
    if isinstance(value, str):
        return "\n".join(_clean_line(line) for line in value.split("\n"))
    if isinstance(value, list):
        return [sanitise_data(v) for v in value]
    if isinstance(value, dict):
        return {k: sanitise_data(v) for k, v in value.items()}
    return value


_UNVERIFIABLE = re.compile(
    r"\b(?:no|zero|without any|not any)\s+(?:customer|user|client|business)s?\s+(?:impact|were affected|was affected|affected)"
    r"|\bno\s+(?:customers?|users?|clients?)\s+(?:were|was|are|is)\s+affected"
    r"|\bno\s+data\s+(?:was\s+|were\s+)?(?:lost|loss|affected|corrupted|leaked)"
    r"|\b(?:has|have)\s+(?:been\s+)?(?:resolved|fixed|mitigated|recovered)"
    r"|\b(?:is|are|was|were)\s+(?:now\s+)?(?:resolved|fixed|mitigated|recovered)",
    re.IGNORECASE,
)


def hedge(text: str) -> str:
    """G2 over one piece of model-written text: mark each claim WARDEN cannot verify."""
    return _UNVERIFIABLE.sub(lambda m: f"[unverified: {m.group(0)}]", text)


def leaked_kinds(text: str) -> list[str]:
    """G5: secret kinds the redactor still finds in `text` - identifiers an operator may show excluded."""
    found = redact(text).mapping
    kinds = {placeholder.strip("<>").rsplit("_", 1)[0] for placeholder in found}
    return sorted(kinds - _SHOWABLE)


def _strings(value: Any):
    """Every string VALUE in a structure. Not a JSON dump: `"credentials_ref": "warden-prod-deploy"`
    serialised is a key=value shape the redactor rightly treats as a credential."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def data_leaks(data: Any) -> list[str]:
    return sorted({k for s in _strings(data) for k in leaked_kinds(s)})


def enforce(text: str, *, alert_id: str = "", before_redaction: str | None = None,
            data_before_redaction: Any = None) -> GateResult:
    """The gate over one outgoing text. `before_redaction`, when the caller re-redacts on the way
    out, is the text as it was built: G5 checks THAT, or it could never fire (audit A-C-8 - the
    re-redaction masked every leak first, and the gate then found none)."""
    leaks = sorted(set(leaked_kinds(text)) | set(leaked_kinds(before_redaction or ""))
                   | set(data_leaks(data_before_redaction)))
    if leaks:
        stub = (f"WARDEN report{f' for alert {alert_id}' if alert_id else ''} was withheld by the outbound "
                f"gate: it still contained {', '.join(leaks)} after redaction. A person must read the full "
                "report where WARDEN ran - nothing was sent.")
        return GateResult("BLOCK", stub, [f"G5: {k} in the outgoing text" for k in leaks])
    clean = sanitise_text(text)
    if clean != text:
        return GateResult("REWRITE", clean, [("G3: images, links, URLs, HTML or control characters removed "
                                              "outside code blocks")])
    return GateResult("PASS", text, [])


def for_terminal(text: str) -> str:
    """What WARDEN prints: no secret (G5) and no control character. Links are left alone - a terminal
    does not fetch them, and the ESC sequence that would make one clickable is stripped."""
    leaks = leaked_kinds(text)
    if leaks:
        return f"[withheld by the outbound gate: {', '.join(leaks)} in this text]"
    return strip_controls(text)


def outbound_data(data: Any) -> tuple[str, Any]:
    """The gate over structured data leaving the process (an MCP result, a generic webhook):
    BLOCK on any secret, else G3 on every string. Returns (verdict, data)."""
    leaks = data_leaks(data)
    if leaks:
        return "BLOCK", {"withheld": True, "reasons": [f"G5: {k} in the outgoing data" for k in leaks]}
    clean = sanitise_data(data)
    return ("PASS" if clean == data else "REWRITE"), clean
