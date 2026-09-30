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
  Since the second review (2026-09-30), G3 never writes text it did not inspect:
  - an HTML/character reference is neutralised (`&#96;` -> `&amp;#96;`), never decoded: decoding it
    and writing the result out turned `&#96;&#96;&#96;` into a real fence the gate had never seen;
  - `<` becomes `‹` outside `<KIND_n>` placeholders, so no HTML block, comment or autolink starts;
  - `]:` is broken (no link reference definition, whatever its label spans), and so is a setext
    underline;
  - control characters and CR line endings are removed BEFORE fences are found;
  - a run of three backticks or tildes inside a line is broken - Slack opens code at one anywhere;
  - the inside of a `~~~` block is sanitised like prose: Slack has no `~~~` fences;
  - every domain outside inline code is defanged, whatever its top-level domain, emails included.
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

# A link label may hold escaped brackets (`[a\]b]`); a destination may be anything but `)`.
_LABEL = r"\[((?:[^\]\\\n]|\\.)*)\]"
_IMAGE = re.compile(r"!" + _LABEL + r"\([^)]*\)")
# Any inline link, whatever its target: `//host/...` (protocol-relative) carries data out as well as
# `https://` does (audit A-C-9).
_MDLINK = re.compile(_LABEL + r"\(\s*[^)\s]+[^)]*\)")
# A link reference definition `[x]: target`, also inside a list item or a quote, and with an escaped
# label - CommonMark accepts all three (independent review 2026-09-28: `- [r]: h&#116;tps://...`
# plus `![x][r]` rendered a zero-click image with verdict PASS).
_REFDEF = re.compile(r"^\s{0,3}(?:(?:[-*+]|\d{1,9}[.)])\s+|>\s*)*" + _LABEL + r":\s*\S")
# Any scheme with `//`, the schemes that act without one, and protocol-relative `//host.`.
_URL = re.compile(r"(?:\b[a-z][a-z0-9+.\-]{1,30}://|\b(?:https?|mailto|data|javascript|vbscript|tel|slack|"
                  r"ms-teams|vscode|ssh|smb|file|sms|facetime|skype|zoommtg|itms-services):"
                  r"|(?<![\w:/])//[\w-]+\.)[^\s)>\]'\"]*", re.IGNORECASE)
# An IP address with a port or a path is a link to a chat client.
_IP_LINK = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?/\S*")
# A tag, not a `<TENANT_1>` placeholder (placeholders carry `_`, which a tag name never does here).
# `<img/src=...>` is a tag too: a `/` may separate the name from its attributes (audit A-C-9). Tags are
# also removed ACROSS lines before the line pass: `<img\nsrc=...>` is one tag to a renderer.
_HTML = re.compile(r"</?[a-zA-Z][a-zA-Z0-9-]*(?:[\s/][^<>]*)?>", re.DOTALL)
# Slack's own control syntax: <!channel>, <!here>, <!subteam^S1>, <@U123>, <#C123>, <url|text>. And
# the bare words a client may still expand.
_SLACK = re.compile(r"<[!@#][^<>]*>|<[a-z][a-z0-9+.\-]*:[^<>|]*\|[^<>]*>", re.IGNORECASE)
_MENTION = re.compile(r"(?<![\w@])@(here|channel|everyone)\b", re.IGNORECASE)
# Bare domains are defanged (`evil[.]com`) so a chat client does not turn them into links - data can
# ride in a subdomain or a path (audit A-C-9). Every two-letter top-level domain (country codes), the
# common generic ones, punycode, and any non-ASCII label (lookalikes such as a Cyrillic "е") are
# covered - a partial list let `evil.sh`, `evil.it` and `evil.zip` through (review 2026-09-28).
# Any alphabetic top-level domain: a list let `evil.digital` through (second review, 2026-09-30),
# and Slack links a bare domain under any real TLD.
_TLDS = r"[a-z]{2,24}|xn--[a-z0-9-]+|[^\x00-\x7f\W\d_]{2,}"
# Not an email's local part (`priya.nair@`): only what follows the `@` is a host.
_DOMAIN = re.compile(rf"(?<![\w.\[/-])((?:[\w-]+\.)+)({_TLDS})(?![\w@-])", re.IGNORECASE)
_NON_ASCII_HOST = re.compile(r"(?<![\w@.\[/-])((?:[\w-]*[^\x00-\x7f][\w-]*\.)+)([\w-]+)")
# CommonMark fences: at most 3 spaces of indent, ``` or ~~~, closed by the same character at least as
# long. `lstrip().startswith("```")` let a 4-space-indented or ~~~ line flip the state and leave the
# rest of the message unsanitised (audit A-C-9).
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
# Terminal and text-direction control characters: an ESC sequence can rewrite what a terminal shows
# (or make a hyperlink); bidi overrides reorder what a reader sees.
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")
# A reference CommonMark would decode. `&amp;` itself is left: it decodes to a plain `&`.
_ENTITY = re.compile(r"&(?!amp;)(#[0-9]{1,7};|#[xX][0-9a-fA-F]{1,6};|[A-Za-z][A-Za-z0-9]{1,31};)")
_LT = re.compile(r"<(?![A-Z][A-Z0-9]*_\d+>)")
_RUN = re.compile(r"`{3,}|~{3,}")
_BLOCK_START = re.compile(r"^ {0,3}(?:#{1,6}(?:[ \t]|$)|>|[`~]{3})")
_SETEXT = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
# Inline code both CommonMark and Slack agree on: single backticks, not escaped, nothing inside.
_INLINE_CODE = re.compile(r"(?<![`\\])(`[^`\n]+`)(?!`)")


@dataclass
class GateResult:
    verdict: str                      # PASS | REWRITE | BLOCK
    text: str
    reasons: list[str] = field(default_factory=list)


def strip_controls(text: str) -> str:
    return _CONTROL.sub("", text)


def _defang(m: re.Match[str]) -> str:
    # Every dot: GFM links `www.evil` on its own, so `www.evil[.]digital` was still a link.
    return m.group(0).replace(".", "[.]")


def _break_runs(line: str) -> str:
    return _RUN.sub(lambda m: "\u200b".join(m.group(0)), line)


def _defang_outside_code(line: str) -> str:
    """Domains are defanged except inside inline code, where no renderer makes a link. Only when the
    line's backticks are unambiguous (no double run) - otherwise everything is defanged."""
    parts = [line] if "``" in line else _INLINE_CODE.split(line)
    return "".join(part if i % 2 else _DOMAIN.sub(_defang, _NON_ASCII_HOST.sub(_defang, part))
                   for i, part in enumerate(parts))


def _clean_line(line: str) -> str:
    # ⛔ Nothing here decodes: the gate writes out exactly the text it checked (second review,
    # 2026-09-30). A reference is neutralised below instead, so `h&#116;tps://` is never a link and
    # `&#96;&#96;&#96;` never a fence, in any renderer.
    line = strip_controls(line)
    if _REFDEF.match(line):
        return "[link definition removed]"
    line = _IMAGE.sub("[image removed]", line)
    line = _MDLINK.sub(r"\1 [link removed]", line)
    line = _SLACK.sub("", line)
    line = _URL.sub("[link removed]", line)
    line = _IP_LINK.sub("[link removed]", line)
    line = _HTML.sub("", line)
    line = _LT.sub("\u2039", line)
    line = _ENTITY.sub(r"&amp;\1", line)
    line = _break_runs(line.replace("]:", "]\u200b:"))
    line = _MENTION.sub(r"(at)\1", line)
    return _defang_outside_code(line)


def _clean_prose(lines: list[str]) -> list[str]:
    """One run of non-code lines: tags that span lines go first, then each line."""
    if not lines:
        return []
    out = [_clean_line(line) for line in _HTML.sub("", "\n".join(lines)).split("\n")]
    # A setext underline turns the line above it into a heading.
    return ["\u200b" + line if i and _SETEXT.match(line) and out[i - 1].strip() else line
            for i, line in enumerate(out)]


def sanitise_text(text: str) -> str:
    """G3 over markdown: every line outside a fenced code block (CommonMark fence rules)."""
    # CR is a line ending to CommonMark; controls go BEFORE fences are found (second review: a leading
    # LRM hid a fence from the gate that stripping then revealed to the renderer).
    lines = [strip_controls(line) for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    out: list[str] = []
    prose: list[str] = []
    fence, opened = None, -1
    for line in lines:
        m = _FENCE.match(line)
        if fence is None:
            # A backtick fence's info string cannot contain a backtick; then it is not a fence.
            if m and not (m.group(1)[0] == "`" and "`" in line[m.end():]):
                out += _clean_prose(prose)
                prose = []
                fence, opened = m.group(1), len(out)
                out.append(line)
            else:
                prose.append(line)
        else:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not line[m.end():].strip():
                fence = None
                out.append(line)
            elif fence[0] == "~":
                out += _clean_prose([line])  # Slack has no ~~~ fence: it renders this as prose
            else:
                out.append(_break_runs(line))  # Slack closes code at ``` anywhere on a line
    out += _clean_prose(prose)
    if fence is not None:
        # Never closed. CommonMark runs it to the end; Slack shows the fence as text and renders what
        # follows. Sanitise what follows, so neither reading leaves an active link.
        out[opened + 1:] = _clean_prose(out[opened + 1:])
    return "\n".join(out)


def sanitise_data(value: Any) -> Any:
    """G3 over structured data (a generic webhook, an MCP result): every string and every KEY,
    recursively - a key built from backend data is text like any other (review 2026-09-28)."""
    if isinstance(value, str):
        lines = _clean_prose(value.replace("\r\n", "\n").replace("\r", "\n").split("\n"))
        # A consumer may render a string as markdown: no line may start a heading, quote or fence.
        return "\n".join("\u200b" + ln if _BLOCK_START.match(ln) else ln for ln in lines)
    if isinstance(value, list):
        return [sanitise_data(v) for v in value]
    if isinstance(value, dict):
        return {sanitise_data(k) if isinstance(k, str) else k: sanitise_data(v) for k, v in value.items()}
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
    """Every string in a structure, keys included, each on its own. Not a JSON dump:
    `"credentials_ref": "warden-prod-deploy"` serialised is a key=value shape the redactor rightly
    treats as a credential."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                yield k
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
