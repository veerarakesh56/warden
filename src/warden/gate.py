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
  Since the third review (2026-09-30):
  - code regions come from a CommonMark parser (markdown-it-py), not a line tracker: a fence inside
    a list item ends with the item, and Python's `strip()` closed fences CommonMark keeps open. Only
    the body of a CLOSED backtick fence stays verbatim. The gate parses its own output again, and if
    the fences differ from the ones it kept, everything is cleaned as prose;
  - removals run until nothing changes: removing one token could join the rest into a link or image;
  - a line the gate changed starts no block (heading, quote, list, fence, indented code);
  - a mention becomes `at-here` (`(at)here` after a removed link was a link).
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

import hashlib
import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from markdown_it import MarkdownIt

from .redaction import redact, strip_ansi

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
# Any scheme, one letter too (`p://evil.com` - ninth review), and a bare `://host`.
_URL = re.compile(r"(?:\b[a-z][a-z0-9+.\-]{0,30}://|(?<![\w:])://[\w-]+(?:\.|%2e)|\b(?:https?|mailto|data|javascript|vbscript|tel|slack|"
                  r"ms-teams|vscode|ssh|smb|file|sms|facetime|skype|zoommtg|itms-services):"
                  r"|(?<![\w:/])//[\w-]+(?:\.|%2e))[^\s)>\]'\"`]*", re.IGNORECASE)
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
# Any block a line can start: heading, quote, list item, fence, indented code (third review: removing
# `<b>` from `<b>## Fix - approved` left a real heading).
_ANY_BLOCK = re.compile(r"^(?: {0,3}(?:#{1,6}(?:[ \t]|$)|>|[-*+](?:[ \t]|$)|\d{1,9}[.)](?:[ \t]|$)|[`~]{3})"
                        r"| {4}|[ ]{0,3}\t)")
_MD = MarkdownIt("commonmark")
# The opener or closer of a fence, after any container markers (list items, quotes). A backtick
# fence's info string holds no backtick.
_FENCE_LINE = re.compile(r"^([ \t>*+\-0-9.)]*?)(`{3,}(?=[^`]*$)|~{3,})(.*)$")
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


# Dots a browser turns into "." when a link is opened (fifth review, 2026-10-01: `evil` + U+3002 + `com`
# passed): written as ASCII dots, so the domain is defanged like any other.
_WIDE_DOTS = re.compile("[\u3002\uff0e\uff61]")
# An invisible character next to a dot keeps a domain whole to the matcher, not to a reader or a browser (sixth
# review, 2026-10-01: `evil.<ZWSP>com`, `evil.c<SHY>om`). Removed inside a name before a domain is matched.
# The code points a WHATWG URL parser drops from a host (Node 22's, over all 1.1M code points; seventh review,
# 2026-10-01): a browser joins `evil.<U+FE0F>com` into one domain. Not ZWNJ/ZWJ: the parser keeps those, and
# removing them rewrote Persian text.
_INVISIBLE = re.compile(r"[\u00ad\u034f\u180b-\u180d\u180f\u200b\u2060\u2064\ufe00-\ufe0f\ufeff\U0001bca0-\U0001bca3\U000e0100-\U000e01ef]+")


# Only between ASCII name characters - where it hides a link or splits a key - not everywhere: removing U+FE0F
# everywhere broke emoji, a CJK or Mongolian variation selector was lost (ninth review, 2026-10-01).
_INVISIBLE_IN_NAME = re.compile(r"(?<=[A-Za-z0-9_.:/@\-])" + _INVISIBLE.pattern + r"(?=[A-Za-z0-9_.:/@\-])")
# A terminal escape written out as text - argparse's repr() of an argument: `'\x1b[2JAKIA...'`.
_ANSI_AS_TEXT = re.compile(r"(?:\\x1[bB]|\\033|\\[eE]|\\u001[bB])\[[0-?]*[ -/]*[@-~]")


def normalise(text: str) -> str:
    """The text as a browser or a terminal reads it: no control characters, none of the code points a URL parser
    drops. Done FIRST - before the leak check and before links are removed: done after, `htt<SHY>p://evil.com` hid
    from link removal and the gate itself then joined it into a live link, and `AKIA<ZWSP>...` passed G5 and
    went out whole (eighth review, 2026-10-01)."""
    return _INVISIBLE_IN_NAME.sub("", strip_controls(strip_ansi(text)))


# Emphasis, strike and code markers. Not `_`: a key split by it is whole as written already (`\w` holds it).
_RENDERED_MARKUP = re.compile(r"[*~`]")


def _views(text: str) -> set[str]:
    """Every way a reader may see `text`: as written; without escape sequences (a space where one glued two words,
    and also written out as text); without control characters; and without any invisible character. A key split
    by one of them is whole in some view, and a key the removal glues to a letter is bounded in another (ninth
    review: checking only the normalised text sent `x<BEL>AKIA...` whole)."""
    views = {text, strip_ansi(text), _ANSI_AS_TEXT.sub(" ", text)}
    views |= {strip_controls(v) for v in list(views)}
    views |= {_INVISIBLE.sub("", v) for v in list(views)}
    return views


def _rendered(views: set[str]) -> set[str]:
    """As a renderer shows them (register R9-O1): Slack and Markdown consume emphasis, strike and code markers and
    decode entities, so `AKIA**IOSFODNN7...**` and `AKIA&amp;...` show a key joined that no view held whole."""
    return {_RENDERED_MARKUP.sub("", html.unescape(v)) for v in views}


def _defang_outside_code(line: str) -> str:
    """Domains are defanged except inside inline code, where no renderer makes a link. Only when the
    line's backticks are unambiguous (no double run) - otherwise everything is defanged."""
    parts = [line] if "``" in line else _INLINE_CODE.split(line)
    return "".join(part if i % 2 else _DOMAIN.sub(_defang, _NON_ASCII_HOST.sub(_defang, _WIDE_DOTS.sub(".", part)))
                   for i, part in enumerate(parts))


def _clean_line(line: str) -> str:
    # ⛔ Nothing here decodes: the gate writes out exactly the text it checked (second review,
    # 2026-09-30). A reference is neutralised below instead, so `h&#116;tps://` is never a link and
    # `&#96;&#96;&#96;` never a fence, in any renderer.
    line = normalise(line)
    # To a fixed point: removing one token can join what is left into a new one (third review:
    # `![a]<!here>(//evil%2Ecom/p.png)` became an image once `<!here>` was gone).
    for _ in range(50):
        if _REFDEF.match(line):
            return "[link definition removed]"
        before = line
        line = _IMAGE.sub("[image removed]", line)
        line = _MDLINK.sub(r"\1 [link removed]", line)
        line = _SLACK.sub("", line)
        line = _URL.sub("[link removed]", line)
        line = _IP_LINK.sub("[link removed]", line)
        line = _HTML.sub("", line)
        if line == before:
            break
    line = _LT.sub("\u2039", line)
    line = _ENTITY.sub(r"&amp;\1", line)
    line = _break_runs(line.replace("]:", "]\u200b:"))
    line = _MENTION.sub(r"at-\1", line)  # not `(at)`: after `[link removed]` that is a link
    return _defang_outside_code(line)


def _clean_prose(lines: list[str]) -> list[str]:
    """One run of non-code lines: tags that span lines go first, then each line."""
    if not lines:
        return []
    joined = _HTML.sub("", "\n".join(lines)).split("\n")
    out = [_clean_line(line) for line in joined]
    # A line cleaning changed starts no block: the gate did not write that structure, the input did not
    # have it. (A tag across lines shifts the lines: then every line counts as changed.)
    same = len(joined) == len(lines)
    out = ["\u200b" + c if _ANY_BLOCK.match(c) and not (same and c == lines[i]) else c
           for i, c in enumerate(out)]
    # A setext underline turns the line above it into a heading.
    return ["\u200b" + line if i and _SETEXT.match(line) and out[i - 1].strip() else line
            for i, line in enumerate(out)]


def _closed_fences(text: str) -> list[tuple[int, int, str]]:
    """(opener line, closer line, marker character) of every CLOSED fence, as CommonMark reads the
    text - inside lists and quotes too, where a fence ends with its container (third review,
    2026-09-30). An unclosed fence is not listed: Slack shows its marker as text, so it is prose."""
    lines = text.split("\n")
    spans = []
    for t in _MD.parse(text):
        if t.type != "fence" or not t.map:
            continue
        start, last = t.map[0], t.map[1] - 1
        m = _FENCE_LINE.match(lines[last]) if last > start else None
        if (m and m.group(2)[0] == t.markup[0] and len(m.group(2)) >= len(t.markup)
                and not m.group(3).strip(" \t")):
            spans.append((start, last, t.markup[0]))
    return spans


def _all_prose(lines: list[str]) -> str:
    return "\n".join(_clean_prose(lines))


def sanitise_text(text: str) -> str:
    """G3 over markdown. Only the body of a CLOSED backtick fence stays verbatim - CommonMark shows it
    as code and Slack toggles code on its ``` lines. A closed `~~~` fence stays a fence with its body
    cleaned (Slack has no `~~~`); everything else, indented code included, is cleaned as prose. The code regions come from a CommonMark parser, and the output is
    parsed again: if its fences are not exactly the ones kept, everything is cleaned as prose."""
    # CR is a line ending to CommonMark. The parser reads the text as a renderer gets it, controls
    # included: a control before ``` makes that line prose, which is cleaned - and cleaning strips the
    # control, breaks the run, and counts the line as changed, so it starts no block.
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[str] = []
    kept: list[tuple[int, int]] = []
    pos = 0
    for start, last, char in _closed_fences("\n".join(lines)):
        opener, closer = _FENCE_LINE.match(lines[start]), _FENCE_LINE.match(lines[last])
        if not opener or not closer:
            return _all_prose(lines)
        out += _clean_prose(lines[pos:start])
        begin = len(out)
        # Markers normalised to three: the body holds no run, so three close it as the original marker
        # did. The info string is cleaned (Slack shows it).
        out.append(opener.group(1) + char * 3 + _clean_line(opener.group(3)))
        body = lines[start + 1:last]
        # A backtick body is code in both readers (Slack closes code at ``` anywhere, so runs are broken;
        # a control could hide one). Slack has no ~~~: that body is prose to it and is cleaned.
        out += ([_break_runs(strip_controls(line)) for line in body] if char == "`"
                else [_clean_line(line) for line in body])
        out.append(closer.group(1) + char * 3)
        kept.append((begin, len(out) - 1, char))
        pos = last + 1
    out += _clean_prose(lines[pos:])
    result = "\n".join(out)
    markers = {i for k in kept for i in k[:2]}
    if _closed_fences(result) != kept or _RUN.search("\n".join(
            line for i, line in enumerate(out) if i not in markers)):
        return _all_prose(lines)
    return result


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
    views = _views(text)
    found = [p for view in views for p in redact(view).mapping]
    # A key-shaped value joined by a renderer. Not `name = value` shapes there: with the code marks gone, WARDEN's own
    # metric `secret_changed_age_s` = 1.36e+04 read as a credential; a value split by markup is already one as written.
    found += [p for view in _rendered(views) - views for p in redact(view).mapping if not p.startswith("<SECRET_")]
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


def assembled_kinds(original: str, sent: str) -> list[str]:
    """G5 over what is actually sent, for what the cleaning ASSEMBLED: removing `<b></b>`, `<!here>` or a comment
    from inside a key joined a key G5 had never seen (ninth review). Only a value not written as such in the
    original counts - one that is (`password=<nil> user_id=42`, the `<nil>` removed) was already judged there."""
    if sent == original:
        return []
    views = _views(original)
    found = {}
    for view in _views(sent):
        found.update(redact(view).mapping)
    kinds = {p.strip("<>").rsplit("_", 1)[0] for p, value in found.items() if not any(value in v for v in views)}
    return sorted(kinds - _SHOWABLE)


def enforce(text: str, *, alert_id: str = "", before_redaction: str | None = None,
            data_before_redaction: Any = None) -> GateResult:
    """The gate over one outgoing text. `before_redaction`, when the caller re-redacts on the way
    out, is the text as it was built: G5 checks THAT, or it could never fire (audit A-C-8 - the
    re-redaction masked every leak first, and the gate then found none)."""
    leaks = sorted(set(leaked_kinds(text)) | set(leaked_kinds(before_redaction or ""))
                   | set(data_leaks(data_before_redaction)) | set(assembled_kinds(text, sanitise_text(text))))
    if leaks:
        # The id through the same cleaning as any text: `click.evil.example` is a valid alert id and was a
        # link in the stub (fifth review, 2026-10-01).
        # Redacted WITH the blocked text, so a value found there is masked in the id too: an id that is a secret
        # only in context went out in the stub (seventh review, 2026-10-01); a key-shaped one too (sixth).
        # With the blocked DATA too, normalised, and left out when it is part of a value withheld (eighth review:
        # a secret in the data, an invisible inside the id, or a prefix of the secret went out in the stub).
        # The id, cleaned like any text (audit A-C-24: the notice names its alert) - unless any part of it could
        # be part of a withheld value: masked itself, or sharing four characters, in any case or width, with one.
        # Then a hash names it (register R9-O1: an overlap, an upper-cased copy and a fullwidth variant each showed
        # part of the value). `ref-` keeps the hash from starting a number.
        label = ""
        if alert_id:
            blocked = normalise("\n".join([before_redaction or text, *_strings(data_before_redaction)]))
            ident = " ".join(normalise(alert_id).split())
            masked = redact(f"{blocked}\n{ident}")
            withheld = [unicodedata.normalize("NFKC", v).casefold() for v in masked.mapping.values()]
            probe = unicodedata.normalize("NFKC", ident).casefold()
            width = min(4, len(probe))
            shares = any(probe[i:i + width] in w for w in withheld for i in range(len(probe) - width + 1))
            safe = probe and not shares and masked.text.rsplit("\n", 1)[-1] == ident
            label = sanitise_text(ident) if safe else f"ref-{hashlib.sha256(alert_id.encode('utf-8')).hexdigest()[:12]}"
        stub = (f"WARDEN report{f' for alert {label}' if label else ''} was withheld by the outbound "
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
    out = strip_controls(strip_ansi(text))
    leaks = sorted(set(leaked_kinds(text)) | set(assembled_kinds(text, out)))
    if leaks:
        return f"[withheld by the outbound gate: {', '.join(leaks)} in this text]"
    return out


def outbound_data(data: Any) -> tuple[str, Any]:
    """The gate over structured data leaving the process (an MCP result, a generic webhook):
    BLOCK on any secret, else G3 on every string. Returns (verdict, data)."""
    clean = sanitise_data(data)
    # And in what G3 made of it (ninth review): the strings joined, so a value is judged against all of them.
    leaks = sorted(set(data_leaks(data)) | set(assembled_kinds("\n".join(_strings(data)), "\n".join(_strings(clean)))))
    if leaks:
        return "BLOCK", {"withheld": True, "reasons": [f"G5: {k} in the outgoing data" for k in leaks]}
    return ("PASS" if clean == data else "REWRITE"), clean
