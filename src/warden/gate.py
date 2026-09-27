"""The outbound gate: the last check on what WARDEN says before it leaves the process.

v0 (Phase 0 of the v2 re-architecture, 2026-09-27). Two of the planned rules:

- **G3, untrusted text.** Outside code blocks, markdown images, raw HTML, markdown links and bare
  URLs are removed. The model's hypothesis and reasoning are rendered as markdown, and they can
  repeat text an attacker planted in a log line - an image or a link whose URL carries data out.
  The report's own templates contain no URLs, so nothing legitimate is lost. Inside code blocks the
  text is shown verbatim and nothing is followed.
- **G5, leaks.** If the final text still contains anything the redactor classes as secret (every
  kind except the identifiers an operator may choose to show), the message is BLOCKED and a stub
  goes out instead: a person reads the full report locally.

Verdicts: PASS (unchanged), REWRITE (G3 removed something), BLOCK (G5).
Later phases add G1/G2 (claims must be grounded in evidence) and G4 (commands only from an approved plan).
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
_MDLINK = re.compile(r"\[([^\]]*)\]\(\s*[a-zA-Z][a-zA-Z0-9+.-]*:[^)]*\)")
_URL = re.compile(r"\b(?:https?|ftp|file|data|javascript):[^\s)>\]'\"]+", re.IGNORECASE)
# A tag, not a `<TENANT_1>` placeholder (placeholders carry `_`, which a tag name never does here).
_HTML = re.compile(r"</?[a-zA-Z][a-zA-Z0-9-]*(?:\s[^<>]*)?/?>")


@dataclass
class GateResult:
    verdict: str                      # PASS | REWRITE | BLOCK
    text: str
    reasons: list[str] = field(default_factory=list)


def _clean_line(line: str) -> str:
    line = _IMAGE.sub("[image removed]", line)
    line = _MDLINK.sub(r"\1 [link removed]", line)
    line = _URL.sub("[link removed]", line)
    return _HTML.sub("", line)


def sanitise_text(text: str) -> str:
    """G3 over markdown: every line outside a ``` block."""
    out, in_code = [], False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            in_code = not in_code
            out.append(line)
            continue
        out.append(line if in_code else _clean_line(line))
    return "\n".join(out)


def sanitise_data(value: Any) -> Any:
    """G3 over structured data (a generic webhook sends it as JSON): every string, recursively."""
    if isinstance(value, str):
        return _clean_line(value)
    if isinstance(value, list):
        return [sanitise_data(v) for v in value]
    if isinstance(value, dict):
        return {k: sanitise_data(v) for k, v in value.items()}
    return value


def leaked_kinds(text: str) -> list[str]:
    """G5: secret kinds the redactor still finds in `text` - identifiers an operator may show excluded."""
    found = redact(text).mapping
    kinds = {placeholder.strip("<>").rsplit("_", 1)[0] for placeholder in found}
    return sorted(kinds - _SHOWABLE)


def enforce(text: str, *, alert_id: str = "") -> GateResult:
    leaks = leaked_kinds(text)
    if leaks:
        stub = (f"WARDEN report{f' for alert {alert_id}' if alert_id else ''} was withheld by the outbound "
                f"gate: it still contained {', '.join(leaks)} after redaction. A person must read the full "
                "report where WARDEN ran - nothing was sent.")
        return GateResult("BLOCK", stub, [f"G5: {k} in the outgoing text" for k in leaks])
    clean = sanitise_text(text)
    if clean != text:
        return GateResult("REWRITE", clean, ["G3: images, links, URLs or HTML removed outside code blocks"])
    return GateResult("PASS", text, [])
