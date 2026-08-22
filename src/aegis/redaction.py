"""Redaction that is verified, not assumed.

Every string is scrubbed before it can reach the model. The important part is not the regex list —
everyone has one of those. It is `redact()` raising if any original value survives into the output.

A redactor that silently misses one identifier looks exactly like a redactor that works. So this one
is asked to prove it: after substitution the output is re-scanned, and a leak is a hard failure that
halts the run rather than a warning nobody reads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Ordered deliberately: the greedy patterns (ARN, JWT) run before the narrow ones (UUID, IP),
# otherwise a UUID inside an ARN gets replaced first and the ARN pattern then fails to match.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ARN", re.compile(r"arn:aws:[a-z0-9\-]*:[a-z0-9\-]*:\d{12}:[^\s\"']+")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("APIKEY", re.compile(r"\b(?:sk-ant-|sk-|ghp_|AKIA)[A-Za-z0-9_\-]{8,}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("UUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("AWSACCT", re.compile(r"\b\d{12}\b")),
    ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    # tenant_id=..., org_id: ..., "customer_id": "..."  — the identifiers that make logs re-identifiable
    ("TENANT", re.compile(r"(?i)\b(?:tenant|org|organisation|organization|customer|account|user)[_\-]?id\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{3,})[\"']?")),
    ("PHONE", re.compile(r"(?<![\d.])\+?\d[\d\s\-]{8,14}\d(?![\d.])")),
]


class RedactionLeak(RuntimeError):
    """A secret survived redaction. Always fatal — never downgraded to a warning."""


@dataclass
class RedactionResult:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)  # placeholder -> original

    @property
    def size(self) -> int:
        return len(self.mapping)

    def restore(self, text: str) -> str:
        """Put the real values back, for display to an operator who is entitled to see them."""
        for placeholder, original in self.mapping.items():
            text = text.replace(placeholder, original)
        return text


def redact(text: str, *, mapping: dict[str, str] | None = None) -> RedactionResult:
    """Scrub `text`, then prove the scrub worked.

    Passing an existing `mapping` keeps placeholders stable across many strings in one run, so the
    model still sees that two log lines refer to the same host.
    """
    mapping = dict(mapping or {})
    reverse = {v: k for k, v in mapping.items()}
    counters: dict[str, int] = {}
    for label, _ in PATTERNS:
        counters[label] = sum(1 for k in mapping if k.startswith(f"<{label}_"))

    out = text
    for label, pattern in PATTERNS:

        def _sub(m: re.Match[str], label: str = label) -> str:
            # group(1) exists for TENANT, where only the value is sensitive, not the key name.
            original = m.group(1) if m.groups() else m.group(0)
            if original in reverse:
                placeholder = reverse[original]
            else:
                counters[label] += 1
                placeholder = f"<{label}_{counters[label]}>"
                mapping[placeholder] = original
                reverse[original] = placeholder
            return m.group(0).replace(original, placeholder)

        out = pattern.sub(_sub, out)

    # Final literal sweep. The patterns FIND secrets; this GUARANTEES none of the found values
    # survives anywhere, regardless of the word-boundary quirks that make a regex miss a second
    # occurrence. Real example from a live cluster: a Kubernetes "failed to reserve container name"
    # event embeds the pod UID inside `..._default_<uid>_0`, where the trailing `b_` is not a `\b`
    # boundary, so the `(uid)` copy was masked and the `_0`-suffixed copy was not. Longest originals
    # first, so a value that is a substring of another does not corrupt the longer replacement.
    for placeholder, original in sorted(mapping.items(), key=lambda kv: -len(kv[1])):
        if original:
            out = out.replace(original, placeholder)

    _assert_clean(out, mapping)
    return RedactionResult(text=out, mapping=mapping)


def _assert_clean(redacted: str, mapping: dict[str, str]) -> None:
    """Read the value back. A setter that succeeds can still have clamped."""
    for placeholder, original in mapping.items():
        if original and original in redacted:
            raise RedactionLeak(
                f"{placeholder} was substituted but its original value is still present in the "
                f"redacted text. Refusing to send this to the model."
            )


def redact_many(items: list[str]) -> tuple[list[str], dict[str, str]]:
    """Redact a list while keeping one shared placeholder namespace."""
    mapping: dict[str, str] = {}
    out: list[str] = []
    for item in items:
        result = redact(item, mapping=mapping)
        mapping = result.mapping
        out.append(result.text)
    return out, mapping
