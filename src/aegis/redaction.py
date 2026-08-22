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
    # IPv6 — we redact IPv4, so an IPv6 address (common in dual-stack k8s pod logs) is the same
    # identifier and must be masked too. Deliberately matches ONLY real addresses: either a `::`
    # compression or a full 8 groups, so a `10:02:11` timestamp or a `00:1a:2b:3c:4d:5e` MAC (no
    # `::`, not 8 groups) is left alone.
    ("IPV6", re.compile(
        r"(?<![:.\w])(?:"
        r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,7}:(?:[A-Fa-f0-9]{1,4})?(?::[A-Fa-f0-9]{1,4}){0,6}"
        r")(?![:.\w])"
    )),
    # tenant_id=..., org_id: ..., "customer_id": "..."  — the identifiers that make logs re-identifiable
    ("TENANT", re.compile(r"(?i)\b(?:tenant|org|organisation|organization|customer|account|user)[_\-]?id\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{3,})[\"']?")),
    # The negative lookahead stops an ISO-8601 date (YYYY-MM-DD, which every log line starts with)
    # being masked as a phone number — that was masking timestamps and losing evidence.
    ("PHONE", re.compile(r"(?<![\d.])(?!\d{4}-\d\d-\d\d)\+?\d[\d\s\-]{8,14}\d(?![\d.])")),
]


# A placeholder token, captured so `re.split` keeps it as its own segment: `<LABEL_123>`.
_PLACEHOLDER = re.compile(r"(<[A-Z][A-Z0-9]*_\d+>)")


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
    # boundary, so the `(uid)` copy was masked and the `_0`-suffixed copy was not.
    #
    # ⛔ The sweep must NOT run inside placeholders already placed. If a TENANT value happens to be
    # the literal `UUID_1`, a naive sweep rewrites the neighbouring `<UUID_1>` to `<<TENANT_1>>` -
    # no leak, but two distinct secrets collapse to one label and restore() breaks. So the text is
    # split on placeholder tokens and only the segments BETWEEN them are swept. Longest originals
    # first, so a value that is a substring of another does not corrupt the longer replacement.
    ordered = sorted(mapping.items(), key=lambda kv: -len(kv[1]))
    parts = _PLACEHOLDER.split(out)  # even indices = free text, odd indices = whole placeholders
    for i in range(0, len(parts), 2):
        for placeholder, original in ordered:
            if original:
                parts[i] = parts[i].replace(original, placeholder)
    out = "".join(parts)

    _assert_clean(out, mapping)
    return RedactionResult(text=out, mapping=mapping)


def _assert_clean(redacted: str, mapping: dict[str, str]) -> None:
    """Read the value back. A setter that succeeds can still have clamped.

    Only the text OUTSIDE placeholders counts. A secret value that happens to equal a placeholder's
    internal text - a tenant literally named `UUID_1`, which collides with the token `<UUID_1>` - is
    not a leak of that value; the real value is gone and only the label coincides. Stripping whole
    `<LABEL_N>` tokens first means a genuine free-text leak is still caught (it is not part of a
    token, so it survives the strip), while the coincidence is not a false alarm that refuses the run.
    """
    free_text = _PLACEHOLDER.sub(" ", redacted)
    for placeholder, original in mapping.items():
        if original and original in free_text:
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
