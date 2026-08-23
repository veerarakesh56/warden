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

# Ordered deliberately: the greedy/most-specific patterns run before the narrow ones, otherwise a
# narrow pattern eats part of a broader secret (a UUID inside an ARN, an EMAIL inside a connection
# string) and the broader pattern then fails to match.
#
# ⛔ Every pattern with a capturing group masks group(1) — the SENSITIVE part only — keeping the
# surrounding structure (`password=<SECRET_1>`, `postgres://user:<URLCRED_1>@host`) so the model can
# still reason about the shape. Value char classes EXCLUDE `<` so a value that is already a
# placeholder (`api_key=<APIKEY_1>`) is never re-matched and corrupted.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # A whole PEM private key block — the highest-value secret that turns up in a misconfig dump.
    ("PRIVKEY", re.compile(r"-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z0-9 ]*PRIVATE KEY-----")),
    ("ARN", re.compile(r"arn:aws:[a-z0-9\-]*:[a-z0-9\-]*:\d{12}:[^\s\"']+")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    # Vendor key prefixes: OpenAI/Anthropic (sk-), GitHub classic (ghp_/gho_/ghu_/ghs_/ghr_) and
    # fine-grained (github_pat_), AWS (AKIA), Slack (xoxb-/...), GitLab (glpat-), Google (AIza),
    # Stripe (sk_live_/pk_live_), npm (npm_).
    ("APIKEY", re.compile(r"\b(?:sk-ant-|sk-|sk_live_|pk_live_|github_pat_|ghp_|gho_|ghu_|ghs_|ghr_|AKIA|xox[baprs]-|glpat-|AIza|npm_)[A-Za-z0-9_\-]{8,}\b")),
    # GCP OAuth2 access token (ya29.<long>). Masked whole and BEFORE the phone pattern, which would
    # otherwise fragment a digit-run inside it and leave the rest exposed. Cloud-neutral: GCP.
    ("GCPTOKEN", re.compile(r"\bya29\.[A-Za-z0-9._\-]{20,}")),
    # Azure Shared Access Signature: the `sig=` query parameter is the credential. Cloud-neutral: Azure.
    ("AZURESAS", re.compile(r"(?i)(?<=[?&])sig=([^\s&\"'<]{16,})")),
    # Incoming-webhook URLs carry the credential in the PATH (no key=value, no vendor prefix) — the
    # whole URL IS the secret (anyone holding it can post). Slack, Discord, MS Teams. Cloud-neutral.
    ("WEBHOOK", re.compile(
        r"(?i)https://(?:"
        r"hooks\.slack\.com/services/[A-Za-z0-9/]+"
        r"|(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"
        r"|[a-z0-9.\-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9@/\-]+"
        r")"
    )),
    # Credentials embedded in a URL / connection string: scheme://user:PASSWORD@host. Masks the
    # password (group 1). A literal `@` inside a password is only partially covered (rare — real
    # passwords are URL-encoded), and the SECRET pattern below is the backstop for `password=` forms.
    ("URLCRED", re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]*:([^\s@<]{2,256})@")),
    # `@` OR its URL-encoding `%40` — a URL-encoded email (normal in HTTP access logs, the exact
    # evidence source) reads as the email to both the model and an operator, so it must be masked too.
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._+\-]+(?:@|%40)[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("UUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    # A bare 12-digit id: an AWS account id, a GCP project number, or any 12-digit account id. The
    # label is cloud-NEUTRAL (was AWSACCT, which mislabelled a GCP project number as an AWS account
    # id on a non-AWS deployment) since AEGIS runs on any cloud.
    ("ACCOUNTID", re.compile(r"\b\d{12}\b")),
    ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    # IPv6 — we redact IPv4, so an IPv6 address (common in dual-stack k8s pod logs) is the same
    # identifier and must be masked too. Deliberately matches ONLY real addresses: either a `::`
    # compression or a full 8 groups, so a `10:02:11` timestamp is left alone. (A MAC has its own
    # pattern below — it is a device re-identifier, so it IS masked, just not as an IPv6.)
    ("IPV6", re.compile(
        r"(?<![:.\w])(?:"
        r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,7}:(?:[A-Fa-f0-9]{1,4})?(?::[A-Fa-f0-9]{1,4}){0,6}"
        r")(?![:.\w])"
    )),
    # MAC address (colon, dash, or Cisco dotted) — a persistent device re-identifier, like an IP.
    # Six pairs, so a 3-group `10:02:11` time does not match.
    ("MAC", re.compile(
        r"(?:\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"
        r"|\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b)"
    )),
    # tenant_id=..., org_id: ..., "customer_id": "..."  — the identifiers that make logs re-identifiable
    ("TENANT", re.compile(r"(?i)\b(?:tenant|org|organisation|organization|customer|account|user)[_\-]?id\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{3,})[\"']?")),
    # A token following `Bearer ` in an Authorization header (when it is not already a JWT/API key).
    ("BEARER", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/\-]{12,}=*)")),
    # HTTP Basic auth: `Authorization: Basic <base64 of user:pass>` - the base64 IS the credential.
    ("BASIC", re.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/]{8,}={0,2})")),
    # The negative lookahead stops an ISO-8601 date (YYYY-MM-DD, which every log line starts with)
    # being masked as a phone number — that was masking timestamps and losing evidence.
    ("PHONE", re.compile(r"(?<![\d.])(?!\d{4}-\d\d-\d\d)\+?\d[\d\s\-]{8,14}\d(?![\d.])")),
    # password=..., secret: ..., aws_secret_access_key="...": the value after a credential-ish key.
    # Runs LAST so anything already masked (a placeholder starting with `<`, excluded from the value
    # class) is left alone. The bounded [\w.\-] prefix/suffix lets the sensitive word sit INSIDE a
    # compound key (`aws_secret_access_key`, `db_password`), which a `\b`-anchored form missed — the
    # AWS secret access key (the credential paired with the AKIA id) is the case that exposed it.
    # Keywords are cloud-neutral: AWS (aws_secret_access_key), Azure (AccountKey, SharedAccessKey),
    # GCP and generic (private_key, client_secret, api_key, password, token, credential).
    ("SECRET", re.compile(
        # Leading delimiter includes ? & : so URL QUERY-PARAM credentials (?password=, &token=) and
        # the .npmrc form (//registry/:_authToken=) are caught — ubiquitous in access/CI logs.
        r"(?i)(?:^|[\s\"',;{(\[=?&:])[\w.\-]{0,40}"
        r"(?:password|passwd|pwd|secret|access[_\-]?key|account[_\-]?key|shared[_\-]?access[_\-]?key"
        r"|private[_\-]?key|api[_\-]?key|apikey|auth[_\-]?token|access[_\-]?token|sas[_\-]?token"
        # kubeconfig secrets: client-key-data (the private key), certificate-data.
        r"|key[_\-]?data|cert(?:ificate)?[_\-]?data"
        # session cookies are live bearer credentials: sessionid, JSESSIONID, PHPSESSID, connect.sid.
        r"|session[_\-]?id|jsessionid|phpsessid|sessid|connect\.sid"
        r"|client[_\-]?secret|credential|token)[\w.\-]{0,20}"
        # optional closing quote after the key so a JSON credential ("password": "x") is matched too
        r"[\"']?\s*[:=]\s*[\"']?"
        # The value: any non-separator char, OR a comma that does NOT begin a new key=value pair
        # (so a comma-bearing secret is masked WHOLE, but `k=v,k2=v2` is not gobbled). `&` stops a
        # URL query-param value at the next parameter. Char-by-char, so no catastrophic backtracking.
        r"((?:[^\s\"'<;,&]|,(?!\s*[\w.\-]+\s*[:=]))+)"
    )),
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
