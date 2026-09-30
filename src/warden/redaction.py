"""Pattern-based redaction.

Every string is scrubbed before it can reach the model. Patterns FIND values; a final sweep then masks
the other copies of each found value - every copy of a SECRET, every standalone copy of an identifier
(see _sweep). Strings that belong together (one incident's lines, labels, errors) are redacted as ONE
text: a value found in any of them is masked in all of them (redact_many, second review 2026-09-30).

⚠ What this is not (audit A-C-23): nothing here can see a secret NO pattern matches. The patterns are
the control; HIGHENTROPY is their backstop; the outbound gate's G5 re-runs them, independently, on
everything that leaves. (A re-scan inside redact() used the sweep's own rule and could never fire, so
it was removed - second review, 2026-09-30.)
"""

from __future__ import annotations

import functools
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
# A credential command-line flag: any name with `--`; with a single `-` only password/passwd, since
# `-token` or `-secret` is as often a word in a message as a flag.
_CRED_FLAG = (r"(?i)(?<![\w-])(?:--(?:[a-z0-9]+-){0,2}"
              r"(?:password|passwd|pass|pwd|secret|token|api-?key|access-key|secret-key|private-key|"
              r"auth-token|access-token)|-(?:password|passwd))(?![\w-])")
# Space between a flag and its value: a no-break space (and the other Unicode spaces) as well.
_SP = "[ \t\u00a0\u2000-\u200a\u202f\u205f\u3000]"

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # A whole PEM private key block — the highest-value secret that turns up in a misconfig dump.
    # PEM and PGP. A key cut off by a line-length limit has no END line: mask to the end.
    ("PRIVKEY", re.compile(r"-----BEGIN[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
                           r"(?:-----END[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)")),
    ("PRIVKEY", re.compile(r"Private-Lines:[ \t]*\d+[ \t]*\r?\n([\s\S]+?)(?=\r?\nPrivate-MAC|\Z)")),  # PuTTY
    ("ARN", re.compile(r"arn:aws:[a-z0-9\-]*:[a-z0-9\-]*:\d{12}:[^\s\"']+")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    # Vendor key prefixes: OpenAI/Anthropic (sk-), GitHub classic (ghp_/gho_/ghu_/ghs_/ghr_) and
    # fine-grained (github_pat_), AWS permanent (AKIA) and STS temporary (ASIA) access-key ids,
    # Slack (xoxb-/...), GitLab (glpat-), Google (AIza), Stripe (sk_live_/pk_live_), npm (npm_).
    # AKIA/ASIA share one shape (prefix + 16 base32); ASIA is the temporary sibling that travels
    # with a session token in AssumeRole/SSO bundles and appears bare in botocore errors.
    ("APIKEY", re.compile(r"\b(?:sk-ant-|sk-|sk_live_|sk_test_|rk_live_|rk_test_|pk_live_|github_pat_|ghp_|gho_|ghu_|ghs_|ghr_|AKIA|ASIA|xox[baprs]-|glpat-|glrt-|AIza|npm_|hf_|hvs\.|hvb\.|xapp-)[A-Za-z0-9_\-]{8,}\b")),
    # 2026-09-27 audit: shapes that passed unredacted. SendGrid keys carry dots.
    ("APIKEY", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}")),
    ("APIKEY", re.compile(r"\bwhsec_[A-Za-z0-9+/=_\-]{8,}")),  # Stripe webhook secrets carry + and /
    # Legacy Vault tokens: s. (service), b. (batch), r. (recovery), with a digit somewhere.
    ("APIKEY", re.compile(r"\b[sbr]\.(?=[A-Za-z]*\d)[A-Za-z0-9]{16,}\b")),
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
    # The password runs to the LAST "@" before the host: `admin:p@ss@db` used to mask only "p" and
    # leave "ss@db" to be read as an e-mail address (revealable in Slack).
    ("URLCRED", re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]*:([^\s<]{2,256}?)@(?=[A-Za-z0-9.\-]+(?::\d+)?(?:[/?#\s]|$))")),
    # `@` OR its URL-encoding `%40` — a URL-encoded email (normal in HTTP access logs, the exact
    # evidence source) reads as the email to both the model and an operator, so it must be masked too.
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._+\-]+(?:@|%40)[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    # IBAN (ISO 13616): a REAL country code + 2 check digits + 11-30 alnum BBAN. Financial PII in
    # payment/refund incident logs (SEPA charge/transfer). Masked WHOLE and BEFORE ACCOUNTID/PHONE,
    # which would otherwise fragment its digit runs and leak the country+bank prefix. The prefix is
    # restricted to the SWIFT IBAN-registry country set (not any two letters) so an uppercase
    # evidence token like `AB12CDEF...` is NOT clobbered — only a genuine IBAN country prefix fires.
    ("IBAN", re.compile(
        r"\b(?:AD|AE|AL|AT|AZ|BA|BE|BG|BH|BI|BR|BY|CH|CR|CY|CZ|DE|DJ|DK|DO|EE|EG|ES|FI|FO|FR|GB|GE"
        r"|GI|GL|GR|GT|HN|HR|HU|IE|IL|IQ|IS|IT|JO|KW|KZ|LB|LC|LI|LT|LU|LV|LY|MC|MD|ME|MK|MN|MR|MT"
        r"|MU|NI|NL|NO|PK|PL|PS|PT|QA|RO|RS|RU|SA|SC|SD|SE|SI|SK|SM|SO|ST|SV|TL|TN|TR|UA|VA|VG|XK)"
        r"\d{2}[A-Za-z0-9]{11,30}\b"
    )),
    ("UUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    # A bare 12-digit id: an AWS account id, a GCP project number, or any 12-digit account id. The
    # label is cloud-NEUTRAL (was AWSACCT, which mislabelled a GCP project number as an AWS account
    # id on a non-AWS deployment) since WARDEN runs on any cloud.
    ("ACCOUNTID", re.compile(r"\b\d{12}\b")),
    # An EC2 private DNS name carries the address with dashes: ip-10-0-3-22(.region.compute.internal).
    ("IPV4", re.compile(r"\b(?:ip|ec2)-(\d{1,3}(?:-\d{1,3}){3})\b")),
    ("IPV4", re.compile(r"\b(\d{1,3}(?:-\d{1,3}){3})\.[\w-]+\.pod\b")),  # k8s pod DNS
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
    # A grouped payment-card number (4-4-4-4 with space or dash separators). Masked WHOLE and BEFORE
    # PHONE, which otherwise catches only the first 12-14 digits and leaks the final group. A
    # contiguous 16-digit card is already caught by PHONE; this closes the spaced/dashed form.
    ("CREDITCARD", re.compile(r"\b\d{4}[ \-]\d{4}[ \-]\d{4}[ \-]\d{4}\b")),
    # The negative lookahead stops an ISO-8601 date (YYYY-MM-DD, which every log line starts with)
    # being masked as a phone number — that was masking timestamps and losing evidence.
    #
    # ⛔ Two more guards, added 2026-09-25 after reports reached Slack reading
    # `node=ip-<PHONE_1>-08-21T14:12:03Z` and `wave<PHONE_1>T115746Z`:
    #   - the separator class is `[ \-]`, not `\s` - `\s` matched the NEWLINE between two log lines,
    #     so one "phone number" swallowed the end of one line and the timestamp of the next;
    #   - it may not start inside an identifier: not after a letter, digit, `_`, `-` or `.`. The
    #     digits in `ip-10-0-3-22`, `orders-db-ro-1` and `wave2-2026-...` are names, not numbers.
    # A phone number written as a phone number (`+1 415-555-0132`, `phone=4155550132`) still starts
    # at a boundary and is still masked; so is a contiguous card number, which relies on this rule.
    ("PHONE", re.compile(r"(?<![\w.\-])(?!\d{4}-\d\d-\d\d)\+?\d[\d \-]{8,14}\d(?![\d.])")),
    # password=..., secret: ..., aws_secret_access_key="...": the value after a credential-ish key.
    # Runs LAST so anything already masked (a placeholder starting with `<`, excluded from the value
    # class) is left alone. The bounded [\w.\-] prefix/suffix lets the sensitive word sit INSIDE a
    # compound key (`aws_secret_access_key`, `db_password`), which a `\b`-anchored form missed — the
    # AWS secret access key (the credential paired with the AKIA id) is the case that exposed it.
    # Keywords are cloud-neutral: AWS (aws_secret_access_key), Azure (AccountKey, SharedAccessKey),
    # GCP and generic (private_key, client_secret, api_key, password, token, credential).
    # Header values and client flags that carry a credential whole (2026-09-27 audit).
    ("SECRET", re.compile(r"(?i)\bauthorization\s*[:=]\s*(?:[A-Za-z]+\s+)?([^\s\"']{8,})")),
    ("SECRET", re.compile(r"(?i)\b(?:set-)?cookie\s*:\s*([^\r\n]{4,})")),
    ("SECRET", re.compile(r"\b(?:mysql|mariadb)(?:-?dump|-?admin)?\b[^\r\n]*?\s-p([^\s\"']{3,})")),
    # A credential passed as a command-line flag. EXACT flag names (independent review 2026-09-28:
    # `--secret-name`, `--token-file`, `--token-ttl` are not credentials, and masking them removed
    # resource names from the evidence). Same line only; a value never starts with `-` or a quote.
    # `=` or whitespace before the opening quote: in JSON argv `"--password","x"` the quote right
    # after the flag is the flag's own closing quote, not the value's opening one.
    ("SECRET", re.compile(_CRED_FLAG + rf"(?:{_SP}*={_SP}*|{_SP}+)\"([^\"\n<][^\"\n]{{0,255}})\"")),
    ("SECRET", re.compile(_CRED_FLAG + rf"(?:{_SP}*={_SP}*|{_SP}+)'([^'\n<][^'\n]{{0,255}})'")),
    # `docker build --secret id=npmrc,src=.npmrc` names a secret; it is not one.
    ("SECRET", re.compile(_CRED_FLAG + rf"(?:=|{_SP}+(?![A-Za-z_][\w.-]*=))(?![-\"'])([^\s\"'<]{{3,}})")),
    ("SECRET", re.compile(r"(?i)\"--?(?:[a-z0-9]+-){0,2}(?:password|passwd|pass|pwd|api-?key|apikey|token|secret)"
                          r"\"\s*,\s*\"([^\"<]{1,256})\"")),
    # Client tools whose short flag carries the password (same line only).
    ("SECRET", re.compile(r"\bredis-cli\b[^\r\n]*?[ \t]-a[ \t]+([^\s\"'<]{3,})")),
    ("SECRET", re.compile(r"\bsshpass[ \t]+-p[ \t]*([^\s\"'<]{3,})")),
    ("SECRET", re.compile(r"\b(?:docker[ \t]+login|mongo(?:sh)?|az[ \t]+login)\b[^\r\n]*?[ \t]-p[ \t]+([^\s\"'<]{3,})")),
    ("SECRET", re.compile(r"\bsqlcmd\b[^\r\n]*?[ \t]-P[ \t]*([^\s\"'<]{3,})")),
    ("SECRET", re.compile(r"\bldap\w*\b[^\r\n]*?[ \t]-w[ \t]+([^\s\"'<]{3,})")),
    ("SECRET", re.compile(r"\bhtpasswd\b[^\r\n]*?[ \t]-\w*b\w*[ \t]+\S+[ \t]+\S+[ \t]+([^\s\"'<]{3,})")),
    ("SECRET", re.compile(r"\bcurl\b[^\r\n]*?[ \t](?:-u[ \t]*|--user(?:=|[ \t]+))[^:\s]+:([^\s\"'<]{3,})")),
    ("SECRET", re.compile(r"(?i)\"auth\"\s*:\s*\"([^\"]{8,})\"")),
    # A quoted secret value is masked WHOLE: `password='hunter 2 x'` used to leak "2 x".
    ("SECRET", re.compile(
        r"(?i)(?:password|passwd|pwd|pass|secret|token|api[_\-]?key|apikey|credential|session)"
        r"[\w.\-]{0,20}[\"']?\s*[:=]\s*\"([^\"<][^\"]{0,255})\"")),
    ("SECRET", re.compile(
        r"(?i)(?:password|passwd|pwd|pass|secret|token|api[_\-]?key|apikey|credential|session)"
        r"[\w.\-]{0,20}[\"']?\s*[:=]\s*'([^'<][^']{0,255})'")),
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
        r"|client[_\-]?secret|credential|token|pass(?=[\"']?\s*[:=])|auth(?=[\"']?\s*[:=])"
        r"|session(?=[\"']?\s*[:=]))[\w.\-]{0,20}"
        # optional closing quote after the key so a JSON credential ("password": "x") is matched too
        r"[\"']?\s*[:=]\s*[\"']?"
        # The value: any non-separator char, OR a comma that does NOT begin a new key=value pair
        # (so a comma-bearing secret is masked WHOLE, but `k=v,k2=v2` is not gobbled). `&` stops a
        # URL query-param value at the next parameter. Char-by-char, so no catastrophic backtracking.
        r"((?:[^\s\"'<;,&]|,(?!\s*[\w.\-]+\s*[:=]))+)"
    )),
    # Last: a long high-entropy run no named pattern claimed - a bare AWS secret key, one line of a
    # private key logged line by line (a pod log splits it), a base64 credential. Upper, lower AND a
    # digit, so hex digests, ids and plain words do not match.
    # It may start right after `=`: the lookbehind used to exclude it, so a secret after `blob=` (a key
    # no credential pattern names) was never masked (found 2026-09-30).
    ("HIGHENTROPY", re.compile(
        r"(?<![A-Za-z0-9+/_\-])(?=[A-Za-z0-9+/=_\-]*[A-Z])(?=[A-Za-z0-9+/=_\-]*[a-z])"
        r"(?=[A-Za-z0-9+/=_\-]*\d)[A-Za-z0-9+/_\-]{40,}={0,2}(?![A-Za-z0-9+/=_\-])")),
]


# Words that follow a credential key or flag in prose - "--token not set", "password: field
# required", "api_key=true", usage text "--password PASSWORD" - and are not its value. Masked, each
# was also swept from every other line ("invalidating" -> "<SECRET_1>ating", second review 2026-09-30).
# A password that IS one of these words is not protected by redaction anyway.
_NOT_A_VALUE = frozenset({
    "not", "set", "unset", "flag", "flags", "argument", "arguments", "option", "options", "is", "was",
    "are", "be", "required", "missing", "invalid", "field", "value", "values", "must", "should", "true",
    "false", "null", "none", "nil", "empty", "provided", "given", "supplied", "expired", "rejected",
    "denied", "incorrect", "wrong", "deprecated", "changed", "rotated", "reset", "found", "specified",
    "configured", "needed", "ok", "yes", "no", "on", "off", "enabled", "disabled", "password",
    "passwd", "pass", "pwd", "secret", "secrets", "token", "tokens", "key", "apikey", "api_key",
    "credential", "credentials", "redacted", "hidden", "masked", "file", "env", "stdin",
})

# A placeholder token, captured so `re.split` keeps it as its own segment: `<LABEL_123>`.
_LABELS = tuple(dict.fromkeys(label for label, _ in PATTERNS))
_PLACEHOLDER = re.compile(r"(<[A-Z][A-Z0-9]*_\d+>)")


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


def redact(text: str, *, mapping: dict[str, str] | None = None, _sweep_copies: bool = True) -> RedactionResult:
    """Scrub `text`, then prove the scrub worked.

    Passing an existing `mapping` keeps placeholders stable across many strings in one run, so the
    model still sees that two log lines refer to the same host.
    """
    mapping = dict(mapping or {})
    reverse = {v: k for k, v in mapping.items()}
    counters: dict[str, int] = dict.fromkeys(_LABELS, 0)
    for k in mapping:
        kind = _kind(k)
        if kind in counters:
            counters[kind] += 1

    out = text
    for label, pattern in PATTERNS:

        def _sub(m: re.Match[str], label: str = label) -> str:
            # group(1) exists for TENANT, where only the value is sensitive, not the key name.
            original = m.group(1) if m.groups() else m.group(0)
            if label == "SECRET" and original.lower().strip(".,;:)(") in _NOT_A_VALUE:
                return m.group(0)
            if original in reverse:
                placeholder = reverse[original]
            else:
                counters[label] += 1
                placeholder = f"<{label}_{counters[label]}>"
                mapping[placeholder] = original
                reverse[original] = placeholder
            return m.group(0).replace(original, placeholder)

        out = pattern.sub(_sub, out)

    # Final literal sweep. The patterns FIND values; this masks the copies a regex boundary missed,
    # by the rule in _sweep: every copy of a secret, every standalone copy of an identifier. Real example from a live cluster: a Kubernetes "failed to reserve container name"
    # event embeds the pod UID inside `..._default_<uid>_0`, where the trailing `b_` is not a `\b`
    # boundary, so the `(uid)` copy was masked and the `_0`-suffixed copy was not.
    #
    # ⛔ The sweep must NOT run inside placeholders already placed. If a TENANT value happens to be
    # the literal `UUID_1`, a naive sweep rewrites the neighbouring `<UUID_1>` to `<<TENANT_1>>` -
    # no leak, but two distinct secrets collapse to one label and restore() breaks. So the text is
    # split on placeholder tokens and only the segments BETWEEN them are swept. Longest originals
    # first, so a value that is a substring of another does not corrupt the longer replacement.
    if not _sweep_copies:  # redact_many's first pass only FINDS values; its second pass masks
        return RedactionResult(text=out, mapping=mapping)
    ordered = sorted(mapping.items(), key=lambda kv: -len(kv[1]))
    parts = _PLACEHOLDER.split(out)  # even indices = free text, odd indices = whole placeholders
    for i in range(0, len(parts), 2):
        for placeholder, original in ordered:
            # A substring test first: most values are not in most lines. Every value compiled and run
            # over every line cost 68 s on 300 lines once there were more values than Python's regex
            # cache holds (third review, 2026-09-30).
            if original not in parts[i]:
                continue
            rule = _sweep(placeholder, original)
            if rule is None:
                continue
            parts[i] = parts[i].replace(original, placeholder) if rule is _EVERY_COPY else rule.sub(placeholder, parts[i])
    out = "".join(parts)
    return RedactionResult(text=out, mapping=mapping)


# ⛔ Audit A-C-4: the sweep replaced every copy of every found value, so a TENANT `user_id=500` turned
# every HTTP 500 in the text into <TENANT_1>. The first fix (length thresholds) let SHORT SECRETS
# survive in other lines - URL-encoded, glued, repeated - and made the leak check vacuous
# (independent review, 2026-09-28). The rule now depends on what the value is:
#   - a SECRET (a key, token, password, credential): every copy, anywhere, from 4 characters. A
#     secret must never survive; rewriting a stray substring is the lesser harm.
#   - an IDENTIFIER (tenant, IP, email, account id, ...): every copy that stands as its own token.
#     All-digit values under 6 characters ("500") and common words ("prod", "admin") are not swept:
#     the pattern still masks every occurrence it matches, and a bare "500" elsewhere is a status
#     code far more often than the tenant.
SECRET_KINDS = frozenset({"PRIVKEY", "JWT", "APIKEY", "GCPTOKEN", "AZURESAS", "WEBHOOK", "URLCRED",
                          "BEARER", "BASIC", "SECRET", "HIGHENTROPY", "IBAN", "CREDITCARD"})
_COMMON = frozenset({"prod", "production", "test", "dev", "stage", "staging", "default", "admin",
                     "root", "user", "users", "none", "null", "true", "false", "main", "master", "api",
                     "app", "web", "db", "public", "local", "info", "error", "debug"})


def _kind(placeholder: str) -> str:
    return placeholder.strip("<>").rsplit("_", 1)[0]


_PLAIN_WORD = re.compile(r"[A-Za-z][A-Za-z._-]*")
_ASSIGNMENT = re.compile(r"\w=.")
# Every copy, anywhere: plain str.replace, which is what the escaped regex did.
_EVERY_COPY = object()


def _sweep(placeholder: str, original: str):
    """How the copies of `original` are swept: every copy (_EVERY_COPY), every standalone copy (a
    compiled pattern), or not at all (None)."""
    if len(original) < 3:
        return None
    if _kind(placeholder) in SECRET_KINDS and len(original) >= 4:
        # A plain word or an assignment is not swept (third review, 2026-09-30): one log line
        # `password=OutOfMemoryError token=timed api_key=reserved_concurrency=0` erased those words from
        # every line, WARDEN's own config read included. A credential is neither; a value that is one is
        # a weak password or a planted one, and it stays masked where the pattern found it. Known limit:
        # a letters-only password repeated elsewhere WITHOUT its key is not masked there.
        if _PLAIN_WORD.fullmatch(original) or _ASSIGNMENT.search(original):
            return None
        return _EVERY_COPY
    if (original.isdigit() and len(original) < 6) or original.lower() in _COMMON:
        return None
    return _standalone(original)


@functools.lru_cache(maxsize=8192)
def _standalone(original: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![A-Za-z0-9]){re.escape(original)}(?![A-Za-z0-9])")


def redact_many(items: list[str], mapping: dict[str, str] | None = None) -> tuple[list[str], dict[str, str]]:
    """Redact several strings as ONE text, with one placeholder namespace: a value found in any of them
    is masked in all of them. One pass left a secret found in a later line in clear in the earlier
    ones (second review, 2026-09-30); the first pass now only finds, the second masks."""
    mapping = dict(mapping or {})
    for item in items:
        mapping = redact(item, mapping=mapping, _sweep_copies=False).mapping
    out: list[str] = []
    for item in items:
        result = redact(item, mapping=mapping)
        mapping = result.mapping
        out.append(result.text)
    return out, mapping
