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
from typing import Any

# Ordered deliberately: the greedy/most-specific patterns run before the narrow ones, otherwise a
# narrow pattern eats part of a broader secret (a UUID inside an ARN, an EMAIL inside a connection
# string) and the broader pattern then fails to match.
#
# ⛔ Every pattern with a capturing group masks group(1) — the SENSITIVE part only — keeping the
# surrounding structure (`password=<SECRET_1>`, `postgres://user:<URLCRED_1>@host`) so the model can
# still reason about the shape. A value that is nothing but placeholders (`api_key=<APIKEY_1>`) is masked
# already and left alone; one that holds a placeholder AND more (`password=<UUID_1>.hunter2x`) is masked whole and
# stored restored, so restore() gives it back in one step. Value classes used to stop at `<` instead, and left
# whatever followed a placeholder in clear (eighth review, 2026-10-01).
# A credential command-line flag: any name with `--`; with a single `-` only password/passwd, since
# `-token` or `-secret` is as often a word in a message as a flag.
_CRED_FLAG = (r"(?i)(?<![\w-])(?:--(?:[a-z0-9]+-){0,2}"
              r"(?:password|passwd|pass|pwd|secret|token|api-?key|access-key|secret-key|private-key|"
              r"auth-token|access-token)|-(?:password|passwd))(?![\w-])")
# Space between a flag and its value: a no-break space (and the other Unicode spaces) as well.
_SP = "[ \t\u00a0\u2000-\u200a\u202f\u205f\u3000]"

# A key that names a cookie: `Cookie`, `Set-Cookie`, `X-Auth-Cookie`, `HTTP_COOKIE`, `"http_cookie"`, `cookies`.
_COOKIE_KEY = r"(?i)(?<![A-Za-z])(?:set-)?cookies?[\"'\]]*\s*"
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # A whole PEM private key block — the highest-value secret that turns up in a misconfig dump.
    # PEM and PGP. A key cut off by a line-length limit has no END line: mask to the end.
    ("PRIVKEY", re.compile(r"-----BEGIN[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
                           r"(?:-----END[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)")),
    ("PRIVKEY", re.compile(r"Private-Lines:[ \t]*\d+[ \t]*\r?\n([\s\S]+?)(?=\r?\nPrivate-MAC|\Z)")),  # PuTTY
    ("ARN", re.compile(r"arn:aws:[a-z0-9\-]*:[a-z0-9\-]*:\d{12}:[^\s\"']+")),
    # Three segments (a JWS) to five (a JWE, whose second may be empty): a JWE's last two parts were left in clear
    # (eighth review, 2026-10-01).
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]*){0,2}")),
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
    ("AZURESAS", re.compile(r"(?i)(?<=[?&])sig=([^\s&\"']{16,})")),
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
    ("URLCRED", re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]*:([^\s]{2,256}?)@(?=[A-Za-z0-9.\-]+(?::\d+)?(?:[/?#\s]|$))")),
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
    # `<>` too: a value whose start an earlier pattern masked (`Bearer <UUID_1>.rest`) is masked whole (ninth review).
    ("BEARER", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/\-<>]{12,}=*)")),
    # HTTP Basic auth: `Authorization: Basic <base64 of user:pass>` - the base64 IS the credential.
    ("BASIC", re.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/<>_]{8,}={0,2})")),
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
    # Runs LAST: a value already masked whole is left alone. The bounded [\w.\-] prefix/suffix lets the sensitive word sit INSIDE a
    # compound key (`aws_secret_access_key`, `db_password`), which a `\b`-anchored form missed — the
    # AWS secret access key (the credential paired with the AKIA id) is the case that exposed it.
    # Keywords are cloud-neutral: AWS (aws_secret_access_key), Azure (AccountKey, SharedAccessKey),
    # GCP and generic (private_key, client_secret, api_key, password, token, credential).
    # Header values and client flags that carry a credential whole (2026-09-27 audit).
    ("SECRET", re.compile(r"(?i)\bauthorization[\"']?\s*[:=]\s*[\"']?(?:[A-Za-z]+\s+)?([^\s\"']{8,})")),
    # The whole cookie value: it may hold placeholders already placed (they are stored restored, see find()).
    # Stopping at `<` left every cookie after a masked one in clear (seventh review, 2026-10-01). Any key ending
    # in cookie (`X-Auth-Cookie`, `HTTP_COOKIE`, `"http_cookie"`), then `:`, `=` or `=>`, then the value as it is
    # written: quoted (escapes kept), a list (Go's `Cookie:[...]`, every item of a Set-Cookie list), a dict, a
    # header to the end of the line, or an assignment (`cookie=sid=...; b=...`, a logfmt `cookie=x` value only)
    # - eighth and ninth reviews: a lookahead and a `\w-` boundary let Go's form and prefixed keys through.
    # A header value that is a placeholder followed by prose is a report quoting a masked cookie, not a cookie.
    ("SECRET", re.compile(_COOKIE_KEY + r"(?:=>|[:=])\s*+(?:\"((?:\\.|[^\"\\\r\n]){4,})\"|'((?:\\.|[^'\\\r\n]){4,})'"
                          r"|\[([^\]\r\n]{4,})\]|\{([^}\r\n]{4,})\})")),
    ("SECRET", re.compile(_COOKIE_KEY + r":\s*+(?!<[A-Z][A-Z0-9]*_\d+>(?:\s|$))[\"']?([^\r\n\"'`\]]{4,})")),
    ("SECRET", re.compile(_COOKIE_KEY + r"(?:=>|=(?!>))\s*+([^\s;,\"'\[{]+(?:;\s*[^\s;=]+=[^\s;]*)*)")),
    # A HAR entry (`{"name": "Cookie", "value": "..."}`), curl's `--cookie`/`-b`, and a cookie jar's repr.
    ("SECRET", re.compile(r"(?i)\"name\"\s*:\s*\"(?:set-)?cookie\"\s*,\s*\"value\"\s*:\s*\"((?:\\.|[^\"\\\r\n]){4,})\"")),
    ("SECRET", re.compile(r"(?<![\w-])(?:--cookie|-b)(?:\s+|=)(?:\"([^\"\r\n]{4,})\"|'([^'\r\n]{4,})'|([^\s\"'-][^\s\"']{3,}))")),
    ("SECRET", re.compile(r"<Cookie\s+([^\s=<>]+=[^\s<>]{4,})")),
    ("SECRET", re.compile(r"\b(?:mysql|mariadb)(?:-?dump|-?admin)?\b[^\r\n]*?\s-p([^\s\"']{3,})")),
    # A credential passed as a command-line flag. EXACT flag names (independent review 2026-09-28:
    # `--secret-name`, `--token-file`, `--token-ttl` are not credentials, and masking them removed
    # resource names from the evidence). Same line only; a value never starts with `-` or a quote.
    # `=` or whitespace before the opening quote: in JSON argv `"--password","x"` the quote right
    # after the flag is the flag's own closing quote, not the value's opening one.
    ("SECRET", re.compile(_CRED_FLAG + rf"(?:{_SP}*={_SP}*|{_SP}+)\"([^\"\n][^\"\n]{{0,255}})\"")),
    ("SECRET", re.compile(_CRED_FLAG + rf"(?:{_SP}*={_SP}*|{_SP}+)'([^'\n][^'\n]{{0,255}})'")),
    # `docker build --secret id=npmrc,src=.npmrc` names a secret; it is not one.
    ("SECRET", re.compile(_CRED_FLAG + rf"(?:=|{_SP}+(?![A-Za-z_][\w.-]*=))(?![-\"'])([^\s\"']{{3,}})")),
    ("SECRET", re.compile(r"(?i)\"--?(?:[a-z0-9]+-){0,2}(?:password|passwd|pass|pwd|api-?key|apikey|token|secret)"
                          r"\"\s*,\s*\"([^\"]{1,256})\"")),
    # Client tools whose short flag carries the password (same line only).
    ("SECRET", re.compile(r"\bredis-cli\b[^\r\n]*?[ \t]-a[ \t]+([^\s\"']{3,})")),
    ("SECRET", re.compile(r"\bsshpass[ \t]+-p[ \t]*([^\s\"']{3,})")),
    ("SECRET", re.compile(r"\b(?:docker[ \t]+login|mongo(?:sh)?|az[ \t]+login)\b[^\r\n]*?[ \t]-p[ \t]+([^\s\"']{3,})")),
    ("SECRET", re.compile(r"\bsqlcmd\b[^\r\n]*?[ \t]-P[ \t]*([^\s\"']{3,})")),
    ("SECRET", re.compile(r"\bldap\w*\b[^\r\n]*?[ \t]-w[ \t]+([^\s\"']{3,})")),
    ("SECRET", re.compile(r"\bhtpasswd\b[^\r\n]*?[ \t]-\w*b\w*[ \t]+\S+[ \t]+\S+[ \t]+([^\s\"']{3,})")),
    ("SECRET", re.compile(r"\bcurl\b[^\r\n]*?[ \t](?:-u[ \t]*|--user(?:=|[ \t]+))[^:\s]+:([^\s\"']{3,})")),
    ("SECRET", re.compile(r"(?i)\"auth\"\s*:\s*\"([^\"]{8,})\"")),
    # A quoted secret value is masked WHOLE: `password='hunter 2 x'` used to leak "2 x".
    ("SECRET", re.compile(
        r"(?i)(?:password|passwd|pwd|pass|secret|token|api[_\-]?key|apikey|credential|session)"
        r"[\w.\-]{0,20}[\"']?\s*[:=]\s*\"([^\"][^\"]{0,255})\"")),
    ("SECRET", re.compile(
        r"(?i)(?:password|passwd|pwd|pass|secret|token|api[_\-]?key|apikey|credential|session)"
        r"[\w.\-]{0,20}[\"']?\s*[:=]\s*'([^'][^']{0,255})'")),
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
        r"((?:[^\s\"';,&]|,(?!\s*[\w.\-]+\s*[:=]))+)"
    )),
    # A hex key under a credential's name no pattern above lists - `ENCRYPTION_KEY=`, `hmac_key=`,
    # `signing_key:`, `DD_APP_KEY=`, `Ocp-Apim-Subscription-Key:` - 32 or more hex characters (fourth
    # review, 2026-09-30, B-N8; HIGHENTROPY below needs upper case, lower case and a digit). Only these
    # names: "any name ending in key" also took `cache_key=<sha>` and `object_key=<digest>`, and a SECRET is
    # swept from every line, so a commit sha vanished from WARDEN's own deploy record (fifth review).
    ("SECRET", re.compile(r"(?i)(?:^|[\s\"',;{(\[?&])[\w.\-]{0,40}?(?:encryption|encrypt|crypt|hmac|signing|"
                          r"sign|secret|private|master|app|application|api|access|subscription|client|account|"
                          r"auth|service|license|webhook|session|storage|shared|vault|consumer|root|data|"
                          r"deploy|host|oauth|token|master|wrapping|kms|cmk|dek|kek)[_\-.]?key[\"']?\s*[:=]\s*"
                          r"[\"']?([0-9a-f]{32,})(?![0-9a-z])")),
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
    "credential", "credentials", "redacted", "hidden", "masked", "file", "env", "stdin", "absent",
})
# A value written as a word in angle brackets is a tool saying there is none: Go's `<nil>`, kubectl's `<none>` and
# `<set to the key ...>` (ninth review: since values may hold `<`, each was a secret swept from every line).
_SAYS_NONE = re.compile(r"<[a-z][a-z -]*>?")
# The pieces of a compound value (`_gh_sess=...; theme=dark`, `<uuid>.<secret>`): one with a letter and a digit is
# swept on its own too - masked only as the whole, the same secret echoed alone elsewhere stayed in clear (ninth).
def _secret_shaped(piece: str) -> bool:
    """Upper, lower and a digit, or 20+ characters of letters and digits: a session id or a key, not a region
    (`ap-south-2`) or a name an earlier pattern took in (an ARN after `secret:` swept the region everywhere)."""
    has = [any(c.isupper() for c in piece), any(c.islower() for c in piece), any(c.isdigit() for c in piece)]
    return all(has) or (len(piece) >= 20 and has[2] and (has[0] or has[1]))


_PIECE = re.compile(r"[^\s;,&=.:\"'\[\]{}<>]{8,}")

# A placeholder token, captured so `re.split` keeps it as its own segment: `<LABEL_123>`.
_LABELS = tuple(dict.fromkeys(label for label, _ in PATTERNS))
_PLACEHOLDER = re.compile(r"(<[A-Z][A-Z0-9]*_\d+>)")
# A terminal escape sequence (colour, cursor, title): not text, and glued to a key it hid the key from every pattern
# that needs a word boundary - `ESC[1mAKIA...` read as `mAKIA...` (ninth review, 2026-10-01).
_ANSI = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]")


def strip_ansi(text: str) -> str:
    """Escape sequences removed; a space where one stood between two word characters, so a boundary stays."""
    def cut(m: re.Match[str]) -> str:
        s, e = m.start(), m.end()
        glued = s > 0 and e < len(text) and (text[s - 1].isalnum() or text[s - 1] == "_") and \
            (text[e].isalnum() or text[e] == "_")
        return " " if glued else ""
    return _ANSI.sub(cut, text) if "\x1b" in text or "\x9b" in text else text


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
    r = _Redactor(mapping)
    out = r.find(text)
    if _sweep_copies:  # redact_many's first pass only FINDS values; its second pass masks
        out = r.sweep(out)
    return RedactionResult(text=out, mapping=r.mapping)


class _Redactor:
    """One placeholder namespace (map, reverse map, counters) shared by every text of one call."""

    def __init__(self, mapping: dict[str, str] | None) -> None:
        self.mapping = dict(mapping or {})
        self.reverse = {v: k for k, v in self.mapping.items()}
        self.counters: dict[str, int] = dict.fromkeys(_LABELS, 0)
        for k in self.mapping:
            kind = _kind(k)
            if kind in self.counters:
                self.counters[kind] += 1
        self._built_for = -1
        self._rules: dict[str, tuple[int, str, Any]] = {}
        self._finders: list[tuple[re.Pattern[str], dict[str, list[str]]]] = []
        self._slow: list[str] = []  # values checked one by one: nested too deep for the finder
        self._ordered: list[tuple[str, str]] = []

    def find(self, text: str) -> str:
        out = strip_ansi(text)
        for label, pattern in PATTERNS:

            def _sub(m: re.Match[str], label: str = label) -> str:
                # group(1) exists for TENANT, where only the value is sensitive, not the key name.
                # The first group that took part: a pattern may offer the value in several written forms.
                original = next((g for g in m.groups() if g is not None), m.group(0))
                if label == "SECRET" and (original.lower().strip(".,;:)(<>") in _NOT_A_VALUE
                                          or _SAYS_NONE.fullmatch(original)):
                    return m.group(0)
                # A value holding placeholders already placed (`Cookie: a=<JWT_1>; sid=...`) is stored restored,
                # so restore() gives the original back in one step; one that is nothing but placeholders is
                # masked already (seventh review: excluding `<` instead left the cookies after it in clear).
                full = _PLACEHOLDER.sub(lambda p: self.mapping.get(p.group(1), p.group(1)), original)
                # By its shape, not the map: the gate re-scans with a fresh one, and took `Cookie: <SECRET_1>` for a
                # new secret - every report quoting a masked cookie was withheld (eighth review, 2026-10-01).
                if _PLACEHOLDER.search(original) and not re.search(r"[A-Za-z0-9]", _PLACEHOLDER.sub("", original)):
                    return m.group(0)
                if full in self.reverse:
                    placeholder = self.reverse[full]
                else:
                    self.counters[label] += 1
                    placeholder = f"<{label}_{self.counters[label]}>"
                    self.mapping[placeholder] = full
                    self.reverse[full] = placeholder
                    for piece in _PIECE.findall(_PLACEHOLDER.sub(" ", original)) if label in SECRET_KINDS else ():
                        if piece != full and piece not in self.reverse and _secret_shaped(piece):
                            self.counters[label] += 1
                            self.mapping[f"<{label}_{self.counters[label]}>"] = piece
                            self.reverse[piece] = f"<{label}_{self.counters[label]}>"
                return m.group(0).replace(original, placeholder)

            out = pattern.sub(_sub, out)
        return out

    def _build(self) -> None:
        self._ordered = sorted(self.mapping.items(), key=lambda kv: -len(kv[1]))
        self._rules = {}
        for n, (placeholder, original) in enumerate(self._ordered):
            rule = _sweep(placeholder, original)
            if rule is not None and original not in self._rules:
                self._rules[original] = (n, placeholder, rule)
        # Values nested deeper than _MAX_NESTING (a planted chain like `aaaaZ`, `aaaaaZ`, ...) would nest one
        # finder's groups past the recursion limit. They are split into groups, round-robin in sorted order,
        # until every group is shallow enough for a finder of its own: checking them one by one against every
        # segment was quadratic - a comb of 8,008 values within the log caps took 126-144 s a pass (fifth
        # review, 2026-10-01). Only if no split works are they checked one by one.
        trie = _trie(self._rules)
        deep = {w for w in self._rules if _nesting(trie, w) > _MAX_NESTING}
        fast = [w for w in self._rules if w not in deep]
        split = _split(sorted(deep)) if deep else []
        self._slow = [] if split is not None else sorted(deep)
        # Each finder reports one value per position, the longest of its group. A shorter value starting at the
        # same position is always a prefix of it, and it must be checked too: when the longer one is an
        # identifier that is not standalone there, it is not replaced, and a shorter SECRET inside it stayed in
        # clear (fifth review, 2026-10-01). Read off each group's trie: the values ending along each path.
        self._finders = []
        try:
            for group in [g for g in [fast, *(split or [])] if g]:
                group_trie = _trie(group)
                self._finders.append((re.compile("(?=(" + _trie_regex(group_trie) + "))"),
                                      {w: _prefixes(group_trie, w) for w in group}))
        except (RecursionError, re.error, OverflowError):
            self._finders, self._slow = [], list(self._rules)  # the exact per-value loop
        self._built_for = len(self.mapping)

    def sweep(self, out: str) -> str:
        # Final literal sweep. The patterns FIND values; this masks the copies a regex boundary missed,
        # by the rule in _sweep: every copy of a secret, every standalone copy of an identifier. Real
        # example from a live cluster: a Kubernetes "failed to reserve container name" event embeds the pod
        # UID inside `..._default_<uid>_0`, where the trailing `b_` is not a `\b` boundary, so the `(uid)`
        # copy was masked and the `_0`-suffixed copy was not.
        #
        # ⛔ The sweep must NOT run inside placeholders already placed. If a TENANT value happens to be
        # the literal `UUID_1`, a naive sweep rewrites the neighbouring `<UUID_1>` to `<<TENANT_1>>` -
        # no leak, but two distinct secrets collapse to one label and restore() breaks. So the text is
        # split on placeholder tokens and only the segments BETWEEN them are swept. Longest originals
        # first, so a value that is a substring of another does not corrupt the longer replacement.
        #
        # Which values occur in a segment is found by ONE trie-shaped regex over all of them, built once
        # per map: testing every value against every segment was quadratic - 217 s for 2,000 lines of
        # 22,500 distinct values (fourth review, 2026-09-30).
        if self._built_for != len(self.mapping):
            self._build()
        parts = _PLACEHOLDER.split(out)  # even indices = free text, odd indices = whole placeholders
        for i in range(0, len(parts), 2):
            segment = parts[i]
            if not segment:
                continue
            present = {w for w in self._slow if w in segment}
            for finder, prefixes in self._finders:
                found = {m.group(1) for m in finder.finditer(segment)}
                present |= found.union(*(prefixes.get(w, ()) for w in found))
            todo = sorted((self._rules[o] for o in present if o in self._rules), key=lambda r: r[0])
            todo = [(self._ordered[n][1], ph, rule) for n, ph, rule in todo]
            for original, placeholder, rule in todo:
                if original not in segment:
                    continue
                if rule is _EVERY_COPY:
                    segment = segment.replace(original, placeholder)
                else:
                    segment = _standalone(original).sub(placeholder, segment)
            parts[i] = segment
        return "".join(parts)


_MAX_NESTING = 200


def _trie(words) -> dict[str, dict]:
    root: dict[str, dict] = {}
    for w in words:
        node = root
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = {}
    return root


def _nesting(root: dict[str, dict], word: str) -> int:
    """How many groups the finder would nest along `word`: its branching or ending nodes."""
    depth, node = 0, root
    for ch in word:
        node = node[ch]
        depth += len(node) > 1 or "" in node
    return depth


def _split(words: list[str]) -> list[list[str]] | None:
    """`words` in 2, 4, ... 64 round-robin groups, each nested no deeper than _MAX_NESTING; None if none works.
    Sorted first, so values that are prefixes of each other land in different groups."""
    groups = 2
    while groups <= 64:
        buckets = [words[i::groups] for i in range(groups)]
        if all(_nesting(t, w) <= _MAX_NESTING for b in buckets if b for t in [_trie(b)] for w in b):
            return buckets
        groups *= 2
    return None


def _prefixes(root: dict[str, dict], word: str) -> list[str]:
    """The other values of the trie that are prefixes of `word`."""
    out, node = [], root
    for i, ch in enumerate(word[:-1]):
        node = node[ch]
        if "" in node:
            out.append(word[:i + 1])
    return out


def _trie_regex(root: dict[str, dict]) -> str:
    """One regex matching any word of the trie at a position, longest first (greedy)."""

    def build(node: dict[str, dict]) -> str:
        alts = []
        for ch in sorted(k for k in node if k):
            chars, child = [ch], node[ch]
            while len(child) == 1 and "" not in child:  # a chain with no branch: one literal
                ((nxt, child),) = child.items()
                chars.append(nxt)
            alts.append(re.escape("".join(chars)) + build(child))
        if not alts:
            return ""
        body = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        return "(?:" + body + ")?" if "" in node else body

    return build(root)


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


# Every copy, anywhere: plain str.replace, which is what the escaped regex did.
_EVERY_COPY = object()
# Every standalone copy: the pattern is compiled when the value is found in a segment, not for every value.
_STANDALONE = object()


def _sweep(placeholder: str, original: str):
    """How the copies of `original` are swept: every copy (_EVERY_COPY), every standalone copy (a
    compiled pattern), or not at all (None)."""
    if len(original) < 3:
        return None
    if _kind(placeholder) in SECRET_KINDS and len(original) >= 4:
        # Every copy, whatever it looks like. An exemption for "plain words and assignments" (932d515)
        # left real secrets in clear - a base64 key ending in `==`, a passphrase, a letters-only
        # password - and the gate passed them (fourth review, 2026-09-30). Known limit, open (audit
        # B-N4 row): a log writer who plants `password=<word>` masks that word in every line, WARDEN's
        # own reads included. A secret or an identifier must never stay in clear, so that limit is
        # handled by escalating, not by leaving copies unmasked.
        return _EVERY_COPY
    if (original.isdigit() and len(original) < 6) or original.lower() in _COMMON:
        return None
    return _STANDALONE


@functools.lru_cache(maxsize=8192)
def _standalone(original: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![A-Za-z0-9]){re.escape(original)}(?![A-Za-z0-9])")


def redact_many(items: list[str], mapping: dict[str, str] | None = None) -> tuple[list[str], dict[str, str]]:
    """Redact several strings as ONE text, with one placeholder namespace: a value found in any of them
    is masked in all of them. One pass left a secret found in a later line in clear in the earlier
    ones (second review, 2026-09-30); the first pass now only finds, the second masks."""
    r = _Redactor(mapping)
    found = [r.find(item) for item in items]
    return [r.sweep(text) for text in found], r.mapping
