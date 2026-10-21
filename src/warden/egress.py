"""Egress: everything WARDEN sends out of its network, named, checked and recorded (owner, 2026-10-20).

Every destination is on one inventory (DESTINATIONS) with what it carries. Three guards hold it:

- **The model.** Every model provider's `complete` (providers._REGISTRY - Eldane's provider included) is wrapped by
  `guard_model`: the system prompt and the user prompt are scanned with every redaction pattern, STRICTLY - an email,
  an IP address, a tenant or account id is as much a leak to a model as a key is - and a prompt that still holds one
  is refused before it is sent (fail closed). The model is shown placeholders (`<EMAIL_1>`) and nothing else.
- **Every HTTP request urllib makes** (Slack, GitHub, Datadog, PagerDuty, webhooks, AWS's documentation): an
  interpreter audit hook (`install`) sees each one before a connection is made. A host on no destination is refused;
  a request to a destination outside the network has its body and query scanned the same strict way, minus the
  destination's own credential fields (Slack's OAuth client secret, PagerDuty's routing key) and WARDEN's own
  approval and record links; one that still holds a value is refused (fail closed).
- **Every name lookup** (`socket.getaddrinfo`: the model SDKs, boto3, Slack's socket client, the OTLP exporter): a host
  on no destination is refused. A new destination is a code change to this inventory, reviewed.

Every request to a destination outside the network, and every model call, is recorded - masked: the destination,
its purpose, the payload's size and SHA-256, how many placeholders of each kind it carries, and the verdict. One JSON
log line per egress (logger `warden.egress`: CloudWatch Logs, Live Tail and Logs Insights read it),
and a row on the signed audit (`egress.sent` / `egress.blocked`) where the process has opened it
(runtime_base.open_audit). A blocked egress names the kinds it found, never a value.

Honest limits:
- Temporal's client is Rust (temporalio's core): its connections raise no Python audit event. Its payloads are
  encrypted (codec.py) and the runtime's network rules limit where it can connect (terraform, register B23).
- Behind a proxy (HTTPS_PROXY), a client other than urllib looks up the proxy's name, not its target's: the name
  check cannot see where such a client goes through the proxy (urllib's requests are still checked by their real
  address). The runtime sets no proxy; a laptop that does keeps that limit.
- A raw socket connected to an IP address without a lookup bypasses the name check; nothing in src/warden does that
  (tests/test_egress.py holds the static inventory of every module that opens a network client).
- The hook is installed by the processes that talk to a real environment (`warden ...` with WARDEN_ENV set, every
  Lambda). The model guard holds in every process, installed or not.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
import threading
import urllib.error
import urllib.parse
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .gate import normalise
from .redaction import redact

_LOG = logging.getLogger("warden.egress")
_LOG.setLevel(logging.INFO)  # the ledger is wanted wherever the root logger shows warnings only (the Lambdas)

SENT = "egress.sent"
BLOCKED = "egress.blocked"


@dataclass(frozen=True)
class Destination:
    """One place WARDEN's traffic goes. `outside`: a third party, outside the network - its content is checked and
    every request recorded. `hosts`: exact names, or `*.suffix` for any name under it. `credentials`: body fields
    that are the destination's own credential, sent to it by design and not scanned. `secret_path`: the URL's path is
    itself a secret (an incoming webhook), so the ledger names only its first segment."""
    name: str
    outside: bool
    hosts: tuple[str, ...]
    carries: str
    credentials: frozenset[str] = frozenset()
    secret_path: bool = False
    bodies_checked: bool = False  # inside the network, but a body sent to it by urllib is checked and recorded


_MODEL = "a model prompt: redacted evidence, placeholders only"
_REPORT = "the gated incident report"
_SERVICE_READS = "reads only: queries naming a service"
_DOCS = "an AWS error code and a service word"
_LINE = "egress %s"  # every ledger line: Logs Insights finds them by it (docs/DATA-EGRESS.md)
# The inventory. docs/DATA-EGRESS.md is written from it; tests/test_egress.py holds every network client in src/warden
# to one of these names.
STATIC: tuple[Destination, ...] = (
    Destination("anthropic", True, ("api.anthropic.com",), _MODEL),
    Destination("openai", True, ("api.openai.com",), _MODEL),
    Destination("groq", True, ("api.groq.com",), _MODEL),
    Destination("openrouter", True, ("openrouter.ai",), _MODEL),
    Destination("gemini", True, ("generativelanguage.googleapis.com",), _MODEL),
    Destination("slack-webhook", True, ("hooks.slack.com",), _REPORT, secret_path=True),
    Destination("slack", True, ("slack.com", "*.slack.com"),
                "the gated incident report and thread replies; sign-in with Slack (OAuth code exchange)",
                credentials=frozenset({"client_id", "client_secret", "code"})),
    Destination("teams-webhook", True, ("*.webhook.office.com",), _REPORT, secret_path=True),
    Destination("github", True, ("api.github.com",),
                "the gated change record (an issue); reads of recent commits and of code review's findings (GET)"),
    # Code review's findings on a deployed pull request (findings.py, #41): a GET whose query names the project and
    # the pull request's number, no body.
    Destination("sonarcloud", True, ("sonarcloud.io",), "reads only: a pull request's code-review findings (GET)"),
    Destination("datadog", True, ("api.datadoghq.com", "api.us3.datadoghq.com", "api.us5.datadoghq.com",
                                  "api.datadoghq.eu", "api.ap1.datadoghq.com", "api.ap2.datadoghq.com",
                                  "api.uk1.datadoghq.com", "api.ddog-gov.com", "api.us2.ddog-gov.com"),
                "reads only: queries naming a service, a time window and fixed metrics"),
    Destination("pagerduty", True, ("events.pagerduty.com",), "a page: the gated report's first line",
                credentials=frozenset({"routing_key"})),
    Destination("aws-docs", True, ("knowledge-mcp.global.api.aws",), _DOCS),
    # AWS's What's New and blog feeds (the AWS updates watch, register B6): a GET, no payload; the text read is untrusted.
    Destination("aws-news", True, ("aws.amazon.com",), "reads only: AWS's What's New and blog RSS feeds (GET)"),
    Destination("temporal", True, ("*.tmprl.cloud",), "encrypted workflow payloads (codec.py); ids and names in clear"),
    # The AWS account WARDEN runs in and watches: its own APIs, not a third party.
    # A name under AWS's domains may be another account's (a bucket, an API): WARDEN's own AWS calls go through boto3,
    # never urllib, so a urllib request with a body to any of them is checked and recorded like one outside (review).
    Destination("aws", False, ("*.amazonaws.com", "*.amazonaws.com.cn"),
                "WARDEN's own AWS account: reads, the approved fix, the audit, secrets, KMS", bodies_checked=True),
    Destination("in-network", False, ("localhost", "*.svc", "*.cluster.local", "*.internal"),
                "this machine and the private network: a cluster's services, instance metadata"),
)

# A setting holding a URL or address WARDEN is told to reach: its host is that destination.
_CONFIGURED = (
    ("WARDEN_WEBHOOK_URL", "generic-webhook", True, _REPORT, True),
    ("WARDEN_TEAMS_WEBHOOK", "teams-webhook", True, _REPORT, True),
    ("WARDEN_SLACK_WEBHOOK", "slack-webhook", True, _REPORT, True),
    ("WARDEN_BASE_URL", "model-api", True, _MODEL, False),
    ("WARDEN_AWS_DOCS_URL", "aws-docs", True, _DOCS, False),
    ("WARDEN_ALERTMANAGER_URL", "alertmanager", True, "reads only: which alerts are active", False),
    ("WARDEN_GRAFANA_LOGS_URL", "grafana", True, _SERVICE_READS, False),
    ("WARDEN_GRAFANA_TRACES_URL", "grafana", True, _SERVICE_READS, False),
    ("WARDEN_GRAFANA_METRICS_URL", "grafana", True, _SERVICE_READS, False),
    ("OTEL_EXPORTER_OTLP_ENDPOINT", "tracing", True, "spans: node names, timings, scrubbed error text", False),
    ("WARDEN_TEMPORAL_ADDRESS", "temporal", True, "encrypted workflow payloads (codec.py)", False),
    # A proxy carries the other destinations' traffic: its name is looked up, not theirs. What is sent through it is
    # still checked by its real address (review, 2026-10-20).
    ("HTTPS_PROXY", "proxy", False, "the tunnel to a listed destination", False),
    ("https_proxy", "proxy", False, "the tunnel to a listed destination", False),
    ("HTTP_PROXY", "proxy", False, "requests to a listed destination", False),
    ("http_proxy", "proxy", False, "requests to a listed destination", False),
)
# A database WARDEN reads or writes: its address is in a DSN.
_DSNS = ("WARDEN_DB_DSN", "WARDEN_DB_TERMINATE_DSN", "WARDEN_STACK_DB_PRIMARY_RO_DSN", "WARDEN_STACK_DB_REPLICA_RO_DSN",
         "WARDEN_AUDIT_DSN", "WARDEN_STACK_REDIS_RO_DSN")


class EgressBlocked(urllib.error.URLError):
    """An egress refused before it was sent. An OSError, as every caller already treats a failed call; `sent` False
    and a status that is not a retryable one, so the model client neither retries it nor counts it billed. Its text
    names the destination and the kinds found - never a value."""

    sent = False
    status_code = 0  # not an HTTP status: refused here, and a retry would be refused the same way

    def __init__(self, destination: str, why: str, kinds: Iterable[str] = ()) -> None:
        self.destination, self.kinds = destination, sorted(set(kinds))
        found = f": {', '.join(self.kinds)} still in it" if self.kinds else ""
        super().__init__(f"egress to {destination} refused - {why}{found}")


def _host_of(value: str) -> str:
    if "://" not in value:
        value = "//" + value  # host:port, as the Temporal address is written
    return (urllib.parse.urlsplit(value).hostname or "").lower()


def destinations(env: dict[str, str] | None = None) -> tuple[Destination, ...]:
    """The inventory for this process: the static destinations, then each configured address's host."""
    env = os.environ if env is None else env
    extra: list[Destination] = []
    for name, dest, outside, carries, secret_path in _CONFIGURED:
        host = _host_of(env.get(name, "").strip()) if env.get(name, "").strip() else ""
        if host:
            extra.append(Destination(dest, outside, (host,), carries, secret_path=secret_path))
    for name in _DSNS:
        host = _host_of(env.get(name, "").strip()) if env.get(name, "").strip() else ""
        if host:
            extra.append(Destination("database", False, (host,), "SQL to WARDEN's own or a watched database"))
    return STATIC + tuple(extra)


def _matches(pattern: str, host: str) -> bool:
    return host.endswith(pattern[1:]) if pattern.startswith("*.") else host == pattern


def destination_of(host: str | bytes | None, env: dict[str, str] | None = None) -> Destination | None:
    """The destination a host belongs to; None when it is on no destination. An address is the private network's
    when it is not globally routable (private, loopback, link-local - instance and task metadata), and no
    destination's otherwise."""
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    name = str(host or "").strip().strip("[]").rstrip(".").lower()
    if not name:
        return None
    try:
        address = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        address = None
    if address is not None and address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped  # `::ffff:<public IPv4>` is that IPv4 (some Python releases call it non-global)
    if address is not None:
        # Not globally routable (private, loopback, link-local, shared, reserved): it cannot be a host on the
        # internet, so it is the private network's - or nobody's.
        return None if address.is_global else STATIC[-1]
    found = [d for d in destinations(env) if any(_matches(p, name) for p in d.hosts)]
    # A configured destination's exact host before a wildcard: a webhook on an AWS name is the webhook's.
    exact = [d for d in found if name in d.hosts]
    return (exact or found or [None])[0]


# --------------------------------------------------------------------------- the content check

_PLACEHOLDER = re.compile(r"<([A-Z][A-Z0-9]*)_\d+>")
_DIGITS = re.compile(r"\d+")


def kinds_in(text: str) -> list[str]:
    """The kinds of value the redactor still finds in `text`, as written and normalised (an invisible character or
    a control between a key's letters hides it from a pattern as written) - every kind: nothing is showable here."""
    found: set[str] = set()
    for view in {text, normalise(text)}:
        found.update(p.strip("<>").rsplit("_", 1)[0] for p in redact(view).mapping)
    return sorted(found)


def _query_kinds(query: str) -> list[str]:
    """As kinds_in, for a URL's query values: a value that is only digits is a number (an epoch time, a page size),
    not a phone number."""
    found: set[str] = set()
    for _key, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        if not _DIGITS.fullmatch(value):
            found.update(kinds_in(value))
    return sorted(found)


def _own_links() -> re.Pattern[str] | None:
    """WARDEN's own approval and record links, exactly as chatops.approval_links lets them out: capability URLs on
    the approval domain, sent to Slack by design."""
    rp = os.environ.get("WARDEN_APPROVAL_RP_ID", "").strip()
    if not rp:
        return None
    # The approval link's token is a capability and is exempt whole. A record link's incident id is NOT: only the
    # address before it is taken out, and the id is scanned like any text (review: `/r/<an address>` hid the address).
    return re.compile(rf"https://{re.escape(rp)}/(?:a/[A-Za-z0-9_-]{{43}}(?![A-Za-z0-9_-])|r/?)")


def _strings(value: Any, skip: frozenset[str]) -> Iterable[str]:
    """Every string in a structure, keys included, each on its own (a JSON dump is a key=value shape the redactor
    would rightly read as a credential); the destination's own credential fields left out."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                yield k
            if k not in skip:
                yield from _strings(v, skip)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v, skip)


def body_strings(data: Any, content_type: str = "", skip: frozenset[str] = frozenset()) -> list[str]:
    """A request body as the strings it carries: JSON's strings, a form's fields, or the text itself."""
    if data is None:
        return []
    if isinstance(data, (bytes, bytearray, memoryview)):
        text = bytes(data).decode("utf-8", "replace")
    elif isinstance(data, str):
        text = data
    else:  # a file or an iterable: what it holds cannot be read here without consuming it
        raise EgressBlocked("a request", f"its body ({type(data).__name__}) cannot be checked")
    if "x-www-form-urlencoded" in content_type.lower():
        pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
        return [s for k, v in pairs for s in (k, *(() if k in skip else (v,)))]
    try:
        return list(_strings(json.loads(text), skip))
    except ValueError:
        return [text]


def content_kinds(strings: Iterable[str]) -> list[str]:
    """The kinds found in `strings`, WARDEN's own links taken out first: Teams and a generic webhook carry them inside
    a line of text (`label: link`), Slack as a button's whole address."""
    links = _own_links()
    return sorted({k for s in strings for k in kinds_in(links.sub(" ", s) if links else s)})


# --------------------------------------------------------------------------- the ledger

_SINK: dict[str, Any] = {}
_OPEN: list[Any] = []  # every log ledger_to was given and not yet forgotten, the newest last


def _audit_errors() -> tuple[type[BaseException], ...]:
    """What a failed audit write raises: the database driver's errors (SQLite's, and PostgreSQL's when installed),
    a lost connection, a refused KMS signature."""
    import sqlite3

    errors: list[type[BaseException]] = [OSError, ValueError, RuntimeError, sqlite3.Error]
    try:
        import psycopg

        errors.append(psycopg.Error)
    except ImportError:
        pass
    try:
        from botocore.exceptions import BotoCoreError, ClientError

        errors += [BotoCoreError, ClientError]
    except ImportError:
        pass
    return tuple(errors)


_AUDIT_ERRORS = _audit_errors()
_GUARD = threading.local()


def ledger_to(log: Any) -> None:
    """Record egress rows on this audit log too (runtime_base.open_audit: every runtime process)."""
    _OPEN.append(log)
    _SINK["audit"] = log


def forget(log: Any) -> None:
    """`log` is closing: its rows stop (AuditLog.close). Another log the process opened since is kept; when the
    closing one was the newest, the newest log still open takes the rows again (review: closing a second log left
    the first, still open, without them)."""
    _OPEN[:] = [o for o in _OPEN if o is not log]
    if _SINK.get("audit") is log:
        if _OPEN:
            _SINK["audit"] = _OPEN[-1]
        else:
            _SINK.pop("audit", None)


def _correlation() -> str:
    """The incident an egress belongs to: the workflow of the activity sending it, when there is one."""
    try:
        from temporalio import activity

        if activity.in_activity():
            return activity.info().workflow_id
    except (ImportError, RuntimeError):  # outside Temporal there is simply no workflow
        return "egress"
    return "egress"


def placeholders(payload: str) -> dict[str, int]:
    return dict(sorted(Counter(m.group(1) for m in _PLACEHOLDER.finditer(payload)).items()))


def record(destination: Destination, purpose: str, payload: str, verdict: str, kinds: Iterable[str] = ()) -> dict:
    """One ledger row: written as a JSON log line, and on the audit where one is open. Never a value."""
    raw = payload.encode("utf-8", "replace")
    row = {"destination": destination.name, "outside": destination.outside, "purpose": purpose,
           "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "placeholders": placeholders(payload),
           "verdict": verdict, "kinds": sorted(set(kinds))}
    _LOG.log(logging.WARNING if verdict == "BLOCK" else logging.INFO, _LINE,
             json.dumps(row, sort_keys=True, separators=(",", ":")))
    log = _SINK.get("audit")
    if log is not None and not getattr(_GUARD, "busy", False):
        _GUARD.busy = True
        try:
            log.append(_correlation(), BLOCKED if verdict == "BLOCK" else SENT, row)
        except _AUDIT_ERRORS as exc:
            # No row, no egress: an egress the audit cannot hold is not made (fail closed). The audit being down stops
            # every step of an incident anyway; this one says so on the log.
            _LOG.exception("egress: the audit row could not be written (%s): not sent", type(exc).__name__)
            raise EgressBlocked(destination.name, "its ledger row could not be written") from None
        finally:
            _GUARD.busy = False
    return row


# --------------------------------------------------------------------------- the model

_PROVIDER_DESTINATION = {"anthropic": "anthropic", "claude_cli": "anthropic", "claude-cli": "anthropic",
                         "gemini": "gemini", "bedrock": "aws"}


def _model_destination(provider: Any) -> Destination:
    name = str(getattr(provider, "name", "") or "")
    by_name = {d.name: d for d in destinations()}
    if name in _PROVIDER_DESTINATION:
        return by_name[_PROVIDER_DESTINATION[name]]
    base = str(getattr(provider, "base_url", "") or "")
    if not base:  # no host at all: a provider in this process (a test's, a replay) is named as itself
        return Destination(f"model:{name or 'unknown'}", True, (), _MODEL)
    found = destination_of(_host_of(base))
    if found is None:
        # A model host on no destination is refused, never recorded under a made-up name (review: an unlisted
        # base_url was named `model:openai` and sent wherever the hook was not installed).
        raise _unlisted(redact(_host_of(base)).text[:120])
    return found


def guard_model(provider: Any, system: str, user: str) -> None:
    """The check before any prompt reaches any model (every provider, local ones too): no value the redactor finds,
    of any kind. Recorded either way; raises EgressBlocked when it refuses."""
    dest = _model_destination(provider)
    payload = f"{system}\n\n{user}"
    kinds = sorted(set(kinds_in(system)) | set(kinds_in(user)))
    purpose = f"model {getattr(provider, 'model', '')}".strip()
    record(dest, purpose, payload, "BLOCK" if kinds else "PASS", kinds)
    if kinds:
        raise EgressBlocked(dest.name, "the prompt is not fully masked", kinds)


def guard_provider(cls: type) -> type:
    """Wrap a provider class's `complete` with guard_model, once. Every class in providers._REGISTRY is wrapped where
    the registry is defined, so a provider built from it - by resolve() or directly, as Eldane does - is guarded."""
    original: Callable[..., Any] = cls.complete
    if getattr(original, "warden_egress", False):
        return cls

    def complete(self: Any, *, system: str, user: str, schema: Any = None) -> Any:
        guard_model(self, system, user)
        return original(self, system=system, user=user, schema=schema)

    complete.warden_egress = True
    complete.__doc__ = original.__doc__
    cls.complete = complete
    return cls


# --------------------------------------------------------------------------- the interpreter hook

# `on`: the hook checks. install() turns it on and nothing in src/warden turns it off; the test suite's conftest turns
# it back off after a test that installed it (an audit hook cannot be removed), so no test depends on which ran before.
_STATE: dict[str, Any] = {"installed": False, "on": False, "seen": set()}


def _purpose(dest: Destination, method: str, url: str) -> str:
    path = urllib.parse.urlsplit(url).path or "/"
    keep = 1 if dest.secret_path else 3
    shown = "/".join(path.split("/")[: keep + 1])
    return f"{method} {redact(shown).text}"[:120]


def _unlisted(host: str) -> EgressBlocked:
    """The refusal of a host on no destination, on the ledger first (its name redacted)."""
    _LOG.warning(_LINE, json.dumps({"destination": None, "verdict": "BLOCK", "why": "no destination", "host": host}))
    return EgressBlocked("an unlisted host", "it is on no destination (egress.DESTINATIONS)")


def check_request(url: str, data: bytes | str | None, headers: dict[str, str] | None, method: str) -> None:
    """The check urllib's every request passes (install): its host on a destination; to one outside the network,
    nothing the redactor finds in its body or query, and a row on the ledger. Raises EgressBlocked."""
    parts = urllib.parse.urlsplit(url)
    dest = destination_of(parts.hostname)
    if dest is None:
        raise _unlisted(redact(str(parts.hostname or "")).text[:120])
    if not (dest.outside or (dest.bodies_checked and data is not None)):
        return
    content_type = next((v for k, v in (headers or {}).items() if k.lower() == "content-type"), "")
    strings = body_strings(data, content_type, dest.credentials)
    query = _query_kinds(parts.query) if dest.outside else []  # a presigned AWS address carries its signature there
    kinds = sorted(set(content_kinds(strings)) | set(query))
    payload = "\n".join(strings)
    record(dest, _purpose(dest, method, url), payload, "BLOCK" if kinds else "PASS", kinds)
    if kinds:
        raise EgressBlocked(dest.name, "the request is not fully masked", kinds)


def check_host(host: Any) -> None:
    """The check every name lookup passes (install): a host on no destination is refused. The first lookup of each
    destination in a process is on the ledger."""
    if host is None or host in ("", b""):
        return  # a listener's own address (getaddrinfo(None, port)): nothing is looked up, nothing leaves
    dest = destination_of(host)
    shown = redact(str(host.decode("ascii", "replace") if isinstance(host, bytes) else host)).text[:120]
    if dest is None:
        raise _unlisted(shown)
    if (dest.name, shown) not in _STATE["seen"]:
        _STATE["seen"].add((dest.name, shown))
        _LOG.info(_LINE, json.dumps({"destination": dest.name, "outside": dest.outside, "connect": shown}))


# Every lookup the socket module offers (review: gethostbyname bypassed getaddrinfo's event), and urllib's request.
_EVENTS = frozenset({"urllib.Request", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex",
                     "socket.gethostbyaddr"})


def _hook(event: str, args: tuple) -> None:
    if event not in _EVENTS or not _STATE["on"] or getattr(_GUARD, "hooked", False):
        return
    _GUARD.hooked = True  # the ledger's own writes (the audit, KMS) pass the hook too, unchecked twice
    try:
        if event == "urllib.Request":
            url, data, headers, method = args
            check_request(str(url), data, dict(headers or {}), str(method))
        else:
            check_host(args[0])
    finally:
        _GUARD.hooked = False


def install() -> bool:
    """Put the hook on this interpreter, once (an audit hook cannot be removed). True when it is on."""
    if not _STATE["installed"]:
        sys.addaudithook(_hook)
        _STATE["installed"] = True
    _STATE["on"] = True
    return True


def install_for_environment() -> bool:
    """`install`, for a process that talks to a real environment (WARDEN_ENV named): the runtime's workers and
    Lambdas, and the laptop's commands against them. A demo or a test with no environment is left as it is."""
    return install() if os.environ.get("WARDEN_ENV", "").strip() else False
