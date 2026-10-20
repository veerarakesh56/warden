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


_MODEL = "a model prompt: redacted evidence, placeholders only"
# The inventory. docs/DATA-EGRESS.md is written from it; tests/test_egress.py holds every network client in src/warden
# to one of these names.
STATIC: tuple[Destination, ...] = (
    Destination("anthropic", True, ("api.anthropic.com",), _MODEL),
    Destination("openai", True, ("api.openai.com",), _MODEL),
    Destination("groq", True, ("api.groq.com",), _MODEL),
    Destination("openrouter", True, ("openrouter.ai",), _MODEL),
    Destination("gemini", True, ("generativelanguage.googleapis.com",), _MODEL),
    Destination("slack-webhook", True, ("hooks.slack.com",), "the gated incident report", secret_path=True),
    Destination("slack", True, ("slack.com", "*.slack.com"),
                "the gated incident report and thread replies; sign-in with Slack (OAuth code exchange)",
                credentials=frozenset({"client_id", "client_secret", "code"})),
    Destination("teams-webhook", True, ("*.webhook.office.com",), "the gated incident report", secret_path=True),
    Destination("github", True, ("api.github.com",), "the gated change record (an issue); reads of recent commits"),
    Destination("datadog", True, ("api.datadoghq.com", "api.us3.datadoghq.com", "api.us5.datadoghq.com",
                                  "api.datadoghq.eu", "api.ap1.datadoghq.com", "api.ap2.datadoghq.com",
                                  "api.uk1.datadoghq.com", "api.ddog-gov.com", "api.us2.ddog-gov.com"),
                "reads only: queries naming a service, a time window and fixed metrics"),
    Destination("pagerduty", True, ("events.pagerduty.com",), "a page: the gated report's first line",
                credentials=frozenset({"routing_key"})),
    Destination("aws-docs", True, ("knowledge-mcp.global.api.aws",), "an AWS error code and a service word"),
    Destination("temporal", True, ("*.tmprl.cloud",), "encrypted workflow payloads (codec.py); ids and names in clear"),
    # The AWS account WARDEN runs in and watches: its own APIs, not a third party.
    Destination("aws", False, ("*.amazonaws.com", "*.amazonaws.com.cn", "*.api.aws"),
                "WARDEN's own AWS account: reads, the approved fix, the audit, secrets, KMS"),
    Destination("in-network", False, ("localhost", "*.svc", "*.cluster.local", "*.internal"),
                "this machine and the private network: a cluster's services, instance metadata"),
)

# A setting holding a URL or address WARDEN is told to reach: its host is that destination.
_CONFIGURED = (
    ("WARDEN_WEBHOOK_URL", "generic-webhook", True, "the gated incident report", True),
    ("WARDEN_TEAMS_WEBHOOK", "teams-webhook", True, "the gated incident report", True),
    ("WARDEN_SLACK_WEBHOOK", "slack-webhook", True, "the gated incident report", True),
    ("WARDEN_BASE_URL", "model-api", True, _MODEL, False),
    ("WARDEN_AWS_DOCS_URL", "aws-docs", True, "an AWS error code and a service word", False),
    ("WARDEN_ALERTMANAGER_URL", "alertmanager", True, "reads only: which alerts are active", False),
    ("WARDEN_GRAFANA_LOGS_URL", "grafana", True, "reads only: queries naming a service", False),
    ("WARDEN_GRAFANA_TRACES_URL", "grafana", True, "reads only: queries naming a service", False),
    ("WARDEN_GRAFANA_METRICS_URL", "grafana", True, "reads only: queries naming a service", False),
    ("OTEL_EXPORTER_OTLP_ENDPOINT", "tracing", True, "spans: node names, timings, scrubbed error text", False),
    ("WARDEN_TEMPORAL_ADDRESS", "temporal", True, "encrypted workflow payloads (codec.py)", False),
)
# A database WARDEN reads or writes: its address is in a DSN.
_DSNS = ("WARDEN_DB_DSN", "WARDEN_DB_TERMINATE_DSN", "WARDEN_STACK_DB_PRIMARY_RO_DSN", "WARDEN_STACK_DB_REPLICA_RO_DSN",
         "WARDEN_AUDIT_DSN")


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


# The private network's addresses: RFC 1918 and a VPC's shared range, loopback, link-local (instance and task metadata),
# IPv6 unique-local. Not `is_private`, which also takes the documentation ranges and other reserved space.
_PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
                                                    "fe80::/10"))


def _matches(pattern: str, host: str) -> bool:
    return host.endswith(pattern[1:]) if pattern.startswith("*.") else host == pattern


def destination_of(host: str | bytes | None, env: dict[str, str] | None = None) -> Destination | None:
    """The destination a host belongs to; None when it is on no destination. An address is the private network's
    when it is private, loopback or link-local (instance and task metadata), and no destination's otherwise."""
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    name = str(host or "").strip().strip("[]").rstrip(".").lower()
    if not name:
        return None
    try:
        address = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        address = None
    if address is not None:
        return STATIC[-1] if any(address in net for net in _PRIVATE if net.version == address.version) else None
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
    return re.compile(rf"https://{re.escape(rp)}/(?:a/[A-Za-z0-9_-]{{43}}|r(?:/[A-Za-z0-9._-]{{1,120}})?)")


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


def body_strings(data: bytes | str | None, content_type: str = "", skip: frozenset[str] = frozenset()) -> list[str]:
    """A request body as the strings it carries: JSON's strings, a form's fields, or the text itself."""
    if data is None:
        return []
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    if "x-www-form-urlencoded" in content_type.lower():
        pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
        return [s for k, v in pairs for s in (k, *(() if k in skip else (v,)))]
    try:
        return list(_strings(json.loads(text), skip))
    except ValueError:
        return [text]


def content_kinds(strings: Iterable[str]) -> list[str]:
    links = _own_links()
    return sorted({k for s in strings if not (links and links.fullmatch(s)) for k in kinds_in(s)})


# --------------------------------------------------------------------------- the ledger

_SINK: dict[str, Any] = {}


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
    _SINK["audit"] = log


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
    _LOG.log(logging.WARNING if verdict == "BLOCK" else logging.INFO, "egress %s",
             json.dumps(row, sort_keys=True, separators=(",", ":")))
    log = _SINK.get("audit")
    if log is not None and not getattr(_GUARD, "busy", False):
        _GUARD.busy = True
        try:
            log.append(_correlation(), BLOCKED if verdict == "BLOCK" else SENT, row)
        except _AUDIT_ERRORS as exc:
            # No row, no egress: an egress the audit cannot hold is not made (fail closed). The audit being down stops
            # every step of an incident anyway; this one says so on the log.
            _LOG.error("egress: the audit row could not be written (%s): not sent", type(exc).__name__)
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
    found = destination_of(_host_of(base)) if base else None
    return found or Destination(f"model:{name or 'unknown'}", True, (), _MODEL)


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

_STATE: dict[str, Any] = {"installed": False, "seen": set()}


def _purpose(dest: Destination, method: str, url: str) -> str:
    path = urllib.parse.urlsplit(url).path or "/"
    keep = 1 if dest.secret_path else 3
    shown = "/".join(path.split("/")[: keep + 1])
    return f"{method} {redact(shown).text}"[:120]


def check_request(url: str, data: bytes | str | None, headers: dict[str, str] | None, method: str) -> None:
    """The check urllib's every request passes (install): its host on a destination; to one outside the network,
    nothing the redactor finds in its body or query, and a row on the ledger. Raises EgressBlocked."""
    parts = urllib.parse.urlsplit(url)
    dest = destination_of(parts.hostname)
    if dest is None:
        _LOG.warning("egress %s", json.dumps({"destination": None, "verdict": "BLOCK", "why": "no destination",
                                               "host": redact(str(parts.hostname or "")).text[:120]}))
        raise EgressBlocked("an unlisted host", "it is on no destination (egress.DESTINATIONS)")
    if not dest.outside:
        return
    content_type = next((v for k, v in (headers or {}).items() if k.lower() == "content-type"), "")
    strings = body_strings(data, content_type, dest.credentials)
    kinds = sorted(set(content_kinds(strings)) | set(_query_kinds(parts.query)))
    payload = "\n".join(strings)
    record(dest, _purpose(dest, method, url), payload, "BLOCK" if kinds else "PASS", kinds)
    if kinds:
        raise EgressBlocked(dest.name, "the request is not fully masked", kinds)


def check_host(host: Any) -> None:
    """The check every name lookup passes (install): a host on no destination is refused. The first lookup of each
    destination in a process is on the ledger."""
    dest = destination_of(host)
    shown = redact(str(host.decode("ascii", "replace") if isinstance(host, bytes) else host)).text[:120]
    if dest is None:
        _LOG.warning("egress %s", json.dumps({"destination": None, "verdict": "BLOCK", "why": "no destination",
                                               "host": shown}))
        raise EgressBlocked("an unlisted host", "it is on no destination (egress.DESTINATIONS)")
    if (dest.name, shown) not in _STATE["seen"]:
        _STATE["seen"].add((dest.name, shown))
        _LOG.info("egress %s", json.dumps({"destination": dest.name, "outside": dest.outside, "connect": shown}))


def _hook(event: str, args: tuple) -> None:
    if event not in ("urllib.Request", "socket.getaddrinfo") or getattr(_GUARD, "hooked", False):
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
    return True


def install_for_environment() -> bool:
    """`install`, for a process that talks to a real environment (WARDEN_ENV named): the runtime's workers and
    Lambdas, and the laptop's commands against them. A demo or a test with no environment is left as it is."""
    return install() if os.environ.get("WARDEN_ENV", "").strip() else False
