"""Which more resources an investigation may read (G9-B, 2026-10-10; tightened after the independent review).

The model may ask, after a diagnosis, to read up to three related resources before deciding again, each a resource
kind and a name. A request is read only when every rule holds:

- the kind is one WARDEN reads through the environment's reader role (READABLE): never a database (its readers use
  the runtime's connection string), a Kubernetes namespace or deployment (read with the worker's own credentials), a
  secret, a log group or the alarm itself (independent review 2026-10-10, F2/F9);
- the name is WARDEN's own knowledge for that kind: an alert label of THAT kind (a label's value is never re-read
  under another kind - review F1), a `STATE <kind> <name>` line of that kind, or a token of another trusted,
  structured evidence item (kind C: CONFIG, ALARM, CHANGE ... lines from AWS's API responses);
- the name belongs to the incident's environment (its environment prefix): nothing in another environment is read,
  even where the reader role's grant is not name-scoped (review F9).
A name from a log line, an event, a fact or the model's own words is refused and audited.
"""

from __future__ import annotations

import re
from typing import Any

from . import evidence
from .aws_describe import TABLE
from .environments import env_of_name
from .models import Alert, ContextBundle

MAX_REQUESTS = 3
# What the stack backend reads, for a resource label, through the environment's reader role.
READABLE = frozenset(TABLE) | frozenset({"lambda", "sqs", "dynamodb_table", "eventbridge_rule", "sns_topic"})
# Labels the stack backend reads as comma lists (aws_stack._names): a second resource of that kind is added to them.
_LISTS = frozenset({"lambda", "sqs", "eventbridge_rule"})
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}")
_STATE = re.compile(r"^STATE ([a-z][a-z0-9_]{1,40}) (\S+)")


def known_names(alert: Alert, context: ContextBundle) -> tuple[dict[str, set[str]], set[str]]:
    """Names WARDEN itself holds: by kind (an alert label of that kind, a STATE line of that kind), and kind-free (the
    tokens of the other trusted, structured items)."""
    by_kind: dict[str, set[str]] = {}
    for k, v in alert.labels.items():
        by_kind.setdefault(k, set()).update(x.strip() for x in v.split(",") if x.strip())
    loose: set[str] = set()
    for item in evidence.index(context).values():
        if item.id[0] != "C":
            continue
        m = _STATE.match(item.text)
        if m:
            by_kind.setdefault(m.group(1), set()).add(m.group(2))
            continue
        loose |= {part for part in re.split(r"[\s,=\[\]()]+", item.text) if _TOKEN.fullmatch(part)}
    return by_kind, loose


def _why_refused(kind: str, name: str, environment: str, known: tuple[dict[str, set[str]], set[str], set[str]],
                 labels: dict[str, str]) -> str:
    """Why one request is refused, or "" when it is accepted. `known`: the names WARDEN knows by kind, the loose
    names in its trusted evidence, and the names the alert's labels already give."""
    by_kind, loose, labelled = known
    if kind not in READABLE:
        return "not a resource kind WARDEN reads through the environment's reader role"
    if not _TOKEN.fullmatch(name):
        return "not a plain resource name"
    if env_of_name(name) != environment:
        return "not a resource of the incident's environment"
    if name not in by_kind.get(kind, set()) and (name in labelled or name not in loose):
        return "the name is not WARDEN's own knowledge for that kind"
    if labels.get(kind) and name in labels[kind].split(","):
        return "already read"
    if labels.get(kind) and kind not in _LISTS:
        return f"another {kind} is already read"
    return ""


def widen(alert: Alert, context: ContextBundle, requests: list[dict[str, Any]]) -> tuple[Alert, list, list]:
    """The alert with the accepted requests added to its resource labels, and what was accepted and refused (why)."""
    by_kind, loose = known_names(alert, context)
    labelled = {v for vals in (x.split(",") for x in alert.labels.values()) for v in vals}
    labels = dict(alert.labels)
    accepted: list[dict[str, str]] = []
    refused: list[dict[str, str]] = []
    for raw in requests[: MAX_REQUESTS * 2]:
        kind, name = str(raw.get("kind", "")), str(raw.get("name", ""))
        why = (f"at most {MAX_REQUESTS} per round" if len(accepted) >= MAX_REQUESTS
               else _why_refused(kind, name, alert.environment, (by_kind, loose, labelled), labels))
        if why:
            refused.append({"kind": kind[:40], "name": name[:120], "why": why})
            continue
        labels[kind] = f"{labels[kind]},{name}" if labels.get(kind) else name
        accepted.append({"kind": kind, "name": name})
    widened = Alert.model_validate({**alert.model_dump(), "labels": labels})
    return widened, accepted, refused
