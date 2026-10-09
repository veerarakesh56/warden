"""Which more resources an investigation may read (G9-B, 2026-10-10).

The model may ask, after a diagnosis, to read up to three related resources before deciding again. It names each by a
resource kind (a resources.LABEL_KEYS label) and a name. This module decides which requests are read: only a name that
is already WARDEN's own knowledge - the alert's resource labels, or a token in a trusted, structured evidence item (kind
C: CONFIG, STATE, ALARM, CHANGE ... lines, written from AWS's API responses) - is accepted. A name that appears only in a
log line, an event, a fact or the model's own words is refused: text an application wrote must not choose what WARDEN
reads (the research's "trusted targets only", 2026-10-10).
"""

from __future__ import annotations

import re
from typing import Any

from . import evidence
from .models import Alert, ContextBundle
from .resources import LABEL_KEYS

MAX_REQUESTS = 3
# Labels the stack backend reads as comma lists (aws_stack._names): a second resource of that kind is added to them.
_LISTS = frozenset({"lambda", "sqs", "eventbridge_rule", "deployment"})
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}")


def known_names(alert: Alert, context: ContextBundle) -> set[str]:
    """Every name WARDEN itself holds for this incident: its resource labels' values and the tokens of its trusted
    structured evidence items (each `key=value` value, each bare token)."""
    names = {v.strip() for k, v in alert.labels.items() if k in LABEL_KEYS for v in v.split(",") if v.strip()}
    for item in evidence.index(context).values():
        if item.id[0] != "C":
            continue
        for part in re.split(r"[\s,=\[\]()]+", item.text):
            if _TOKEN.fullmatch(part):
                names.add(part)
    return names


def widen(alert: Alert, context: ContextBundle, requests: list[dict[str, Any]]) -> tuple[Alert, list, list]:
    """The alert with the accepted requests added to its resource labels, and what was accepted and refused (why)."""
    known = known_names(alert, context)
    labels = dict(alert.labels)
    accepted: list[dict[str, str]] = []
    refused: list[dict[str, str]] = []
    for raw in requests[: MAX_REQUESTS * 2]:
        kind, name = str(raw.get("kind", "")), str(raw.get("name", ""))
        why = ""
        if len(accepted) >= MAX_REQUESTS:
            why = f"at most {MAX_REQUESTS} per round"
        elif kind not in LABEL_KEYS:
            why = "not a resource kind WARDEN reads"
        elif not _TOKEN.fullmatch(name):
            why = "not a plain resource name"
        elif name not in known:
            why = "the name is not in the alert's labels or any trusted evidence item"
        elif labels.get(kind) and name in labels[kind].split(","):
            why = "already read"
        elif labels.get(kind) and kind not in _LISTS:
            why = f"another {kind} is already read"
        if why:
            refused.append({"kind": kind[:40], "name": name[:120], "why": why})
            continue
        labels[kind] = f"{labels[kind]},{name}" if labels.get(kind) else name
        accepted.append({"kind": kind, "name": name})
    widened = Alert.model_validate({**alert.model_dump(), "labels": labels})
    return widened, accepted, refused
