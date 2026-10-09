"""From an approved diagnosis to a fix plan (G9-D1, 2026-10-10).

The audit (2026-10-10, finding 4): a diagnosis never became a plan. FOR_ACTION had no caller; a fix started only when
someone called the MCP `request_remediation` tool with an entry and its parameters. Now, when the verifier passes a
proposal for a person (approved_for_human), this module turns it into a catalogue request - and the RemediationWorkflow
it starts still waits for a signed human approval before anything changes.

Deterministic, and never from text:
- the platform and the resource come from the alert's resource LABELS (resources.py, from the alarm's own metric);
  the proposal's target must be that resource's name, or nothing is planned;
- each reference parameter (the version to move to, the task definition to roll back to) is filled only when the
  platform's live read allows exactly one value - the known-good one it computed (catalog C8); never chosen here;
- a bounded number (capacity, concurrency) is the catalogue's own bound applied to the live value, conservatively.
Anything that does not resolve is a reason, recorded, and the incident stays with the person who was told.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import catalog
from .models import ActionKind, Alert, RemediationProposal

# The labels that name one platform's resource, and the catalogue parameters they fill (outermost first).
_PLATFORM_LABELS: dict[str, tuple[tuple[str, str], ...]] = {
    "lambda": (("lambda", "function"),),
    "ecs": (("ecs_cluster", "cluster"), ("ecs_service", "service")),
    "dynamodb": (("dynamodb_table", "table"),),
    "k8s": (("namespace", "namespace"), ("deployment", "deployment")),
    "rds": (("aurora_cluster", "cluster"),),
}


def _platform(alert: Alert, target: str) -> tuple[str, dict[str, str]] | None:
    """The platform whose labelled resource the target names, and the parameters the labels give."""
    for platform, labels in _PLATFORM_LABELS.items():
        values = [alert.labels.get(label, "") for label, _ in labels]
        if all(values) and "," not in "".join(values) and values[-1] == target:
            return platform, {param: alert.labels[label] for label, param in labels}
    return None


def _bounded(entry: catalog.Entry, params: dict[str, Any], live: dict[str, Any]) -> dict[str, Any] | str:
    """The catalogue's bounded numbers, conservatively, from the live value."""
    if "concurrency" in entry.params:
        cur, free = live.get("current_concurrency"), live.get("unreserved_account_concurrency")
        if not isinstance(cur, int) or not isinstance(free, int):
            return "the current concurrency was not read"
        room = free - 100  # AWS keeps 100 unreserved for the account
        step = min(max(cur, 10), room)  # at most double, never past the account's room
        if step < 1:
            return "the account has no room for more concurrency"
        return {**params, "concurrency": cur + step}
    if "capacity" in entry.params:
        cur = live.get("current_capacity")
        if not isinstance(cur, int) or cur < 1:
            return "the current capacity was not read"
        return {**params, "capacity": 2 * cur}
    if "replicas" in entry.params:
        cur = live.get("current_replicas")
        if not isinstance(cur, int) or cur < 1:
            return "the current replica count was not read"
        return {**params, "replicas": cur + 1}
    return params


def request_for(alert: Alert, proposal: RemediationProposal, live: Any) -> tuple[dict[str, Any] | None, str]:
    """A FixRequest's fields for this proposal, or None and why. `live(entry, params)` is the platform's live read."""
    if proposal.action in (ActionKind.no_action, ActionKind.escalate_to_human):
        return None, "the proposal is to hand the incident to a person"
    found = _platform(alert, proposal.target)
    if found is None:
        return None, "the proposal's target is not a resource the alert's labels name"
    platform, params = found
    entry = catalog.for_action(proposal.action, platform)
    if entry is None:
        return None, f"no catalogue entry carries out {proposal.action.value} on {platform}"
    if entry.name == "lambda_move_alias":
        alias = alert.labels.get("lambda_qualifier", "")
        if not alias or alias.isdigit() or alias == "$LATEST":
            return None, "the alarm names no Lambda alias to move"
        params["alias"] = alias
    state = live(entry.name, params)
    for name, spec in entry.params.items():
        if name in params or spec.kind != "ref":
            continue
        allowed = state.get(name)
        if not isinstance(allowed, (set, frozenset, list, tuple)) or len(allowed) != 1:
            return None, f"no single known-good {name} was read (WARDEN does not choose one)"
        params[name] = next(iter(allowed))
    params = _bounded(entry, params, state)
    if isinstance(params, str):
        return None, params
    problems = catalog.validate(entry.name, params, state)
    if problems:
        return None, "; ".join(problems)
    return {"entry": entry.name, "params": params, "service": params[entry.target_param],
            "environment": alert.environment, "incident_id": alert.alert_id}, ""


def workflow_id(request: dict[str, Any]) -> str:
    """One open remediation per resource and environment (register C3) - the MCP path's own id scheme."""
    key = catalog.target_key(request["entry"], request["params"])
    return f"rem-{request['environment']}-{hashlib.sha256(key.encode()).hexdigest()[:16]}"
