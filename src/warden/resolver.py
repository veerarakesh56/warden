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
import re
from typing import Any

from . import catalog
from .models import ActionKind, Alert, RemediationProposal

# The labels that name one platform's resource, and the catalogue parameters they fill (outermost first).
_PLATFORM_LABELS: dict[str, tuple[tuple[str, str], ...]] = {
    "lambda": (("lambda", "function"),),
    "events": (("eventbridge_rule", "rule"),),
    "sqs": (("sqs", "queue"),),
    "athena": (("athena_workgroup", "workgroup"),),
    "elb": (("load_balancer", "load_balancer"),),
    "apigw": (("apigw_stage", "stage"), ("apigw_rest", "api")),  # the API is what a person names
    "ecs": (("ecs_cluster", "cluster"), ("ecs_service", "service")),
    "dynamodb": (("dynamodb_table", "table"),),
    "k8s": (("namespace", "namespace"), ("deployment", "deployment")),
    "rds": (("aurora_cluster", "cluster"),),
}


def _bare(alert: Alert, target: str) -> str:
    """The target as the labels write it: the model often names `lambda:warden-dev-x` for the label `warden-dev-x`
    (held-out G9-F: 9 of 48 targets), and a right fix was then never planned. Only a short kind word before the
    first colon is dropped, and only when what is left is a label's exact value - never an ARN's parts."""
    kind, sep, rest = target.partition(":")
    if sep and _KIND_WORD.fullmatch(kind) and rest in alert.labels.values():
        return rest
    return target


_KIND_WORD = re.compile(r"[a-z][a-z0-9_-]{1,23}")


def _platform(alert: Alert, target: str) -> tuple[str, dict[str, str]] | None:
    """The platform whose labelled resource the target names, and the parameters the labels give."""
    target = _bare(alert, target)
    for platform, labels in _PLATFORM_LABELS.items():
        values = [alert.labels.get(label, "") for label, _ in labels]
        if all(values) and "," not in "".join(values) and values[-1] == target:
            return platform, {param: alert.labels[label] for label, param in labels}
    return None


# The label that names each platform's resource (the last of _PLATFORM_LABELS), and labels that only qualify one.
_NAMING_LABEL = {labels[-1][0]: platform for platform, labels in _PLATFORM_LABELS.items()}
_QUALIFIERS = frozenset({"alarm", "namespace", "ecs_cluster", "eks_cluster", "apigw_stage", "selector", "log_group",
                         "cluster", "lambda_qualifier", "service", "environment", "region", "account"})
# The resource kinds each special path is reached from (_configuration: the AppConfig application, never a label).
_SPECIAL_KINDS = {ActionKind.revert_config: frozenset(), ActionKind.freeze_changes: frozenset({"lambda", "ecs"})}


def no_fix_path(alert: Alert, proposal: RemediationProposal) -> str:
    """Why no catalogue entry could carry out this proposal, or "" when one might (G10-B, policy P30).

    Decided only when the target is a resource the labels name: a NAT gateway, a file system, a Lambda function. A
    target the labels do not name is left to the planner and to P14 - unknown is not "none"."""
    if proposal.action in (ActionKind.no_action, ActionKind.escalate_to_human):
        return ""
    target = _bare(alert, proposal.target)
    kinds = {key for key, value in alert.labels.items() if value == target and key not in _QUALIFIERS}
    if not kinds:
        return ""
    platforms = {_NAMING_LABEL.get(key) for key in kinds} | {"db" for key in kinds if key in _DB_LABELS}
    able = _SPECIAL_KINDS.get(proposal.action, frozenset(catalog.FOR_ACTION.get(proposal.action, {})))
    if platforms & able:
        return ""
    named = ", ".join(sorted(kinds))
    return f"no catalogue entry carries out {proposal.action.value} on {target} (labelled {named})"


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
    if "minutes" in entry.params:
        return {**params, "minutes": 60}  # an hour, then ARC ends it by itself
    if "per_second" in entry.params:
        # Slow enough not to flood the consumer, fast enough to finish inside the verify window (review H3).
        waiting = live.get("waiting")
        if not isinstance(waiting, int):
            return "the dead-letter queue's depth was not read"
        rate = max(1, -(-waiting // catalog.REDRIVE_SECONDS))
        if rate > 50:
            return f"{waiting} messages cannot move inside the verify window at 50 a second; a person runs it"
        return {**params, "per_second": rate}
    if "rate_limit" in entry.params:
        out = dict(params)
        for key in ("rate_limit", "burst_limit"):
            cur, cap = live.get(f"current_{key}"), live.get(f"account_{key}")
            if not isinstance(cur, int) or cur < 1 or not isinstance(cap, int) or cap <= cur:
                return f"the stage's {key} or the account's room for it was not read"
            out[key] = min(2 * cur, cap)
        return out
    if "replicas" in entry.params:
        cur = live.get("current_replicas")
        if not isinstance(cur, int) or cur < 1:
            return "the current replica count was not read"
        return {**params, "replicas": cur + 1}
    return params


def _configuration(alert: Alert, proposal: RemediationProposal, live: Any) -> tuple[dict[str, Any] | None, str]:
    """revert_config: the AppConfig environment whose monitors name the alarm (AWS's own link), its latest deployment
    - and the proposal must name that configuration."""
    alarm = alert.labels.get("alarm", "")
    if not alarm or "," in alarm:
        return None, "the alert names no single alarm, so no configuration it guards can be found"
    entry = catalog.CATALOG["appconfig_revert"]
    state = live(entry.name, {"alarm": alarm})
    one = {k: state.get(k) for k in ("application", "config_env", "deployment")}
    if not all(isinstance(v, set | frozenset) and len(v) == 1 for v in one.values()):
        return None, "no single AppConfig deployment WARDEN may revert is guarded by this alarm"
    params = {"alarm": alarm, **{k: next(iter(v)) for k, v in one.items()}}
    if proposal.target not in (params["application"], f"{params['application']}/{params['config_env']}"):
        return None, "the proposal's target is not the configuration this alarm guards"
    problems = catalog.validate(entry.name, params, state)
    if problems:
        return None, "; ".join(problems)
    return {"entry": entry.name, "params": params, "service": params[entry.target_param],
            "environment": alert.environment, "incident_id": alert.alert_id}, ""


def _security_group(alert: Alert, proposal: RemediationProposal, live: Any) -> tuple[dict[str, Any] | None, str]:
    """revert_change on a security group (G10-D): the ONE write CloudTrail recorded on it before the alarm went off -
    the platform's live read decides which, and whether it may be undone; the model only names the group."""
    alarm = alert.labels.get("alarm", "")
    if not alarm or "," in alarm:
        return None, "the alert names no single alarm, so no change before it can be dated"
    group = _bare(alert, proposal.target)
    entry = catalog.CATALOG["ec2_revert_sg_change"]
    state = live(entry.name, {"group": group, "alarm": alarm})
    events = state.get("event")
    if not isinstance(events, set | frozenset) or len(events) != 1:
        return None, f"no change to {group} WARDEN may undo: {state.get('refused') or 'the group could not be read'}"
    params = {"alarm": alarm, "group": group, "event": next(iter(events))}
    problems = catalog.validate(entry.name, params, state)
    if problems:
        return None, "; ".join(problems)
    return {"entry": entry.name, "params": params, "service": params[entry.target_param],
            "environment": alert.environment, "incident_id": alert.alert_id}, ""


# A security group's id: what revert_change names when a CHANGE line shows a write to one.
_SG_ID = re.compile(r"sg-[0-9a-f]{8,17}")


def _sessions(alert: Alert, proposal: RemediationProposal, live: Any) -> tuple[dict[str, Any] | None, str]:
    """terminate_connections (G10-B): the labelled database cluster or instance, when the database platform's
    connection goes to that very server - a database carries no tag, so its endpoint's own name is the link (an RDS
    endpoint starts with the instance or cluster id). A `hostaddr` decides the address whatever the host says, so a
    connection that names one is never taken for the labelled server. The platform then closes only its own
    application logins' sessions, idle in a transaction for at least five minutes (platforms/db.py)."""
    target = _bare(alert, proposal.target)
    if not any(alert.labels.get(key) == target for key in _DB_LABELS):
        return None, "the proposal's target is not a database the alert's labels name"
    entry = catalog.CATALOG["db_terminate_idle_in_tx"]
    state = live(entry.name, {})
    names, server = state.get("database"), str((state.get("state") or {}).get("server", ""))
    if not isinstance(names, set | frozenset) or len(names) != 1:
        return None, "the database platform is not connected, or names no application logins it may close"
    if "hostaddr" in server or not re.search(rf"(?:^|[\s=,@]){re.escape(target)}\.", server):
        return None, f"the database WARDEN is connected to is not {target}"
    params = {"database": next(iter(names)), "min_idle_seconds": 300, "max_sessions": 20}
    problems = catalog.validate(entry.name, params, state)
    if problems:
        return None, "; ".join(problems)
    return {"entry": entry.name, "params": params, "service": params[entry.target_param],
            "environment": alert.environment, "incident_id": alert.alert_id}, ""


# Labels that name a database server: the database platform's link from an alarm (G10-B).
_DB_LABELS = ("database", "aurora_cluster", "rds_instance", "rds_cluster", "db_instance")


def _freeze(alert: Alert, proposal: RemediationProposal, live: Any) -> tuple[dict[str, Any] | None, str]:
    """freeze_changes: the labelled Lambda function or ECS service, and the pipeline stage its own tag names."""
    labels, target = alert.labels, _bare(alert, proposal.target)
    if labels.get("lambda") and "," not in labels["lambda"] and target == labels["lambda"]:
        resource = labels["lambda"]
    elif labels.get("ecs_cluster") and labels.get("ecs_service") and target == labels["ecs_service"]:
        resource = f"{labels['ecs_cluster']}/{labels['ecs_service']}"
    else:
        return None, "the proposal's target is not a Lambda function or ECS service the alert's labels name"
    entry = catalog.CATALOG["codepipeline_freeze"]
    state = live(entry.name, {"resource": resource})
    one = {k: state.get(k) for k in ("pipeline", "stage")}
    if not all(isinstance(v, set | frozenset) and len(v) == 1 for v in one.values()):
        return None, (f"{resource} names no pipeline stage WARDEN may freeze (its warden:pipeline tag, a stage that "
                      "exists, of its environment, with deploys still flowing)")
    params = {"resource": resource, **{k: next(iter(v)) for k, v in one.items()}}
    problems = catalog.validate(entry.name, params, state)
    if problems:
        return None, "; ".join(problems)
    return {"entry": entry.name, "params": params, "service": params[entry.target_param],
            "environment": alert.environment, "incident_id": alert.alert_id}, ""


def request_for(alert: Alert, proposal: RemediationProposal, live: Any) -> tuple[dict[str, Any] | None, str]:
    """A FixRequest's fields for this proposal, or None and why. `live(entry, params)` is the platform's live read."""
    if proposal.action in (ActionKind.no_action, ActionKind.escalate_to_human):
        return None, "the proposal is to hand the incident to a person"
    if proposal.action is ActionKind.revert_config:
        return _configuration(alert, proposal, live)
    if proposal.action is ActionKind.freeze_changes:
        return _freeze(alert, proposal, live)
    if proposal.action is ActionKind.terminate_connections:
        return _sessions(alert, proposal, live)
    if proposal.action is ActionKind.revert_change and _SG_ID.fullmatch(_bare(alert, proposal.target)):
        return _security_group(alert, proposal, live)
    found = _platform(alert, proposal.target)
    if found is None:
        return None, "the proposal's target is not a resource the alert's labels name"
    platform, params = found
    entry = catalog.for_action(proposal.action, platform)
    if entry is None:
        return None, f"no catalogue entry carries out {proposal.action.value} on {platform}"
    if "alarm" in entry.params:  # G10-D3: the change is dated by the alarm going off
        alarm = alert.labels.get("alarm", "")
        if not alarm or "," in alarm:
            return None, "the alert names no single alarm, so no change before it can be dated"
        params["alarm"] = alarm
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
