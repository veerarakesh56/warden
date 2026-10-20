"""B12: the actor role's own permissions, checked before anyone is asked to approve a plan.

A plan a person approves and the actor role then cannot carry out wastes the approval, and its undo failing half-way
trips the kill switch. So when a plan is made (activities.resolve_plan, in the read zone), the AWS policy simulator
(iam:SimulatePrincipalPolicy - read-only, nothing is changed) is asked whether the environment's actor role allows
the exact calls the fix will make: a plan it denies is refused before any approval request is sent.

The calls are the executor's own, never a list kept beside it that could drift: the entry's write code runs up to
its first call to AWS against an actor that records the session it asks for (actions, exact resources, condition)
and sends nothing (`trace`). The undo's calls are the same actions on the same resources, except where the undo is
another action (UNDO), or where nothing is undone (NO_UNDO); every AWS entry is in one of the three tables.

Honest limits:
- The simulator evaluates the role's identity policies, its permissions boundary and the organization's SCPs. It
  does not read resource policies (a KMS key policy, a queue policy) - a call those deny still fails at apply.
- A condition key WARDEN cannot supply leaves a call "unconfirmed": recorded and kept beside the plan, not a refusal.
  The keys supplied: the session's SourceIdentity (`inc-<id>`), the target's own environment tag (P18 already made it
  the plan's environment), and every key in the session's own condition.
- A plan whose write code refuses while being traced is unconfirmed too: its apply refuses on its own.
- Only the AWS platform is checked: the Kubernetes and database platforms say "not checked".
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from . import identity
from .observability import _safe_error

ALLOWED = "allowed"
DENIED = "ACTOR-PERMISSION"
_PUT_CONCURRENCY = "lambda:PutFunctionConcurrency"
# The undo is another action: forward action -> the undo's actions, per entry (platforms/aws.py, `back=True`).
_SG = {f"ec2:{a}SecurityGroup{s}": (f"ec2:{b}SecurityGroup{s}",)
       for s in ("Ingress", "Egress") for a, b in (("Authorize", "Revoke"), ("Revoke", "Authorize"))}
UNDO: dict[str, dict[str, tuple[str, ...]]] = {
    "events_enable_rule": {"events:EnableRule": ("events:DisableRule",)},
    "events_disable_rule": {"events:DisableRule": ("events:EnableRule",)},
    "arc_zonal_shift": {"arc-zonal-shift:StartZonalShift": ("arc-zonal-shift:CancelZonalShift",)},
    "sqs_redrive_dlq": {"sqs:StartMessageMoveTask": ("sqs:CancelMessageMoveTask",)},
    "codepipeline_freeze": {"codepipeline:DisableStageTransition": ("codepipeline:EnableStageTransition",)},
    "elb_reregister_targets": {"elasticloadbalancing:RegisterTargets": ("elasticloadbalancing:DeregisterTargets",)},
    "asg_resume_processes": {"autoscaling:ResumeProcesses": ("autoscaling:SuspendProcesses",)},
    "ec2_revert_sg_change": _SG,
    "ec2_restore_route": {"ec2:CreateRoute": ("ec2:DeleteRoute",), "ec2:DeleteRoute": ("ec2:CreateRoute",)},
}
# The undo's action read from the plan's snapshot: back to the reserved concurrency the change set (`after`) - none
# deletes the reservation, a number puts it (aws._lambda_restore).
UNDO_BY_SNAPSHOT: dict[str, Callable[[dict[str, Any]], tuple[str, ...]]] = {
    "lambda_restore_concurrency": lambda snap: (("lambda:DeleteFunctionConcurrency",) if snap.get("after") is None
                                                else (_PUT_CONCURRENCY,)),
}
# The undo is the same actions on the same resources.
SAME_UNDO = frozenset({"lambda_move_alias", "lambda_set_reserved_concurrency", "lambda_enable_esm",
                       "lambda_disable_esm", "dynamodb_raise_capacity", "ecs_rollback_service", "ecs_scale_service",
                       "apigw_raise_stage_throttle", "ecs_restore_desired", "lambda_restore_settings",
                       "sqs_restore_attributes", "dynamodb_restore_capacity", "asg_restore_capacity",
                       "apigw_restore_stage"})
# Nothing is undone (AwsPlatform.rollback says "nothing to roll back"): only the apply's calls are checked.
NO_UNDO = frozenset({"athena_stop_query", "appconfig_revert", "ecs_restart_service", "kms_cancel_key_deletion",
                     "secrets_restore_secret", "kinesis_restore_retention", "aurora_failover"})


class Traced(Exception):
    """Raised by the recording client at the executor's first call to AWS: nothing was sent, and the sessions asked
    for are recorded. The write code may wrap it (AwsPlatform._change turns any exception into its own error, `from`
    it): `trace` finds it in the chain of causes."""


def _traced(exc: BaseException | None) -> bool:
    seen = 0
    while exc is not None and seen < 20:
        if isinstance(exc, Traced):
            return True
        exc, seen = exc.__cause__ or exc.__context__, seen + 1
    return False


def recorder(sessions: list[dict[str, Any]]) -> Callable[..., Callable[[str], Any]]:
    """An actor (platforms/aws.py `Actor`) that records each session asked for and hands out clients that send
    nothing: their first call ends the trace."""

    class _Stop:
        def __getattr__(self, name: str) -> Callable[..., Any]:
            def call(*_a: Any, **_kw: Any) -> Any:
                raise Traced(name)
            return call

    def actor(who: dict[str, Any], actions: list[str], resources: list[str], condition: dict[str, Any] | None,
              also: Any = ()) -> Callable[[str], Any]:
        sessions.append({"actions": sorted(set(actions)), "resources": sorted(set(resources)),
                         "condition": condition or {}})
        for acts, res in also:
            sessions.append({"actions": sorted(set(acts)), "resources": sorted(set(res)), "condition": {}})
        return lambda _service: _Stop()

    return actor


def trace(run: Callable[[Callable[..., Any]], Any]) -> list[dict[str, Any]]:
    """The sessions `run(actor)` asks for before its first call to AWS. Its own refusal - an exception the trace's
    stop did not cause - propagates."""
    sessions: list[dict[str, Any]] = []
    try:
        run(recorder(sessions))
    except Exception as exc:
        if not _traced(exc):
            raise
    return sessions


def undo_sessions(entry: str, sessions: list[dict[str, Any]],
                  snapshot: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """The sessions the entry's undo asks for, from its apply's (and, for some, the plan's snapshot). Raises KeyError
    for an entry in none of the tables: a new entry is declared before it is checked (tests/test_permits_b12.py)."""
    if entry in NO_UNDO:
        return []
    if entry in SAME_UNDO:
        return [dict(s) for s in sessions]
    if entry in UNDO_BY_SNAPSHOT:
        acts = sorted(UNDO_BY_SNAPSHOT[entry](snapshot or {}))
        return [{**s, "actions": acts} for s in sessions]
    swap = UNDO[entry]
    out = []
    for s in sessions:
        acts = sorted({u for a in s["actions"] for u in swap.get(a, (a,))})
        out.append({**s, "actions": acts, "resources": _undo_resources(entry, acts, s["resources"])})
    return out


def _undo_resources(entry: str, actions: list[str], resources: list[str]) -> list[str]:
    """The undo's resources. The same as the apply's, except a security group change: an authorize is checked on the
    group and the rule it creates (`security-group-rule/*`, as aws._sg_revert asks), a revoke on the group only."""
    if entry != "ec2_revert_sg_change":
        return list(resources)
    groups = [r for r in resources if ":security-group/" in r]
    rules = [f"{g.rsplit(':', 1)[0]}:security-group-rule/*" for g in groups
             if any(a.startswith("ec2:AuthorizeSecurityGroup") for a in actions)]
    return sorted({*groups, *rules})


def actor_role_arn(environment: str) -> str:
    """The environment's actor role, as platforms/aws.from_environment names it; "" when none is configured."""
    template = os.environ.get("WARDEN_AWS_ROLE_ARN_TEMPLATE", "").strip()
    if template:
        return template.format(env=environment, role="actor") if "{env}" in template and "{role}" in template else ""
    return os.environ.get("WARDEN_AWS_ACTOR_ROLE_ARN", "").strip()


def _context(incident: str, environment: str, env_tag: str, condition: dict[str, Any]) -> list[dict[str, Any]]:
    keys: dict[str, str] = {"aws:SourceIdentity": identity.correlation(incident),
                            f"aws:ResourceTag/{env_tag}": environment}
    for values in condition.values():
        for key, value in (values or {}).items():
            keys[str(key)] = str(value)
    return [{"ContextKeyName": k, "ContextKeyValues": [v], "ContextKeyType": "string"} for k, v in sorted(keys.items())]


def _results(iam: Any, role: str, session: dict[str, Any], context: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out, marker = [], None
    for _ in range(10):  # a session names a handful of actions and resources: one page, rarely two
        got = iam.simulate_principal_policy(PolicySourceArn=role, ActionNames=session["actions"],
                                            ResourceArns=session["resources"], ContextEntries=context,
                                            **({"Marker": marker} if marker else {}))
        out += got.get("EvaluationResults") or []
        if got.get("IsTruncated") and not got.get("Marker"):
            raise RuntimeError("the simulator said its answer goes on, and gave no way to read the rest")
        marker = got.get("Marker") if got.get("IsTruncated") else None
        if not marker:
            return out
    # A denial on a page not read would be lost: an answer read in part is an answer not read.
    raise RuntimeError("the simulator's answer had more pages than WARDEN reads")


def _resource(arn: str) -> str:
    """A resource as said in a reason: its type and name, without the account and Region."""
    parts = str(arn).split(":", 5)
    return parts[5] if len(parts) == 6 else str(arn)


def _verdicts(results: list[dict[str, Any]]) -> list[tuple[str, str, str, list[str]]]:
    """(action, resource, decision, missing context keys), per resource when the simulator says so."""
    out = []
    for r in results:
        action = str(r.get("EvalActionName", "?"))
        per = r.get("ResourceSpecificResults") or [
            {"EvalResourceName": r.get("EvalResourceName", "*"), "EvalResourceDecision": r.get("EvalDecision"),
             "MissingContextValues": r.get("MissingContextValues")}]
        for p in per:
            missing = sorted({*(p.get("MissingContextValues") or []), *(r.get("MissingContextValues") or [])})
            out.append((action, str(p.get("EvalResourceName", "*")), str(p.get("EvalResourceDecision")), missing))
    return out


def _unanswered(session: dict[str, Any], results: list[dict[str, Any]]) -> list[str]:
    """Each action and resource the session asked about that the simulator's answer does not cover."""
    out = []
    for action in session["actions"]:
        rows = [r for r in results if r.get("EvalActionName") == action]
        if rows and any(not r.get("ResourceSpecificResults") for r in rows):
            continue  # one decision for the action on every resource asked about
        covered = {str(p.get("EvalResourceName")) for r in rows for p in r["ResourceSpecificResults"]} if rows else set()
        out += [f"{action} on {_resource(res)}" for res in session["resources"] if res not in covered]
    return out


def _aws_errors() -> tuple[type[Exception], ...]:
    """What a call to AWS raises when it fails: botocore's own errors, a refused session, a lost connection."""
    errors: list[type[Exception]] = [RuntimeError, OSError]
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:  # no AWS extra installed: nothing but the platform's own errors can come
        return tuple(errors)
    return (*errors, BotoCoreError, ClientError)


def check(entry: str, *, run: Callable[[Callable[..., Any]], Any], iam: Callable[[], Any], incident: str,
          environment: str, env_tag: str = "Environment", role: str | None = None,
          snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
    """Whether the environment's actor role allows the calls this plan's apply and its undo would make. `run(actor)`
    runs the entry's write code with that actor; `iam()` is the environment reader's IAM client. Returns the record:
    `denied` (reasons that refuse the plan), `unconfirmed` (said, not refused) and what was checked."""
    role = actor_role_arn(environment) if role is None else role
    record: dict[str, Any] = {"checked": False, "role": role.rsplit("/", 1)[-1], "denied": [], "unconfirmed": []}
    if not role:
        record["unconfirmed"].append("no actor role is configured for this environment; its permissions were not read")
        return record
    try:
        applies = trace(run)
    except RuntimeError as exc:  # the write code refused (AwsPlatform._change raises only its own errors)
        record["unconfirmed"].append(f"the fix's calls could not be traced: {_safe_error(exc)}")
        return record
    if not applies:
        record["unconfirmed"].append("the fix asked for no actor session before its first call; nothing to check")
        return record
    calls = [("apply", s) for s in applies] + [("undo", s) for s in undo_sessions(entry, applies, snapshot)]
    record["calls"] = [{"step": step, "actions": s["actions"], "resources": [_resource(r) for r in s["resources"]]}
                       for step, s in calls]
    try:
        client = iam()
        verdicts, unanswered = [], []
        for step, s in calls:
            results = _results(client, role, s, _context(incident, environment, env_tag, s["condition"]))
            verdicts += [(step, v) for v in _verdicts(results)]
            unanswered += [f"{step}: the simulator gave no decision for {u}" for u in _unanswered(s, results)]
    except _aws_errors() as exc:
        record["unconfirmed"].append(f"the policy simulator could not be read: {_safe_error(exc)}")
        return record
    record["unconfirmed"] += unanswered
    seen: set[tuple[str, str, str]] = set()
    for step, (action, resource, decision, missing) in verdicts:
        if (step, action, resource) in seen or decision == ALLOWED:
            continue
        seen.add((step, action, resource))
        said = f"{action} on {_resource(resource)}"
        if missing:
            record["unconfirmed"].append(f"{step}: {said} needs {', '.join(missing)}, which WARDEN cannot supply")
        else:
            record["denied"].append(f"{DENIED}: the actor role {record['role']} may not {said} ({decision}), "
                                    f"which the fix's {step} needs; a person grants it before this plan is made")
    record["checked"] = not unanswered  # every action and resource asked about has its decision
    return record
