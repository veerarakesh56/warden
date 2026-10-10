"""Per-incident AWS sessions (decision D14, audit A-P-5): who approved a change travels with the credentials
that make it.

`actor_session` assumes an environment's actor role for one approved plan: at most 900 s, SourceIdentity the
incident (`inc-...`, which the role's trust requires and CloudTrail stamps on every call, sticky through any
role chain), session tags naming the approvers, the incident and the plan, and a session policy that allows
only the plan's actions on the plan's exact resources - whatever the role itself may do. `reader_session` is
the same without the tags of an approval, for the reads of one incident.

Nothing here decides whether to act: the workflow has verified the approval before this is called.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any

MAX_SECONDS = 900  # the shortest session STS allows, and the longest an actor gets
# STS limits (AssumeRole, read 2026-10-03): session name 2-64 of [\w+=,.@-]; SourceIdentity 2-64 of the same;
# tag values up to 256 of letters, digits, spaces and _.:/=+-@; a session policy up to 2,048 characters before
# packing.
_NAME = re.compile(r"^[\w+=,.@-]{2,64}$", re.ASCII)
_TAG_VALUE = re.compile(r"^[\w .:/=+\-@]{0,256}$")
MAX_POLICY_CHARS = 2048


class IdentityError(ValueError):
    pass


def session_policy(actions: Sequence[str], resources: Sequence[str], condition: dict[str, Any] | None = None,
                   also: Sequence[tuple[Sequence[str], Sequence[str]]] = ()) -> str:
    """The session policy: these actions on these resources, nothing else - an intersection with the role's own
    policy, so it can only narrow it. No wildcard resource: a plan names what it changes. The one exception is an
    action whose resource IAM names only through a condition key (an event source mapping, by its function's ARN):
    then `*` goes with that exact condition, never alone. `also`: further (actions, exact resources) statements, for a
    call AWS authorizes against more than one resource with different actions (an SQS redrive: receive and delete on
    the dead-letter queue, send on the destination) - each pair exact, never the cross product."""
    statements = []
    for i, (acts, res) in enumerate([(actions, resources), *also]):
        if not acts or not res:
            raise IdentityError("a session policy needs the plan's actions and its exact resources")
        if any("*" in r for r in res) and not (i == 0 and list(res) == ["*"] and condition):
            raise IdentityError(f"a plan's resources are exact ARNs, not patterns: {sorted(res)}")
        statements.append({"Effect": "Allow", "Action": sorted(set(acts)), "Resource": sorted(set(res))})
    if condition and any("*" in str(v) for op in condition.values() for v in op.values()):
        raise IdentityError(f"a session policy's condition names exact values, not patterns: {condition}")
    if condition:
        statements[0]["Condition"] = condition
    doc = json.dumps({"Version": "2012-10-17", "Statement": statements}, separators=(",", ":"))
    if len(doc) > MAX_POLICY_CHARS:
        raise IdentityError(f"the session policy is {len(doc)} characters; STS takes at most {MAX_POLICY_CHARS}")
    return doc


def _check(label: str, value: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise IdentityError(f"{label} {value!r} is not something STS accepts")
    return value


def actor_session(sts: Any, *, role_arn: str, incident: str, plan_hash: str, approvers: Sequence[str],
                  actions: Sequence[str], resources: Sequence[str],
                  condition: dict[str, Any] | None = None,
                  also: Sequence[tuple[Sequence[str], Sequence[str]]] = ()) -> dict[str, str]:
    """Credentials for one approved plan, naming who approved it (register A-P-5)."""
    if not approvers:
        raise IdentityError("an actor session is minted only for a plan someone approved")
    who = "+".join(sorted(set(approvers)))
    tags = [{"Key": "approver", "Value": _check("approver", who, _TAG_VALUE)},
            {"Key": "incident", "Value": _check("incident", incident, _TAG_VALUE)},
            {"Key": "plan", "Value": _check("plan hash", plan_hash[:16], _TAG_VALUE)}]
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=_check("incident", incident, _NAME),
                           SourceIdentity=_check("incident", incident, _NAME), DurationSeconds=MAX_SECONDS,
                           Tags=tags, Policy=session_policy(actions, resources, condition, also))
    return _credentials(resp)


def reader_session(sts: Any, *, role_arn: str, incident: str) -> dict[str, str]:
    """The reads of one incident, in that environment's reader role."""
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=_check("incident", incident, _NAME),
                           SourceIdentity=_check("incident", incident, _NAME), DurationSeconds=MAX_SECONDS)
    return _credentials(resp)


def _credentials(resp: dict[str, Any]) -> dict[str, str]:
    c = resp["Credentials"]
    return {"aws_access_key_id": c["AccessKeyId"], "aws_secret_access_key": c["SecretAccessKey"],
            "aws_session_token": c["SessionToken"]}
