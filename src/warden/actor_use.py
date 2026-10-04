"""Was this actor session approved? (G6, plan: "pages on any actor-role use without a matching approval.accepted row")

AWS records every AssumeRole of a `warden-<env>-actor` role in CloudTrail, and the runtime's `actor-use` Lambda gets
each one from EventBridge. The worker mints an actor session only after the approval loop (identity.actor_session),
tagging it with the incident, the plan hash's first 16 characters and who approved it. `check` holds the session to
the audit: the incident must hold `approval.accepted` rows for that plan, from every approver the session names, at
least as many as the plan's tier required. Anything else - missing tags, no approval, an approver who did not approve
- is a problem, and the Lambda pages. CloudTrail is AWS's record, not WARDEN's, so a session minted by anything that
bypassed the workflow is still seen.
"""

from __future__ import annotations

import re
from typing import Any

# Any account; the role name says which environment's actor it is.
ACTOR_ROLE = re.compile(r"^arn:aws:iam::\d+:role/warden-[a-z0-9-]+-actor$")


def _tags(params: dict[str, Any]) -> dict[str, str]:
    """CloudTrail records the request's tags as [{"key": .., "value": ..}]; accept the API's Key/Value too."""
    out = {}
    for t in params.get("tags") or []:
        if isinstance(t, dict):
            key, value = t.get("key", t.get("Key")), t.get("value", t.get("Value"))
            if isinstance(key, str) and isinstance(value, str):
                out[key] = value
    return out


def is_actor_session(detail: dict[str, Any]) -> bool:
    """A successful AssumeRole of an actor role: what this check is about. A refused call minted nothing."""
    params = detail.get("requestParameters") or {}
    return (detail.get("eventName") == "AssumeRole" and not detail.get("errorCode")
            and isinstance(params, dict) and bool(ACTOR_ROLE.match(str(params.get("roleArn", "")))))


def check(detail: dict[str, Any], audit: Any) -> list[str]:
    """The problems with one CloudTrail AssumeRole event's session; [] when it is not an actor session or the audit
    holds its approval."""
    if not is_actor_session(detail):
        return []
    params = detail["requestParameters"]
    role, tags = params["roleArn"], _tags(params)
    incident, plan, named = tags.get("incident", ""), tags.get("plan", ""), tags.get("approver", "")
    if not (incident and plan and named):
        return [f"{role} was assumed without the incident, plan and approver tags an approved session carries"]
    problems = []
    if params.get("sourceIdentity") != incident:
        problems.append(f"the session's source identity {params.get('sourceIdentity')!r} is not its incident {incident!r}")
    rows = [e["body"] for e in audit.entries(incident, kinds=("approval.accepted",))
            if str(e["body"].get("plan_hash", "")).startswith(plan)]
    if not rows:
        return [*problems, f"incident {incident} holds no accepted approval of plan {plan}"]
    approvers = {str(b.get("approver")) for b in rows}
    if missing := set(named.split("+")) - approvers:
        problems.append(f"the session names {sorted(missing)}, who did not approve plan {plan}")
    required = max(int(b.get("required") or 1) for b in rows)
    if len(approvers) < required:
        problems.append(f"plan {plan} needed {required} approvers and has {len(approvers)}")
    return problems
