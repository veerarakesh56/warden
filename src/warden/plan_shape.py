"""The shape of a Terraform plan, checked before any model reads it (owner, 2026-10-17, B3).

Eldane may approve a dev infrastructure plan (plan_review.py) only when the plan's SHAPE - which resource types it
touches and how - is one this policy allows. The policy is deterministic and runs first; Eldane can only add a "no"
to what it lets through. Read from `terraform show -json <saved plan>` (its `resource_changes`):

- access - IAM, resource policies, security groups and their rules, network ACLs, cluster access entries, and the
  role a function or a task runs as (changed, or unknown until apply): ANY change goes to a person (Eldane never
  changes access, eldane.SYSTEM rule 4);
- what a plan does outside its resource changes (`action_invocations`, `deferred_changes`): a person;
- data stores, networking, and the platform - what runs the services (clusters, services, functions) and what
  watches them (alarms, the budget): created or updated, yes; deleted, replaced or dropped from state, a person;
- a provider this repository's stacks do not use, an action Terraform added after this was written, or more than
  MAX_CHANGES changes: a person.

What a model is shown (summary) is each change's address, type and action and the NAMES of the attributes that change
- never a value - redacted (redaction.redact), with ids [R1].. it must cite. Stdlib and the redactor only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_CHANGES = 60
# The providers terraform/fullstack and terraform/undo-lab use (their required_providers), and Terraform's own.
PROVIDERS = frozenset({"registry.terraform.io/hashicorp/aws", "registry.terraform.io/hashicorp/random",
                       "registry.terraform.io/hashicorp/archive", "terraform.io/builtin/terraform"})
ACCESS = re.compile(r"^aws_(iam_.+|lambda_permission|lambda_function_url|kms_grant|ram_.+|organizations_.+"
                    r"|(sqs_queue|sns_topic|s3_bucket|ecr_repository|ecr_registry|secretsmanager_secret|kms_key"
                    r"|cloudwatch_log_resource|cloudwatch_event_bus|api_gateway_rest_api|efs_file_system"
                    r"|opensearch_domain|elasticsearch_domain|glacier_vault|backup_vault|vpc_endpoint)_policy"
                    r"|s3_bucket_public_access_block|s3_account_public_access_block|s3_bucket_acl"
                    r"|security_group(_rule)?|vpc_security_group_.+|default_security_group|network_acl(_.+)?"
                    r"|default_network_acl|eks_access_.+|eks_pod_identity_association)$")
DATA = re.compile(r"^aws_(db_.+|rds_.+|dynamodb_.+|s3_bucket(_.+)?|elasticache_.+|kinesis_.+|sqs_queue|efs_.+"
                  r"|secretsmanager_.+|kms_.+|cloudwatch_log_group|ecr_repository|ecr_lifecycle_policy|backup_.+"
                  r"|opensearch_.+|msk_.+|ebs_volume|docdb_.+|neptune_.+|memorydb_.+|redshift_.+)$")
NETWORK = re.compile(r"^aws_(vpc|vpc_.+|subnet|route|route_table(_association)?|main_route_table_association"
                     r"|nat_gateway|internet_gateway|egress_only_internet_gateway|eip(_association)?|lb|alb"
                     r"|lb_listener(_rule)?|lb_target_group(_attachment)?|route53_.+|ec2_transit_gateway.*)$")
# What runs the services, and what watches them: WARDEN's alarms, the budget.
PLATFORM = re.compile(r"^aws_(eks_cluster|eks_node_group|eks_addon|ecs_cluster|ecs_cluster_capacity_providers"
                      r"|ecs_service|lambda_function|apigatewayv2_api|autoscaling_group|cloudwatch_metric_alarm"
                      r"|cloudwatch_composite_alarm|budgets_budget)$")
REMOVES = {"delete", "forget"}
# Fields that name the role a resource runs as (CodeRabbit, #171): a function's or a task's role changing, or not known
# until apply, is an access change - whatever else of the resource changes, and however many attributes do.
ROLE_FIELDS = {"aws_lambda_function": ("role",),
               "aws_ecs_task_definition": ("task_role_arn", "execution_role_arn")}
KNOWN = frozenset({"no-op", "read", "create", "update", "delete", "forget"})


@dataclass
class Change:
    address: str
    type: str
    action: str  # create, update, delete, replace, forget
    attributes: list[str] = field(default_factory=list)  # the names of what changes - never a value


@dataclass
class Shape:
    changes: list[Change]
    problems: list[str]  # each reason a person must review this plan; [] when the shape allows Eldane's review


def _action(actions: list[str]) -> str:
    if set(actions) == {"delete", "create"}:
        return "replace"
    return actions[0] if len(actions) == 1 else "+".join(actions)


def _changed(change: dict[str, Any]) -> list[str]:
    before, after = change.get("before") or {}, change.get("after") or {}
    unknown = change.get("after_unknown") or {}
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    keys = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
    keys |= {k for k, v in (unknown.items() if isinstance(unknown, dict) else []) if v}
    return sorted(str(k) for k in keys)[:20]


def kind_of(rtype: str) -> str:
    """access, data, network, platform, or "" for any other resource type."""
    if ACCESS.match(rtype):
        return "access"
    for name, pattern in (("data", DATA), ("network", NETWORK), ("platform", PLATFORM)):
        if pattern.match(rtype):
            return name
    return ""


def _role_changes(rtype: str, change: dict[str, Any], action: str) -> list[str]:
    """The role-bearing fields an update or replace of `rtype` changes, or leaves unknown until apply - read from the
    whole before/after, never the capped attribute list a model is shown."""
    fields = ROLE_FIELDS.get(rtype, ())
    if not fields or action not in ("update", "replace"):
        return []
    before, after = change.get("before") or {}, change.get("after") or {}
    unknown = change.get("after_unknown") or {}
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}
    unknown = unknown if isinstance(unknown, dict) else {}
    return [f for f in fields if before.get(f) != after.get(f) or unknown.get(f)]


def _problem(rc: dict[str, Any], change: Change, actions: list[str]) -> str:
    """Why this one change needs a person, or "" when its shape allows Eldane's review."""
    address, action, kind = change.address, change.action, kind_of(change.type)
    if set(actions) - KNOWN:
        return f"{address}: an action this policy does not know ({action})"
    if rc.get("provider_name") not in PROVIDERS:
        return f"{address}: a provider these stacks do not use"
    if kind == "access":
        return f"{address}: changes access ({action}) - a person reviews every access change"
    if roles := _role_changes(change.type, rc.get("change") or {}, action):
        return (f"{address}: changes the role it runs as ({', '.join(roles)}, {action}) - a person reviews every "
                "access change")
    if kind and set(actions) & REMOVES:
        return f"{address}: {action} of {kind} - a person reviews every delete or replace of {kind}"
    return ""


def check(plan: dict[str, Any]) -> Shape:
    """The plan's managed-resource changes and every reason its shape needs a person."""
    changes, problems = [], []
    for rc in plan.get("resource_changes") or []:
        actions = list((rc.get("change") or {}).get("actions") or [])
        if rc.get("mode", "managed") != "managed" or not set(actions) - {"no-op", "read"}:
            continue
        action = _action(actions)
        change = Change(str(rc.get("address", "")), str(rc.get("type", "")), action,
                        _changed(rc.get("change") or {}) if action == "update" else [])
        changes.append(change)
        if problem := _problem(rc, change, actions):
            problems.append(problem)
    if len(changes) > MAX_CHANGES:
        problems.append(f"{len(changes)} changes: more than {MAX_CHANGES} in one plan go to a person")
    return Shape(changes, problems + _outside(plan))


def _outside(plan: dict[str, Any]) -> list[str]:
    """CodeRabbit, #171: what a plan does besides its resource changes - provider actions it invokes, changes Terraform
    deferred - is not in resource_changes, so a plan holding any is never read as empty or approvable."""
    return [f"the plan {said} ({key}), which this policy does not read: a person reviews it"
            for key, said in (("action_invocations", "invokes provider actions"), ("deferred_changes", "defers changes"))
            if plan.get(key)]


def summary(changes: list[Change]) -> tuple[str, set[str]]:
    """What Eldane is shown: one line per change with its id, redacted; and the ids."""
    from .redaction import redact

    lines, ids = [], set()
    for n, c in enumerate(changes, 1):
        ids.add(f"R{n}")
        what = f" - attributes changing: {', '.join(c.attributes)}" if c.attributes else ""
        lines.append(f"[R{n}] {c.action} {c.address} (type {c.type}{', ' + kind_of(c.type) if kind_of(c.type) else ''}){what}")
    return redact("\n".join(lines)).text, ids
