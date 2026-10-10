"""The remediation catalogue: the ONLY writes WARDEN can ever apply.

The model proposes an `ActionKind`. That is advice. What can be applied is an entry here, and an
entry either restores a known-good state that WARDEN itself observed (the previous served version,
the previous steady task definition, the last Ready rollout revision, the Terraform baseline) or
makes a small numeric change clamped against live values.

Every parameter is one of:
- `ref`: must be one of the values WARDEN read from live state (`live[<param>]`, a set). A target
  taken from a log line, or anything with shell syntax in it, is not in that set, so it is refused.
- `int`: a whole number inside fixed limits, and inside limits relative to the live value
  (`relative` below), e.g. "at most double the current capacity".

Tiers: T1 single, reversible, bounded. T2 service-level, reversible. T3 irreversible or IAM / network
/ Terraform (a signed approval, a cooling-off time and, for infra, a Helios check).

Never in the catalogue, whatever a model or a person asks for: purging a queue, writing an IAM
policy, applying a Secret, deleting anything, raw SQL, a shell command.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .models import ActionKind

EXCLUDED = frozenset({"purge_queue", "put_role_policy", "apply_secret", "delete", "raw_sql", "shell"})


@dataclass(frozen=True)
class Param:
    kind: str  # "ref" | "int"
    lo: int | None = None
    hi: int | None = None


@dataclass(frozen=True)
class Entry:
    name: str
    tier: str
    platform: str
    restores: str
    params: dict[str, Param]
    # Limits relative to live values: (params, live) -> problems.
    relative: Callable[[dict[str, Any], dict[str, Any]], list[str]] | None = field(default=None, compare=False)
    # The parameters naming the changed resource, outermost first, when not the platform's own (TARGET_PARAMS).
    target: tuple[str, ...] = ()

    @property
    def action_class(self) -> str:
        return self.name

    @property
    def target_params(self) -> tuple[str, ...]:
        return self.target or TARGET_PARAMS[self.platform]

    @property
    def target_param(self) -> str:
        """The parameter naming what the fix changes - what its health check is about."""
        return self.target_params[-1]


# Per platform: the parameters that together name the changed resource, outermost first. The request's `service`
# must be the last, or the success check would judge another object than the one changed (sixth review,
# 2026-10-01); all of them key the bounds and the per-target mutex (target_key).
TARGET_PARAMS = {"lambda": ("function",), "events": ("rule",), "sqs": ("queue",), "athena": ("workgroup",),
                 "apigw": ("api", "stage"), "dynamodb": ("table",), "ecs": ("cluster", "service"),
                 "k8s": ("namespace", "deployment"), "db": ("database",), "rds": ("cluster",), "terraform": ("stack",)}


def _ref(*names: str) -> dict[str, Param]:
    return {n: Param("ref") for n in names}


def _at_most_double(p: dict, live: dict) -> list[str]:
    cur = live.get("current_capacity")
    if not isinstance(cur, int) or cur <= 0:
        return ["the current capacity was not read, so no increase can be bounded"]
    return [] if cur < p["capacity"] <= 2 * cur else [f"capacity must be above {cur} and at most {2 * cur}"]


def _raise_concurrency(p: dict, live: dict) -> list[str]:
    cur, free = live.get("current_concurrency"), live.get("unreserved_account_concurrency")
    if not isinstance(cur, int) or not isinstance(free, int):
        return ["current and account concurrency were not read"]
    if p["concurrency"] <= cur:
        return ["reserved concurrency may only be raised"]
    if p["concurrency"] - cur > free - 100:  # AWS keeps 100 unreserved for the account
        return ["the account has no room for that increase; escalate"]
    return []


def _raise_throttle(p: dict, live: dict) -> list[str]:
    """A stage's rate and burst: each above the current, at most double, and never past the account's own limits."""
    out = []
    for key, acct in (("rate_limit", "account_rate_limit"), ("burst_limit", "account_burst_limit")):
        cur, cap = live.get(f"current_{key}"), live.get(acct)
        if not isinstance(cur, int) or cur < 1 or not isinstance(cap, int):
            out.append(f"the stage's current {key} or the account's was not read")
        elif not cur < p[key] <= min(2 * cur, cap):
            out.append(f"{key} must be above {cur} and at most {min(2 * cur, cap)}")
    return out


def _scale_up_by_two(p: dict, live: dict) -> list[str]:
    cur = live.get("current_replicas")
    if not isinstance(cur, int) or cur < 1:
        return ["the current replica count was not read"]
    return [] if cur < p["replicas"] <= cur + 2 else [f"replicas must be above {cur} and at most {cur + 2}"]


CATALOG: dict[str, Entry] = {e.name: e for e in [
    Entry("lambda_move_alias", "T2", "lambda", "the version the alias served before the incident",
          _ref("function", "alias", "to_version")),
    Entry("lambda_restore_config", "T2", "lambda", "the configuration of the previous published version",
          _ref("function", "from_version")),
    Entry("lambda_set_reserved_concurrency", "T1", "lambda", "n/a (bounded increase)",
          {**_ref("function"), "concurrency": Param("int", 1, 1000)}, _raise_concurrency),
    # The function names the mapping's owner: a mapping of another function is never in the allowed set (G9-D).
    Entry("lambda_enable_esm", "T1", "lambda", "the event source mapping's enabled state", _ref("function", "mapping"),
          target=("mapping",)),
    # Pause (G9-D): only a mapping reading an SQS queue - its messages wait in the queue. A stream's records age out
    # while paused, so a stream mapping is never paused here.
    Entry("lambda_disable_esm", "T1", "lambda", "the event source mapping's enabled state",
          _ref("function", "mapping"), target=("mapping",)),
    Entry("events_enable_rule", "T1", "events", "the rule's enabled state", _ref("rule")),
    # Pause (G9-D): only a SCHEDULED rule - it misses its ticks while paused. An event-pattern rule drops the events
    # that match while it is disabled, so one is never paused here.
    Entry("events_disable_rule", "T1", "events", "the rule's enabled state", _ref("rule")),
    # G9-D: a dead-letter queue's messages back to its ONE source queue, at most 50 a second (AWS allows 500). Moved
    # messages are not moved back; cancelling stops the rest, and one that fails again returns by the source queue's
    # own redrive policy. A KMS-encrypted queue is refused: the actor holds no key permissions.
    Entry("sqs_redrive_dlq", "T2", "sqs", "n/a (cancelling stops the move; moved messages stay)",
          {**_ref("queue", "to_queue"), "per_second": Param("int", 1, 50)}),
    # G9-D: the one query running longer than the runaway bound in the workgroup; the query is lost, the session and
    # the data are untouched, and it can be run again.
    Entry("athena_stop_query", "T1", "athena", "n/a (the query can be run again)", _ref("workgroup", "query")),
    # G9-D: a REST API stage's all-methods throttle, only where one is already set (AWS can replace it, not remove a
    # new one); above the current, at most double, within the account's limits.
    Entry("apigw_raise_stage_throttle", "T1", "apigw", "n/a (bounded increase)",
          {**_ref("api", "stage"), "rate_limit": Param("int", 1, 10000), "burst_limit": Param("int", 1, 5000)},
          _raise_throttle),
    Entry("dynamodb_raise_capacity", "T1", "dynamodb", "n/a (bounded increase)",
          {**_ref("table"), "capacity": Param("int", 1, 40000)}, _at_most_double),
    Entry("ecs_rollback_service", "T2", "ecs", "the service's previous steady task definition",
          _ref("cluster", "service", "to_task_definition")),
    # G9-D: a restart only when every container image is pinned by digest - forcing a new deployment pulls whatever
    # a tag points to now, which would roll out new code (AWS ECS API reference, read 2026-10-10).
    Entry("ecs_restart_service", "T1", "ecs", "n/a (same task definition, new tasks)", _ref("cluster", "service")),
    Entry("ecs_scale_service", "T1", "ecs", "n/a (bounded increase)",
          {**_ref("cluster", "service"), "replicas": Param("int", 1, 100)}, _scale_up_by_two),
    Entry("k8s_rollout_undo", "T2", "k8s", "the last revision that was Ready",
          _ref("namespace", "deployment", "to_revision")),
    Entry("k8s_restart", "T1", "k8s", "n/a (same spec, new pods)", _ref("namespace", "deployment")),
    Entry("k8s_scale", "T1", "k8s", "n/a (bounded increase)",
          {**_ref("namespace", "deployment"), "replicas": Param("int", 1, 50)}, _scale_up_by_two),
    Entry("db_terminate_idle_in_tx", "T1", "db", "n/a (the session is closed, the data is untouched)",
          {**_ref("database"), "min_idle_seconds": Param("int", 300, 86400), "max_sessions": Param("int", 1, 20)}),
    Entry("db_terminate_blocker", "T2", "db", "n/a (the blocking session is closed)", _ref("database", "pid")),
    Entry("aurora_failover", "T3", "rds", "n/a (irreversible)", _ref("cluster", "target_instance")),
    Entry("infra_restore_baseline", "T3", "terraform", "the Terraform-declared baseline", _ref("stack")),
]}

# Which entries can carry out what the model proposed, per platform. An action with no entry is
# advice only: it escalates to a person.
FOR_ACTION: dict[ActionKind, dict[str, str]] = {
    ActionKind.rollback_deploy: {"lambda": "lambda_move_alias", "ecs": "ecs_rollback_service",
                                 "k8s": "k8s_rollout_undo"},
    ActionKind.restart_pods: {"k8s": "k8s_restart", "ecs": "ecs_restart_service"},
    ActionKind.scale_up: {"k8s": "k8s_scale", "lambda": "lambda_set_reserved_concurrency",
                          "dynamodb": "dynamodb_raise_capacity", "ecs": "ecs_scale_service"},
    ActionKind.terminate_connections: {"db": "db_terminate_idle_in_tx"},
    ActionKind.failover_replica: {"rds": "aurora_failover"},
    # G9-D: the generic classes, as far as an entry carries them out today.
    ActionKind.pause_flow: {"lambda": "lambda_disable_esm", "events": "events_disable_rule"},
    ActionKind.resume_flow: {"lambda": "lambda_enable_esm", "events": "events_enable_rule"},
    ActionKind.raise_limit: {"lambda": "lambda_set_reserved_concurrency", "apigw": "apigw_raise_stage_throttle"},
    ActionKind.cancel_query: {"athena": "athena_stop_query"},
    ActionKind.redrive_messages: {"sqs": "sqs_redrive_dlq"},
}


def target_key(name: str, params: dict[str, Any]) -> str:
    """The resource a fix changes, as one key: its platform and the parameters naming it, outermost first
    (`k8s:shop/orders`). The bounds, the mutex and the workflow id key on it - never on a free-text service
    name, which let `orders` in two namespaces share one rate limit and one open fix (audit C3, A-B-M4)."""
    entry = CATALOG[name]
    return entry.platform + ":" + "/".join(str(params.get(p, "")) for p in entry.target_params)


def fingerprint() -> str:
    """What the catalogue allows, as one hash: a plan made under one catalogue is not applied under another
    (register O5). The `relative` limits are code, covered by the code hash (activities.code_version)."""
    material = [[e.name, e.tier, e.platform, list(e.target_params),
                 sorted([k, p.kind, p.lo, p.hi] for k, p in e.params.items())]
                for e in sorted(CATALOG.values(), key=lambda e: e.name)]
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def for_action(action: ActionKind, platform: str) -> Entry | None:
    name = FOR_ACTION.get(action, {}).get(platform)
    return CATALOG[name] if name else None


ROLLS_PODS = frozenset({"k8s_restart", "ecs_restart_service"})  # entries that replace a workload's pods through its own rollout (C10)
# Entries an autoscaler would undo (register C4): a HorizontalPodAutoscaler, or Application Auto Scaling on a table.
SCALES = frozenset({"k8s_scale", "dynamodb_raise_capacity", "ecs_scale_service"})


def validate(name: str, params: dict[str, Any], live: dict[str, Any]) -> list[str]:
    """Every reason these parameters must not be applied. `live` holds what WARDEN read: for a `ref`
    parameter a set of allowed values, plus the current values `relative` limits need."""
    if name in EXCLUDED or name not in CATALOG:
        return [f"{name!r} is not in the catalogue"]
    entry = CATALOG[name]
    problems = [f"unexpected parameter {p!r}" for p in params if p not in entry.params]
    for pname, spec in entry.params.items():
        if pname not in params:
            problems.append(f"missing parameter {pname!r}")
            continue
        value = params[pname]
        if spec.kind == "ref":
            allowed = live.get(pname)
            if not isinstance(value, str) or not isinstance(allowed, set | frozenset) or value not in allowed:
                problems.append(f"{pname}={value!r} is not something WARDEN read from live state")
        elif not isinstance(value, int) or isinstance(value, bool) or not spec.lo <= value <= spec.hi:
            problems.append(f"{pname}={value!r} is outside {spec.lo}..{spec.hi}")
    if not problems and entry.relative:
        problems += entry.relative(params, live)
    if not problems and name in ROLLS_PODS:
        # Register C10: a restart goes through the target's own rolling settings, so those settings must keep most of
        # it serving - never Recreate, never more than half the pods down together, and never unknown.
        at_once, replicas = live.get("at_once"), live.get("current_replicas")
        if not isinstance(at_once, int) or not isinstance(replicas, int):
            problems.append("C10: the target's rollout strategy could not be read; a restart is not sent blind")
        elif replicas > 1 and at_once * 2 > replicas:
            problems.append(f"C10: the target's strategy would take {at_once} of {replicas} pods down at once; a "
                            "restart is refused until it keeps most of them serving")
    if not problems and live.get("gitops"):
        # Register C4: Argo CD or Flux would revert the change at its next sync - the fix belongs in Git.
        problems.append(f"C4: {live['gitops']} manages this target and reverts a direct change; make the change in Git")
    if not problems and name in SCALES and "autoscaled" in live and live["autoscaled"] is not False:
        problems.append("C4: an autoscaler (a HorizontalPodAutoscaler, Application Auto Scaling) owns this target's "
                        "count; a manual change would be undone" if live["autoscaled"] else
                        "C4: whether an autoscaler owns this target's count could not be read; no change is sent")
    if live.get("rollout") == "progressing":
        # Register C5: a change made mid-rollout fights the rollout, and the next read cannot tell which did what.
        problems.append("P21-ROLLOUT-IN-PROGRESS: a rollout of this target is under way; act after it completes "
                        "or misses its deadline")
    return problems
