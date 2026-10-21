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
                 "elb": ("load_balancer",), "appconfig": ("application", "config_env"),
                 "codepipeline": ("pipeline", "stage"),
                 "apigw": ("stage", "api"), "dynamodb": ("table",), "ecs": ("cluster", "service"),
                 "k8s": ("namespace", "deployment"), "db": ("database",), "rds": ("cluster",), "terraform": ("stack",),
                 "ec2": ("group",), "asg": ("asg",), "kms": ("key",), "secretsmanager": ("secret",),
                 "kinesis": ("stream",)}


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


def _redrive_in_time(p: dict, live: dict) -> list[str]:
    """The move finishes inside the verify window, or the run would always roll back (review H3)."""
    waiting = live.get("waiting")
    if not isinstance(waiting, int):
        return ["the dead-letter queue's depth was not read"]
    if waiting > p["per_second"] * REDRIVE_SECONDS:
        return [f"{waiting} messages at {p['per_second']} a second do not move inside {REDRIVE_SECONDS} s"]
    return []


def _scale_up_by_two(p: dict, live: dict) -> list[str]:
    cur = live.get("current_replicas")
    if not isinstance(cur, int) or cur < 1:
        return ["the current replica count was not read"]
    return [] if cur < p["replicas"] <= cur + 2 else [f"replicas must be above {cur} and at most {cur + 2}"]


# What a bounded increase restores: nothing - it only raises a limit within its cap.
BOUNDED_INCREASE = "n/a (bounded increase)"

CATALOG: dict[str, Entry] = {e.name: e for e in [
    Entry("lambda_move_alias", "T2", "lambda", "the version the alias served before the incident",
          _ref("function", "alias", "to_version")),
    Entry("lambda_restore_config", "T2", "lambda", "the configuration of the previous published version",
          _ref("function", "from_version")),
    Entry("lambda_set_reserved_concurrency", "T1", "lambda", BOUNDED_INCREASE,
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
          {**_ref("queue", "to_queue"), "per_second": Param("int", 1, 50)}, _redrive_in_time),
    # G9-D: the one query running longer than the runaway bound in the workgroup; the query is lost, the session and
    # the data are untouched, and it can be run again.
    Entry("athena_stop_query", "T1", "athena", "n/a (the query can be run again)", _ref("workgroup", "query")),
    # G9-D: a REST API stage's all-methods throttle, only where one is already set (AWS can replace it, not remove a
    # new one); above the current, at most double, within the account's limits.
    Entry("apigw_raise_stage_throttle", "T1", "apigw", BOUNDED_INCREASE,
          {**_ref("api", "stage"), "rate_limit": Param("int", 1, 10000), "burst_limit": Param("int", 1, 5000)},
          _raise_throttle),
    # G9-D: traffic away from the load balancer's ONE impaired zone for a set time (ARC ends it at its expiry; the
    # rollback cancels it). Only where the load balancer allows zonal shifts, one shift at a time.
    Entry("arc_zonal_shift", "T2", "elb", "n/a (ends at its expiry, or cancelled)",
          {**_ref("load_balancer", "away_from"), "minutes": Param("int", 30, 180)}),
    # G9-D: stop the deployment of the AppConfig environment whose monitors name the firing alarm, reverting it to the
    # configuration before it (AllowRevert: up to 72 hours after it completed - AWS, read 2026-10-10). `config_env`,
    # not "environment": that word is the resource's own Environment tag everywhere WARDEN reads (P18).
    Entry("appconfig_revert", "T2", "appconfig", "the configuration deployed before it",
          _ref("alarm", "application", "config_env", "deployment"), target=("application", "config_env")),
    # G9-D: no deploy reaches the service while a person looks - the inbound transition of the pipeline stage the
    # service's own `warden:pipeline` tag names (AWS has no link of its own from a service to its pipeline).
    Entry("codepipeline_freeze", "T1", "codepipeline", "the stage's inbound transition, enabled again",
          _ref("resource", "pipeline", "stage")),
    Entry("dynamodb_raise_capacity", "T1", "dynamodb", BOUNDED_INCREASE,
          {**_ref("table"), "capacity": Param("int", 1, 40000)}, _at_most_double),
    Entry("ecs_rollback_service", "T2", "ecs", "the service's previous steady task definition",
          _ref("cluster", "service", "to_task_definition")),
    # G9-D: a restart only when every container image is pinned by digest - forcing a new deployment pulls whatever
    # a tag points to now, which would roll out new code (AWS ECS API reference, read 2026-10-10).
    Entry("ecs_restart_service", "T1", "ecs", "n/a (same task definition, new tasks)", _ref("cluster", "service")),
    Entry("ecs_scale_service", "T1", "ecs", BOUNDED_INCREASE,
          {**_ref("cluster", "service"), "replicas": Param("int", 1, 100)}, _scale_up_by_two),
    Entry("k8s_rollout_undo", "T2", "k8s", "the last revision that was Ready",
          _ref("namespace", "deployment", "to_revision")),
    Entry("k8s_restart", "T1", "k8s", "n/a (same spec, new pods)", _ref("namespace", "deployment")),
    Entry("k8s_scale", "T1", "k8s", BOUNDED_INCREASE,
          {**_ref("namespace", "deployment"), "replicas": Param("int", 1, 50)}, _scale_up_by_two),
    Entry("db_terminate_idle_in_tx", "T1", "db", "n/a (the session is closed, the data is untouched)",
          {**_ref("database"), "min_idle_seconds": Param("int", 300, 86400), "max_sessions": Param("int", 1, 20)}),
    Entry("db_terminate_blocker", "T2", "db", "n/a (the blocking session is closed)", _ref("database", "pid")),
    Entry("aurora_failover", "T3", "rds", "n/a (irreversible)", _ref("cluster", "target_instance")),
    Entry("infra_restore_baseline", "T3", "terraform", "the Terraform-declared baseline", _ref("stack")),
    # G10-D: undo the ONE security group write CloudTrail recorded in the hours before the alarm went into ALARM -
    # re-authorize exactly the rules a revoke removed (AWS's own response lists them), or revoke only the rule ids an
    # authorize created. T3: network and security-adjacent. Refusals (platforms/aws.py): ingress from the whole
    # internet, a change by root, by an AWS service, by WARDEN or by a principal the owner named, any other write to
    # the group since, a change after the alarm went off (it may be the fix).
    Entry("ec2_revert_sg_change", "T3", "ec2", "the group's rules as CloudTrail recorded them before the change",
          _ref("alarm", "group", "event"), target=("group",)),
    # G10 v2, owner decision 2026-10-10: a route deleted or replaced, back to the target AWS Config recorded before the
    # change - routes only (a network ACL is a security control, and stays with a person). T3: a passkey approves.
    Entry("ec2_restore_route", "T3", "ec2", "the route AWS Config recorded before the change",
          _ref("alarm", "route_table", "event"), target=("route_table",)),
    # G10-D3: a value back to what AWS Config recorded just before ONE recorded change (Config's own relatedEvents
    # name the change), the hours before the alarm, with the same refusals; Config must record continuously.
    Entry("ecs_restore_desired", "T2", "ecs", "the desired count AWS Config recorded before the change",
          _ref("alarm", "cluster", "service", "event", "desired")),
    Entry("lambda_restore_concurrency", "T2", "lambda", "the reserved concurrency AWS Config recorded before the change",
          _ref("alarm", "function", "event", "concurrency")),
    # G10-D4: a function's timeout, memory or ephemeral storage, never its role, environment, code or network.
    Entry("lambda_restore_settings", "T2", "lambda",
          "the timeout, memory and ephemeral storage AWS Config recorded before the change",
          _ref("alarm", "function", "event", "settings")),
    # G10 v2: a queue's timing and size settings (never its policy, redrive, encryption or FIFO settings), and a
    # stream's retention - each back to what AWS Config recorded before the one recorded change.
    Entry("sqs_restore_attributes", "T2", "sqs", "the queue's timing and size settings AWS Config recorded before the change",
          _ref("alarm", "queue", "event", "attributes")),
    Entry("kinesis_restore_retention", "T2", "kinesis", "the retention AWS Config recorded before the change",
          _ref("alarm", "stream", "event", "hours")),
    # G10 held-out (2026-10-11, three cases of a person's cut): a table's provisioned read and write capacity back to
    # what AWS Config recorded before the ONE recorded UpdateTable that only cut it - never a billing mode, an index, a
    # raise, or a table an autoscaler owns.
    Entry("dynamodb_restore_capacity", "T2", "dynamodb",
          "the provisioned capacity AWS Config recorded before the change", _ref("alarm", "table", "event", "throughput")),
    Entry("asg_restore_capacity", "T2", "asg", "the desired capacity AWS Config recorded before the change",
          _ref("alarm", "asg", "event", "desired")),
    # G10 held-out (2026-10-11, g10-103): the processes ONE recorded SuspendProcesses stopped, resumed - the event
    # itself holds the undo. The group then acts again: it replaces unhealthy instances, and those are not brought back.
    Entry("asg_resume_processes", "T2", "asg",
          "the processes suspended again (instances the group replaced meanwhile stay replaced)",
          _ref("alarm", "asg", "event")),
    # A stage moved to another deployment: back to the one before, which must still exist - a "stage rollback".
    Entry("apigw_restore_stage", "T2", "apigw", "the deployment AWS Config recorded before the change",
          _ref("alarm", "api", "stage", "event", "deployment")),
    # G10-D2: the event itself holds the undo. Targets a PERSON deregistered (an ECS service's or an Auto Scaling
    # group's own deregistrations are AWS-made, refused); a key's scheduled deletion (it stays disabled - enabling is a
    # person's); a deleted secret still in its recovery window.
    Entry("elb_reregister_targets", "T2", "elb", "the targets the recorded change deregistered",
          _ref("alarm", "target_group", "event"), target=("target_group",)),
    Entry("kms_cancel_key_deletion", "T1", "kms", "n/a (the key is kept; it stays disabled)", _ref("alarm", "key", "event")),
    Entry("secrets_restore_secret", "T1", "secretsmanager", "n/a (the secret is restored as it was)",
          _ref("alarm", "secret", "event")),
]}

# What can go wrong if a fix is approved (owner, 2026-10-17, U3-2): said to the person - and to Eldane - as "risks if
# approved", beside the plan, on the approval page and in the channel. Plain words, each from the entry's own limits
# above; tests/test_eldane_critique.py holds that every entry has them.
RISKS: dict[str, tuple[str, ...]] = {
    "lambda_move_alias": ("the version it moves back to lacks every fix made since it was published",
                          "requests already running finish on the version they started on"),
    "lambda_restore_config": ("settings changed on purpose since that version go back too",),
    "lambda_set_reserved_concurrency": ("more concurrent runs put more load on what the function calls",
                                        "the raise takes concurrency the account's other functions could use"),
    "lambda_enable_esm": ("the messages that waited are processed at once, a burst on the function and what it calls",),
    "lambda_disable_esm": ("messages wait in the queue and age until it is enabled again",
                           "work that depends on them is delayed"),
    "events_enable_rule": ("the rule's targets run again from the next match or tick",),
    "events_disable_rule": ("the scheduled runs it misses while disabled are not run later",),
    "sqs_redrive_dlq": ("messages that failed before may fail again and load the consumer",
                        "moved messages are not moved back"),
    "athena_stop_query": ("the query's work is lost and must be run again",),
    "apigw_raise_stage_throttle": ("more requests reach the backend behind the API",),
    "arc_zonal_shift": ("the remaining zones carry all the traffic until the shift ends",),
    "appconfig_revert": ("configuration changes made on purpose in that deployment are undone",),
    "codepipeline_freeze": ("no deploy reaches the service, an urgent fix included, until a person enables it again",),
    "dynamodb_raise_capacity": ("higher provisioned capacity costs more until it is lowered",),
    "ecs_rollback_service": ("the previous task definition lacks every change made since it",
                             "tasks are replaced, and requests on stopping tasks can fail"),
    "ecs_restart_service": ("tasks are replaced, and requests on stopping tasks can fail",
                            "a fault that is not in the running tasks comes back"),
    "ecs_scale_service": ("more tasks cost more and put more load on what they call",),
    "k8s_rollout_undo": ("the earlier revision lacks every change made since it",
                         "pods are replaced, and requests on terminating pods can fail"),
    "k8s_restart": ("pods are replaced, and requests on terminating pods can fail",
                    "a fault that is not in the running pods comes back"),
    "k8s_scale": ("more pods use more of the cluster and load what they call",),
    "db_terminate_idle_in_tx": ("the closed sessions' open transactions roll back; the application sees an error on them",),
    "db_terminate_blocker": ("the blocking session's transaction rolls back; its work is lost",),
    "aurora_failover": ("connections drop while the writer moves; it cannot be undone",),
    "infra_restore_baseline": ("infrastructure changed outside Terraform since the baseline is changed back",),
    "ec2_revert_sg_change": ("traffic the change allowed or blocked on purpose is blocked or allowed again",),
    "ec2_restore_route": ("traffic that took the new route on purpose goes the old way again",),
    "ecs_restore_desired": ("the service runs the earlier number of tasks, as cost and load were then",),
    "lambda_restore_concurrency": ("the earlier concurrency can throttle the function, or other functions, again",),
    "lambda_restore_settings": ("the earlier timeout, memory or storage may be what the change fixed",),
    "sqs_restore_attributes": ("the earlier timing or size settings may be what the change fixed",),
    "kinesis_restore_retention": ("records older than the earlier retention are dropped sooner",),
    "dynamodb_restore_capacity": ("the earlier capacity costs more than the cut it reverses",),
    "asg_restore_capacity": ("the group runs the earlier number of instances, as cost and load were then",),
    "asg_resume_processes": ("the group acts again: it may replace or launch instances at once",),
    "apigw_restore_stage": ("the earlier deployment lacks every change made since it",),
    "elb_reregister_targets": ("traffic goes to the targets again, healthy or not until checks fail them",),
    "kms_cancel_key_deletion": ("the key is kept, disabled - deleting it later needs a new decision",),
    "secrets_restore_secret": ("a secret someone deleted on purpose is back and readable again",),
}


def risks_of(entry: str) -> tuple[str, ...]:
    """What can go wrong if the fix `entry` is approved, in plain words; () for an entry not in the catalogue."""
    return RISKS.get(entry, ())


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
    # A queue's own alarm too (first live run, 2026-10-12): its one switched-off consumer mapping, which the
    # platform's live read finds by the queue's ARN (AwsPlatform._live_esm).
    ActionKind.resume_flow: {"lambda": "lambda_enable_esm", "events": "events_enable_rule",
                             "sqs": "lambda_enable_esm"},
    # A Lambda's reserved concurrency again too (G10-B): the schema tells the model raise_limit means it, and the
    # held-out author's key agreed - so a right answer was never planned. Review H1's harm stays closed by its other
    # half: raise_limit's own evidence words (grounding: throttl, quota, 429, burst) - "too many connections" or an
    # error rate supports it no more (tests/test_review_g9d.py h1), and P11 refuses it against an OOM.
    ActionKind.raise_limit: {"apigw": "apigw_raise_stage_throttle", "lambda": "lambda_set_reserved_concurrency"},
    ActionKind.cancel_query: {"athena": "athena_stop_query"},
    ActionKind.shift_traffic: {"elb": "arc_zonal_shift"},
    ActionKind.revert_config: {"appconfig": "appconfig_revert"},
    ActionKind.freeze_changes: {"codepipeline": "codepipeline_freeze"},
    ActionKind.redrive_messages: {"sqs": "sqs_redrive_dlq"},
    # G10-D: a recorded change undone - a security group's rules, or a rule or consumer a change disabled (the same
    # writes as resume_flow, reached as the undo of that change).
    ActionKind.revert_change: {"ec2": "ec2_revert_sg_change", "events": "events_enable_rule",
                               "ecs": "ecs_restore_desired", "lambda": "lambda_restore_concurrency",
                               "sqs": "sqs_restore_attributes", "kinesis": "kinesis_restore_retention",
                               "asg": "asg_restore_capacity", "apigw": "apigw_restore_stage",
                               "elb": "elb_reregister_targets", "kms": "kms_cancel_key_deletion",
                               "dynamodb": "dynamodb_restore_capacity",
                               "secretsmanager": "secrets_restore_secret"},
}


def _arrow(what: str, before: Any, after: Any) -> str:
    return f"{what}: {'unknown' if before is None else before} -> {after}"


# What each entry changes, from the plan's own snapshot (what WARDEN read) and values: the approver reads the change
# itself, not only the entry's name (G9-D owner decision: a dry-run diff on the approval screen). Both are in the plan
# hash the approver signs, so this text cannot differ from what is applied.
_CHANGES: dict[str, Callable[[dict[str, Any], dict[str, Any]], list[str]]] = {
    "lambda_move_alias": lambda p, s: [_arrow(f"alias {p['alias']} of {p['function']} serves version", s.get("version"),
                                              p["to_version"])],
    "lambda_set_reserved_concurrency": lambda p, s: [_arrow(f"reserved concurrency of {p['function']}",
                                                            s.get("reserved"), p["concurrency"])],
    "lambda_enable_esm": lambda p, s: [_arrow(f"event source mapping {p['mapping']}", "disabled", "enabled")],
    "lambda_disable_esm": lambda p, s: [_arrow(f"event source mapping {p['mapping']} (reads {s.get('source')})",
                                               "enabled", f"disabled; its messages wait in the queue, kept "
                                               f"{s.get('retention_s')} s; it stays paused until a person resumes it")],
    "events_enable_rule": lambda p, s: [_arrow(f"rule {p['rule']}", "disabled", "enabled")],
    "elb_reregister_targets": lambda p, s: [(f"target group {p['target_group']}: register again "
                                             f"{', '.join(f'{t}:{port}' for t, port in s.get('targets') or [])} - "
                                             f"undoing {s.get('event_name')} at {s.get('event_time')} by "
                                             f"{s.get('actor')}")],
    "kms_cancel_key_deletion": lambda p, s: [_arrow(f"key {p['key']}", "pending deletion",
                                                    "kept, still disabled (a person enables it)")],
    "secrets_restore_secret": lambda p, s: [_arrow(f"secret {p['secret']}", "deleted (recoverable)", "restored")],
    "asg_restore_capacity": lambda p, s: [_arrow(f"desired capacity of group {p['asg']}", s.get("desired_now"),
                                                 f"{p['desired']} (what AWS Config recorded before {s.get('event_name')} "
                                                 f"at {s.get('event_time')} by {s.get('actor')})")],
    "asg_resume_processes": lambda p, s: [(f"group {p['asg']}: resume {', '.join(s.get('processes') or ['?'])} - "
                                           f"undoing {s.get('event_name')} at {s.get('event_time')} by "
                                           f"{s.get('actor')}; the group then acts again - it replaces unhealthy "
                                           "instances, and those are not brought back")],
    "apigw_restore_stage": lambda p, s: [_arrow(f"deployment of stage {p['stage']} of {p['api']}",
                                                s.get("deployment_now"),
                                                f"{p['deployment']} (what AWS Config recorded before "
                                                f"{s.get('event_name')} at {s.get('event_time')} by {s.get('actor')})")],
    "dynamodb_restore_capacity": lambda p, s: [_arrow(f"read/write capacity units of table {p['table']}",
                                                      "/".join(str(u) for u in s.get("after") or []) or None,
                                                      f"{p['throughput']} (what AWS Config recorded before "
                                                      f"{s.get('event_name')} at {s.get('event_time')} by "
                                                      f"{s.get('actor')})")],
    "ecs_restore_desired": lambda p, s: [_arrow(f"desired tasks of service {p['service']}", s.get("desired_now"),
                                                f"{p['desired']} (what AWS Config recorded before {s.get('event_name')} "
                                                f"at {s.get('event_time')} by {s.get('actor')})")],
    "sqs_restore_attributes": lambda p, s: [_arrow(f"queue {p['queue']}", s.get("after"),
                                                   f"{p['attributes']} (what AWS Config recorded before "
                                                   f"{s.get('event_name')} at {s.get('event_time')} by {s.get('actor')})")],
    "kinesis_restore_retention": lambda p, s: [_arrow(f"retention of stream {p['stream']}", s.get("after"),
                                                      f"{p['hours']} h (what AWS Config recorded before "
                                                      f"{s.get('event_name')} at {s.get('event_time')} by "
                                                      f"{s.get('actor')})")],
    "lambda_restore_settings": lambda p, s: [_arrow(f"settings of {p['function']}", s.get("after"),
                                                    f"{p['settings']} (what AWS Config recorded before "
                                                    f"{s.get('event_name')} at {s.get('event_time')} by "
                                                    f"{s.get('actor')})")],
    "lambda_restore_concurrency": lambda p, s: [_arrow(f"reserved concurrency of {p['function']}", s.get("reserved"),
                                                       f"{p['concurrency']} (what AWS Config recorded before "
                                                       f"{s.get('event_name')} at {s.get('event_time')} by "
                                                       f"{s.get('actor')})")],
    "ec2_restore_route": lambda p, s: [(f"route table {p['route_table']}: {s.get('undo')} - undoing "
                                        f"{s.get('event_name')} at {s.get('event_time')} by {s.get('actor')} "
                                        f"(event {p['event']}; AWS Config's record before it)")],
    "ec2_revert_sg_change": lambda p, s: [(f"security group {p['group']}: {s.get('undo')} - undoing "
                                           f"{s.get('event_name')} at {s.get('event_time')} by {s.get('actor')} "
                                           f"(event {p['event']})")],
    "events_disable_rule": lambda p, s: [_arrow(f"scheduled rule {p['rule']}", "enabled",
                                                "disabled; it misses its runs while disabled")],
    "dynamodb_raise_capacity": lambda p, s: [_arrow(f"write capacity of table {p['table']}", s.get("write"),
                                                    p["capacity"])],
    "ecs_rollback_service": lambda p, s: [_arrow(f"task definition of service {p['service']}",
                                                 s.get("task_definition"), p["to_task_definition"])],
    "ecs_restart_service": lambda p, s: [(f"service {p['service']}: every task replaced by a new one of the same "
                                          f"task definition {s.get('task_definition')} (its secrets are read again)")],
    "ecs_scale_service": lambda p, s: [_arrow(f"desired tasks of service {p['service']}", s.get("desired"),
                                              p["replicas"])],
    "sqs_redrive_dlq": lambda p, s: [(f"the messages waiting in {p['queue']} "
                                      f"({'unknown' if s.get('waiting') is None else s['waiting']} when planned; the "
                                      f"count moves) move to {p['to_queue']} at {p['per_second']} a second; moved "
                                      "messages are not moved back")],
    "athena_stop_query": lambda p, s: [_arrow(f"query {p['query']} in workgroup {p['workgroup']}",
                                              s.get("query_state"), "cancelled")],
    "apigw_raise_stage_throttle": lambda p, s: [
        _arrow(f"rate limit of stage {p['stage']} of {p['api']}", s.get("rate_limit"), p["rate_limit"]),
        _arrow(f"burst limit of stage {p['stage']} of {p['api']}", s.get("burst_limit"), p["burst_limit"])],
    "arc_zonal_shift": lambda p, s: [(f"load balancer {p['load_balancer']}: traffic shifted away from zone "
                                      f"{p['away_from']} ({s.get('impaired_name')}) for {p['minutes']} minutes; "
                                      f"the zones left serve it all: {', '.join(s.get('serving') or []) or 'unknown'}")],
    "appconfig_revert": lambda p, s: [(f"configuration {p['application']}/{p['config_env']}: deployment "
                                       f"{p['deployment']} of profile {s.get('profile')} (version {s.get('version')}, "
                                       f"{s.get('deploy_state')}, started {s.get('started')}, completed "
                                       f"{s.get('completed') or 'not yet'}; the alarm fired {s.get('alarm_since')}) is "
                                       "stopped and reverted to the configuration deployed before it")],
    "codepipeline_freeze": lambda p, s: [_arrow(f"deploys of {p['resource']} through pipeline {p['pipeline']} "
                                                f"stage {p['stage']}", "flowing",
                                                "frozen until a person enables them (a deploy already inside the "
                                                "stage finishes)")],
    "aurora_failover": lambda p, s: [_arrow(f"writer of cluster {p['cluster']}", s.get("writer"),
                                            p["target_instance"]) + " (not undone automatically)"],
}


def change_of(name: str, params: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    """The plan's change, before -> after, in words. An entry without its own description shows its values."""
    describe = _CHANGES.get(name)
    if describe is not None:
        try:
            return describe(params, snapshot or {})
        except (KeyError, TypeError):
            pass  # a plan missing a value it needs is refused elsewhere; show the values instead
    return [f"{name} with " + ", ".join(f"{k}={v}" for k, v in sorted(params.items()))]


def target_key(name: str, params: dict[str, Any]) -> str:
    """The resource a fix changes, as one key: its platform and the parameters naming it, outermost first
    (`k8s:shop/orders`). The bounds, the mutex and the workflow id key on it - never on a free-text service
    name, which let `orders` in two namespaces share one rate limit and one open fix (audit C3, A-B-M4)."""
    entry = CATALOG[name]
    return entry.platform + ":" + "/".join(str(params.get(p, "")) for p in entry.target_params)


# A target named by an id a person cannot read is shown by its owner: an event source mapping's UUID - also the shape
# of many API keys, so the outbound gate withheld the whole approval request that named it (fs-07, live, 2026-10-15).
_SHOWN_BY = {"mapping": ("function", "event source mapping of {}")}


def shown_target(environment: str, name: str, params: dict[str, Any]) -> str:
    """The plan's target as a person reads it in a message; target_key stays the key the bounds and mutex use."""
    entry = CATALOG[name]
    parts = []
    for p in entry.target_params:
        owner, said = _SHOWN_BY.get(p, ("", ""))
        parts.append(said.format(params[owner]) if owner and params.get(owner) else str(params.get(p, "")))
    return f"{environment}/{entry.platform}:" + "/".join(parts)


# Research 2026-10-16 ("who will change this field back, and when?"): a runtime fix lasts only as long as whatever else
# owns the field leaves it. Each entry says how long its fix lasts and what has to follow, and the approver reads it
# before deciding - a rollback the next deploy undoes, or a value the next infrastructure apply sets back, is not a fix
# that holds. A new entry without one fails tests/test_fix_lasts.py.
_RESTORES = ("restores", ("it puts back the state from before the change. The change was made outside the normal "
                         "path: find who made it and why, so it is not made again."))
_UNTIL_DEPLOY = ("until_deploy", ("it lasts until the next deploy of this code or configuration. Revert or fix the "
                                  "change in Git first, or the next deploy brings it back."))
_UNTIL_APPLY = ("until_apply", ("infrastructure as code may declare this value; if it does, its next apply sets it "
                                "back. Change the value there too."))
_UNTIL_SCALED = ("until_scaled", ("an autoscaler or infrastructure as code may own this count and set it back; if "
                                  "one does, change it there."))
_TEMPORARY = ("temporary", "it holds the harm, not the cause: the cause still needs its own fix.")
_ONE_OFF = ("one_off", "a one-off action that nothing changes back; the cause still needs its own fix.")
# The time a fix was applied in this run, handed by check_success to the platform's health check in a copy of the
# plan's parameters (never planned, never hashed): a fix is judged on what came after it (live, 2026-10-16).
APPLIED_AT = "_applied_at"

LASTS: dict[str, tuple[str, str]] = {
    "lambda_move_alias": _UNTIL_DEPLOY, "lambda_restore_config": _UNTIL_DEPLOY,
    "lambda_set_reserved_concurrency": _UNTIL_APPLY, "lambda_enable_esm": _RESTORES, "lambda_disable_esm": _TEMPORARY,
    "events_enable_rule": _RESTORES, "events_disable_rule": _TEMPORARY, "sqs_redrive_dlq": _ONE_OFF,
    "athena_stop_query": _ONE_OFF, "apigw_raise_stage_throttle": _UNTIL_APPLY, "arc_zonal_shift": _TEMPORARY,
    "appconfig_revert": _UNTIL_DEPLOY, "codepipeline_freeze": _TEMPORARY, "dynamodb_raise_capacity": _UNTIL_APPLY,
    "ecs_rollback_service": _UNTIL_DEPLOY, "ecs_restart_service": _ONE_OFF, "ecs_scale_service": _UNTIL_SCALED,
    "k8s_rollout_undo": _UNTIL_DEPLOY, "k8s_restart": _ONE_OFF, "k8s_scale": _UNTIL_SCALED,
    "db_terminate_idle_in_tx": _ONE_OFF, "db_terminate_blocker": _ONE_OFF, "aurora_failover": _TEMPORARY,
    "infra_restore_baseline": _RESTORES, "ec2_revert_sg_change": _RESTORES, "ec2_restore_route": _RESTORES,
    "ecs_restore_desired": _RESTORES, "lambda_restore_concurrency": _RESTORES, "lambda_restore_settings": _RESTORES,
    "sqs_restore_attributes": _RESTORES, "kinesis_restore_retention": _RESTORES, "dynamodb_restore_capacity": _RESTORES,
    "asg_restore_capacity": _RESTORES, "asg_resume_processes": _RESTORES, "apigw_restore_stage": _RESTORES,
    "elb_reregister_targets": _RESTORES, "kms_cancel_key_deletion": _RESTORES, "secrets_restore_secret": _RESTORES,
}


def lasts(name: str) -> str:
    """How long the entry's fix lasts and what has to follow, as one sentence for the approver - or empty."""
    kind = LASTS.get(name)
    return f"How long it lasts: {kind[1]}" if kind else ""


def fingerprint() -> str:
    """What the catalogue allows, as one hash: a plan made under one catalogue is not applied under another
    (register O5). The `relative` limits are code, covered by the code hash (activities.code_version)."""
    material = [[e.name, e.tier, e.platform, list(e.target_params),
                 sorted([k, p.kind, p.lo, p.hi] for k, p in e.params.items())]
                for e in sorted(CATALOG.values(), key=lambda e: e.name)]
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


# A platform with more than one kind of recorded change to undo: the resolver uses the entry that found the change,
# and refuses when more than one did (WARDEN does not choose between two changes).
REVERT_ALSO = {"lambda": ("lambda_restore_settings",), "asg": ("asg_resume_processes",)}
# When none of them found a recorded change: a consumer a change switched off is undone by switching it on - the same
# write as resume_flow (G10 held-out, 2026-10-11: the undo of a disabled event source mapping was never planned).
REVERT_ELSE = {"lambda": ("lambda_enable_esm", "mapping")}


def for_action(action: ActionKind, platform: str) -> Entry | None:
    name = FOR_ACTION.get(action, {}).get(platform)
    return CATALOG[name] if name else None


ROLLS_PODS = frozenset({"k8s_restart", "ecs_restart_service"})
# A pause holds the harm, it fixes nothing (independent review 2026-10-10, H2): its run ends "mitigated" - the page is
# not resolved and a person resumes the flow.
MITIGATES = {"lambda_disable_esm": "it stays paused until a person resumes it",
             "events_disable_rule": "it stays paused until a person resumes it",
             "arc_zonal_shift": "traffic avoids the impaired zone until the shift expires; the zone is not fixed",
             "codepipeline_freeze": "deploys stay frozen until a person enables the stage's transition again",
             "kms_cancel_key_deletion": "the key is kept but stays disabled until a person enables it"}
# Snapshot values that move on their own while a plan waits: shown to the approver, left out of the drift hash (M6).
VOLATILE = {"sqs_redrive_dlq": ("waiting",)}
# A queue a paused mapping reads must keep its messages at least this long (H2: a 60 s retention expires them).
MIN_PAUSE_RETENTION_S = 86400
# A redrive must finish inside the default verify window (H3): at most this many seconds of moving.
REDRIVE_SECONDS = 180  # leaves the 3 consecutive 30 s checks inside the 5-minute window (review-e L5)  # entries that replace a workload's pods through its own rollout (C10)
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
        problem = _param_problem(pname, spec, params, live)
        if problem:
            problems.append(problem)
    if not problems and entry.relative:
        problems += entry.relative(params, live)
    if not problems and name in ROLLS_PODS:
        problems += _rolling_problems(live)
    if not problems and _gitops_reverts(name, live):
        problems.append(f"C4: {live['gitops']} manages this target and reverts a direct change; make the change in Git")
    if not problems and name in SCALES:
        problems += _autoscaler_problems(live)
    if live.get("rollout") == "progressing":
        # Register C5: a change made mid-rollout fights the rollout, and the next read cannot tell which did what.
        problems.append("P21-ROLLOUT-IN-PROGRESS: a rollout of this target is under way; act after it completes "
                        "or misses its deadline")
    return problems


def _param_problem(pname: str, spec: Param, params: dict[str, Any], live: dict[str, Any]) -> str | None:
    """Why one declared parameter is missing or out of bounds, or None when it is fine."""
    if pname not in params:
        return f"missing parameter {pname!r}"
    value = params[pname]
    if spec.kind == "ref":
        allowed = live.get(pname)
        if not isinstance(value, str) or not isinstance(allowed, set | frozenset) or value not in allowed:
            return f"{pname}={value!r} is not something WARDEN read from live state"
    elif not isinstance(value, int) or isinstance(value, bool) or not spec.lo <= value <= spec.hi:
        return f"{pname}={value!r} is outside {spec.lo}..{spec.hi}"
    return None


def _rolling_problems(live: dict[str, Any]) -> list[str]:
    """Register C10: a rollout strategy that keeps most of the target serving."""
    # Register C10: a restart goes through the target's own rolling settings, so those settings must keep most of
    # it serving - never Recreate, never more than half the pods down together, and never unknown.
    at_once, replicas = live.get("at_once"), live.get("current_replicas")
    if not isinstance(at_once, int) or not isinstance(replicas, int):
        return ["C10: the target's rollout strategy could not be read; a restart is not sent blind"]
    if replicas > 1 and at_once * 2 > replicas:
        return [(f"C10: the target's strategy would take {at_once} of {replicas} pods down at once; a "
                 "restart is refused until it keeps most of them serving")]
    return []


def _autoscaler_problems(live: dict[str, Any]) -> list[str]:
    """Register C4: an autoscaler that owns the count (or may: it could not be read) would undo a manual change."""
    if "autoscaled" not in live or live["autoscaled"] is False:
        return []
    if live["autoscaled"]:
        return [("C4: an autoscaler (a HorizontalPodAutoscaler, Application Auto Scaling) owns this target's "
                 "count; a manual change would be undone")]
    return ["C4: whether an autoscaler owns this target's count could not be read; no change is sent"]


def _gitops_reverts(name: str, live: dict[str, Any]) -> bool:
    """Whether a GitOps controller manages the target and would revert a direct change."""
    # Register C4: Argo CD or Flux would revert the change at its next sync - the fix belongs in Git. The one
    # exception (owner decision 2026-10-17): a restart of a Deployment whose Argo CD Application was read live
    # and ignores the restart annotation - self-heal leaves it, and a restart changes nothing Git holds. A scale,
    # an undo or anything else on a Git-managed workload would fight Git, and stays refused.
    if not live.get("gitops"):
        return False
    return not (name == "k8s_restart" and live["gitops"] == "Argo CD" and live.get("gitops_ignores_restart") is True)
