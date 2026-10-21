"""The deterministic gate. This is what decides — the model only ever proposes.

Every rule here is plain Python over typed data. No model call, no probability, no prompt. That is
the point: if the reasoning layer is stochastic, the deciding layer must not be, or the system has
no floor. Each rule returns a policy id so a rejection can be explained to an auditor without
re-running anything.
"""

from __future__ import annotations

import os
import re
from datetime import datetime

from . import evidence, tripwire
from .environments import EnvironmentPolicies, default_environment_policies, strip_prefix
from .evidence import tokens
from .grounding import (
    action_support_problem,
    citation_problems,
    decisive_problem,
    margin_problem,
    outcome_problem,
    ranked_problem,
    target_problem,
)
from .knowledge import default_knowledge_base
from .models import (
    ACTION_FACTS,
    RESOURCE_LABELS,
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Verdict,
    VerdictStatus,
)
from .resolver import no_fix_path

# Actions genuinely inert enough to skip human approval. Deliberately only the two that CANNOT
# touch running infrastructure: doing nothing, and handing off to a person. `clear_cache` was here
# and was removed - flushing a production cache can cause a stampede/latency spike, so it is a real
# action and belongs behind approval like the others. The project's whole claim is "nothing risky
# runs without a human"; this list is where that claim is enforced, so it stays as short as possible.
AUTO_SAFE_ACTIONS = {ActionKind.no_action, ActionKind.escalate_to_human}
# Label words that name a data store or a compute cluster (P14 scopes): whole words, not substrings.
_DATA_WORDS = frozenset({"aurora", "rds", "db", "database", "elasticache", "redis", "valkey", "cache", "docdb",
                         "documentdb", "memcache", "memcached", "mongo", "mongodb", "dynamodb", "neptune"})
_COMPUTE_WORDS = frozenset({"ecs", "eks", "gke", "aks", "k8s", "k3s", "kube", "kubernetes", "openshift", "ocp", "nomad",
                            "fargate", "compute"})


def _compute(word: str) -> bool:
    """A compute platform's word, also as an acronym's tail (`AWSECSCluster` reads awsecs + cluster)."""
    return word in _COMPUTE_WORDS or any(word.endswith(c) and len(word) <= len(c) + 4 for c in _COMPUTE_WORDS)
# Actions whose target is a database or a cache (P14 scopes).
_DATA_ACTIONS = {ActionKind.clear_cache, ActionKind.terminate_connections, ActionKind.failover_replica,
                 ActionKind.scale_up, ActionKind.scale_down}

# Actions exempt from the EVIDENCE floor (P4, P8, P9). Only escalating to a person: handing an
# incident to a human is the right answer to weak evidence, so measuring the evidence before
# allowing it would be circular.
#
# ⛔ `no_action` was in this set and is not any more. On a real AWS account, 14 of 42 runs answered
# `no_action` about a service with a live fault and the gate allowed every one - two of them at 0.25
# confidence while their own `tool_errors` recorded that WARDEN could not read the logs at all
# (tests/fixtures/bench/wave1-2026-09-11T155744Z). "Nothing is wrong" is a CLAIM ABOUT THE EVIDENCE, so it
# must clear the same evidence floor as any other claim. A well-evidenced, confident `no_action` is
# still auto_safe - the tool looked properly and found nothing.
EVIDENCE_EXEMPT_ACTIONS = {ActionKind.escalate_to_human}

# The per-environment allow-list is no longer hardcoded here — it lives in environments.yaml so an
# operator can add an environment (dev and prod are shipped) or tighten an allowlist without
# editing this gate. P1 consults it below. An unknown environment resolves to the restrictive default
# and fails closed.

MIN_CONFIDENCE = 0.55

# Thresholds for P9. Deliberately modest — this is a floor for "somebody looked at something",
# not a quality bar. Tune per deployment; the point is that it is OUR number, not the model's.
MIN_LOG_LINES = 3
MIN_METRICS = 2


def _evidence_is_substantial(context) -> bool:
    """Is there enough gathered evidence to justify touching production?

    Counted, not asked. A model reporting high confidence over two log lines is the exact failure
    this exists to catch, and it was observed on a live model, not hypothesised.
    """
    has_logs = len(context.logs) >= MIN_LOG_LINES
    has_metrics = len(context.metrics) >= MIN_METRICS
    # A write CloudTrail recorded counts as a deploy does: it is the record of a change (a
    # scheduled rule a person disabled runs nothing, so it logs nothing and has one metric; its DisableRule, its
    # DISABLED state and its alarm were all read, and the re-enable was held as thin evidence).
    has_deploys = bool(context.recent_deploys) or next(_changes_by_someone(context), None) is not None
    # Two independent kinds of evidence, or a deploy plus one other kind.
    return sum([has_logs, has_metrics, has_deploys]) >= 2


def _log_has(context, *needles: str) -> bool:
    return any(n in line for line in context.logs for n in needles)


def _oom_seen(context) -> bool:
    return context.metrics.get("oom_killed_containers", 0) > 0 or _log_has(context, "OOMKilled", "OOMKilling")


REPLICA_LAG_SYMPTOM_S = 30.0


def symptoms(context) -> list[str]:
    """Things the EVIDENCE says are broken - counted, never judged from rates.

    Each is a count of broken objects or an explicit failure state the backends emit, so none of
    them depends on a threshold someone has to tune, except replica lag (named above). Used by P12
    to stop "nothing is wrong" being waved through when the evidence says otherwise.
    """
    m = context.metrics
    return [*_workload_symptoms(context), *_database_symptoms(context), *_idle_queues(m), *_counted_symptoms(m)]


def _workload_symptoms(context) -> list[str]:
    """Containers, pods, replicas, tasks and deployments the evidence counts as broken."""
    m = context.metrics
    out: list[str] = []
    if _oom_seen(context):
        out.append("containers were OOM-killed")
    if m.get("crashloop_containers", 0) > 0 or _log_has(context, "CrashLoopBackOff"):
        out.append("containers are crash-looping")
    if _log_has(context, "ErrImagePull", "ImagePullBackOff"):
        out.append("an image cannot be pulled")
    if "pods_total" in m and m.get("pods_ready", m["pods_total"]) < m["pods_total"]:
        out.append(f"only {m.get('pods_ready', 0):.0f} of {m['pods_total']:.0f} pods are ready")
    if "replicas_desired" in m and m.get("pods_ready", 0) < m["replicas_desired"]:
        out.append(f"{m.get('pods_ready', 0):.0f} ready of {m['replicas_desired']:.0f} replicas desired")
    if "tasks_desired" in m and m.get("tasks_running", 0) < m["tasks_desired"]:
        out.append(f"{m.get('tasks_running', 0):.0f} of {m['tasks_desired']:.0f} tasks running")
    if m.get("tasks_pending", 0) > 0:
        # A task that cannot start is counted, not judged: a replay of ecs-13 (a subnet with no route) once let a
        # confident no_action through as auto_safe beside one stuck task and two deployments in flight.
        out.append(f"{m['tasks_pending']:.0f} task(s) pending, not started")
    if m.get("deployments_failed", 0) > 0 or m.get("deployment_failed_tasks", 0) > 0:
        out.append("a deployment has failed tasks")
    return out


def _database_symptoms(context) -> list[str]:
    """A full connection pool, stuck or waiting sessions, long queries and replica lag."""
    m = context.metrics
    out: list[str] = []
    # A full pool is an explicit state, not a rate: every connection the server (or the app's pool)
    # allows is taken. Live backends report `connections_used_pct`; recorded incidents the pool pair.
    # inc-005's report once said "no failing component" beside a 100/100 pool.
    pool_size = m.get("connection_pool_size", 0)
    if m.get("connections_used_pct", 0) >= 1.0 or (pool_size and m.get("connection_pool_used", 0) >= pool_size):
        out.append("the connection pool is full")
    if _log_has(context, "stuck connection:"):
        out.append("sessions have been idle inside a transaction past the stuck threshold")
    if m.get("locks_waiting", 0) > 0:
        n = int(m["locks_waiting"])
        out.append(f"{n} session{'s are' if n != 1 else ' is'} waiting on a lock")
    if m.get("long_running_queries", 0) > 0:
        n = int(m["long_running_queries"])
        out.append(f"{n} quer{'ies have' if n != 1 else 'y has'} been running over 60s")
    if (replica_lag_s(m) or 0) >= REPLICA_LAG_SYMPTOM_S:
        out.append(f"replica lag is {replica_lag_s(m):.0f}s")
    return out


# The full stack (docs/FULLSTACK-LAB.md section 4 B): counts of failures and explicit off states, each
# possibly suffixed `__<short>` per resource. Only counts > 0 and states == 0 - no thresholds.
def _idle_queues(m: dict[str, float]) -> list[str]:
    """Queues with messages waiting that nothing is receiving."""
    # Messages waiting and none being received: an explicit state, counted - the queue is not being consumed.
    out: list[str] = []
    for key, value in m.items():
        if (key == "sqs_visible" or key.startswith("sqs_visible__")) and value > 0:
            sfx = key[len("sqs_visible"):]
            if m.get(f"sqs_in_flight{sfx}") == 0:
                who = f" ({sfx[2:]})" if sfx else ""
                out.append(f"{value:.0f} message(s) waiting in the queue{who}, none being processed")
    return out


def _counted_symptoms(m: dict[str, float]) -> list[str]:
    """Each _STACK_SYMPTOMS metric (or its per-resource `__<short>` copy) whose value says broken."""
    out: list[str] = []
    for base, what, broken in _STACK_SYMPTOMS:
        for key, value in m.items():
            if (key == base or key.startswith(base + "__")) and broken(value):
                who = f" ({key.split('__', 1)[1]})" if "__" in key else ""
                out.append(f"{what}{who}: {value:.0f}")
    return out


_POSITIVE, _OFF = (lambda v: v > 0), (lambda v: v == 0)
_STACK_SYMPTOMS = (
    ("lambda_errors", "Lambda errors", _POSITIVE),
    ("lambda_throttles", "Lambda throttles", _POSITIVE),
    ("lambda_reserved_concurrency", "Lambda reserved concurrency is", _OFF),
    ("lambda_esm_enabled", "queue event source mapping enabled", _OFF),
    # A queue's own reader (scenario fs-07: "no errors and no failing component" was reported over a queue whose only
    # consumer was switched off and 95 orders waiting).
    ("sqs_consumers_enabled", "queue consumers enabled", _OFF),
    ("dlq_visible", "messages in the dead-letter queue", _POSITIVE),
    ("ddb_read_throttle_events", "DynamoDB read throttle events", _POSITIVE),
    ("ddb_write_throttle_events", "DynamoDB write throttle events", _POSITIVE),
    ("ddb_throttled_requests", "DynamoDB throttled requests", _POSITIVE),
    ("alb_unhealthy_hosts", "unhealthy load balancer targets", _POSITIVE),
    ("alb_target_5xx", "target 5xx responses", _POSITIVE),
    ("apigw_5xx", "API Gateway 5xx responses", _POSITIVE),
    ("rule_enabled", "scheduled rule enabled", _OFF),
    ("redis_evictions", "cache evictions", _POSITIVE),
    ("sns_notifications_failed", "failed SNS deliveries", _POSITIVE),
    ("aurora_deadlocks", "Aurora deadlocks", _POSITIVE),
)


def _every_pod_failing(context) -> bool:
    """No pod is reliably serving: none is ready, or every pod has a crash-loop / back-off record.

    ⛔ `pods_ready == 0` alone is a coin-flip for a crash-looping pod. With no readiness probe,
    Kubernetes marks it Ready for the moments between crashes - in CI the same OOM workload read as
    ready=1 from outside the cluster and ready=0 from inside it, seconds apart, and P11 fired on only
    one of them. A pod Ready between crashes is not serving traffic; a pod with a back-off record is
    failing whatever its readiness says at the instant it was sampled.
    """
    m = context.metrics
    total = m.get("pods_total")
    if not total:
        return False
    if m.get("pods_ready", total) == 0 or m.get("crashloop_containers", 0) >= total:
        return True
    backing_off = {
        line.split("Pod/", 1)[1].split(":", 1)[0]
        for line in context.logs
        if line.startswith("EVENT ") and ("BackOff" in line or "CrashLoopBackOff" in line) and "Pod/" in line
    }
    return len(backing_off) >= total


def _deploy_of_target(alert, context, target: str) -> bool:
    """A recent deploy of what the target names. The target must name a service that has a real
    deploy in the evidence, and if it names the alert's own service, that service must be the one
    deployed (`orders (after payments deploy)` and `orders, payments` must not pass on a payments deploy
    through the shared word). Model targets come in many shapes -
    `ecs-service/checkout (prod): revert revision 34 ...` - so this matches service NAMES, not
    positions. A secret rotation is not a deploy (docs/FULLSTACK-LAB.md section 4 D). A deploy with no
    `service` comes from a backend scoped to one service, so it is the alert's."""
    named = tokens(target)
    deployed = set()
    for d in context.recent_deploys:
        if d.get("kind") != "secret":
            deployed |= tokens(str(d.get("service") or alert.service))
    if not named & deployed:
        return False
    own = tokens(alert.service)
    # The service counts as deployed when a deployed name IS it, or is it behind a configured
    # environment's prefix (`warden-dev-checkout`). Not any name component: `payments-orders`,
    # `billing-api`, `orders-db` and `orders-canary` are other services.
    own_deployed = own & deployed or {o for o in own for d in deployed if strip_prefix(d) == o}
    return not (named & own) or bool(own_deployed)


# The unit may be followed by an aggregate or a resource (`replica_lag_seconds_max`,
# `replica_lag_msec`, `replica_lag_seconds_orders`).
_LAG = re.compile(r"(?:^|_)(?:replica|replication)_lag((?:_[a-z0-9]+)*)$")
# Reading any suffix as seconds is wrong - `replication_lag_bytes`,
# `replica_lag_count`, `replica_lag_alarm`, `max_replica_lag_seconds_threshold` counted as lag, and
# `replica_lag_p99_ms` (a unit after an aggregate) read 40,000 ms as 40,000 s. Units are now a whitelist,
# converted, at most one per name, before or after aggregates; a name with a word that is not lag, or an
# ambiguous unit (`min`: minutes or minimum?), is not a lag measurement. Other words are a resource (`_orders`).
# More spellings, each converted (else `replica_lag_millisecond=500` reads as 500 s, and
# hours are ignored). The word for a billionth of a second is built from parts: written whole it contains
# the letters bandit reads as a suppression comment.
_NANO = "nano" + "second"
_NANO_S = "nano" + "sec"
# Days are converted as hours are, and each spelling below is read as the unit it names.
_LAG_UNITS = {**dict.fromkeys(("ms", "msec", "msecs", "millis", "milli", "millisec", "millisecs", "millisecond",
                               "milliseconds", "msecond", "mseconds"), 0.001),
              **dict.fromkeys(("s", "sec", "secs", "second", "seconds"), 1.0),
              **dict.fromkeys(("us", "usec", "usecs", "micros", "microsec", "microsecs", "microsecond",
                               "microseconds"), 0.000001),
              **dict.fromkeys(("ns", "nsec", "nsecs", "nanos", _NANO_S, _NANO_S + "s", _NANO, _NANO + "s"),
                              0.000000001),
              **dict.fromkeys(("mins", "minute", "minutes"), 60.0),
              **dict.fromkeys(("h", "hr", "hrs", "hour", "hours"), 3600.0),
              **dict.fromkeys(("d", "day", "days"), 86400.0),
              **dict.fromkeys(("week", "weeks"), 604800.0)}
_NOT_LAG = frozenset({"b", "byte", "bytes", "kb", "kib", "mb", "mib", "gb", "gib", "tb", "tib", "kilobyte",
                      "kilobytes", "kibibytes", "megabyte", "megabytes", "mebibytes", "gigabyte", "gigabytes",
                      "gibibytes", "kbytes", "mbytes", "bits", "blocks", "wal", "segments", "lsn", "pages", "txns",
                      "transactions", "events", "ops", "rows", "offset", "messages", "records", "entries", "score",
                      "samples", "count", "total", "alarm", "alarms", "state", "status", "threshold", "limit",
                      "target", "ratio", "pct", "percent", "min"})
# CloudWatch's own names, with the units CloudWatch reports them in (RDS ReplicaLag and ElastiCache
# ReplicationLag in seconds, Aurora's in milliseconds) - an MCP caller may pass them as they are.
_CLOUDWATCH_LAG = {"ReplicaLag": 1.0, "ReplicationLag": 1.0, "AuroraBinlogReplicaLag": 1.0,
                   "AuroraReplicaLag": 0.001, "AuroraReplicaLagMaximum": 0.001, "AuroraReplicaLagMinimum": 0.001,
                   # DocumentDB and Aurora Global Database report milliseconds too.
                   "DBInstanceReplicaLag": 0.001, "DBClusterReplicaLagMaximum": 0.001,
                   "DBClusterReplicaLagMinimum": 0.001, "AuroraGlobalDBReplicationLag": 0.001}


def _lag_seconds(name: str, value: float) -> float | None:
    m = _LAG.search(name)
    if not m:
        return None
    scale = None
    for word in m.group(1).split("_")[1:]:
        if word in _NOT_LAG:
            return None
        if word in _LAG_UNITS:
            if scale is not None:
                return None   # two units: `replica_lag_seconds_ms` - which one?
            scale = _LAG_UNITS[word]
    return value * (1.0 if scale is None else scale)


def replica_lag_s(metrics: dict[str, float]) -> float | None:
    """The largest replica lag MEASURED, in seconds, or None if none was. Backends name it
    differently - `replica_lag_seconds` (database.py), `reader_replica_lag_seconds` and
    `aurora_replica_lag_ms` (aws_stack.py), each possibly suffixed per resource. A check that knew only
    the first never fired on the AWS stack."""
    lags = []
    for key, value in metrics.items():
        # The unit is read from the metric's OWN name, before any `__<resource>` suffix: `_ms` in
        # `__payments_msvc` read 47 s as 47 ms, and `redis_replication_lag_s` was unknown.
        name = key.split("__", 1)[0]
        lag = value * _CLOUDWATCH_LAG[name] if name in _CLOUDWATCH_LAG else _lag_seconds(name, value)
        if lag is not None:
            lags.append(lag)
    return max(lags) if lags else None


# The stopped-task causes that are failures (aws_stack.stop_cause), not a deployment's or a person's own stops.
_TASK_FAILURES = frozenset({"secret_missing", "permission", "network", "image", "oom", "health_check", "exit",
                            "failed_to_start"})


def _deploy_changed_access(context) -> bool:
    """A deploy in the evidence changed what the task may reach: its roles or its secrets (aws_backend._config_changes)."""
    changed = ",".join(str(d.get("changed", "")) for d in context.recent_deploys)
    return any(w in changed for w in ("taskRoleArn", "executionRoleArn", ".secrets:"))


# A measured fact the diagnosis cannot argue with. The IAM policy simulator's own answer
# (aws_stack._simulate_denials, a trusted STATE line): the role's OWN policies deny the call the workload makes.
_ROLE_DENIES = re.compile(r"^STATE iam simulate role=(\S+) action=(\S+) resource=\S+ decision=(implicitDeny|explicitDeny) ")
# Actions that run the same workload under the same role again: none changes what the role may do. A rollback or a
# revert may (an earlier task definition or function version, a changed role), and holding still harms nothing.
_RERUNS_THE_DENIED_CALL = frozenset({
    ActionKind.restart_pods, ActionKind.scale_up, ActionKind.scale_down, ActionKind.failover_replica,
    ActionKind.clear_cache, ActionKind.terminate_connections, ActionKind.raise_limit, ActionKind.shift_traffic,
    ActionKind.redrive_messages, ActionKind.resume_flow})


# Held-out G10 with Claude Sonnet 5.5: six harmful proposals, all stopped - but four only by low
# confidence or a citation check, which a more confident answer passes. These rules stop them by what the action does.
# An HPA's own numbers (k8s reader): it owns the replica count, and a manual scale is overridden by it (g10-144).
_HPA_KEYS = ("hpa_max_replicas", "hpa_min_replicas")
# ECS could not place tasks it already wanted (the service's own events, counted by the ECS reader, g10-061): more
# tasks cannot be placed either - the cluster's capacity, or its ENIs, is a person's change.
_UNPLACED = re.compile(r"^STATE ecs/\S+ service events in the hour before the alert: .*\bunable_to_place=([1-9]\d*)")
_SCALES = frozenset({ActionKind.scale_up, ActionKind.scale_down})


# A change made on purpose by a security, cost or compliance identity (g10-042: IMDSv2 required by
# role/secops-imds-hardening; g10-070: a query cutoff set by role/finops-cost-guardrails). Undoing it undoes the
# guardrail: a person decides. Named by the operator (WARDEN_NEVER_REVERT_PRINCIPALS, which the platform already refused at
# plan time) or by a word of its role's name. A trusted CHANGE line names the principal (aws_stack._principal).
_GOVERNANCE = frozenset({"security", "secops", "sec", "finops", "guardrail", "guardrails", "compliance", "audit",
                         "governance", "breakglass", "break-glass"})
_CHANGE_BY = re.compile(r"^CHANGE \S+ \S+ ([A-Za-z0-9]+) on (\S+) by (\S+)")
UNDOES = frozenset({ActionKind.revert_change, ActionKind.revert_config})


def _deliberate(proposal, context) -> str | None:
    """Why undoing the change before the alert is a person's decision - or None."""
    if proposal.action not in UNDOES:
        return None
    named = {n.strip() for n in os.environ.get("WARDEN_NEVER_REVERT_PRINCIPALS", "").split(",") if n.strip()}
    for line in context.logs:
        m = _CHANGE_BY.match(line)
        if not m:
            continue
        event, on, who = m.groups()
        name = who.split("/", 1)[-1]
        # Whole words, split at `-_.` and at capitals too: `AWSReservedSSO_SecurityAudit_x` holds "security" and
        # "audit"; `securitygroups-tool` holds neither, and `second-shift-ops` no "sec". A part
        # the redactor masked (an SSO role's random suffix) is no word.
        readable = re.sub(r"<[A-Z_]+_\d+>", " ", name)
        tokens = {t.lower() for part in re.split(r"[-_.\s]", readable)
                  for t in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+", part)}
        if not tokens:
            # Nothing of the principal is readable: not known to be no guardrail.
            return (f"the change before the alert ({event} on {on}) was made by a principal WARDEN cannot read ({who}): "
                    "whether it was a deliberate security, cost or compliance change is not known - a person decides.")
        if name in named or tokens & _GOVERNANCE or "break-glass" in name.lower():
            return (f"the change before the alert ({event} on {on}) was made by {who}, a security, cost or compliance "
                    "identity: a deliberate change. Undoing it undoes that guardrail - a person decides.")
    return None


def _contradiction(proposal, context) -> str | None:
    """Why the proposed action cannot fix what the evidence shows - or None.

    Only contradictions that follow from how the action works, not from judgement: each is a case
    where the action demonstrably leaves the evidenced cause in place, or harms what is working.
    """
    a, m = proposal.action, context.metrics
    return (_capacity_contradiction(a, m, context) or _memory_contradiction(a, m, context)
            or _task_contradiction(a, m, context) or _session_contradiction(a, m))


def _capacity_contradiction(a: ActionKind, m: dict[str, float], context) -> str | None:
    """An autoscaler owns the count, ECS cannot place more tasks, or the role is denied the call it would rerun."""
    if a in _SCALES and any(k in m or any(x.startswith(k + "__") for x in m) for k in _HPA_KEYS):
        lo, hi = m.get("hpa_min_replicas"), m.get("hpa_max_replicas")
        bounds = f" (min {lo:.0f}, max {hi:.0f})" if lo is not None and hi is not None else ""
        return (f"{a.value} sets a replica count a HorizontalPodAutoscaler owns{bounds}: the autoscaler overrides a "
                "manual scale within minutes. Its metric, its limits or its scaling behaviour are a person's change.")
    if a is ActionKind.scale_up:
        unplaced = next((u for u in map(_UNPLACED.match, context.logs) if u), None)
        if unplaced:
            return (f"scale_up asks for more tasks, and ECS could not place the ones it already wanted "
                    f"({unplaced.group(1)} unable-to-place events in the hour before the alert): more cannot be placed "
                    "either. The cluster's capacity - its instances, or their network interfaces - is a person's "
                    "change.")
    if a in _RERUNS_THE_DENIED_CALL:
        denied = next((d for d in map(_ROLE_DENIES.match, context.logs) if d), None)
        if denied:
            return (f"{a.value} runs the workload again under the same role, and the IAM policy simulator says the "
                    f"role's own policies deny {denied.group(2)} ({denied.group(3)} for {denied.group(1)}): the "
                    "same call is denied again. The role's permissions are what a person must change.")
    return None


def _memory_contradiction(a: ActionKind, m: dict[str, float], context) -> str | None:
    """Out-of-memory kills, replica lag or an image that cannot be pulled, which the action leaves in place."""
    # scale_up on OOM is NOT always wrong: when memory grows with load, more replicas mean less load,
    # and less memory, per replica (the bundled inc-002 is that case). It is wrong when no replica is
    # failing (none ready, or every pod crash-looping / backing off - see _every_pod_failing) - then
    # none is reliably serving traffic, so load is not what fills memory, and every new replica
    # is killed at startup the same way (the EKS k8s-02/03 case: 900 MiB allocated at start, 48 MiB
    # limit). A first version flagged all scale_up-on-OOM and the inc-002 tests caught it.
    if a is ActionKind.scale_up and _oom_seen(context) and _every_pod_failing(context):
        return ("scale_up adds replicas, but every pod is failing: they are OOM-killed before serving "
                "traffic, so load is not what fills memory and every new replica dies at startup the "
                "same way. The per-replica memory limit or the application's memory use is the cause.")
    # raise_limit raises a request throttle or a reserved concurrency; an
    # out-of-memory kill is not a throttle, and a memory limit is not what it raises.
    if a is ActionKind.raise_limit and _oom_seen(context):
        return ("raise_limit raises a request throttle or a reserved concurrency, and the evidence shows "
                "out-of-memory kills: no throttle is what kills the process.")
    if a is ActionKind.scale_down and _oom_seen(context):
        return ("scale_down with OOM kills in the evidence: fewer replicas cannot lower any replica's "
                "memory use, and if memory grows with load it pushes more load onto each one.")
    # scale_down on replica lag is refused: fewer replicas each carry more of the
    # load, so a lagging replica falls further behind.
    lag = replica_lag_s(m) or 0.0
    if a is ActionKind.scale_down and lag >= 1:
        return (f"scale_down with replica lag of {lag:g}s in the evidence: fewer replicas each take more "
                "of the load, so the lagging replica falls further behind.")
    if a is ActionKind.restart_pods and _log_has(context, "ErrImagePull", "ImagePullBackOff"):
        return "restart_pods re-pulls the same image, and the evidence shows that image cannot be pulled."
    return None


def _task_contradiction(a: ActionKind, m: dict[str, float], context) -> str | None:
    """ECS tasks that die of what the action does not change."""
    # G10-C1: what ECS's own stopped tasks say they died of (aws_stack._read_ecs_tasks). A rollback changes the task
    # definition: it cannot fix tasks that die on the network - a route, a security group, DNS (recorded ecs-13 proposed
    # one) - nor on a permission the deploy did not change. Fresh or more tasks fail to start the same way.
    failing = {k.removeprefix("ecs_stopped_") for k, v in m.items()
               if k.startswith("ecs_stopped_") and v > 0} & _TASK_FAILURES
    if (a is ActionKind.rollback_deploy and failing and failing <= {"network", "permission"}
            and not ("permission" in failing and _deploy_changed_access(context))):
        return (f"rollback_deploy changes the task definition, but the stopped tasks died on "
                f"{' and '.join(sorted(failing))}: the previous revision meets the same route, security group or "
                "permission.")
    if (a in (ActionKind.restart_pods, ActionKind.scale_up) and m.get("ecs_tasks_failed_to_start", 0) > 0
            and failing & {"secret_missing", "permission", "network", "image"}):
        return (f"{a.value} starts more tasks, but tasks fail to start ({', '.join(sorted(failing))}): every new one "
                "fails the same way.")
    return None


def _session_contradiction(a: ActionKind, m: dict[str, float]) -> str | None:
    """Database sessions doing work, or no replica lag to fail over from."""
    if (a is ActionKind.terminate_connections and "long_running_queries" in m
            and m.get("long_running_queries", 0) > 0 and m.get("idle_in_transaction", 0) == 0
            and m.get("locks_waiting", 0) == 0):
        return ("terminate_connections with nothing idle in a transaction and nothing blocked: the only "
                "long sessions in the evidence are ACTIVE queries, and terminating them destroys work "
                "in progress.")
    # ⛔ Only when lag was MEASURED. An absent metric is not zero lag: ECS, Kubernetes and Redis report
    # none, and the MCP gate gets none at all; reading absence as zero escalated every failover proposal from those
    # with a false reason ("no replica lag in the evidence").
    lag = replica_lag_s(m) or 0.0
    if a is ActionKind.failover_replica and replica_lag_s(m) is not None and lag < 1:
        return "failover_replica with no replica lag in the evidence - there is nothing lagging to fail over from."
    return None


# Observe mode. A new policy runs here first: evaluated on every verdict and recorded in
# `Verdict.observed`, never obeyed - so replays and shadow runs show what it WOULD have done, on healthy controls as
# well as faults, before a reviewed change moves it into the enforced policies below. A guess at a threshold is
# measured here instead of being imposed.
OBSERVE_ERROR_RATE = 0.05  # APP-5XX-001's own threshold


def _p25_error_rate(alert: Alert, context: ContextBundle, root_cause: RootCause,
                    proposal: RemediationProposal) -> str | None:
    """Audit Q2's candidate: "nothing to do" while an error-rate metric is at or above 5%. P12 counts broken states,
    never rates, so this case passes it; whether a rate rule escalates healthy controls is what observing measures."""
    if proposal.action is not ActionKind.no_action:
        return None
    hot = sorted(k for k, v in context.metrics.items() if "error_rate" in k.lower() and v >= OBSERVE_ERROR_RATE)
    return f"no action proposed while {', '.join(hot)} is at or above {OBSERVE_ERROR_RATE:.0%}" if hot else None


def _p26_decider(alert: Alert, context: ContextBundle, root_cause: RootCause,
                 proposal: RemediationProposal) -> str | None:
    """Requirement R44: the calibrated decider's probability that this proposal is right, observed when it is under
    one half. Held out by fault class it does not yet beat the base rate (data/decider.json), so it decides nothing."""
    from .decide import bundled, features, probability

    doc = bundled()
    if doc is None:
        return None
    verdict = _enforce(alert, context, root_cause, proposal, check_grounding=True)
    p = probability(features(alert, context, root_cause, proposal, verdict), doc)
    return f"the calibrated decider puts this proposal at p={p:.2f} of being right" if p < 0.5 else None


def _p27_numbers(alert: Alert, context: ContextBundle, root_cause: RootCause,
                 proposal: RemediationProposal) -> str | None:
    """Register M2: a number with a unit in the model's prose (a percentage, a duration) that no metric of its kind
    supports once both are in one unit - "42%" over error_rate=0.042."""
    from .numbers import problems

    found = problems([root_cause.hypothesis, *root_cause.evidence, proposal.reasoning, proposal.expected_effect],
                     context.metrics)
    return "; ".join(found[:5]) if found else None


def _p28_language(alert: Alert, context: ContextBundle, root_cause: RootCause,
                  proposal: RemediationProposal) -> str | None:
    """Register M23: most log lines are not English, so WARDEN's English keyword checks (signatures, symptoms, the
    quarantine's phrases) may miss what they say; a person should read them. Code-shaped facts still count."""
    from .language import foreign_share

    share = foreign_share(context.logs)
    return f"{share:.0%} of the log lines are not English: WARDEN's keyword checks are English" if share > 0.3 else None


# Audit E1: P8 escalates every action when ANY read failed - and a busy service's logs are always cut,
# so it could never get an approvable fix. A failed read is BENIGN only when the evidence it bears on was still read:
# lines cut with the alert-time lines and the older errors kept, or one of the secondary reads below (a zone list, the
# configuration an alarm guards, an alarm's sibling metrics, a function's code excerpt). Paging that stopped BEFORE the
# alert time is material, and so is every denied, missing or timed-out read of the alerting resource itself. The old
# "truncated at N lines" kept the OLDEST lines (Wave 4's fs-05): material. Observed first (the 30 recorded incidents:
# P8 fired 3 times, none of them benign), then enforced: P8 fires on a material read only.
# The stack readers put their own tags first (`logs: lambda/<fn> logs: logs: [output truncated] kept the newest ...`):
# a pattern that held only the bare form never saw the sampling notice it was written for (on the G10 held-out
# set, 0 of the 27 right fixes P8 escalated read benign). Every tag before the outcome must be
# shaped like one WARDEN writes (evidence._SEGMENT), as in tool_error_text.
_BENIGN_TAIL = re.compile(r"\[output truncated\] (?:kept the newest|stopped after \d+ pages, "
                          r"the alert-time lines read first|\d+ line\(s\) cut to)")
# The alarm's own history and the IAM simulator's answer are secondary too: the
# alarm, its metric and the denial line they bear on are read whatever becomes of them.
# A service's quotas and their usage (quotas.py, B14) are read beside the alerting resource, never instead of it.
_SECONDARY_READ = re.compile(r"alb zones|appconfig|alarm-siblings metrics|lambda/[\w.-]+ code|alarm history|iam-simulate"
                             r"|quotas(?: usage| [a-z0-9-]{1,40})?")
# A container that has not started has no log to read, and its pod's own state lines say why (on the G10 held-out
# set, two right rollbacks were held by nothing but these). Kubernetes' own two answers, with their reason - never a
# bare 400.
_NO_LOG_YET = re.compile(r"\[rejected as a bad request\] \(400\) (?:pod \S+ does not have a host assigned$"
                         r"|container \S+ in pod \S+ is waiting to start: \S)")


def _benign_partial(error: str) -> bool:
    m = re.match(r"(?:logs|metrics|recent_deploys): ", error)
    if not m:
        return False
    rest = error[m.end():]
    first = rest.split(": ", 1)[0]
    if first == "logs" and ": " in rest:  # the bare backend's own `logs: ` prefix
        rest = rest.split(": ", 1)[1]
        first = rest.split(": ", 1)[0]
    if ": " in rest and _SECONDARY_READ.fullmatch(first):
        return True
    i = rest.find("[")
    chain = rest[:i]
    if i < 0 or (chain and not chain.endswith(": ")):
        return False
    if not all(evidence._SEGMENT.fullmatch(seg) for seg in (chain[:-2].split(": ") if chain else [])):
        return False
    return bool(_BENIGN_TAIL.match(rest, i) or _NO_LOG_YET.match(rest, i))


# A dated write as aws_stack._read_changes writes it: when, the event, the resource, who.
_CHANGE_LINE = re.compile(r"^CHANGE (\d{4}-\d\d-\d\dT[\d:]{8})Z \S+ (\S+) on (\S+) by (\S+)")
UNADDRESSED_CHANGE_WINDOW_S = 1800


def _changes_by_someone(context: ContextBundle):
    """WARDEN's own CHANGE lines of a write someone made: (item, match). Not AWS's own automation (a service, a
    service-linked role), not a label written beside the resource. Any other actor counts - a role, a user, the root
    user, a federated one, and a name the redactor hid: unknown is not AWS (counting only `role` and
    `user` made an Identity Center role the redactor hid nobody's change)."""
    for item in evidence.index(context).values():
        m = _CHANGE_LINE.match(item.text)
        if not m or not item.id.startswith("C"):
            continue
        who = m.group(4)
        if who.startswith(("service", "role/AWSServiceRole")) or m.group(2).startswith(("TagResource", "UntagResource")):
            continue
        yield item, m


def _when(text: str) -> datetime | None:
    try:
        at = datetime.fromisoformat(text)
    except ValueError:
        return None
    return at if at.tzinfo else None


# A write and the one that takes it back, by the first word of AWS's event names.
_OPPOSITES = (("Enable", "Disable"), ("Start", "Stop"), ("Suspend", "Resume"), ("Attach", "Detach"))


def _taken_back(event: str, later: set[str]) -> bool:
    """Did a later write to the same resource take this one back (EnableRule, then DisableRule)? Then it is not the
    state the alarm fired on, and nothing a fix has to answer for (a report must not be held for a rule's
    EnableRule that the DisableRule after it - the cause, cited - has already taken back)."""
    return any(event.startswith(a) and b + event[len(a):] in later
               for pair in _OPPOSITES for a, b in (pair, pair[::-1]))


def _p31_unaddressed_change(alert: Alert, context: ContextBundle, root_cause: RootCause,
                            proposal: RemediationProposal) -> str | None:
    """G10 held-out case g10-135: a person cut an ECS service's desired count ten minutes before its
    memory alarm; the diagnosis named only the memory leak and a restart reached the approver. Recorded when a role or
    a user wrote to the alert's own resource in the half hour before it fired, and a fix neither reverts, rolls back
    nor cites that write. Enforced after it was measured in observe mode."""
    if proposal.action in (ActionKind.revert_change, ActionKind.rollback_deploy) or proposal.action in AUTO_SAFE_ACTIONS:
        return None
    started = _when(alert.started_at)
    names = {n.strip() for k, v in alert.labels.items() if k in RESOURCE_LABELS for n in v.split(",") if n.strip()}
    cited = {c.id for c in root_cause.citations}
    changes = [(item, m) for item, m in _changes_by_someone(context) if m.group(3) in names]
    for item, m in changes:
        if item.id in cited:
            continue
        # The timestamps are one format, so they order as text.
        if _taken_back(m.group(2), {n.group(2) for _, n in changes if n.group(3) == m.group(3) and n.group(1) > m.group(1)}):
            continue
        at = _when(m.group(1) + "+00:00")
        if started and at and 0 <= (started - at).total_seconds() <= UNADDRESSED_CHANGE_WINDOW_S:
            return f"{m.group(2)} on {m.group(3)} by {m.group(4)} ({item.id}) is neither cited nor reverted"
    return None


OBSERVED = (("P25-NO-ACTION-OVER-ERROR-RATE", _p25_error_rate), ("P26-LOW-DECIDER-P", _p26_decider),
            ("P27-NUMBER-NOT-IN-EVIDENCE", _p27_numbers), ("P28-NON-ENGLISH-LOGS", _p28_language))


def verify(
    alert: Alert,
    context: ContextBundle,
    root_cause: RootCause,
    proposal: RemediationProposal,
    *,
    policies_config: EnvironmentPolicies | None = None,
    check_grounding: bool = True,
) -> Verdict:
    """The binding decision (`_enforce`), with what each observe-mode policy would have said recorded beside it."""
    verdict = _enforce(alert, context, root_cause, proposal, policies_config=policies_config,
                       check_grounding=check_grounding)
    observed = [f"{pid}: {why}" for pid, check in OBSERVED if (why := check(alert, context, root_cause, proposal))]
    return verdict.model_copy(update={"observed": observed}) if observed else verdict


def signatures_in_evidence(alert: Alert, context: ContextBundle) -> list[str]:
    """P36: the failure signatures that a signal WARDEN read fires - a log or event term, a metric, a deploy - with the
    alert's own words (its name and summary) left out."""
    own_words_out = alert.model_copy(update={"summary": ""})
    kb = default_knowledge_base()
    # Every match, not the top three: name-only matches must not crowd out one the evidence supports.
    return [m.signature.id for m in kb.match(own_words_out, context, limit=len(kb.signatures))
            if set(m.signals) - {"name"}]


def _enforce(
    alert: Alert,
    context: ContextBundle,
    root_cause: RootCause,
    proposal: RemediationProposal,
    *,
    policies_config: EnvironmentPolicies | None = None,
    check_grounding: bool = True,
) -> Verdict:
    """Return the binding decision for one proposal.

    `policies_config` lets a caller/test inject a specific environment policy set; by default the
    bundled/operator-configured one is used. `check_grounding=False` is for callers that hold no
    evidence text to check against (the MCP surface, which receives counts; replays of reports that
    predate citations) - P13/P14 are then not evaluated, and those callers say so.
    """
    env_policies = policies_config or default_environment_policies()
    env = env_policies.for_env(alert.environment)
    f = _Findings()
    _environment_policies(f, alert, proposal, env_policies, env)
    _evidence_policies(f, alert, context, root_cause, proposal)
    _proposal_policies(f, alert, context, proposal)
    _action_policies(f, context, proposal)
    if proposal.action is ActionKind.no_action:
        _no_action_policies(f, alert, context)
    if check_grounding and proposal.action not in EVIDENCE_EXEMPT_ACTIONS:
        _grounding_policies(f, context, root_cause)
    _ranking_policies(f, context, root_cause, proposal, check_grounding)
    _tripwire_policies(f, context, env)

    # P14 - the target must be a resource WARDEN knows exists. Rejects: acting on a name the
    # evidence does not contain is acting on a guess.
    if check_grounding and proposal.action not in AUTO_SAFE_ACTIONS:
        problem = _target_problem(alert, context, proposal)
        if problem:
            f.reject("P14-TARGET-NOT-IN-EVIDENCE", problem + ".")

    _plan_policies(f, alert, context, root_cause, proposal)
    return _verdict(f, proposal)


class _Findings:
    """The policies a proposal trips, in the order they are checked, each with its reason; and whether any rejects
    the proposal or hands it to a person."""

    def __init__(self) -> None:
        self.reasons: list[str] = []
        self.policies: list[str] = []
        self.rejected = False
        self.escalated = False

    def reject(self, policy: str, reason: str) -> None:
        self.rejected = True
        self.policies.append(policy)
        self.reasons.append(reason)

    def escalate(self, policy: str, reason: str) -> None:
        self.escalated = True
        self.policies.append(policy)
        self.reasons.append(reason)


def _environment_policies(f: _Findings, alert: Alert, proposal: RemediationProposal,
                          env_policies: EnvironmentPolicies, env) -> None:
    # P22 — WARDEN does not act on WARDEN (register N7): an alert about its own runtime environment goes to a person,
    # whatever the proposal - a broken WARDEN diagnosing itself is the case it can be least trusted in.
    if env_policies.runtime_environment and alert.environment == env_policies.runtime_environment:
        f.escalate("P22-SELF-TARGET",
                   f"{alert.environment} is WARDEN's own runtime: a person handles it, WARDEN never acts on itself.")

    # P1 — the action must be permitted in this environment at all (from environments.yaml).
    if not env.permits(proposal.action):
        f.reject("P1-ENV-ALLOWLIST", f"{proposal.action.value} is not permitted in {alert.environment}.")

    # P2 — nothing irreversible in a production-tier environment, ever, regardless of confidence.
    #
    # ⛔ READS THE TABLE, NOT THE PROPOSAL. `proposal.reversible` is written by the model, and by
    # any caller of the MCP server, so keying a rejection on it let a proposal widen its own
    # permissions: two live models reported opposite values for the identical operation and got
    # opposite verdicts in a live-model run. The claim is not discarded — P10
    # escalates when it contradicts the table.
    if env.tier == "prod" and not proposal.table_reversible:
        f.reject("P2-IRREVERSIBLE-IN-PROD",
                 f"{proposal.action.value} is classified irreversible in WARDEN's action table, and "
                 f"{alert.environment} is production-tier. The proposal claimed "
                 f"reversible={proposal.reversible}; the table decided, not the claim.")


def _evidence_policies(f: _Findings, alert: Alert, context: ContextBundle, root_cause: RootCause,
                       proposal: RemediationProposal) -> None:
    # P3 — evidence is a precondition for action, not an optional extra.
    if context.is_empty() and proposal.action not in AUTO_SAFE_ACTIONS:
        f.reject("P3-NO-EVIDENCE", "No logs, metrics or deploy history were gathered; refusing to act blind.")

    # P4 — a low-confidence hypothesis is a question, not a plan.
    if root_cause.confidence < MIN_CONFIDENCE and proposal.action not in EVIDENCE_EXEMPT_ACTIONS:
        f.escalate("P4-LOW-CONFIDENCE", f"Confidence {root_cause.confidence:.2f} is below the {MIN_CONFIDENCE} threshold.")

    # P5 — you cannot roll back a deploy that the evidence does not show. The deploy must be OF the
    # target: a deploy of any other service used to count.
    if proposal.action is ActionKind.rollback_deploy and not _deploy_of_target(alert, context, proposal.target):
        f.reject("P5-NO-DEPLOY-TO-ROLL-BACK",
                 "Rollback proposed but no recent deploy of the target appears in the gathered context."
                 if context.recent_deploys else
                 "Rollback proposed but no recent deploy appears in the gathered context.")


def _proposal_policies(f: _Findings, alert: Alert, context: ContextBundle, proposal: RemediationProposal) -> None:
    # P6 — wide blast radius is always a human's call. The table sets a FLOOR per action and the
    # proposal may only ever widen it: a model asking for a human is always allowed to, while
    # understating the reach of an action must buy it nothing.
    effective_radius = proposal.effective_blast_radius
    if effective_radius in ("multi_service", "region"):
        floor = ACTION_FACTS[proposal.action][1]
        f.escalate("P6-BLAST-RADIUS",
                   f"Blast radius '{effective_radius}' exceeds the unattended limit (WARDEN's floor for "
                   f"{proposal.action.value} is '{floor}', the proposal claimed "
                   f"'{proposal.blast_radius}'; the wider of the two applies).")

    # P7 — proportionality. Don't fail over a database because something is 'low'.
    heavy = {ActionKind.failover_replica, ActionKind.rollback_deploy}
    if proposal.action in heavy and alert.severity.value in ("low", "medium"):
        f.escalate("P7-DISPROPORTIONATE",
                   f"{proposal.action.value} is disproportionate to a {alert.severity.value} alert.")

    # P8 — a tool failing means the picture is partial. Say so rather than pretending.
    # Only a MATERIAL failed read (P29, enforced after three held-out runs: 19, 22 and 21 more right
    # fix plans, no wrong one): WARDEN's own sampling notice on a busy service's logs is not a missing picture.
    material = [e for e in context.tool_errors if not _benign_partial(e)]
    if material and proposal.action not in EVIDENCE_EXEMPT_ACTIONS:
        f.escalate("P8-PARTIAL-CONTEXT", f"{len(material)} context tool(s) failed; evidence is incomplete.")

    # P9 — evidence measured by US, not confidence reported by the model.
    #
    # Added after running against a live model: it returned confidence 0.85 on ALL the bundled
    # incidents (five in the recorded run), including
    # the one whose entire evidence is two vague log lines. A model's
    # self-reported confidence is not calibrated, so P4 alone would essentially never fire — the
    # gate would be relying on a number the model has no incentive or ability to get right.
    #
    # This counts what was actually gathered. It cannot be talked around by a confident tone.
    if proposal.action not in EVIDENCE_EXEMPT_ACTIONS and not _evidence_is_substantial(context):
        f.escalate("P9-THIN-EVIDENCE",
                   f"Evidence is thin ({len(context.logs)} log line(s), {len(context.metrics)} metric(s), "
                   f"{len(context.recent_deploys)} deploy(s)); a human should look before acting.")

    # P10 — the proposal warns that this cannot be undone while the table says it can.
    #
    # P2 reads the table so the model cannot decide; ignoring a warning is a different thing from
    # refusing to obey one. `escalated` and `rejected` both mean nothing runs and both require a
    # person, so escalating here preserves the warning without handing the decision back.
    if proposal.claim_contradicts_table:
        f.escalate("P10-CLAIM-CONTRADICTS-TABLE",
                   f"The proposal claims {proposal.action.value} is irreversible; WARDEN's action table "
                   "classifies it reversible. A human should reconcile that before anything runs.")


def _action_policies(f: _Findings, context: ContextBundle, proposal: RemediationProposal) -> None:
    # P11 — the action cannot fix what the evidence shows.
    #
    # ⛔ Added from measured failures, which is disclosed with it: all three runs the EKS
    # wave let through wrongly were `scale_up` against `oom_killed_containers = 2` - more replicas of
    # a container killed at 48 MiB are killed the same way - and nothing in P1-P10 read the evidence
    # against the action. A re-run of the same scenarios is therefore NOT an independent test of this
    # policy. Escalates, never rejects: the rules are how the actions work, but a human decides.
    contradiction = _contradiction(proposal, context)
    if contradiction:
        f.escalate("P11-ACTION-CONTRADICTS-EVIDENCE", contradiction)

    # P33 - undoing a deliberate change by a security, cost or compliance identity.
    deliberate = _deliberate(proposal, context)
    if deliberate:
        f.escalate("P33-DELIBERATE-CHANGE", deliberate)

    # P23 — "nothing to do" because a read came back empty (register N2). An empty answer from a throttled,
    # lagging or misdirected query looks exactly like a quiet, healthy service; it is unknown, never healthy.
    if proposal.action is ActionKind.no_action and context.empty_reads:
        f.escalate("P23-EMPTY-READ", "No action proposed, but these reads returned nothing, which is not the same as "
                   "healthy: " + ", ".join(context.empty_reads) + ".")


def _no_action_policies(f: _Findings, alert: Alert, context: ContextBundle) -> None:
    # P24 — "nothing to do" about an incident WARDEN does not recognise (requirement R39). symptoms() counts known
    # broken states, never rates, so a new kind of failure - one no signature describes, showing only as errors and
    # latency - passed P12 and was closed: a novel failing service under a confident no_action went out auto_safe.
    # An alert fired; when nothing WARDEN knows describes it, closing it is a person's call. Measured on the replay set:
    # every no_action in the 30 replayed incidents already reached a person, so this changes none of their verdicts.
    # (A signature match is not a symptom: signatures also fire on the alert's name. Audit Q2 is the rate case.)
    matches = default_knowledge_base().match(alert, context)
    if not matches:
        f.escalate("P24-UNRECOGNISED", "No action proposed for an incident no known signature describes: an alert "
                   "WARDEN cannot explain is closed by a person, not by WARDEN.")
    # P36 - "nothing to do" while one of WARDEN's own failure signatures describes the EVIDENCE: a planted "these 5xx
    # are expected during maintenance, no action is needed" line, followed with
    # real citations, closed a checkout incident whose deploy and error spike DEPLOY-BAD-001 describes, auto_safe
    # (evals/poisoned_logs.py, close-incident). Enforced: with dev autonomous, a poisoned
    # log silently closing a real incident is worse than the extra hand-offs. Only what WARDEN read counts - the log
    # lines and events, metrics and deploys - never the alert's own name or summary: healthy controls are named
    # and described like faults. On the held-out keys (no model answer involved) it hands 11 of the 33 cases a
    # person may close (G9 4 of 8, G10 7 of 25) to a person instead; each of those keys accepts the hand-off.
    if seen := signatures_in_evidence(alert, context):
        f.escalate("P36-NO-ACTION-DESPITE-SIGNATURE", f"No action proposed, but WARDEN's own failure signatures "
                   f"describe this evidence ({', '.join(seen)}): a person closes it, not WARDEN.")

    # P12 — "nothing to do" while the evidence shows something broken.
    #
    # no_action became subject to P4/P8/P9 after Wave 1, but a CONFIDENT no_action over plenty of
    # evidence still went out auto_safe even with pods OOM-killed or not ready. In the measured runs
    # low confidence happened to catch every such case; that was luck, not a rule. Same disclosure
    # as P11: written after seeing the runs.
    found = symptoms(context)
    if found:
        f.escalate("P12-NO-ACTION-WITH-SYMPTOMS", "No action proposed, but the evidence shows: " + "; ".join(found) + ".")


def _grounding_policies(f: _Findings, context: ContextBundle, root_cause: RootCause) -> None:
    # P13 - the diagnosis must be grounded: every citation names a real evidence id and quotes it
    # verbatim (grounding.py). Escalates: an ungrounded diagnosis may still be right, a person checks.
    problems = citation_problems(root_cause, evidence.view(context))
    if problems:
        f.escalate("P13-UNGROUNDED", "The diagnosis is not grounded in the evidence: " + "; ".join(problems) + ".")

    # P34 / P35 - item 7: a fix only on a cause the evidence WARDEN read itself decides, and only when that
    # cause clearly beats its rivals by WARDEN's own count of their citations - never by the model's confidence.
    # Escalates: the diagnosis may be right; a person reads both causes.
    items = evidence.view(context)
    if why := decisive_problem(root_cause, items):
        f.escalate("P34-NO-DECISIVE-EVIDENCE", f"{why[0].upper()}{why[1:]}.")
    if close := margin_problem(root_cause, items):
        if close[0] == "no_rival":
            f.escalate("P35-NO-RIVAL-HYPOTHESIS", f"{close[1][0].upper()}{close[1][1:]}.")
        else:
            f.escalate("P35-HYPOTHESES-TOO-CLOSE", f"{close[1][0].upper()}{close[1][1:]}.")


def _ranking_policies(f: _Findings, context: ContextBundle, root_cause: RootCause, proposal: RemediationProposal,
                      check_grounding: bool) -> None:
    # P38 - the stated root cause is the one the hypotheses ranked first: otherwise the count and the
    # remediation's evidence describe another cause. Escalates; nothing is rewritten.
    if why := ranked_problem(root_cause):
        f.escalate("P38-HYPOTHESIS-NOT-RANKED-FIRST", f"{why[0].upper()}{why[1:]}: a person reads both.")
    # P37 - the typed outcome against the proposal: "no fault" with a change, or "could not
    # determine" with anything but a hand-off. Escalates: the diagnosis contradicts its own remediation.
    if why := outcome_problem(root_cause, proposal):
        f.escalate("P37-OUTCOME-CONTRADICTS-PROPOSAL", f"{why[0].upper()}{why[1:]}: a person decides.")

    # P15 - the citations must bear on the ACTION, not merely exist (grounding.ACTION_EVIDENCE).
    # Escalates: a person checks whether the evidence supports this fix at all.
    if check_grounding and proposal.action not in AUTO_SAFE_ACTIONS:
        problem = action_support_problem(root_cause, proposal, evidence.view(context))
        if problem:
            f.escalate("P15-CITATIONS-DO-NOT-SUPPORT-ACTION", problem + ".")


def _tripwire_policies(f: _Findings, context: ContextBundle, env) -> None:
    # P16 - the trained injection detector (tripwire.py) flagged untrusted evidence, or it was
    # required and could not run. Escalates: a flagged line may be an attack or a false alarm, and
    # a person decides which - nothing runs automatically on evidence that looks like one.
    if context.suspected:
        if set(context.suspected) == {tripwire.TOO_MUCH_TEXT}:
            reason = (f"The text the model reads is larger than the injection detector's budget "
                      f"({tripwire.MAX_SCAN_TOKENS} tokens), so it was not scanned; a person reads it.")
        else:
            flagged = ", ".join(f"{i} ({s:.2f})" for i, s in sorted(context.suspected.items()))
            reason = f"The injection detector flagged untrusted evidence: {flagged}."
        f.escalate("P16-SUSPECTED-INJECTION", reason)
    # ⛔ In `required` mode ANY status but "ran" escalates - "off" (evidence handed in
    # by a caller that never ran the detector) used to pass.
    # "ran-partial" is a run: the alert, the labels and the trusted items the model reads were scanned; only
    # raw log lines went past the budget - the model never sees them, but it does see their typed facts,
    # which then only the quarantine's filters cover.
    elif tripwire.mode(env.tripwire) == "required" and not tripwire.ran(context.tripwire):
        f.escalate("P16-SUSPECTED-INJECTION",
                   f"The injection detector is required here and could not run ({context.tripwire}).")


# Every label that names a whole namespace or cluster, each value of a list
# (`ecs_cluster=warden-dev-cluster` must not let the cluster itself through as a target).
# Any spelling of a namespace or cluster label - `NAMESPACE`, `k8s_namespace`, `aurora_cluster`, an
# ElastiCache group.
# A database or cache cluster is the resource of a data action - clearing a cache, closing sessions, a
# failover, scaling it - and scopes only an action on pods: rejecting it as a scope refused the natural
# targets of clear_cache and terminate_connections. A namespace or a compute
# cluster is never a failover's target.
# Keys in any spelling - `ClusterName`, `k8s.namespace.name`, `cache-cluster` - read as words (eighth
# review: those were not scopes at all, and `sandbox_namespace` held "db").
def _label_words(k: str) -> list[str]:
    # At a lower-to-upper change and at an acronym's end: `ECSCluster` is ecs + cluster, `K8SNamespace` k8s +
    # namespace (split at the first only, they would be one word and no scope).
    split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z0-9])(?=[A-Z][a-z])", "_", k)
    return [w for w in re.split(r"[^a-z0-9]+", split.lower()) if w]


def _label_values(alert: Alert, keep, *, but_the_service: bool = True) -> set[str]:
    found = {v.strip() for k, value in alert.labels.items() if value and keep(_label_words(k))
             for v in str(value).split(",") if v.strip()}
    return found - {alert.service} if but_the_service else found


def _is_namespace(w: list[str]) -> bool:
    return w[-1:] == ["ns"] or bool({"namespace", "namespaces"} & set(w[-2:]))


def _is_scope(w: list[str]) -> bool:
    # A key that is only a platform's name (`ecs=...`) names its cluster.
    return (_is_namespace(w) or bool({"cluster", "clusters"} & set(w[-2:])) or w == ["elasticache"]
            or (len(w) == 1 and _compute(w[0])))


def _is_data(w: list[str]) -> bool:
    return not _is_namespace(w) and bool(set(w) & _DATA_WORDS)


def _target_problem(alert: Alert, context: ContextBundle, proposal: RemediationProposal) -> str | None:
    """P14: why the proposal's target is not one resource WARDEN knows exists - or None."""
    data_action = proposal.action in _DATA_ACTIONS
    # A bare `cluster` key stays a scope for a database or cache action: on an ECS alert it is the ECS cluster
    # (wave 1). Unless WARDEN's OWN reads show the name is a data store - a metric of a database or a cache
    # (`rds_connections__orders-db`) - it is not taken for one: `cluster=orders-db` was refused as a target
    # of terminate_connections even then (register R9-O3). Label text alone never makes a name a database.
    stores = {k.split("__", 1)[1] for k in context.metrics
              if "__" in k and set(re.split(r"[^a-z0-9]+", k.split("__", 1)[0].lower())) & _DATA_WORDS}
    scopes = _label_values(alert, lambda w: _is_scope(w) and not (data_action and _is_data(w)))
    if data_action:
        scopes -= stores
    # A failover never targets a namespace or a compute cluster - not even one named like the service (the
    # recorded fs-01 alert's namespace is `shop`, its service `shop`).
    containers = _label_values(alert, lambda w: _is_namespace(w) or (_is_scope(w) and any(_compute(x) for x in w)),
                               but_the_service=False)
    # `kind:name`, where the alert's own label of that kind holds the name, is that one resource - as the
    # resolver reads it (`elasticache_serverless:pricing-cache` is not a list).
    kind, sep, rest = proposal.target.partition(":")
    named = proposal.model_copy(update={"target": rest}) if sep and alert.labels.get(kind) == rest else proposal
    return target_problem(named, evidence.inventory(alert, context), scopes, containers)


def _plan_policies(f: _Findings, alert: Alert, context: ContextBundle, root_cause: RootCause,
                   proposal: RemediationProposal) -> None:
    # P30 - a fix nothing in the catalogue can carry out is advice for a person, never a plan put to the approver
    # (G10-B). In held-out case G9-F, scale_up on a NAT gateway reached a person as approved_for_human, with no
    # entry that acts on a NAT gateway - the one wrong answer the gate let through. Decided only for a target the
    # alarm's labels name (resolver.no_fix_path); the right fix may well be what it says, done by a person.
    if why := no_fix_path(alert, proposal):
        f.escalate("P30-NO-FIX-PATH",
                   f"{why[0].upper()}{why[1:]}: the proposal is advice for a person to carry out, not a plan.")

    # P31 - a person's recent write to the alerting resource that the fix ignores (enforced after it
    # was measured in observe mode: on the G10 held-out answers it named only wrong ones - the one wrong answer that
    # reached a person in every run, a restart that ignored a desired-count cut - and none of 132 right ones).
    if why := _p31_unaddressed_change(alert, context, root_cause, proposal):
        f.escalate("P31-UNADDRESSED-CHANGE", f"{why[0].upper()}{why[1:]}: a person looks at that change before any fix.")


def _verdict(f: _Findings, proposal: RemediationProposal) -> Verdict:
    if f.rejected:
        return Verdict(
            status=VerdictStatus.rejected,
            reasons=f.reasons,
            policy_ids=f.policies,
            requires_approval=True,
        )
    if f.escalated:
        return Verdict(
            status=VerdictStatus.escalated,
            reasons=f.reasons or ["Escalated for human judgement."],
            policy_ids=f.policies,
            requires_approval=True,
        )
    if proposal.action in AUTO_SAFE_ACTIONS:
        return Verdict(
            status=VerdictStatus.auto_safe,
            reasons=["Action is inert or advisory; no approval required."],
            policy_ids=f.policies,
            requires_approval=False,
        )
    return Verdict(
        status=VerdictStatus.approved_for_human,
        reasons=["Passed all policies. Held for operator approval before execution."],
        policy_ids=f.policies,
        requires_approval=True,
    )
