"""The deterministic gate. This is what decides — the model only ever proposes.

Every rule here is plain Python over typed data. No model call, no probability, no prompt. That is
the point: if the reasoning layer is stochastic, the deciding layer must not be, or the system has
no floor. Each rule returns a policy id so a rejection can be explained to an auditor without
re-running anything.
"""

from __future__ import annotations

import re
from datetime import datetime

from . import evidence, tripwire
from .environments import EnvironmentPolicies, default_environment_policies, strip_prefix
from .evidence import tokens
from .grounding import action_support_problem, citation_problems, target_problem
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
# Label words that name a data store or a compute cluster (P14 scopes, eighth review): whole words, not substrings.
_DATA_WORDS = frozenset({"aurora", "rds", "db", "database", "elasticache", "redis", "valkey", "cache", "docdb",
                         "documentdb", "memcache", "memcached", "mongo", "mongodb", "dynamodb", "neptune"})
_COMPUTE_WORDS = frozenset({"ecs", "eks", "gke", "aks", "k8s", "k3s", "kube", "kubernetes", "openshift", "ocp", "nomad",
                            "fargate", "compute"})


def _compute(word: str) -> bool:
    """A compute platform's word, also as an acronym's tail (`AWSECSCluster` reads awsecs + cluster)."""
    return word in _COMPUTE_WORDS or any(word.endswith(c) and len(word) <= len(c) + 4 for c in _COMPUTE_WORDS)
# Actions whose target is a database or a cache (P14 scopes, seventh review).
_DATA_ACTIONS = {ActionKind.clear_cache, ActionKind.terminate_connections, ActionKind.failover_replica,
                 ActionKind.scale_up, ActionKind.scale_down}

# Actions exempt from the EVIDENCE floor (P4, P8, P9). Only escalating to a person: handing an
# incident to a human is the right answer to weak evidence, so measuring the evidence before
# allowing it would be circular.
#
# ⛔ `no_action` was in this set and is not any more. On a real AWS account, 14 of 42 runs answered
# `no_action` about a service with a live fault and the gate allowed every one - two of them at 0.25
# confidence while their own `tool_errors` recorded that WARDEN could not read the logs at all
# (docs/bench/wave1-2026-09-11T155744Z). "Nothing is wrong" is a CLAIM ABOUT THE EVIDENCE, so it
# must clear the same evidence floor as any other claim. A well-evidenced, confident `no_action` is
# still auto_safe - the tool looked properly and found nothing.
EVIDENCE_EXEMPT_ACTIONS = {ActionKind.escalate_to_human}

# The per-environment allow-list is no longer hardcoded here — it lives in environments.yaml so an
# operator can add an environment (qa-staging, pre-prod, qa-prod, ...) or tighten an allowlist without
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
    has_deploys = bool(context.recent_deploys)
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
        # A task that cannot start is counted, not judged: 2026-10-03 a replay of ecs-13 (a subnet with no route) let a
        # confident no_action through as auto_safe beside one stuck task and two deployments in flight.
        out.append(f"{m['tasks_pending']:.0f} task(s) pending, not started")
    if m.get("deployments_failed", 0) > 0 or m.get("deployment_failed_tasks", 0) > 0:
        out.append("a deployment has failed tasks")
    # A full pool is an explicit state, not a rate: every connection the server (or the app's pool)
    # allows is taken. Live backends report `connections_used_pct`; recorded incidents the pool pair.
    # Added 2026-09-25: inc-005's report said "no failing component" beside a 100/100 pool.
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
    # The full stack (docs/WAVE4-CONTRACT.md B): counts of failures and explicit off states, each
    # possibly suffixed `__<short>` per resource. Only counts > 0 and states == 0 - no thresholds.
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
    deployed (independent review 2026-09-28: `orders (after payments deploy)` and `orders, payments`
    passed on a payments deploy, through the shared word). Model targets come in many shapes -
    `ecs-service/checkout (prod): revert revision 34 ...` - so this matches service NAMES, not
    positions. A secret rotation is not a deploy (docs/WAVE4-CONTRACT.md D). A deploy with no
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
    # `billing-api`, `orders-db` and `orders-canary` are other services (third review, 2026-09-30).
    own_deployed = own & deployed or {o for o in own for d in deployed if strip_prefix(d) == o}
    return not (named & own) or bool(own_deployed)


# The unit may be followed by an aggregate or a resource (third review: `replica_lag_seconds_max`,
# `replica_lag_msec`, `replica_lag_seconds_orders` were no longer read).
_LAG = re.compile(r"(?:^|_)(?:replica|replication)_lag((?:_[a-z0-9]+)*)$")
# Fourth review (2026-09-30, C-7): any suffix was read as seconds - `replication_lag_bytes`,
# `replica_lag_count`, `replica_lag_alarm`, `max_replica_lag_seconds_threshold` counted as lag, and
# `replica_lag_p99_ms` (a unit after an aggregate) read 40,000 ms as 40,000 s. Units are now a whitelist,
# converted, at most one per name, before or after aggregates; a name with a word that is not lag, or an
# ambiguous unit (`min`: minutes or minimum?), is not a lag measurement. Other words are a resource (`_orders`).
# Fifth review (2026-10-01): more spellings, each converted (`replica_lag_millisecond=500` was 500 s, and
# hours were ignored). The word for a billionth of a second is built from parts: written whole it contains
# the letters bandit reads as a suppression comment.
_NANO = "nano" + "second"
_NANO_S = "nano" + "sec"
# Sixth review (2026-10-01): days were ignored while hours were converted, and more spellings were misread.
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
                   # DocumentDB and Aurora Global Database report milliseconds too (sixth review).
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
    the first never fired on the AWS stack (independent review 2026-09-28)."""
    lags = []
    for key, value in metrics.items():
        # The unit is read from the metric's OWN name, before any `__<resource>` suffix: `_ms` in
        # `__payments_msvc` read 47 s as 47 ms, and `redis_replication_lag_s` was unknown (second
        # review, 2026-09-30).
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


def _contradiction(proposal, context) -> str | None:
    """Why the proposed action cannot fix what the evidence shows - or None.

    Only contradictions that follow from how the action works, not from judgement: each is a case
    where the action demonstrably leaves the evidenced cause in place, or harms what is working.
    """
    a, m = proposal.action, context.metrics
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
    # G9-D (qualification 2026-10-10): raise_limit raises a request throttle or a reserved concurrency; an
    # out-of-memory kill is not a throttle, and a memory limit is not what it raises.
    if a is ActionKind.raise_limit and _oom_seen(context):
        return ("raise_limit raises a request throttle or a reserved concurrency, and the evidence shows "
                "out-of-memory kills: no throttle is what kills the process.")
    if a is ActionKind.scale_down and _oom_seen(context):
        return ("scale_down with OOM kills in the evidence: fewer replicas cannot lower any replica's "
                "memory use, and if memory grows with load it pushes more load onto each one.")
    # Audit A-C-6: scale_down on replica lag passed in staging. Fewer replicas each carry more of the
    # load, so a lagging replica falls further behind.
    lag = replica_lag_s(m) or 0.0
    if a is ActionKind.scale_down and lag >= 1:
        return (f"scale_down with replica lag of {lag:g}s in the evidence: fewer replicas each take more "
                "of the load, so the lagging replica falls further behind.")
    if a is ActionKind.restart_pods and _log_has(context, "ErrImagePull", "ImagePullBackOff"):
        return "restart_pods re-pulls the same image, and the evidence shows that image cannot be pulled."
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
    if (a is ActionKind.terminate_connections and "long_running_queries" in m
            and m.get("long_running_queries", 0) > 0 and m.get("idle_in_transaction", 0) == 0
            and m.get("locks_waiting", 0) == 0):
        return ("terminate_connections with nothing idle in a transaction and nothing blocked: the only "
                "long sessions in the evidence are ACTIVE queries, and terminating them destroys work "
                "in progress.")
    # ⛔ Only when lag was MEASURED. An absent metric is not zero lag: ECS, Kubernetes and Redis report
    # none, and the MCP gate got none at all, so until 2026-09-25 every failover proposal from those
    # escalated with a false reason ("no replica lag in the evidence").
    if a is ActionKind.failover_replica and replica_lag_s(m) is not None and lag < 1:
        return "failover_replica with no replica lag in the evidence - there is nothing lagging to fail over from."
    return None


# Observe mode (audit A-P-8). A new policy runs here first: evaluated on every verdict and recorded in
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


# Audit E1 (2026-10-10): P8 escalates every action when ANY read failed - and a busy service's logs are always cut,
# so it could never get an approvable fix. A failed read is BENIGN only when the evidence it bears on was still read:
# lines cut with the alert-time lines and the older errors kept, or one of the secondary reads below (a zone list, the
# configuration an alarm guards, an alarm's sibling metrics, a function's code excerpt). Paging that stopped BEFORE the
# alert time is material, and so is every denied, missing or timed-out read of the alerting resource itself. The old
# "truncated at N lines" kept the OLDEST lines (Wave 4's fs-05): material. Observed only, until a live window measures
# it on healthy controls and faults (the 30 recorded incidents: P8 fired 3 times, none of them benign).
# The stack readers put their own tags first (`logs: lambda/<fn> logs: logs: [output truncated] kept the newest ...`):
# the pattern held only the bare form, so P29 never saw the sampling notice it was written for (G10 held-out
# baseline, 2026-10-10: 0 of the 27 right fixes P8 escalated read benign). Every tag before the outcome must be
# shaped like one WARDEN writes (evidence._SEGMENT), as in tool_error_text.
_BENIGN_TAIL = re.compile(r"\[output truncated\] (?:kept the newest|stopped after \d+ pages, "
                          r"the alert-time lines read first|\d+ line\(s\) cut to)")
_SECONDARY_READ = re.compile(r"alb zones|appconfig|alarm-siblings metrics|lambda/[\w.-]+ code")


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
    return bool(_BENIGN_TAIL.match(rest, i))


def _p29_benign_partials(alert: Alert, context: ContextBundle, root_cause: RootCause,
                         proposal: RemediationProposal) -> str | None:
    """Audit E1's candidate: P8 fired, but every failed read was benign - enforcing would let this verdict stand on
    the other policies alone."""
    if not context.tool_errors or proposal.action in EVIDENCE_EXEMPT_ACTIONS:
        return None
    if all(_benign_partial(e) for e in context.tool_errors):
        return f"P8 fired on {len(context.tool_errors)} failed read(s), every one benign"
    return None


# A write to the alert's own resource by a person or a pipeline, as aws_stack._read_changes writes it.
_CHANGE_LINE = re.compile(r"^CHANGE (\d{4}-\d\d-\d\dT[\d:]{8})Z \S+ (\S+) on (\S+) by ((?:role|user)\S*)")
UNADDRESSED_CHANGE_WINDOW_S = 1800


def _when(text: str) -> datetime | None:
    try:
        at = datetime.fromisoformat(text)
    except ValueError:
        return None
    return at if at.tzinfo else None


def _p31_unaddressed_change(alert: Alert, context: ContextBundle, root_cause: RootCause,
                            proposal: RemediationProposal) -> str | None:
    """G10 held-out set (2026-10-10, g10-135): a person cut an ECS service's desired count ten minutes before its
    memory alarm; the diagnosis named only the memory leak and a restart reached the approver. Recorded when a role or
    a user wrote to the alert's own resource in the half hour before it fired, and a fix neither reverts, rolls back
    nor cites that write. Enforced (owner, 2026-10-10) after it was measured in observe mode."""
    if proposal.action in (ActionKind.revert_change, ActionKind.rollback_deploy) or proposal.action in AUTO_SAFE_ACTIONS:
        return None
    started = _when(alert.started_at)
    names = {n.strip() for k, v in alert.labels.items() if k in RESOURCE_LABELS for n in v.split(",") if n.strip()}
    cited = {c.id for c in root_cause.citations}
    for item in evidence.index(context).values():
        m = _CHANGE_LINE.match(item.text)
        if not (m and item.id.startswith("C") and m.group(3) in names) or item.id in cited:
            continue
        if m.group(4).startswith("role/AWSServiceRole") or m.group(2).startswith(("TagResource", "UntagResource")):
            continue  # AWS's own automation, and a label written beside the resource, are not a change made to it
        at = _when(m.group(1) + "+00:00")
        if started and at and 0 <= (started - at).total_seconds() <= UNADDRESSED_CHANGE_WINDOW_S:
            return f"{m.group(2)} on {m.group(3)} by {m.group(4)} ({item.id}) is neither cited nor reverted"
    return None


OBSERVED = (("P25-NO-ACTION-OVER-ERROR-RATE", _p25_error_rate), ("P26-LOW-DECIDER-P", _p26_decider),
            ("P27-NUMBER-NOT-IN-EVIDENCE", _p27_numbers), ("P28-NON-ENGLISH-LOGS", _p28_language),
            ("P29-P8-BENIGN-PARTIALS", _p29_benign_partials))


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

    reasons: list[str] = []
    policies: list[str] = []
    rejected = False
    escalate = False

    # P22 — WARDEN does not act on WARDEN (register N7): an alert about its own runtime environment goes to a person,
    # whatever the proposal - a broken WARDEN diagnosing itself is the case it can be least trusted in.
    if env_policies.runtime_environment and alert.environment == env_policies.runtime_environment:
        escalate = True
        policies.append("P22-SELF-TARGET")
        reasons.append(f"{alert.environment} is WARDEN's own runtime: a person handles it, WARDEN never acts on itself.")

    # P1 — the action must be permitted in this environment at all (from environments.yaml).
    if not env.permits(proposal.action):
        rejected = True
        policies.append("P1-ENV-ALLOWLIST")
        reasons.append(
            f"{proposal.action.value} is not permitted in {alert.environment}."
        )

    # P2 — nothing irreversible in a production-tier environment, ever, regardless of confidence.
    #
    # ⛔ READS THE TABLE, NOT THE PROPOSAL. `proposal.reversible` is written by the model, and by
    # any caller of the MCP server, so keying a rejection on it let a proposal widen its own
    # permissions: two live models reported opposite values for the identical operation and got
    # opposite verdicts (docs/live-model-run-2026-09-06.md §3). The claim is not discarded — P10
    # escalates when it contradicts the table.
    if env.tier == "prod" and not proposal.table_reversible:
        rejected = True
        policies.append("P2-IRREVERSIBLE-IN-PROD")
        reasons.append(
            f"{proposal.action.value} is classified irreversible in WARDEN's action table, and "
            f"{alert.environment} is production-tier. The proposal claimed "
            f"reversible={proposal.reversible}; the table decided, not the claim."
        )

    # P3 — evidence is a precondition for action, not an optional extra.
    if context.is_empty() and proposal.action not in AUTO_SAFE_ACTIONS:
        rejected = True
        policies.append("P3-NO-EVIDENCE")
        reasons.append("No logs, metrics or deploy history were gathered; refusing to act blind.")

    # P4 — a low-confidence hypothesis is a question, not a plan.
    if root_cause.confidence < MIN_CONFIDENCE and proposal.action not in EVIDENCE_EXEMPT_ACTIONS:
        escalate = True
        policies.append("P4-LOW-CONFIDENCE")
        reasons.append(
            f"Confidence {root_cause.confidence:.2f} is below the {MIN_CONFIDENCE} threshold."
        )

    # P5 — you cannot roll back a deploy that the evidence does not show. The deploy must be OF the
    # target (audit A-C-25): a deploy of any other service used to count.
    if proposal.action is ActionKind.rollback_deploy and not _deploy_of_target(alert, context, proposal.target):
        rejected = True
        policies.append("P5-NO-DEPLOY-TO-ROLL-BACK")
        reasons.append("Rollback proposed but no recent deploy of the target appears in the gathered context."
                       if context.recent_deploys else
                       "Rollback proposed but no recent deploy appears in the gathered context.")

    # P6 — wide blast radius is always a human's call. The table sets a FLOOR per action and the
    # proposal may only ever widen it: a model asking for a human is always allowed to, while
    # understating the reach of an action must buy it nothing.
    effective_radius = proposal.effective_blast_radius
    if effective_radius in ("multi_service", "region"):
        escalate = True
        policies.append("P6-BLAST-RADIUS")
        floor = ACTION_FACTS[proposal.action][1]
        reasons.append(
            f"Blast radius '{effective_radius}' exceeds the unattended limit (WARDEN's floor for "
            f"{proposal.action.value} is '{floor}', the proposal claimed "
            f"'{proposal.blast_radius}'; the wider of the two applies)."
        )

    # P7 — proportionality. Don't fail over a database because something is 'low'.
    heavy = {ActionKind.failover_replica, ActionKind.rollback_deploy}
    if proposal.action in heavy and alert.severity.value in ("low", "medium"):
        escalate = True
        policies.append("P7-DISPROPORTIONATE")
        reasons.append(
            f"{proposal.action.value} is disproportionate to a {alert.severity.value} alert."
        )

    # P8 — a tool failing means the picture is partial. Say so rather than pretending.
    if context.tool_errors and proposal.action not in EVIDENCE_EXEMPT_ACTIONS:
        escalate = True
        policies.append("P8-PARTIAL-CONTEXT")
        reasons.append(f"{len(context.tool_errors)} context tool(s) failed; evidence is incomplete.")

    # P9 — evidence measured by US, not confidence reported by the model.
    #
    # Added after running against a live model: it returned confidence 0.85 on ALL the bundled
    # incidents (four then; five in the recorded run, docs/live-model-run-2026-09-06.md), including
    # the one whose entire evidence is two vague log lines. A model's
    # self-reported confidence is not calibrated, so P4 alone would essentially never fire — the
    # gate would be relying on a number the model has no incentive or ability to get right.
    #
    # This counts what was actually gathered. It cannot be talked around by a confident tone.
    if proposal.action not in EVIDENCE_EXEMPT_ACTIONS and not _evidence_is_substantial(context):
        escalate = True
        policies.append("P9-THIN-EVIDENCE")
        reasons.append(
            f"Evidence is thin ({len(context.logs)} log line(s), {len(context.metrics)} metric(s), "
            f"{len(context.recent_deploys)} deploy(s)); a human should look before acting."
        )

    # P10 — the proposal warns that this cannot be undone while the table says it can.
    #
    # P2 reads the table so the model cannot decide; ignoring a warning is a different thing from
    # refusing to obey one. `escalated` and `rejected` both mean nothing runs and both require a
    # person, so escalating here preserves the warning without handing the decision back.
    if proposal.claim_contradicts_table:
        escalate = True
        policies.append("P10-CLAIM-CONTRADICTS-TABLE")
        reasons.append(
            f"The proposal claims {proposal.action.value} is irreversible; WARDEN's action table "
            "classifies it reversible. A human should reconcile that before anything runs."
        )

    # P11 — the action cannot fix what the evidence shows.
    #
    # ⛔ Added 2026-09-25 from measured failures, which is disclosed with it: all three runs the EKS
    # wave let through wrongly were `scale_up` against `oom_killed_containers = 2` - more replicas of
    # a container killed at 48 MiB are killed the same way - and nothing in P1-P10 read the evidence
    # against the action. A re-run of the same scenarios is therefore NOT an independent test of this
    # policy. Escalates, never rejects: the rules are how the actions work, but a human decides.
    contradiction = _contradiction(proposal, context)
    if contradiction:
        escalate = True
        policies.append("P11-ACTION-CONTRADICTS-EVIDENCE")
        reasons.append(contradiction)

    # P23 — "nothing to do" because a read came back empty (register N2). An empty answer from a throttled,
    # lagging or misdirected query looks exactly like a quiet, healthy service; it is unknown, never healthy.
    if proposal.action is ActionKind.no_action and context.empty_reads:
        escalate = True
        policies.append("P23-EMPTY-READ")
        reasons.append("No action proposed, but these reads returned nothing, which is not the same as healthy: "
                       + ", ".join(context.empty_reads) + ".")

    # P24 — "nothing to do" about an incident WARDEN does not recognise (requirement R39). symptoms() counts known
    # broken states, never rates, so a new kind of failure - one no signature describes, showing only as errors and
    # latency - passed P12 and was closed: a novel failing service under a confident no_action went out auto_safe.
    # An alert fired; when nothing WARDEN knows describes it, closing it is a person's call. Measured 2026-10-03:
    # every no_action in the 30 replayed incidents already reached a person, so this changes none of their verdicts.
    # (A signature match is not a symptom: signatures also fire on the alert's name. Audit Q2 is the rate case.)
    if proposal.action is ActionKind.no_action:
        if not default_knowledge_base().match(alert, context):
            escalate = True
            policies.append("P24-UNRECOGNISED")
            reasons.append("No action proposed for an incident no known signature describes: an alert WARDEN cannot "
                           "explain is closed by a person, not by WARDEN.")

        # P12 — "nothing to do" while the evidence shows something broken.
        #
        # no_action became subject to P4/P8/P9 after Wave 1, but a CONFIDENT no_action over plenty of
        # evidence still went out auto_safe even with pods OOM-killed or not ready. In the measured runs
        # low confidence happened to catch every such case; that was luck, not a rule. Same disclosure
        # as P11: written after seeing the runs.
        found = symptoms(context)
        if found:
            escalate = True
            policies.append("P12-NO-ACTION-WITH-SYMPTOMS")
            reasons.append("No action proposed, but the evidence shows: " + "; ".join(found) + ".")

    # P13 - the diagnosis must be grounded: every citation names a real evidence id and quotes it
    # verbatim (grounding.py). Escalates: an ungrounded diagnosis may still be right, a person checks.
    if check_grounding and proposal.action not in EVIDENCE_EXEMPT_ACTIONS:
        problems = citation_problems(root_cause, evidence.view(context))
        if problems:
            escalate = True
            policies.append("P13-UNGROUNDED")
            reasons.append("The diagnosis is not grounded in the evidence: " + "; ".join(problems) + ".")

    # P15 - the citations must bear on the ACTION, not merely exist (grounding.ACTION_EVIDENCE).
    # Escalates: a person checks whether the evidence supports this fix at all.
    if check_grounding and proposal.action not in AUTO_SAFE_ACTIONS:
        problem = action_support_problem(root_cause, proposal, evidence.view(context))
        if problem:
            escalate = True
            policies.append("P15-CITATIONS-DO-NOT-SUPPORT-ACTION")
            reasons.append(problem + ".")

    # P16 - the trained injection detector (tripwire.py) flagged untrusted evidence, or it was
    # required and could not run. Escalates: a flagged line may be an attack or a false alarm, and
    # a person decides which - nothing runs automatically on evidence that looks like one.
    if context.suspected:
        escalate = True
        policies.append("P16-SUSPECTED-INJECTION")
        if set(context.suspected) == {tripwire.TOO_MUCH_TEXT}:
            reasons.append(f"The text the model reads is larger than the injection detector's budget "
                           f"({tripwire.MAX_SCAN_TOKENS} tokens), so it was not scanned; a person reads it.")
        else:
            flagged = ", ".join(f"{i} ({s:.2f})" for i, s in sorted(context.suspected.items()))
            reasons.append(f"The injection detector flagged untrusted evidence: {flagged}.")
    # ⛔ Audit A-C-12: in `required` mode ANY status but "ran" escalates - "off" (evidence handed in
    # by a caller that never ran the detector) used to pass.
    # "ran-partial" is a run: the alert, the labels and the trusted items the model reads were scanned; only
    # raw log lines went past the budget - the model never sees them, but it does see their typed facts,
    # which then only the quarantine's filters cover (fifth review, 2026-10-01).
    elif tripwire.mode(env.tripwire) == "required" and not tripwire.ran(context.tripwire):
        escalate = True
        policies.append("P16-SUSPECTED-INJECTION")
        reasons.append(f"The injection detector is required here and could not run ({context.tripwire}).")

    # P14 - the target must be a resource WARDEN knows exists. Rejects: acting on a name the
    # evidence does not contain is acting on a guess.
    if check_grounding and proposal.action not in AUTO_SAFE_ACTIONS:
        # Every label that names a whole namespace or cluster, each value of a list (fifth review, 2026-10-01:
        # `ecs_cluster=warden-dev-cluster` let the cluster itself through as a target).
        # Any spelling of a namespace or cluster label - `NAMESPACE`, `k8s_namespace`, `aurora_cluster`, an
        # ElastiCache group (sixth review, 2026-10-01).
        # A database or cache cluster is the resource of a data action - clearing a cache, closing sessions, a
        # failover, scaling it - and scopes only an action on pods: rejecting it as a scope refused the natural
        # targets of clear_cache and terminate_connections (seventh review, 2026-10-01). A namespace or a compute
        # cluster is never a failover's target.
        # Keys in any spelling - `ClusterName`, `k8s.namespace.name`, `cache-cluster` - read as words (eighth
        # review: those were not scopes at all, and `sandbox_namespace` held "db").
        def words(k: str) -> list[str]:
            # At a lower-to-upper change and at an acronym's end: `ECSCluster` is ecs + cluster, `K8SNamespace` k8s +
            # namespace (ninth review: split at the first only, they were one word and no scope).
            split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z0-9])(?=[A-Z][a-z])", "_", k)
            return [w for w in re.split(r"[^a-z0-9]+", split.lower()) if w]

        def values(keep, *, but_the_service: bool = True) -> set[str]:
            found = {v.strip() for k, value in alert.labels.items() if value and keep(words(k))
                     for v in str(value).split(",") if v.strip()}
            return found - {alert.service} if but_the_service else found

        def is_namespace(w: list[str]) -> bool:
            return w[-1:] == ["ns"] or bool({"namespace", "namespaces"} & set(w[-2:]))

        def is_scope(w: list[str]) -> bool:
            # A key that is only a platform's name (`ecs=...`) names its cluster (ninth review).
            return (is_namespace(w) or bool({"cluster", "clusters"} & set(w[-2:])) or w == ["elasticache"]
                    or (len(w) == 1 and _compute(w[0])))

        def is_data(w: list[str]) -> bool:
            return not is_namespace(w) and bool(set(w) & _DATA_WORDS)

        data_action = proposal.action in _DATA_ACTIONS
        # A bare `cluster` key stays a scope for a database or cache action: on an ECS alert it is the ECS cluster
        # (wave 1). Unless WARDEN's OWN reads show the name is a data store - a metric of a database or a cache
        # (`rds_connections__orders-db`) - it is not taken for one: `cluster=orders-db` was refused as a target
        # of terminate_connections even then (register R9-O3). Label text alone never makes a name a database.
        stores = {k.split("__", 1)[1] for k in context.metrics
                  if "__" in k and set(re.split(r"[^a-z0-9]+", k.split("__", 1)[0].lower())) & _DATA_WORDS}
        scopes = values(lambda w: is_scope(w) and not (data_action and is_data(w)))
        if data_action:
            scopes -= stores
        # A failover never targets a namespace or a compute cluster - not even one named like the service (the
        # recorded fs-01 alert's namespace is `shop`, its service `shop`).
        containers = values(lambda w: is_namespace(w) or (is_scope(w) and any(_compute(x) for x in w)),
                            but_the_service=False)
        # `kind:name`, where the alert's own label of that kind holds the name, is that one resource - as the
        # resolver reads it (G10 held-out, 2026-10-11: `elasticache_serverless:pricing-cache` was refused as a list).
        kind, sep, rest = proposal.target.partition(":")
        named = proposal.model_copy(update={"target": rest}) if sep and alert.labels.get(kind) == rest else proposal
        problem = target_problem(named, evidence.inventory(alert, context), scopes, containers)
        if problem:
            rejected = True
            policies.append("P14-TARGET-NOT-IN-EVIDENCE")
            reasons.append(problem + ".")

    # P30 - a fix nothing in the catalogue can carry out is advice for a person, never a plan put to the approver
    # (G10-B). Held-out G9-F, 2026-10-10: scale_up on a NAT gateway reached a person as approved_for_human, with no
    # entry that acts on a NAT gateway - the one wrong answer the gate let through. Decided only for a target the
    # alarm's labels name (resolver.no_fix_path); the right fix may well be what it says, done by a person.
    if why := no_fix_path(alert, proposal):
        escalate = True
        policies.append("P30-NO-FIX-PATH")
        reasons.append(f"{why[0].upper()}{why[1:]}: the proposal is advice for a person to carry out, not a plan.")

    # P31 - a person's recent write to the alerting resource that the fix ignores (owner decision 2026-10-10, after it
    # was measured in observe mode: on the G10 held-out answers it named only wrong ones - the one wrong answer that
    # reached a person in every run, a restart that ignored a desired-count cut - and none of 132 right ones).
    if why := _p31_unaddressed_change(alert, context, root_cause, proposal):
        escalate = True
        policies.append("P31-UNADDRESSED-CHANGE")
        reasons.append(f"{why[0].upper()}{why[1:]}: a person looks at that change before any fix.")

    if rejected:
        return Verdict(
            status=VerdictStatus.rejected,
            reasons=reasons,
            policy_ids=policies,
            requires_approval=True,
        )
    if escalate:
        return Verdict(
            status=VerdictStatus.escalated,
            reasons=reasons or ["Escalated for human judgement."],
            policy_ids=policies,
            requires_approval=True,
        )
    if proposal.action in AUTO_SAFE_ACTIONS:
        return Verdict(
            status=VerdictStatus.auto_safe,
            reasons=["Action is inert or advisory; no approval required."],
            policy_ids=policies,
            requires_approval=False,
        )
    return Verdict(
        status=VerdictStatus.approved_for_human,
        reasons=["Passed all policies. Held for operator approval before execution."],
        policy_ids=policies,
        requires_approval=True,
    )
