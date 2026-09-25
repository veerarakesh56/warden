"""The commands an on-call engineer runs next — built from a table, never written by the model.

A report that says "roll back checkout" leaves the reader to work out HOW, on WHICH cluster, whether
it is safe, and how to tell whether it worked. This turns the gated action, the alert's labels and
the evidence into: what to know BEFORE acting, read-only checks, the fix, how to confirm it, and how
to undo it.

⛔ DETERMINISTIC ON PURPOSE. The model proposes an `ActionKind` from a closed set; it never supplies a
command string. Letting a language model write the shell a human is about to paste into production is
the one place a hallucination turns directly into an outage.

⛔ NO PLACEHOLDERS (since 2026-09-25). An operator reading `<namespace>` or `<replicas>` at 3am has to
stop and work it out, and a guessed value that looks right is worse. Every name comes from the alert's
labels or the evidence; when one is genuinely unknown, the runbook first prints a real command that
FINDS it and uses the result (`NS=$(...)`). The one exception is an irreversible action whose target
cannot be identified - then no command is printed at all, and the report says why.

⛔ RISK FIRST. `risk` is rendered BEFORE the steps. A warning after the command is a warning read after
the damage.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field

from . import playbook as pb
from .models import ActionKind, Alert, ContextBundle

# Which platform each WARDEN_BACKEND value reads from.
_PLATFORM = {
    "k8s": "kubernetes", "kubernetes": "kubernetes",
    "aws": "ecs", "ecs": "ecs",
    "postgres": "postgres", "postgresql": "postgres",
}

_IDLE_SECS = int(os.environ.get("WARDEN_DB_TERMINATE_IDLE_SECS", "300"))


@dataclass
class Runbook:
    platform: str
    basis: str = ""                      # how the platform was determined - said, not implied
    note: str = ""
    risk: list[str] = field(default_factory=list)      # rendered BEFORE the steps
    check: list[str] = field(default_factory=list)     # read-only: confirm the diagnosis first
    fix: list[str] = field(default_factory=list)
    confirm: list[str] = field(default_factory=list)
    undo: list[str] = field(default_factory=list)
    # True when WARDEN itself already ran the read-only diagnostics (status, events, previous logs,
    # rollout history) against the live system: `check` is then only a re-check right before acting.
    checked_by_warden: bool = False


def platform_for(alert: Alert, action: ActionKind, backend: str | None = None,
                 context: ContextBundle | None = None) -> tuple[str, str]:
    """(platform, basis) - kubernetes | ecs | postgres | unknown, and how that was decided.

    For the full stack (Wave 4): also lambda | dynamodb | aurora | elasticache | sqs | sns | eventbridge |
    alb | apigw, decided from the evidence - every alert of an application carries the same labels,
    so the labels alone never say which component broke.
    """
    if _is_stack(alert, backend):
        return _stack_platform(alert, action, context or ContextBundle())
    if action in (ActionKind.terminate_connections, ActionKind.failover_replica):
        return "postgres", f"{action.value} is a database action"
    name = (backend or os.environ.get("WARDEN_BACKEND") or "").lower()
    if name in _PLATFORM:
        return _PLATFORM[name], f"evidence was read from the {_PLATFORM[name]} backend"
    labels = alert.labels
    if "cluster" in labels or "ecs_service" in labels:
        return "ecs", "the alert carries ECS labels"
    if "namespace" in labels or "deployment" in labels:
        return "kubernetes", "the alert carries Kubernetes labels"
    logs = " ".join((context.logs if context else [])[:50])
    if any(s in logs for s in ("kubelet", "Pod/", " pod=", "OOMKilled")):
        return "kubernetes", "the log lines are Kubernetes' (kubelet / pod events)"
    return "unknown", "nothing in the alert or the evidence names the platform"


def _current_replicas(context: ContextBundle | None, platform: str, dep: str | None = None) -> int | None:
    """The CURRENT count for this platform's workload, from the evidence - or None.

    ⛔ Per platform: in a stack alert both an ECS service and Deployments are read, and ECS's count
    must never be taken from a Deployment's (or the reverse). A Deployment's metrics carry the
    `__<deployment>` suffix when several are read (contract B)."""
    m = context.metrics if context else {}
    keys = (("tasks_desired",) if platform == "ecs" else
            tuple(k for key in ("replicas_desired", "pods_total")
                  for k in ((f"{key}__{dep}",) if dep else ()) + (key,)))
    for key in keys:
        if key in m:
            return int(m[key])
    return None


def build_runbook(alert: Alert, action: ActionKind, *, backend: str | None = None,
                  pids: list[str] | None = None, context: ContextBundle | None = None) -> Runbook:
    platform, basis = platform_for(alert, action, backend, context)
    stack = _is_stack(alert, backend)
    shown = platform if platform != "unknown" or stack else "kubernetes"
    rb = Runbook(platform=platform, basis=basis)
    ctx = context or ContextBundle()
    if platform == "unknown":
        rb.note = ("WARDEN could not tell which component of the stack failed, so it prints no runbook "
                   "commands; the detected patterns' fix commands (if any) are aimed at what the evidence names."
                   if stack else
                   "The platform could not be identified from the alert or the evidence, so these "
                   "commands assume Kubernetes. Confirm that before running anything.")
    if stack and shown in ("kubernetes", "ecs"):
        (_stack_k8s if shown == "kubernetes" else _stack_ecs)(rb, alert, action, ctx, [])
    elif shown == "kubernetes":
        _kubernetes(rb, alert, action, context)
        if (backend or os.environ.get("WARDEN_BACKEND") or "").lower() in ("k8s", "kubernetes"):
            # WARDEN read events, container status, the crashed containers' output and the rollout
            # history itself (k8s_backend.py); asking a person to run them again is the "doubt" the
            # owner objected to. What stays is a re-check of the CURRENT state, which may have moved.
            already = ("get events", "describe pods", "logs deploy/")
            rb.check = [c for c in rb.check if not any(a in c for a in already)]
            rb.checked_by_warden = True
    elif shown == "ecs":
        _ecs(rb, alert, action, context)
    elif shown == "postgres":
        _postgres(rb, alert, action, pids or [])
    elif shown in _STACK_BUILDERS:
        _STACK_BUILDERS[shown](rb, alert, action, ctx, pids or [])
    elif shown != "unknown":
        _reads_only(rb, alert, shown, action)
    if stack:
        for key in ("check", "fix", "confirm", "undo"):
            setattr(rb, key, [pb.regioned(c) for c in getattr(rb, key)])
    return rb


# --------------------------------------------------------------------------- Kubernetes


def _kubernetes(rb: Runbook, alert: Alert, action: ActionKind, context: ContextBundle | None) -> None:
    labels = alert.labels
    dep = labels.get("deployment", alert.service)
    sel = labels.get("selector", f"app={alert.service}")
    find_ns: list[str] = []
    if "namespace" in labels:
        k = f"kubectl -n {labels['namespace']}"
    else:
        # A real command that finds the namespace, not a `<namespace>` to fill in by hand.
        find_ns = [(f"NS=$(kubectl get deploy -A --field-selector metadata.name={dep} "
                   "-o jsonpath='{.items[0].metadata.namespace}') && echo \"namespace: $NS\"")]
        k = 'kubectl -n "$NS"'
    look = [
        f"{k} get deploy/{dep} -o wide",
        f"{k} get pods -l {sel} -o wide",
        f"{k} get events --sort-by=.lastTimestamp | tail -20",
        f"{k} describe pods -l {sel} | grep -A5 -E 'Last State|Reason|Events'",
        f"{k} logs deploy/{dep} --all-containers --previous --tail=100",
    ]
    if action is ActionKind.rollback_deploy:
        rb.risk = [
            (f"`rollout undo` returns {dep} to the PREVIOUS revision - check in the history below that "
            "it is the known-good one; if the last two deploys were both bad, it reinstates a bad one."),
            "Pods are replaced by a rolling update: in-flight requests on terminating pods can fail.",
            "Reversible: running `rollout undo` again returns to the revision you left.",
        ]
        rb.check = [*find_ns, f"{k} rollout history deploy/{dep}", *look[:4]]
        rb.fix = [f"{k} rollout undo deploy/{dep}"]
        rb.confirm = [f"{k} rollout status deploy/{dep} --timeout=5m", look[1]]
        rb.undo = [f"{k} rollout undo deploy/{dep}"]
    elif action is ActionKind.restart_pods:
        rb.risk = [
            ("A rolling restart replaces every pod: capacity dips while new pods start, and with a single "
            "replica the service is briefly down."),
            ("It fixes nothing that is in the image, the config or a dependency - the new pods start the "
            "same way. Check the events below for why the current pods are failing first."),
        ]
        rb.check = [*find_ns, *look]
        rb.fix = [f"{k} rollout restart deploy/{dep}"]
        rb.confirm = [f"{k} rollout status deploy/{dep} --timeout=5m", look[1]]
    elif action in (ActionKind.scale_up, ActionKind.scale_down):
        cur = _current_replicas(context, "kubernetes", dep)
        hpa = f"{k} get hpa -o wide   # if an HPA manages {dep}, change ITS min/max - a manual scale is overridden"
        if cur is not None:
            target = (max(cur + 1, math.ceil(cur * 1.5)) if action is ActionKind.scale_up
                      else max(1, cur - 1))
            why = (f"currently {cur} (from the evidence); target {target}"
                   + (" = max(+1, x1.5)" if action is ActionKind.scale_up else " = one fewer, never below 1"))
            rb.check = [*find_ns, f"{k} get deploy/{dep} -o jsonpath='{{.spec.replicas}}'   # expect {cur}",
                        hpa, look[1]]
            rb.fix = [f"{k} scale deploy/{dep} --replicas={target}   # {why}"]
            rb.undo = [f"{k} scale deploy/{dep} --replicas={cur}"]
        else:
            rb.check = [*find_ns, f"CUR=$({k} get deploy/{dep} -o jsonpath='{{.spec.replicas}}') && echo \"now: $CUR\"",
                        hpa, look[1]]
            rb.fix = [f"{k} scale deploy/{dep} --replicas=$((CUR+1))" if action is ActionKind.scale_up
                      else f"{k} scale deploy/{dep} --replicas=$((CUR>1 ? CUR-1 : 1))"]
            rb.undo = [f'{k} scale deploy/{dep} --replicas="$CUR"']
        rb.confirm = [f"{k} rollout status deploy/{dep} --timeout=5m", look[1]]
        rb.risk = (
            [("New replicas need node capacity: if the cluster is full they stay Pending (check the "
             "events). More replicas cost more."),
             ("If the pods are failing at startup (OOM-killed, crash-looping, not ready), new replicas fail "
             "the same way - scaling adds load on the scheduler, not capacity.")]
            if action is ActionKind.scale_up else
            ["Fewer replicas means less capacity: every remaining pod takes more load.",
             "If memory or CPU grows with load, scaling down makes the remaining pods more likely to fail."]
        )
    else:
        rb.check = [*find_ns, *look]


# --------------------------------------------------------------------------- ECS


def _ecs(rb: Runbook, alert: Alert, action: ActionKind, context: ContextBundle | None) -> None:
    labels = alert.labels
    cluster = labels.get("cluster") or os.environ.get("WARDEN_AWS_CLUSTER") or ""
    svc = labels.get("ecs_service", alert.service)
    group = labels.get("log_group", f"/ecs/{svc}")
    find: list[str] = []
    if cluster:
        c = cluster
    else:
        find = [(f"CLUSTER=$(aws ecs list-clusters --query 'clusterArns' --output text | tr '\\t' '\\n' | "
                f"while read c; do aws ecs describe-services --cluster \"$c\" --services {svc} "
                f"--query 'services[?status==`ACTIVE`].clusterArn' --output text; done | head -1) "
                "&& echo \"cluster: $CLUSTER\"")]
        c = '"$CLUSTER"'
    a = f"--cluster {c} --services {svc}"
    look = [
        f"aws ecs describe-services {a} --query 'services[0].[deployments,events[:5]]'",
        f"aws ecs list-tasks --cluster {c} --service-name {svc} --desired-status STOPPED --max-items 5",
        f"aws logs tail {group} --since 30m",
    ]
    if action is ActionKind.rollback_deploy:
        prev = (f"PREV=$(aws ecs list-task-definitions --family-prefix {svc} --sort DESC --max-items 2 "
                "--query 'taskDefinitionArns[1]' --output text) && echo \"previous: $PREV\"")
        rb.risk = [
            ("This deploys the task definition revision BEFORE the newest one. Check it is the known-good "
            "one - an earlier bad revision would be reinstated."),
            "ECS replaces tasks gradually; the service is at reduced capacity until it is stable.",
        ]
        rb.check = [*find, *look, prev]
        rb.fix = [f'aws ecs update-service --cluster {c} --service {svc} --task-definition "$PREV"']
        rb.confirm = [f"aws ecs wait services-stable {a}", look[0]]
        rb.undo = [(f"aws ecs update-service --cluster {c} --service {svc} --task-definition "
                    f"$(aws ecs list-task-definitions --family-prefix {svc} --sort DESC --max-items 1 "
                    "--query 'taskDefinitionArns[0]' --output text)")]
    elif action is ActionKind.restart_pods:
        rb.risk = [("A forced new deployment replaces every task; it fixes nothing that is in the task "
                   "definition, the image or a dependency.")]
        rb.check = [*find, *look]
        rb.fix = [f"aws ecs update-service --cluster {c} --service {svc} --force-new-deployment"]
        rb.confirm = [f"aws ecs wait services-stable {a}"]
    elif action in (ActionKind.scale_up, ActionKind.scale_down):
        cur = _current_replicas(context, "ecs")
        if cur is not None:
            target = max(cur + 1, math.ceil(cur * 1.5)) if action is ActionKind.scale_up else max(1, cur - 1)
            rb.fix = [(f"aws ecs update-service --cluster {c} --service {svc} --desired-count {target}"
                      f"   # currently {cur} (from the evidence)")]
            rb.undo = [f"aws ecs update-service --cluster {c} --service {svc} --desired-count {cur}"]
        else:
            rb.check = [*find, f"CUR=$(aws ecs describe-services {a} --query 'services[0].desiredCount' --output text)"]
            rb.fix = [f"aws ecs update-service --cluster {c} --service {svc} --desired-count $((CUR+1))"]
            rb.undo = [f'aws ecs update-service --cluster {c} --service {svc} --desired-count "$CUR"']
        rb.check = rb.check or [*find, look[0]]
        rb.confirm = [f"aws ecs wait services-stable {a}"]
        rb.risk = ["More tasks cost more and need capacity (Fargate account limits, or EC2 capacity).",
                   "Tasks failing at startup fail the same way at any count."]
    else:
        rb.check = [*find, *look]


# --------------------------------------------------------------------------- PostgreSQL


_STUCK = ("SELECT pid, usename, application_name, client_addr, state, now() - xact_start AS in_transaction_for, "
          "left(query, 80) AS last_query FROM pg_stat_activity WHERE state = 'idle in transaction' "
          "ORDER BY xact_start;")
_POOL = ("SELECT state, application_name, client_addr, count(*) FROM pg_stat_activity "
         "GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 10;")
_BLOCKED = ("SELECT pid, pg_blocking_pids(pid) AS blocked_by, now() - query_start AS waiting_for, "
            "left(query, 80) FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid)) > 0;")
_LONG = ("SELECT pid, usename, application_name, now() - query_start AS running_for, left(query, 120) "
         "FROM pg_stat_activity WHERE state = 'active' AND now() - query_start > interval '60 seconds' "
         "AND pid <> pg_backend_pid() ORDER BY query_start;")


def _postgres(rb: Runbook, alert: Alert, action: ActionKind, pids: list[str]) -> None:
    rb.check = [_STUCK, _BLOCKED, _LONG, _POOL]
    if action is ActionKind.terminate_connections:
        rb.risk = [
            # ⚠ Not "IRREVERSIBLE": WARDEN's action table calls terminate_connections reversible (nothing
            # committed is lost; the application reconnects), and the report printed both side by side
            # until 2026-09-25. What cannot be undone is the rolled-back work, and that is what this says.
            ("The rolled-back work cannot be restored. Each terminated session's open transaction is "
            "rolled back (nothing committed is lost) and the client sees an error; that work must be "
            "retried by the application."),
            ("Terminate only sessions that are IDLE in a transaction. A session that is `active` is doing "
            "work - terminating it destroys that work (check the long-running query list first)."),
            ("PIDs are reused by new sessions. The fix below re-checks the state at the moment it runs "
            "instead of trusting a PID from the evidence."),
        ]
        if pids:
            rb.fix = [("SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity "
                       f"WHERE pid IN ({', '.join(pids)}) AND state = 'idle in transaction';"
                       "   -- the pids named in the evidence, only if still idle in a transaction")]
        else:
            rb.fix = [("SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity "
                       f"WHERE state = 'idle in transaction' AND now() - state_change > interval '{_IDLE_SECS} seconds' "
                       "AND pid <> pg_backend_pid();")]
        rb.confirm = [_STUCK, _POOL]
        rb.undo = ["-- none: terminated transactions are rolled back and cannot be restored."]
        rb.note = ("To stop it recurring, on the affected database (no name to fill in - it targets the "
                   "one you are connected to): "
                   "DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET idle_in_transaction_session_timeout = %L', "
                   "current_database(), '5min'); END $$;")
    elif action is ActionKind.failover_replica:
        ident = alert.labels.get("db_instance") or alert.labels.get("instance_id") or ""
        rb.risk = [
            ("Writes are unavailable during the switch (typically one to two minutes on RDS Multi-AZ); "
            "clients must reconnect."),
            ("Anything the replica had not yet replayed is lost - the replica lag at the moment of failover "
            "is the data-loss window."),
            "Not reversible by a command: failing back is a second failover with the same costs.",
        ]
        rb.check = ["SELECT now() - pg_last_xact_replay_timestamp() AS replica_lag;   -- on the replica",
                    *rb.check]
        if ident:
            rb.fix = [f"aws rds reboot-db-instance --db-instance-identifier {ident} --force-failover"]
        else:
            rb.fix = []
            rb.note = ("WARDEN cannot identify the primary instance from the alert or the evidence, so it "
                       "prints no failover command - an irreversible action must not be aimed by guesswork. "
                       "Find it with: aws rds describe-db-instances --query "
                       "\"DBInstances[].[DBInstanceIdentifier,MultiAZ,ReadReplicaSourceDBInstanceIdentifier]\" "
                       "--output table")
        rb.confirm = ["SELECT pg_is_in_recovery();   -- false on the new primary"]


# --------------------------------------------------------------------------- the full stack (Wave 4)
#
# One alert per application, the same labels whatever broke (docs/WAVE4-FULLSTACK.md section 4):
# the component to act on is decided from the evidence - the deploy in the window, the throttling
# metric, the component whose log lines carry the errors. Every aws command gets the region WARDEN
# read (playbook.regioned); every name comes from a label or a contract line (docs/WAVE4-CONTRACT.md).

_STACK_LABELS = frozenset({"lambda", "sqs", "dynamodb_table", "elasticache", "aurora_cluster", "alb_target_group",
                           "apigw", "ecs_cluster", "sns_topic", "eventbridge_rule"})
_KIND = {"lambda": "lambda", "ecs": "ecs", "k8s": "kubernetes"}
_BAD = re.compile(r"(?i)error|exception|traceback|fail|timed out|denied|back-?off|oom|killed|refused|unhealthy")


def _is_stack(alert: Alert, backend: str | None) -> bool:
    name = (backend or os.environ.get("WARDEN_BACKEND") or "").lower()
    return name == "stack" or bool(_STACK_LABELS & alert.labels.keys())


def _failing(ctx: ContextBundle) -> Counter:
    """(kind, name) of each component, by how many error-looking lines its logs carry."""
    return Counter(src for ln in ctx.logs if _BAD.search(ln) and (src := pb._source_of(ln)))


def _stack_platform(alert: Alert, action: ActionKind, ctx: ContextBundle) -> tuple[str, str]:
    labels, m = alert.labels, ctx.metrics
    if action in (ActionKind.terminate_connections, ActionKind.failover_replica):
        if "aurora_cluster" in labels:
            return "aurora", f"{action.value} is a database action; the alert names Aurora cluster {labels['aurora_cluster']}"
        return "postgres", f"{action.value} is a database action"
    if action is ActionKind.clear_cache and "elasticache" in labels:
        return "elasticache", "clear_cache acts on the cache the alert names"
    if action in (ActionKind.scale_up, ActionKind.scale_down):
        if any(v > 0 for v in pb._ddb_throttles(m).values()):
            return "dynamodb", "DynamoDB throttling is in the evidence"
        if (any(v > 0 for _, v in pb._per(m, "lambda_throttles"))
                or any(v == 0 for _, v in pb._per(m, "lambda_reserved_concurrency"))):
            return "lambda", "Lambda throttling is in the evidence"
    if action is ActionKind.rollback_deploy:
        d = next((d for d in ctx.recent_deploys if d.get("kind") in _KIND), None)
        if d:
            return _KIND[d["kind"]], f"the deploy in the window is {d['kind']} `{d.get('service', '?')}`"
    top = _failing(ctx).most_common(1)
    if top:
        (kind, name), n = top[0]
        return _KIND[kind], f"most error lines ({n}) come from {kind} `{name}`"
    for metric, plat in (("alb_unhealthy_hosts", "alb"), ("apigw_5xx", "apigw"), ("dlq_visible", "sqs"),
                         ("sns_notifications_failed", "sns"), ("redis_evictions", "elasticache")):
        if any(v > 0 for _, v in pb._per(m, metric)):
            return plat, f"{metric} > 0 in the evidence"
    if any(v == 0 for _, v in pb._per(m, "lambda_esm_enabled")) or pb._first(ctx, "ESM ", "State=Disabled"):
        return "lambda", "a Lambda's queue event source mapping is disabled"
    if any(v == 0 for _, v in pb._per(m, "rule_enabled")):
        return "eventbridge", "rule_enabled = 0 in the evidence"
    return "unknown", "nothing in the evidence says which component of the stack failed"


def _stack_fn(alert: Alert, ctx: ContextBundle) -> str | None:
    d = pb._deploy(ctx, "lambda")
    if d:
        return d.get("service")
    for (kind, name), _ in _failing(ctx).most_common():
        if kind == "lambda":
            return name
    for base in ("lambda_throttles", "lambda_reserved_concurrency"):
        for short, v in pb._per(ctx.metrics, base):
            if (v > 0) == (base == "lambda_throttles"):
                return pb._named(alert, "lambda", short)
    return pb._named(alert, "lambda", None)


def _lambda(rb: Runbook, alert: Alert, action: ActionKind, ctx: ContextBundle, pids: list[str]) -> None:
    fn = _stack_fn(alert, ctx)
    if not fn:
        rb.note = "WARDEN cannot tell which Lambda function to act on from the evidence, so it prints no commands."
        return
    rb.checked_by_warden = True   # the stack backend read configuration, versions and logs at alert time
    rb.check = [(f"aws lambda get-function-configuration --function-name {fn} "
                "--query '{Timeout:Timeout,Memory:MemorySize,Version:Version,State:State}'"),
                f"aws lambda get-function-concurrency --function-name {fn}",
                f"aws lambda list-aliases --function-name {fn}",
                f"aws lambda list-versions-by-function --function-name {fn} --query 'Versions[-5:].[Version,LastModified]'"]
    tail = f"aws logs tail /aws/lambda/{fn} --since 5m"
    if action is ActionKind.rollback_deploy:
        rb.risk = [("Moving an alias is instant and affects every new invocation through it; in-flight ones finish "
                   "on the version they started on."),
                   "Reversible: pointing the alias back at the version it left undoes it."]
        rb.fix, why = pb._alias_rollback(ctx, fn)
        d = pb._deploy(ctx, "lambda", fn) or {}
        alias = pb._alias(pb._config(ctx, fn)) or d.get("alias")
        if rb.fix and str(d.get("version", "")).isdigit():
            rb.undo = [f"aws lambda update-alias --function-name {fn} --name {alias} --function-version {d['version']}"]
        if not rb.fix:
            rb.note = why
        rb.confirm = [f"aws lambda get-alias --function-name {fn} --name {alias}" if alias else rb.check[2], tail]
    elif action is ActionKind.scale_up:
        rb.risk = [("Reserved concurrency is taken from the account's pool: other functions can be throttled if "
                   "the account runs short. The account always keeps 10 unreserved."),
                   "More concurrency means more load downstream (database connections, table capacity)."]
        rb.fix, why, rb.undo = pb.lambda_concurrency(alert, ctx, fn)
        rb.note = why
        rb.confirm = [f"aws lambda get-function-concurrency --function-name {fn}", tail]
    else:
        rb.note = (f"`{action.value}` has no Lambda equivalent WARDEN prints: a function has no pods or replicas. "
                   "The detected patterns' fix commands are aimed at the cause.")


def _dynamodb(rb: Runbook, alert: Alert, action: ActionKind, ctx: ContextBundle, pids: list[str]) -> None:
    tline = pb._first(ctx, "TABLE ")
    table = tline.split()[1] if tline else alert.labels.get("dynamodb_table", "")
    rb.checked_by_warden = True
    describe = (f"aws dynamodb describe-table --table-name {table} "
                "--query 'Table.[TableStatus,BillingModeSummary.BillingMode,ProvisionedThroughput]'")
    rb.check = [describe] if table else []
    if action is ActionKind.scale_up:
        rb.risk = ["Higher provisioned throughput costs more for every hour it stays.",
                   ("DynamoDB limits how many times a day capacity can be DECREASED: the undo below may be refused "
                   "if decreases were used up today.")]
        rb.fix, why, rb.undo = pb.ddb_capacity(ctx)
        rb.note = why
        rb.confirm = [describe]
    else:
        rb.note = f"`{action.value}` has no DynamoDB command WARDEN prints; raising capacity is `scale_up`."


def _aurora(rb: Runbook, alert: Alert, action: ActionKind, ctx: ContextBundle, pids: list[str]) -> None:
    _postgres(rb, alert, action, pids)
    cl = pb._first(ctx, "CLUSTER aurora ")
    kv = pb._kv(cl) if cl else {}
    cluster = cl.split()[2] if cl else alert.labels.get("aurora_cluster", "")
    members = (f"aws rds describe-db-clusters --db-cluster-identifier {cluster} "
               "--query 'DBClusters[0].DBClusterMembers[].[DBInstanceIdentifier,IsClusterWriter]' --output table")
    rb.check = [members, *rb.check]
    if action is not ActionKind.failover_replica:
        return
    readers = [r for r in kv.get("readers", "[]").strip("[]").split(",") if r]
    writer = kv.get("writer", "")
    rb.risk = [
        "Writes are unavailable for the switch (typically under a minute on Aurora); clients must reconnect.",
        ("Aurora replicas share the cluster's storage: committed data is not lost. But the instances swap roles - "
         "anything pinned to an INSTANCE endpoint (not the cluster endpoint) will then write to a reader."),
        "Not reversible by a command: failing back is a second failover with the same costs.",
    ]
    rb.check = [members, "SELECT pg_is_in_recovery();   -- on each endpoint: true on readers"]
    if cluster and len(readers) == 1 and writer:
        rb.fix = [(f"aws rds failover-db-cluster --db-cluster-identifier {cluster} "
                  f"--target-db-instance-identifier {readers[0]}")]
        rb.undo = [(f"aws rds failover-db-cluster --db-cluster-identifier {cluster} "
                   f"--target-db-instance-identifier {writer}")]
        rb.note = ""
    else:
        rb.fix = []
        rb.note = ("WARDEN prints no failover command: the CLUSTER line does not name exactly one reader to promote"
                   + (f" (readers: {', '.join(readers)})" if readers else "") + ". An irreversible action is not "
                   "aimed by guesswork.")
    rb.confirm = [members]


def _stack_k8s(rb: Runbook, alert: Alert, action: ActionKind, ctx: ContextBundle, pids: list[str]) -> None:
    target = next(((n.split("/", 1)) for (k, n), _ in _failing(ctx).most_common() if k == "k8s" and "/" in n), None)
    target = target or pb._k8s_target(alert, None)
    if not target:
        rb.note = "WARDEN cannot tell which Deployment failed from the evidence, so it prints no commands."
        return
    ns, dep = target
    narrowed = alert.model_copy(update={"labels": {**alert.labels, "namespace": ns, "deployment": dep,
                                                   "selector": alert.labels.get("selector", f"app={dep}")}})
    metrics = {k: v for k, v in ctx.metrics.items() if "__" not in k}
    metrics.update({k.split("__", 1)[0]: v for k, v in ctx.metrics.items() if k.endswith(f"__{dep}")})
    _kubernetes(rb, narrowed, action, ctx.model_copy(update={"metrics": metrics}))
    already = ("get events", "describe pods", "logs deploy/")
    rb.check = [c for c in rb.check if not any(a in c for a in already)]
    rb.checked_by_warden = True


def _stack_ecs(rb: Runbook, alert: Alert, action: ActionKind, ctx: ContextBundle, pids: list[str]) -> None:
    labels = alert.labels
    cluster, svc = labels.get("ecs_cluster") or labels.get("cluster"), labels.get("ecs_service")
    if not (cluster and svc):
        rb.note = "The alert does not name the ECS cluster and service, so WARDEN prints no commands."
        return
    _ecs(rb, alert.model_copy(update={"labels": {**labels, "cluster": cluster}}), action, ctx)
    rb.checked_by_warden = True
    if action is ActionKind.rollback_deploy:
        d = pb._deploy(ctx, "ecs") or {}
        prev, cur = str(d.get("previous", "")), str(d.get("version", ""))
        family_rev = re.compile(r"[\w-]+:\d+")
        if family_rev.fullmatch(prev):
            rb.fix = [f"aws ecs update-service --cluster {cluster} --service {svc} --task-definition {prev}"]
            if family_rev.fullmatch(cur):
                rb.undo = [f"aws ecs update-service --cluster {cluster} --service {svc} --task-definition {cur}"]
            rb.check = [c for c in rb.check if not c.startswith("PREV=")]
        else:
            rb.fix = []
            rb.note = ("No ECS deploy record gives the previous task definition (family:revision), so WARDEN "
                       "prints no rollback command.")


def _reads_only(rb: Runbook, alert: Alert, platform: str, action: ActionKind) -> None:
    """Platforms no closed-set action changes: read-only checks, and the reason there is no fix here."""
    labels = alert.labels
    names = {k: [n.strip() for n in labels.get(k, "").split(",") if n.strip()] for k in labels}
    reads = {
        "sqs": [f"aws sqs get-queue-attributes --queue-url \"$(aws sqs get-queue-url --queue-name {q} --query QueueUrl "
                "--output text)\" --attribute-names All" for q in names.get("sqs", [])],
        "sns": [f"aws sns list-topics --query \"Topics[?ends_with(TopicArn, ':{t}')]\"" for t in names.get("sns_topic", [])],
        "eventbridge": [f"aws events describe-rule --name {r}" for r in names.get("eventbridge_rule", [])],
        "alb": [f"aws elbv2 describe-target-health --target-group-arn \"$(aws elbv2 describe-target-groups --names {t} "
                "--query 'TargetGroups[0].TargetGroupArn' --output text)\"" for t in names.get("alb_target_group", [])],
        "apigw": [f"aws apigatewayv2 get-apis --query \"Items[?Name=='{a}']\"" for a in names.get("apigw", [])],
        "elasticache": [f"aws elasticache describe-replication-groups --replication-group-id {g}"
                        for g in names.get("elasticache", [])],
    }
    rb.check = reads.get(platform, [])
    rb.checked_by_warden = True
    rb.note = (("WARDEN cannot flush Redis: ElastiCache is VPC-only and WARDEN has no Redis access. "
                if platform == "elasticache" and action is ActionKind.clear_cache else "")
               + f"No action in WARDEN's closed set changes {platform} directly; the detected patterns' fix "
               "commands are aimed at the cause.")


_STACK_BUILDERS = {"lambda": _lambda, "dynamodb": _dynamodb, "aurora": _aurora}
