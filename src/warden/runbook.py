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
from dataclasses import dataclass, field

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


def platform_for(alert: Alert, action: ActionKind, backend: str | None = None,
                 context: ContextBundle | None = None) -> tuple[str, str]:
    """(platform, basis) - kubernetes | ecs | postgres | unknown, and how that was decided."""
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


def _current_replicas(context: ContextBundle | None) -> int | None:
    m = context.metrics if context else {}
    for key in ("replicas_desired", "tasks_desired", "pods_total"):
        if key in m:
            return int(m[key])
    return None


def build_runbook(alert: Alert, action: ActionKind, *, backend: str | None = None,
                  pids: list[str] | None = None, context: ContextBundle | None = None) -> Runbook:
    platform, basis = platform_for(alert, action, backend, context)
    shown = platform if platform != "unknown" else "kubernetes"
    rb = Runbook(platform=platform, basis=basis)
    if platform == "unknown":
        rb.note = ("The platform could not be identified from the alert or the evidence, so these "
                   "commands assume Kubernetes. Confirm that before running anything.")
    if shown == "kubernetes":
        _kubernetes(rb, alert, action, context)
    elif shown == "ecs":
        _ecs(rb, alert, action, context)
    elif shown == "postgres":
        _postgres(rb, alert, action, pids or [])
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
        cur = _current_replicas(context)
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
        cur = _current_replicas(context)
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
            ("IRREVERSIBLE. Each terminated session's open transaction is rolled back and the client sees "
            "an error; that work must be retried by the application."),
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
