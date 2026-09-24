"""The commands an on-call engineer runs next — built from a table, never written by the model.

A report that says "roll back checkout" leaves the reader to work out HOW, on WHICH cluster, and how
to tell whether it worked. This turns the gated action and the alert's own labels into the exact
commands for the platform the evidence came from: check first, then the fix, then how to confirm it
and how to undo it.

⛔ DETERMINISTIC ON PURPOSE. The model proposes an `ActionKind` from a closed set; it never supplies a
command string. Letting a language model write the shell a human is about to paste into production is
the one place a hallucination turns directly into an outage.

⚠ Names come from the alert's labels, exactly as the backends resolve them (k8s_backend.py,
aws_backend.py). When a label is missing the command keeps an obvious `<placeholder>` rather than
guessing - a wrong namespace that looks right is worse than one that visibly needs filling in.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .models import ActionKind, Alert

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
    note: str = ""
    check: list[str] = field(default_factory=list)
    fix: list[str] = field(default_factory=list)
    confirm: list[str] = field(default_factory=list)
    undo: list[str] = field(default_factory=list)


def platform_for(alert: Alert, action: ActionKind, backend: str | None = None) -> str:
    """kubernetes | ecs | postgres | unknown - from the backend WARDEN read, then the alert's labels."""
    if action in (ActionKind.terminate_connections, ActionKind.failover_replica):
        return "postgres"
    name = (backend or os.environ.get("WARDEN_BACKEND") or "").lower()
    if name in _PLATFORM:
        return _PLATFORM[name]
    labels = alert.labels
    if "cluster" in labels or "ecs_service" in labels:
        return "ecs"
    if "namespace" in labels or "deployment" in labels:
        return "kubernetes"
    return "unknown"


def build_runbook(alert: Alert, action: ActionKind, *, backend: str | None = None,
                  pids: list[str] | None = None, replicas_hint: int | None = None) -> Runbook:
    platform = platform_for(alert, action, backend)
    shown = platform if platform != "unknown" else "kubernetes"
    labels = alert.labels
    rb = Runbook(platform=platform)
    if platform == "unknown":
        rb.note = ("This incident came from a recorded fixture, so the platform is not known. "
                   "Commands are shown for Kubernetes; the names are the alert's.")

    if shown == "kubernetes":
        ns = labels.get("namespace", "<namespace>")
        dep = labels.get("deployment", alert.service)
        sel = labels.get("selector", f"app={alert.service}")
        k = f"kubectl -n {ns}"
        look = [
            f"{k} get deploy/{dep} -o wide",
            f"{k} get pods -l {sel} -o wide",
            f"{k} get events --sort-by=.lastTimestamp | tail -20",
            f"{k} logs deploy/{dep} --all-containers --previous --tail=100",
        ]
        if action == ActionKind.rollback_deploy:
            rb.check = [f"{k} rollout history deploy/{dep}", *look[:2]]
            rb.fix = [f"{k} rollout undo deploy/{dep}"]
            rb.confirm = [f"{k} rollout status deploy/{dep} --timeout=5m", look[1]]
            rb.undo = [f"{k} rollout undo deploy/{dep}   # returns to the revision you just left"]
        elif action == ActionKind.restart_pods:
            rb.check = look[:3]
            rb.fix = [f"{k} rollout restart deploy/{dep}"]
            rb.confirm = [f"{k} rollout status deploy/{dep} --timeout=5m"]
        elif action in (ActionKind.scale_up, ActionKind.scale_down):
            n = "<replicas>" if replicas_hint is None else str(replicas_hint)
            rb.check = [f"{k} get deploy/{dep} -o jsonpath='{{.spec.replicas}}'", look[1]]
            rb.fix = [f"{k} scale deploy/{dep} --replicas={n}"]
            rb.confirm = [f"{k} rollout status deploy/{dep} --timeout=5m"]
            rb.undo = [f"{k} scale deploy/{dep} --replicas=<previous count from the check above>"]
        else:
            rb.check = look
    elif shown == "ecs":
        cluster = labels.get("cluster") or os.environ.get("WARDEN_AWS_CLUSTER") or "<cluster>"
        svc = labels.get("ecs_service", alert.service)
        group = labels.get("log_group", f"/ecs/{svc}")
        a = f"--cluster {cluster} --services {svc}"
        look = [
            f"aws ecs describe-services {a} --query 'services[0].[deployments,events[:5]]'",
            f"aws logs tail {group} --since 30m",
        ]
        if action == ActionKind.rollback_deploy:
            rb.check = [*look, f"aws ecs list-task-definitions --family-prefix {svc} --sort DESC --max-items 3"]
            rb.fix = [(f"aws ecs update-service --cluster {cluster} --service {svc} "
                      f"--task-definition {svc}:<previous revision from the list above>")]
            rb.confirm = [f"aws ecs wait services-stable {a}"]
        elif action == ActionKind.restart_pods:
            rb.check = look
            rb.fix = [f"aws ecs update-service --cluster {cluster} --service {svc} --force-new-deployment"]
            rb.confirm = [f"aws ecs wait services-stable {a}"]
        elif action in (ActionKind.scale_up, ActionKind.scale_down):
            rb.check = look[:1]
            rb.fix = [f"aws ecs update-service --cluster {cluster} --service {svc} --desired-count <n>"]
            rb.confirm = [f"aws ecs wait services-stable {a}"]
        else:
            rb.check = look
    elif shown == "postgres":
        stuck = ("SELECT pid, usename, application_name, client_addr, state, "
                 "now() - xact_start AS in_transaction_for, left(query, 80) AS last_query "
                 "FROM pg_stat_activity WHERE state = 'idle in transaction' ORDER BY xact_start;")
        rb.check = [stuck,
                    "SELECT count(*) AS used, current_setting('max_connections') AS max FROM pg_stat_activity;",
                    ("SELECT pid, pg_blocking_pids(pid) AS blocked_by, wait_event_type, left(query, 80) "
                    "FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid)) > 0;")]
        if action == ActionKind.terminate_connections:
            if pids:
                rb.fix = [f"SELECT pg_terminate_backend({p});   -- named in the evidence" for p in pids]
            else:
                rb.fix = [("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                          f"WHERE state = 'idle in transaction' AND now() - state_change > interval '{_IDLE_SECS} seconds' "
                          "AND pid <> pg_backend_pid();")]
            rb.confirm = [stuck, rb.check[1]]
            rb.undo = [("-- none: a terminated session's open transaction is rolled back and cannot be "
                       "restored. The application must retry that work.")]
            rb.note = (rb.note + " " if rb.note else "") + (
                "To stop it recurring: ALTER DATABASE <db> SET idle_in_transaction_session_timeout = '5min';")
        elif action == ActionKind.failover_replica:
            rb.check = ["SELECT now() - pg_last_xact_replay_timestamp() AS replica_lag;   -- on the replica",
                        *rb.check]
            rb.fix = ["-- RDS: aws rds reboot-db-instance --db-instance-identifier <primary> --force-failover",
                      "-- Aurora: aws rds failover-db-cluster --db-cluster-identifier <cluster>"]
            rb.confirm = ["SELECT pg_is_in_recovery();   -- false on the new primary"]
    return rb
