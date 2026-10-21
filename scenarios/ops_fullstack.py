"""Fault injection for the FULL STACK proving ground - Wave 4 (docs/FULLSTACK-LAB.md).

The same four rules as `ops.py`, `ops_k8s.py` and `ops_db.py`:

  1. ⛔ NOTHING OUTSIDE THE PROVING GROUND. Before the FIRST write to any resource, `_guard` checks
     that it is named `warden-dev-*` AND that the service's own tag API says
     `Project=warden` (Kubernetes: the namespace label `project=warden`, because
     `catalog-api` is not a prefixed name). Either check alone is too weak.
  2. ⛔ EVERY INJECT HAS A REVERT, and the revert restores the EXACT prior state captured before the
     first write (alias version, timeout, SG rules, queue policy JSON, capacity, task definition ARN,
     ConfigMap/Secret data, probe, ...). The capture is persisted through `Target.persist` BEFORE the
     write, because Wave 4 is operator-driven: `inject` and `revert` run in different processes, hours
     apart. A revert with nothing saved is a no-op (idempotent), never a guess.
  3. ⛔ THE FAULT MUST BE REAL. Real config, real capacity, real IAM, real sessions and locks.
  4. ⛔ THIS MODULE MUST NOT IMPORT `warden`.

⚠ Sessions (fs-12 connection exhaustion, fs-13 lock contention) are held by a DETACHED holder
process (`fullstack_cli _hold`), because the process that injected them exits. Every held session
carries `application_name = warden-bench-hold-<fault>`, so the revert can always end them with
`pg_terminate_backend` even if the holder is gone - under a statement_timeout, so it cannot hang
(the Wave 3 lesson in ops_db.py: a revert that waits on a lock forever hangs the whole wave).

The end of this file records a fix outcome from the gate's verdict alone (`decide_fix`): the harness runs no
fix command (docs/FULLSTACK-LAB.md section 6).
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from scenarios.region import fault_environment, region

from .ops import OpError
from .ops_k8s import _to_dict

# ponytail: the benchmark runs one environment per process - WARDEN_ENV, else environments.yaml's fault environment.
ENV = fault_environment()
PREFIX = f"warden-{ENV}-"
REQUIRED_TAGS = {"Project": "warden", "Environment": ENV}
K8S_LABELS = {"project": "warden", "environment": ENV}
REGION = region()  # environments.yaml aws_region, or AWS_REGION (owner requirement R17)
HOLD_APP_PREFIX = "warden-bench-hold-"

# ⛔ APPLICATION FLAGS the fault injections flip. The stack's baseline MUST set every one of these to
# its baseline value, so the CONFIG line (which shows env var NAMES, never values) looks identical
# before and after the fault - a variable that only appears during a fault names the answer.
FLAGS: dict[str, tuple[str, str, str]] = {
    # fault: (env var, baseline value, fault value)
    "fs-01": ("CHECKOUT_FF_1", "v1", "v2"),        # v2 reads body["sku_id"] -> KeyError
    "fs-02": ("CHECKOUT_FF_2", "0", "2000"),          # sleep before the DynamoDB call
    "fs-16": ("RECONCILER_FF_1", "by_id", "by_customer"),   # query path needing the dropped index
    "fs-20": ("ORDERS_FF_1", "0", "400"),                       # orders-api allocates this at start
}


@dataclass
class Target:
    """The stack's names. Defaults are docs/FULLSTACK-LAB.md section 1; endpoints and ids come
    from the stack description file (fullstack_cli.load_stack)."""

    region: str = REGION
    checkout: str = f"{PREFIX}checkout"
    processor: str = f"{PREFIX}order-processor"
    notifier: str = f"{PREFIX}notifier"
    reconciler: str = f"{PREFIX}reconciler"
    ops_fn: str = f"{PREFIX}ops"
    alias: str = "live"
    orders_queue: str = f"{PREFIX}orders"
    orders_dlq: str = f"{PREFIX}orders-dlq"
    notifications_queue: str = f"{PREFIX}notifications"
    topic: str = f"{PREFIX}order-events"
    table: str = f"{PREFIX}carts"
    table_rcu: int = 5
    table_wcu: int = 5
    redis_group: str = f"{PREFIX}redis"
    redis_sg_id: str = ""
    aurora_cluster: str = f"{PREFIX}aurora"
    writer_instance: str = f"{PREFIX}aurora-1"
    reader_instance: str = f"{PREFIX}aurora-2"
    writer_endpoint: str = ""     # cluster writer endpoint (what the processor's DB_HOST must be)
    reader_endpoint: str = ""     # cluster reader endpoint
    database: str = "shop"
    orders_sql_table: str = "orders"
    slow_index: str = "orders_customer_id_idx"
    checkout_role: str = f"{PREFIX}checkout"
    ecs_cluster: str = f"{PREFIX}ecs"
    ecs_service: str = f"{PREFIX}orders-api"
    ecs_exec_role: str = f"{PREFIX}ecs-exec"
    ecs_task_role: str = f"{PREFIX}orders-api-task"   # signs orders-api's IAM DB tokens (fs-21)
    ecs_baseline_td: str = ""
    target_group: str = f"{PREFIX}orders"
    health_path: str = "/health"
    rule: str = f"{PREFIX}reconcile-5m"
    namespace: str = "shop"
    catalog: str = "catalog-api"
    cart_worker: str = "cart-worker"
    k8s_replicas: dict[str, int] = field(default_factory=lambda: {"catalog-api": 2, "cart-worker": 2})
    configmap: str = "catalog-config"
    config_key: str = "CATALOG_PAGE_SIZE"
    k8s_secret: str = "catalog-secret"
    redis_fill_mb: int = 400
    redis_max_pct: float = 70.0
    # fault id -> what the inject replaced. Persisted by `persist` before the first write.
    saved: dict[str, Any] = field(default_factory=dict)
    persist: Callable[[str], None] = lambda _fid: None
    sleep: Callable[[float], None] = time.sleep
    # (fault id) -> starts the detached session holder; returns its pid. Set by fullstack_cli.
    spawn_holder: Callable[[str], int] | None = None
    wait_holder_ready: Callable[[str, float], dict] | None = None
    stop_holder: Callable[[str], None] | None = None


@dataclass
class Clients:
    lam: Any = None
    sqs: Any = None
    ddb: Any = None
    ec2: Any = None
    rds: Any = None
    ecs: Any = None
    elbv2: Any = None
    iam: Any = None
    events: Any = None
    secrets: Any = None
    cw: Any = None
    ec: Any = None        # elasticache (fs-11 revert undoes a node-type change)
    apps: Any = None      # kubernetes AppsV1Api
    core: Any = None      # kubernetes CoreV1Api
    # (**kw) -> a NEW autocommit psycopg connection to the Aurora WRITER as the admin user (a fresh
    # IAM token each time), with connect_timeout and statement/lock timeouts set. kw may carry
    # application_name.
    sql: Callable[..., Any] | None = None
    # The same, on the READER endpoint (fs-16's slow query runs there).
    sql_reader: Callable[..., Any] | None = None
    _guarded: set = field(default_factory=set)


# =========================================================================== the guard


def _kv(tags: Any) -> dict[str, str]:
    """Tags arrive as {k: v}, [{Key, Value}] or [{key, value}] depending on the service."""
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    out = {}
    for t in tags or []:
        out[str(t.get("Key", t.get("key")))] = str(t.get("Value", t.get("value")))
    return out


def _tags_of(c: Clients, t: Target, kind: str, name: str) -> tuple[str, dict[str, str]]:
    """(the resource's real name, its tags) through that service's own tag API."""
    if kind == "lambda":
        arn = c.lam.get_function_configuration(FunctionName=name)["FunctionArn"]
        return name, _kv(c.lam.list_tags(Resource=arn).get("Tags"))
    if kind == "sqs":
        url = c.sqs.get_queue_url(QueueName=name)["QueueUrl"]
        return name, _kv(c.sqs.list_queue_tags(QueueUrl=url).get("Tags"))
    if kind == "dynamodb":
        arn = c.ddb.describe_table(TableName=name)["Table"]["TableArn"]
        return name, _kv(c.ddb.list_tags_of_resource(ResourceArn=arn).get("Tags"))
    if kind == "sg":
        group = (c.ec2.describe_security_groups(GroupIds=[name]).get("SecurityGroups") or [{}])[0]
        return str(group.get("GroupName", "")), _kv(group.get("Tags"))
    if kind == "rds":
        cluster = c.rds.describe_db_clusters(DBClusterIdentifier=name)["DBClusters"][0]
        return name, _kv(cluster.get("TagList"))
    if kind == "ecs":
        svc = (c.ecs.describe_services(cluster=t.ecs_cluster, services=[name],
                                       include=["TAGS"]).get("services") or [{}])[0]
        return name, _kv(svc.get("tags"))
    if kind == "tg":
        arn = c.elbv2.describe_target_groups(Names=[name])["TargetGroups"][0]["TargetGroupArn"]
        return name, _kv(c.elbv2.describe_tags(ResourceArns=[arn])["TagDescriptions"][0].get("Tags"))
    if kind == "iam":
        return name, _kv(c.iam.list_role_tags(RoleName=name).get("Tags"))
    if kind == "rule":
        arn = c.events.describe_rule(Name=name)["Arn"]
        return name, _kv(c.events.list_tags_for_resource(ResourceARN=arn).get("Tags"))
    if kind == "secret":
        return name, _kv(c.secrets.describe_secret(SecretId=name).get("Tags"))
    if kind == "elasticache":
        arn = c.ec.describe_replication_groups(ReplicationGroupId=name)["ReplicationGroups"][0]["ARN"]
        return name, _kv(c.ec.list_tags_for_resource(ResourceName=arn).get("TagList"))
    raise OpError(f"no guard for resource kind {kind!r}")


def _guard(c: Clients, t: Target, kind: str, name: str) -> None:
    """Refuse unless the resource is named warden-<env>-* AND tagged Project=warden AND
    Environment=<env> (v2 Phase 1.5: one environment can never touch another's resources).

    ⛔ Never relax this. Checked once per resource per process, before the first write."""
    key = (kind, name)
    if key in c._guarded:
        return
    if kind == "k8s":
        ns = _to_dict(c.core.read_namespace(name=name))
        labels = (ns.get("metadata") or {}).get("labels") or {}
        wrong = {k: v for k, v in K8S_LABELS.items() if labels.get(k) != v}
        if wrong:
            raise OpError(f"namespace {name!r} is not labelled {wrong}. Refusing.")
        c._guarded.add(key)
        return
    try:
        real, tags = _tags_of(c, t, kind, name)
    except OpError:
        raise
    except Exception as exc:  # any failure here means "do not touch it"
        raise OpError(f"cannot read the tags of {kind} {name!r}: {type(exc).__name__}") from exc
    if not real.startswith(PREFIX):
        raise OpError(f"{kind} {real!r} is not named {PREFIX}*. Refusing.")
    wrong = {k: v for k, v in REQUIRED_TAGS.items() if tags.get(k) != v}
    if wrong:
        raise OpError(f"{kind} {real!r} is not tagged {wrong}. Refusing.")
    c._guarded.add(key)


def _guard_db(c: Clients, t: Target) -> None:
    if not t.writer_endpoint.startswith(PREFIX + "aurora"):
        raise OpError(f"writer endpoint {t.writer_endpoint!r} is not the {PREFIX}aurora cluster. Refusing.")
    _guard(c, t, "rds", t.aurora_cluster)
    conn = c.sql()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database()")
            name = cur.fetchone()[0]
    finally:
        conn.close()
    if name != t.database:
        raise OpError(f"connected to database {name!r}, expected {t.database!r}. Refusing.")


def _save(t: Target, fid: str, data: dict) -> None:
    """Capture prior state, and put it on disk BEFORE the first write."""
    t.saved[fid] = data
    t.persist(fid)


def _done(t: Target, fid: str) -> None:
    t.saved.pop(fid, None)
    t.persist(fid)


# =========================================================================== small helpers


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _poll(t: Target, check: Callable[[], bool], *, tries: int = 60, every: float = 5) -> bool:
    for _ in range(tries):
        if check():
            return True
        t.sleep(every)
    return False


def _cw(c: Clients, ns: str, metric: str, dims: dict[str, str], minutes: int,
        stat: str = "Sum") -> float | None:
    """A CloudWatch statistic over the last `minutes`. None = no datapoint at all.

    ⛔ GetMetricData, not GetMetricStatistics: the operator is granted only the former. The first
    measured verify (fs-01, 2026-09-26) died on AccessDenied - every metric-based verifier would have
    called a working fix "not fixed"."""
    end = _now()
    resp = c.cw.get_metric_data(
        MetricDataQueries=[{"Id": "m", "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": ns, "MetricName": metric,
                       "Dimensions": [{"Name": k, "Value": v} for k, v in dims.items()]},
            "Period": 60, "Stat": stat}}],
        StartTime=end - dt.timedelta(minutes=minutes), EndTime=end,
    )
    points = [float(v) for r in resp.get("MetricDataResults") or [] for v in r.get("Values") or []]
    if not points:
        return None
    return max(points) if stat == "Maximum" else float(sum(points))


def _lambda_clean(c: Clients, fn: str, minutes: int = 3) -> tuple[bool, str]:
    """No errors and no throttles for `minutes`, and it really was invoked."""
    dims = {"FunctionName": fn}
    errors = _cw(c, "AWS/Lambda", "Errors", dims, minutes) or 0
    throttles = _cw(c, "AWS/Lambda", "Throttles", dims, minutes) or 0
    calls = _cw(c, "AWS/Lambda", "Invocations", dims, minutes) or 0
    ok = errors == 0 and throttles == 0 and calls > 0
    return ok, f"{fn}: {calls:g} invocations, {errors:g} errors, {throttles:g} throttles in {minutes} min"


def _lambda_cfg(c: Clients, fn: str) -> dict:
    return c.lam.get_function_configuration(FunctionName=fn)


def _lambda_env(cfg: dict) -> dict[str, str]:
    return dict((cfg.get("Environment") or {}).get("Variables") or {})


def _wait_lambda(c: Clients, t: Target, fn: str) -> None:
    if not _poll(t, lambda: _lambda_cfg(c, fn).get("LastUpdateStatus") in (None, "Successful"),
                 tries=60, every=2):
        raise OpError(f"{fn}: configuration update did not finish")


# --------------------------------------------------------------------------- lambda


def _lambda_publish_change(c: Clients, t: Target, fid: str, fn: str, *, timeout: int | None = None,
                           env: dict[str, str] | None = None) -> dict:
    """Change $LATEST, publish it as version N+1 and move `live` to it - a real deploy.

    ⚠ The API invokes checkout through the alias, so a config change on $LATEST alone would reach
    no traffic. That makes every checkout config fault a deploy by construction (contract D)."""
    _guard(c, t, "lambda", fn)
    alias = c.lam.get_alias(FunctionName=fn, Name=t.alias)
    cfg = _lambda_cfg(c, fn)
    _save(t, fid, {"fn": fn, "alias_version": alias["FunctionVersion"], "timeout": cfg["Timeout"],
                   "env": _lambda_env(cfg)})
    update: dict[str, Any] = {}
    if timeout is not None:
        update["Timeout"] = int(timeout)
    if env:
        update["Environment"] = {"Variables": {**_lambda_env(cfg), **env}}
    c.lam.update_function_configuration(FunctionName=fn, **update)
    _wait_lambda(c, t, fn)
    version = c.lam.publish_version(FunctionName=fn, Description=f"warden-bench {fid}")["Version"]
    t.saved[fid]["bad_version"] = version
    t.persist(fid)
    c.lam.update_alias(FunctionName=fn, Name=t.alias, FunctionVersion=version)
    return {"function": fn, "alias_from": alias["FunctionVersion"], "alias_to": version}


def _lambda_publish_revert(c: Clients, t: Target, fid: str) -> dict:
    s = t.saved.get(fid)
    if not s:
        return {"nothing_saved": True}
    fn = s["fn"]
    c.lam.update_alias(FunctionName=fn, Name=t.alias, FunctionVersion=s["alias_version"])
    c.lam.update_function_configuration(FunctionName=fn, Timeout=s["timeout"],
                                        Environment={"Variables": s["env"]})
    _wait_lambda(c, t, fn)
    _done(t, fid)
    return {"alias": s["alias_version"], "timeout": s["timeout"]}


def _lambda_env_change(c: Clients, t: Target, fid: str, fn: str, changes: dict[str, str]) -> dict:
    """Change an unaliased function's environment directly (not a deploy)."""
    _guard(c, t, "lambda", fn)
    env = _lambda_env(_lambda_cfg(c, fn))
    _save(t, fid, {"fn": fn, "env": env})
    c.lam.update_function_configuration(FunctionName=fn, Environment={"Variables": {**env, **changes}})
    _wait_lambda(c, t, fn)
    return {"function": fn, "changed": sorted(changes)}


def _lambda_env_revert(c: Clients, t: Target, fid: str) -> dict:
    s = t.saved.get(fid)
    if not s:
        return {"nothing_saved": True}
    c.lam.update_function_configuration(FunctionName=s["fn"], Environment={"Variables": s["env"]})
    _wait_lambda(c, t, s["fn"])
    _done(t, fid)
    return {"restored_env": s["fn"]}


# --------------------------------------------------------------------------- iam


def _actions(statement: dict) -> list[str]:
    a = statement.get("Action") or []
    return [a] if isinstance(a, str) else list(a)


def _iam_remove_action(c: Clients, t: Target, fid: str, role: str, action: str, *,
                       extra: dict | None = None) -> dict:
    """Remove one action from every inline policy of `role` that grants it. Saves every document."""
    _guard(c, t, "iam", role)
    docs = {name: c.iam.get_role_policy(RoleName=role, PolicyName=name)["PolicyDocument"]
            for name in c.iam.list_role_policies(RoleName=role).get("PolicyNames") or []}
    granting = {n: d for n, d in docs.items()
                if any(action in _actions(s) for s in d.get("Statement") or [])}
    if not granting:
        raise OpError(f"no inline policy of {role} grants {action} explicitly - nothing to remove")
    _save(t, fid, {"role": role, "docs": copy.deepcopy(granting), "policies": sorted(docs), **(extra or {})})
    for name, doc in granting.items():
        shrunk = copy.deepcopy(doc)
        kept = []
        for s in shrunk.get("Statement") or []:
            left = [a for a in _actions(s) if a != action]
            if left:
                s["Action"] = left
                kept.append(s)
        shrunk["Statement"] = kept
        if kept:
            c.iam.put_role_policy(RoleName=role, PolicyName=name, PolicyDocument=json.dumps(shrunk))
        else:
            # ⛔ IAM refuses a policy with no statements (MalformedPolicyDocument). fs-18's execution-role
            # policy grants ONLY GetSecretValue and fs-21's task-role policy ONLY rds-db:connect, so
            # removing the action removes the policy; revert re-puts it.
            c.iam.delete_role_policy(RoleName=role, PolicyName=name)
    return {"role": role, "removed": action, "policies": sorted(granting)}


def _iam_restore(c: Clients, t: Target, fid: str) -> dict:
    s = t.saved.get(fid)
    if not s:
        return {"nothing_saved": True}
    for name, doc in s["docs"].items():
        c.iam.put_role_policy(RoleName=s["role"], PolicyName=name, PolicyDocument=json.dumps(doc))
    # ⛔ EXACT prior state: WARDEN's fix adds its OWN inline policy (warden-restore-*). Every inline
    # policy the role did not have before the inject goes, or the next fault starts with an extra
    # grant. (A state saved before this list existed has no "policies" key: nothing is removed.)
    extra: list[str] = []
    if "policies" in s:
        now = c.iam.list_role_policies(RoleName=s["role"]).get("PolicyNames") or []
        extra = sorted(set(now) - set(s["policies"]))
        for name in extra:
            c.iam.delete_role_policy(RoleName=s["role"], PolicyName=name)
    return {"role": s["role"], "restored": sorted(s["docs"]), "removed_extra": extra}


# --------------------------------------------------------------------------- ecs


def _ecs_service(c: Clients, t: Target) -> dict:
    return (c.ecs.describe_services(cluster=t.ecs_cluster, services=[t.ecs_service])
            .get("services") or [{}])[0]


_TD_KEYS = ("family", "taskRoleArn", "executionRoleArn", "networkMode", "containerDefinitions",
            "volumes", "placementConstraints", "requiresCompatibilities", "cpu", "memory",
            "runtimePlatform", "ephemeralStorage")


def _ecs_deploy_variant(c: Clients, t: Target, fid: str, mutate: Callable[[dict], None]) -> dict:
    """Register a revision of the service's current task definition, changed by `mutate`, and roll
    the service onto it. The previous task definition ARN is saved for an exact revert."""
    _guard(c, t, "ecs", t.ecs_service)
    current = _ecs_service(c, t)["taskDefinition"]
    _save(t, fid, {"task_definition": current})
    td = c.ecs.describe_task_definition(taskDefinition=current)["taskDefinition"]
    spec = {k: copy.deepcopy(td[k]) for k in _TD_KEYS if td.get(k) is not None}
    mutate(spec)
    spec["tags"] = [{"key": k, "value": v} for k, v in REQUIRED_TAGS.items()]
    new = c.ecs.register_task_definition(**spec)["taskDefinition"]["taskDefinitionArn"]
    t.saved[fid]["fault_task_definition"] = new
    t.persist(fid)
    c.ecs.update_service(cluster=t.ecs_cluster, service=t.ecs_service, taskDefinition=new)
    return {"from": current.split("/")[-1], "to": new.split("/")[-1]}


def _ecs_restore(c: Clients, t: Target, fid: str) -> dict:
    s = t.saved.get(fid)
    if not s:
        return {"nothing_saved": True}
    c.ecs.update_service(cluster=t.ecs_cluster, service=t.ecs_service,
                         taskDefinition=s["task_definition"], forceNewDeployment=True)
    _done(t, fid)
    return {"task_definition": s["task_definition"].split("/")[-1]}


def _ecs_steady(c: Clients, t: Target, not_td: str = "") -> tuple[bool, str]:
    s = _ecs_service(c, t)
    deps = s.get("deployments") or []
    rollout = (deps[0].get("rolloutState") if deps else None) or "COMPLETED"
    ok = (s.get("desiredCount", 0) > 0 and s.get("runningCount") == s.get("desiredCount")
          and not s.get("pendingCount") and len(deps) == 1 and rollout == "COMPLETED"
          and (not not_td or s.get("taskDefinition") != not_td))
    return ok, (f"{s.get('runningCount')}/{s.get('desiredCount')} running, {len(deps)} deployment(s) "
                f"{rollout}, on {str(s.get('taskDefinition', '')).split('/')[-1]}")


def _alb_healthy(c: Clients, t: Target) -> tuple[bool, str]:
    arn = c.elbv2.describe_target_groups(Names=[t.target_group])["TargetGroups"][0]["TargetGroupArn"]
    states = [h.get("TargetHealth", {}).get("State")
              for h in c.elbv2.describe_target_health(TargetGroupArn=arn).get("TargetHealthDescriptions") or []]
    ok = bool(states) and all(s == "healthy" for s in states)
    return ok, f"targets: {states}"


# --------------------------------------------------------------------------- sql


def _sql_scalar(c: Clients, sql: str, params: tuple = (), *, reader: bool = False) -> Any:
    connect = c.sql_reader if reader else c.sql
    if connect is None:
        raise OpError(f"no {'reader' if reader else 'writer'} SQL connection wired")
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params) if params else cur.execute(sql)
            if cur.description is None:  # DDL / ALTER: no result set
                return None
            row = cur.fetchone()
            return row[0] if row else None
    finally:
        conn.close()


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _terminate_holders(c: Clients, fid: str) -> int:
    """End every session a holder opened for `fid`. The belt to the holder's own braces."""
    conn = c.sql()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                        "WHERE application_name = %s", (HOLD_APP_PREFIX + fid,))
            return int(cur.fetchone()[0] or 0)
    finally:
        conn.close()


def _holders_left(c: Clients, fid: str) -> int:
    return int(_sql_scalar(c, "SELECT count(*) FROM pg_stat_activity WHERE application_name = %s",
                           (HOLD_APP_PREFIX + fid,)) or 0)


# --------------------------------------------------------------------------- the held sessions
#
# Run INSIDE the detached holder process (fullstack_cli _hold). They return once the sessions are
# open; the caller keeps them open until told to stop.


def hold_connections(c: Clients, t: Target, fid: str, *, headroom: int = 3,
                     workers: int = 16) -> tuple[list, dict]:
    """fs-12: open sessions until the server refuses, then give `headroom` back so an operator (and
    WARDEN's read) can still get in - the apps' pools grab them and hit the limit.

    ⛔ Measured in the preflight (2026-09-26): one IAM-token TLS login through the express gateway
    takes ~0.26 s, so 844 in series took 3.7 minutes - past the inject's ready timeout, and the
    revert then raced a holder that was still opening sessions. So: in parallel. And past
    `max_connections` on purpose (+50 attempts): stopping at our own count (the old loop did, with
    `stopped_by` empty) is not proof the SERVER is full; a refusal is."""
    from concurrent.futures import ThreadPoolExecutor

    max_conn = int(_sql_scalar(c, "SHOW max_connections"))

    def one(_: int) -> tuple[Any, str]:
        try:
            return c.sql(application_name=HOLD_APP_PREFIX + fid), ""
        except Exception as exc:  # noqa: BLE001  # the server refusing IS the result here; named
            return None, type(exc).__name__

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, range(max_conn + 50)))
    held = [conn for conn, _ in results if conn is not None]
    errors = [err for _, err in results if err]
    for _ in range(min(headroom, len(held))):
        held.pop().close()
    return held, {"max_connections": max_conn, "held": len(held), "refused": len(errors),
                  "stopped_by": max(set(errors), key=errors.count) if errors else ""}


def hold_lock(c: Clients, t: Target, fid: str) -> tuple[list, dict]:
    """fs-13: one transaction holds a SHARE lock on the orders table, so every INSERT queues."""
    conn = c.sql(application_name=HOLD_APP_PREFIX + fid)
    cur = conn.cursor()
    cur.execute("BEGIN")
    # ⛔ A timeout on the blocker's OWN lock (the Wave 3 lesson): a leaked lock from earlier would
    # otherwise make this wait forever.
    cur.execute("SET LOCAL lock_timeout = '15s'")
    cur.execute(f"LOCK TABLE {_quote_ident(t.orders_sql_table)} IN SHARE MODE")
    cur.execute("SELECT pg_backend_pid()")
    return [conn], {"blocker_pid": int(cur.fetchone()[0])}


HOLDERS: dict[str, Callable[..., tuple[list, dict]]] = {
    "fs-12": hold_connections, "fs-13": hold_lock,
}


def _inject_held(c: Clients, t: Target, fid: str) -> dict:
    _guard_db(c, t)
    if t.spawn_holder is None or t.wait_holder_ready is None:
        raise OpError("no session holder wired - run through fullstack_cli")
    _save(t, fid, {"app_name": HOLD_APP_PREFIX + fid})
    t.saved[fid]["pid"] = t.spawn_holder(fid)
    t.persist(fid)
    ready = t.wait_holder_ready(fid, 180.0)
    if not ready.get("ok"):
        raise OpError(f"the session holder did not report ready: {ready.get('error', ready)}")
    return {k: v for k, v in ready.items() if k != "ok"}


def _revert_held(c: Clients, t: Target, fid: str, *, attempts: int = 12) -> dict:
    """Stop the holder, then end its sessions until none is left. A terminated backend leaves
    `pg_stat_activity` a moment later, and a holder still opening sessions adds more, so the count
    is polled (terminate again each time) before the revert is called failed."""
    if t.stop_holder is not None:
        t.stop_holder(fid)
    ended = 0
    for attempt in range(attempts):
        ended += _terminate_holders(c, fid)
        left = _holders_left(c, fid)
        if not left:
            _done(t, fid)
            return {"terminated_backends": ended}
        if attempt < attempts - 1:
            t.sleep(5)
    raise OpError(f"{left} held session(s) for {fid} are still open after pg_terminate_backend "
                  f"({attempts} tries, 5 s apart)")


# =========================================================================== the faults


def _flag_env(fid: str) -> dict[str, str]:
    name, _base, bad = FLAGS[fid]
    return {name: bad}


# fs-00 -------------------------------------------------------------------------------------------

def _noop(c: Clients, t: Target) -> dict:
    return {"nothing": True}


# fs-01..05 checkout ------------------------------------------------------------------------------

def fs01_inject(c, t):
    return _lambda_publish_change(c, t, "fs-01", t.checkout, env=_flag_env("fs-01"))


def fs01_verify(c, t):
    ok, detail = _lambda_clean(c, t.checkout)
    bad = (t.saved.get("fs-01") or {}).get("bad_version")
    live = c.lam.get_alias(FunctionName=t.checkout, Name=t.alias)["FunctionVersion"]
    return ok and live != bad, f"{detail}; live={live} (fault version {bad})"


def fs02_inject(c, t):
    return _lambda_publish_change(c, t, "fs-02", t.checkout, timeout=1, env=_flag_env("fs-02"))


def fs03_inject(c, t):
    _guard(c, t, "lambda", t.checkout)
    prior = c.lam.get_function_concurrency(FunctionName=t.checkout).get("ReservedConcurrentExecutions")
    _save(t, "fs-03", {"reserved": prior})
    c.lam.put_function_concurrency(FunctionName=t.checkout, ReservedConcurrentExecutions=0)
    return {"reserved_from": prior, "reserved_to": 0}


def fs03_revert(c, t):
    s = t.saved.get("fs-03")
    if not s:
        return {"nothing_saved": True}
    if s["reserved"] is None:
        c.lam.delete_function_concurrency(FunctionName=t.checkout)
    else:
        c.lam.put_function_concurrency(FunctionName=t.checkout,
                                       ReservedConcurrentExecutions=int(s["reserved"]))
    _done(t, "fs-03")
    return {"reserved": s["reserved"]}


def fs04_inject(c, t):
    return _lambda_publish_change(c, t, "fs-04", t.checkout,
                                  env={"TABLE_NAME": t.table + "-v2"})  # a table that does not exist


def fs05_inject(c, t):
    return _iam_remove_action(c, t, "fs-05", t.checkout_role, "dynamodb:PutItem")


def fs05_revert(c, t):
    out = _iam_restore(c, t, "fs-05")
    _done(t, "fs-05")
    return out


def checkout_clean(c, t):
    return _lambda_clean(c, t.checkout)


# fs-06..08 queues ----------------------------------------------------------------------------------

def _queue_url(c, name):
    return c.sqs.get_queue_url(QueueName=name)["QueueUrl"]


def _visible(c, name) -> int:
    attrs = c.sqs.get_queue_attributes(QueueUrl=_queue_url(c, name),
                                       AttributeNames=["ApproximateNumberOfMessages"])["Attributes"]
    return int(attrs.get("ApproximateNumberOfMessages", 0))


def fs06_inject(c, t, count: int = 20):
    _guard(c, t, "sqs", t.orders_queue)
    _guard(c, t, "sqs", t.orders_dlq)
    _save(t, "fs-06", {"dlq_visible_before": _visible(c, t.orders_dlq)})
    url = _queue_url(c, t.orders_queue)
    for n in range(count):
        # Not JSON: the processor's json.loads raises on it, every receive, until the DLQ.
        c.sqs.send_message(QueueUrl=url, MessageBody=f"order-v0|{n}|" + secrets.token_hex(4))
    return {"poison_messages": count}


def _purge(c, name) -> str:
    try:
        c.sqs.purge_queue(QueueUrl=_queue_url(c, name))
        return "purged"
    except Exception as exc:
        if "PurgeQueueInProgress" in f"{type(exc).__name__} {exc}":
            return "purge already in progress"
        raise


def fs06_revert(c, t):
    if not t.saved.get("fs-06"):
        return {"nothing_saved": True}
    # The poison may still be cycling through the source queue, so both are emptied (the baseline
    # DLQ was empty - check_baseline refuses to start a fault otherwise).
    out = {"orders": _purge(c, t.orders_queue), "dlq": _purge(c, t.orders_dlq)}
    _done(t, "fs-06")
    return out


def fs06_verify(c, t):
    dlq = _visible(c, t.orders_dlq)
    ok, detail = _lambda_clean(c, t.processor)
    return ok and dlq == 0, f"dlq visible={dlq}; {detail}"


def _orders_esm(c, t) -> dict:
    for m in c.lam.list_event_source_mappings(FunctionName=t.processor).get("EventSourceMappings") or []:
        if str(m.get("EventSourceArn", "")).endswith(":" + t.orders_queue):
            return m
    raise OpError(f"no event source mapping {t.orders_queue} -> {t.processor}")


def fs07_inject(c, t):
    _guard(c, t, "lambda", t.processor)
    esm = _orders_esm(c, t)
    _save(t, "fs-07", {"uuid": esm["UUID"], "enabled": esm.get("State") in ("Enabled", "Enabling")})
    c.lam.update_event_source_mapping(UUID=esm["UUID"], Enabled=False)
    return {"esm": esm["UUID"], "enabled": False}


def fs07_revert(c, t):
    s = t.saved.get("fs-07")
    if not s:
        return {"nothing_saved": True}
    c.lam.update_event_source_mapping(UUID=s["uuid"], Enabled=bool(s["enabled"]))
    _done(t, "fs-07")
    return {"esm": s["uuid"], "enabled": s["enabled"]}


def fs07_verify(c, t, backlog: int = 20):
    state = _orders_esm(c, t).get("State")
    visible = _visible(c, t.orders_queue)
    return state == "Enabled" and visible < backlog, f"ESM {state}, orders visible={visible}"


def fs08_inject(c, t):
    _guard(c, t, "sqs", t.notifications_queue)
    url = _queue_url(c, t.notifications_queue)
    attrs = c.sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy", "QueueArn"])["Attributes"]
    _save(t, "fs-08", {"policy": attrs.get("Policy")})
    account = attrs["QueueArn"].split(":")[4]
    # Only the account itself may send; the topic may not. Real SNS delivery failures follow.
    locked = {"Version": "2012-10-17", "Statement": [{
        "Sid": "OwnerOnly", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "sqs:SendMessage", "Resource": attrs["QueueArn"]}]}
    c.sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(locked)})
    return {"queue": t.notifications_queue, "policy": "owner-only"}


def fs08_revert(c, t):
    s = t.saved.get("fs-08")
    if not s:
        return {"nothing_saved": True}
    c.sqs.set_queue_attributes(QueueUrl=_queue_url(c, t.notifications_queue),
                               Attributes={"Policy": s["policy"] or ""})
    _done(t, "fs-08")
    return {"policy": "restored verbatim"}


def fs08_verify(c, t):
    failed = _cw(c, "AWS/SNS", "NumberOfNotificationsFailed", {"TopicName": t.topic}, 3) or 0
    delivered = _cw(c, "AWS/SNS", "NumberOfNotificationsDelivered", {"TopicName": t.topic}, 3) or 0
    return failed == 0 and delivered > 0, f"sns failed={failed:g} delivered={delivered:g} in 3 min"


# fs-09 dynamodb ------------------------------------------------------------------------------------

def _table(c, t) -> dict:
    return c.ddb.describe_table(TableName=t.table)["Table"]


def _set_capacity(c, t, rcu: int, wcu: int) -> None:
    pt = _table(c, t).get("ProvisionedThroughput") or {}
    if (pt.get("ReadCapacityUnits"), pt.get("WriteCapacityUnits")) == (rcu, wcu):
        return  # update_table with unchanged values is a ValidationException
    c.ddb.update_table(TableName=t.table,
                       ProvisionedThroughput={"ReadCapacityUnits": rcu, "WriteCapacityUnits": wcu})
    if not _poll(t, lambda: _table(c, t).get("TableStatus") == "ACTIVE"):
        raise OpError(f"{t.table} did not return to ACTIVE")


def fs09_inject(c, t):
    _guard(c, t, "dynamodb", t.table)
    pt = _table(c, t)["ProvisionedThroughput"]
    _save(t, "fs-09", {"rcu": pt["ReadCapacityUnits"], "wcu": pt["WriteCapacityUnits"]})
    _set_capacity(c, t, 1, 1)
    return {"from": [pt["ReadCapacityUnits"], pt["WriteCapacityUnits"]], "to": [1, 1]}


def fs09_revert(c, t):
    s = t.saved.get("fs-09")
    if not s:
        return {"nothing_saved": True}
    _set_capacity(c, t, int(s["rcu"]), int(s["wcu"]))
    _done(t, "fs-09")
    return {"rcu": s["rcu"], "wcu": s["wcu"]}


def fs09_verify(c, t):
    dims = {"TableName": t.table}
    events = sum((_cw(c, "AWS/DynamoDB", m, dims, 3) or 0)
                 for m in ("ReadThrottleEvents", "WriteThrottleEvents"))
    return events == 0, f"throttle events in 3 min: {events:g}"


# fs-10..11 redis -----------------------------------------------------------------------------------

def _sg(c, gid) -> dict:
    return c.ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]


def fs10_inject(c, t):
    if not t.redis_sg_id:
        raise OpError("no redis security group id in the stack description")
    _guard(c, t, "sg", t.redis_sg_id)
    rules = [r for r in _sg(c, t.redis_sg_id).get("IpPermissions") or [] if r.get("UserIdGroupPairs")]
    if not rules:
        raise OpError("the Redis security group has no ingress from other groups - nothing to cut")
    _save(t, "fs-10", {"rules": rules})
    c.ec2.revoke_security_group_ingress(GroupId=t.redis_sg_id, IpPermissions=rules)
    return {"revoked_rules": len(rules)}


def fs10_revert(c, t):
    s = t.saved.get("fs-10")
    if not s:
        return {"nothing_saved": True}
    try:
        c.ec2.authorize_security_group_ingress(GroupId=t.redis_sg_id, IpPermissions=s["rules"])
    except Exception as exc:
        if "Duplicate" not in f"{type(exc).__name__} {exc}":
            raise
        # Some may be back and some not: re-add one rule at a time.
        for rule in s["rules"]:
            try:
                c.ec2.authorize_security_group_ingress(GroupId=t.redis_sg_id, IpPermissions=[rule])
            except Exception as inner:
                if "Duplicate" not in f"{type(inner).__name__} {inner}":
                    raise
    # ⛔ EXACT prior state: a fix may have authorised a group that was never there (WARDEN names the
    # application SGs it read). Anything group-sourced that the saved set lacks is revoked, one pair
    # at a time, so the next fault starts from the baseline and not from a wider network.
    saved = _group_pairs(s["rules"])
    extra = sorted(_group_pairs([r for r in _sg(c, t.redis_sg_id).get("IpPermissions") or []
                                 if r.get("UserIdGroupPairs")]) - saved)
    for proto, lo, hi, gid in extra:
        perm = {"IpProtocol": proto, "UserIdGroupPairs": [{"GroupId": gid}]}
        if proto != "-1":
            perm.update(FromPort=lo, ToPort=hi)
        c.ec2.revoke_security_group_ingress(GroupId=t.redis_sg_id, IpPermissions=[perm])
    _done(t, "fs-10")
    return {"restored_rules": len(s["rules"]), "removed_extra": [e[3] for e in extra]}


def _group_pairs(rules: list[dict]) -> set[tuple]:
    return {(r.get("IpProtocol"), r.get("FromPort"), r.get("ToPort"), p["GroupId"])
            for r in rules for p in r.get("UserIdGroupPairs") or []}


def ops_invoke(c: Clients, t: Target, payload: dict) -> dict:
    """The harness-only admin Lambda: {"op": fill|flush_prefix|info, ...}."""
    _guard(c, t, "lambda", t.ops_fn)
    resp = c.lam.invoke(FunctionName=t.ops_fn, InvocationType="RequestResponse",
                        Payload=json.dumps(payload).encode())
    body = resp["Payload"].read() if hasattr(resp.get("Payload"), "read") else resp.get("Payload") or b"{}"
    if resp.get("FunctionError"):
        raise OpError(f"{t.ops_fn} {payload.get('op')} failed: {str(body)[:200]}")
    return json.loads(body or b"{}")


def _redis_pct(c, t) -> float:
    info = ops_invoke(c, t, {"op": "info"})
    used, cap = float(info.get("used_memory") or 0), float(info.get("maxmemory") or 0)
    return 100.0 * used / cap if cap else 0.0


def fs10_verify(c, t):
    try:
        pct = _redis_pct(c, t)
    except Exception as exc:  # noqa: BLE001  # unreachable for any error is the "not fixed" answer
        return False, f"redis not reachable from the VPC: {type(exc).__name__}"
    return True, f"redis reachable, memory {pct:.0f}%"


def _redis_node_type(c: Clients, t: Target) -> str:
    group = c.ec.describe_replication_groups(ReplicationGroupId=t.redis_group)["ReplicationGroups"][0]
    first = (group.get("MemberClusters") or [""])[0]
    return c.ec.describe_cache_clusters(CacheClusterId=first)["CacheClusters"][0]["CacheNodeType"]


def _redis_wait_available(c: Clients, t: Target, timeout_s: float = 2400) -> str:
    """A node-type change runs for many minutes; another modify is refused until it ends."""
    waited = 0.0
    while True:
        status = c.ec.describe_replication_groups(ReplicationGroupId=t.redis_group)["ReplicationGroups"][0]["Status"]
        if status == "available" or waited >= timeout_s:
            return status
        t.sleep(30)
        waited += 30


def fs11_inject(c, t):
    # The node type is saved too: WARDEN's fix for memory pressure is a bigger node, and the revert
    # must put the original size back or every later fault runs on a different cache.
    _save(t, "fs-11", {"prefix": "filler:", "node_type": _redis_node_type(c, t)})
    out = ops_invoke(c, t, {"op": "fill", "prefix": "filler:", "mb": int(t.redis_fill_mb)})
    return {"filled_mb": int(t.redis_fill_mb), "ops": out}


def fs11_revert(c, t):
    if not t.saved.get("fs-11"):
        return {"nothing_saved": True}
    s = t.saved["fs-11"]
    out = ops_invoke(c, t, {"op": "flush_prefix", "prefix": "filler:"})
    resized = None
    if s.get("node_type"):
        status = _redis_wait_available(c, t)
        if status != "available":
            raise OpError(f"{t.redis_group} is still {status!r}; cannot restore node type {s['node_type']} yet "
                          "- run revert again")
        now = _redis_node_type(c, t)
        if now != s["node_type"]:
            _guard(c, t, "elasticache", t.redis_group)
            c.ec.modify_replication_group(ReplicationGroupId=t.redis_group, CacheNodeType=s["node_type"],
                                          ApplyImmediately=True)
            resized = f"{now} -> {s['node_type']}"
            _redis_wait_available(c, t)
    _done(t, "fs-11")
    return {"flushed": out, "node_type_restored": resized}


def fs11_verify(c, t):
    pct = _redis_pct(c, t)
    return pct < t.redis_max_pct, f"redis memory {pct:.0f}% (threshold {t.redis_max_pct:.0f}%)"


# fs-12..16 aurora ----------------------------------------------------------------------------------

def fs12_verify(c, t):
    used = int(_sql_scalar(c, "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'"))
    cap = int(_sql_scalar(c, "SHOW max_connections"))
    return used < 0.8 * cap, f"{used}/{cap} client connections"


def fs13_verify(c, t):
    waiting = int(_sql_scalar(c, "SELECT count(*) FROM pg_locks WHERE NOT granted"))
    return waiting == 0, f"{waiting} lock waiter(s)"


def fs14_inject(c, t):
    if not t.reader_endpoint:
        raise OpError("no reader endpoint in the stack description")
    return _lambda_env_change(c, t, "fs-14", t.processor, {"DB_HOST": t.reader_endpoint})


def processor_clean(c, t):
    return _lambda_clean(c, t.processor)


def _cluster(c, t) -> dict:
    return c.rds.describe_db_clusters(DBClusterIdentifier=t.aurora_cluster)["DBClusters"][0]


def _writer(c, t) -> str:
    return next((m["DBInstanceIdentifier"] for m in _cluster(c, t).get("DBClusterMembers") or []
                 if m.get("IsClusterWriter")), "")


def _failover_to(c, t, instance: str) -> None:
    c.rds.failover_db_cluster(DBClusterIdentifier=t.aurora_cluster, TargetDBInstanceIdentifier=instance)
    if not _poll(t, lambda: _writer(c, t) == instance and _cluster(c, t).get("Status") == "available",
                 tries=90, every=10):
        raise OpError(f"failover to {instance} did not complete in 15 minutes")


def fs15_inject(c, t):
    _guard(c, t, "rds", t.aurora_cluster)
    _guard(c, t, "lambda", t.processor)
    writer = _writer(c, t)
    readers = [m["DBInstanceIdentifier"] for m in _cluster(c, t).get("DBClusterMembers") or []
               if not m.get("IsClusterWriter")]
    if not writer or not readers:
        raise OpError("the cluster needs a writer and a reader to fail over")
    endpoint = c.rds.describe_db_instances(DBInstanceIdentifier=writer)["DBInstances"][0]["Endpoint"]["Address"]
    env = _lambda_env(_lambda_cfg(c, t.processor))
    _save(t, "fs-15", {"fn": t.processor, "env": env, "writer": writer})
    c.lam.update_function_configuration(FunctionName=t.processor,
                                        Environment={"Variables": {**env, "DB_HOST": endpoint}})
    _wait_lambda(c, t, t.processor)
    _failover_to(c, t, readers[0])
    return {"pinned_to": writer, "failed_over_to": readers[0]}


def fs15_revert(c, t):
    s = t.saved.get("fs-15")
    if not s:
        return {"nothing_saved": True}
    c.lam.update_function_configuration(FunctionName=s["fn"], Environment={"Variables": s["env"]})
    _wait_lambda(c, t, s["fn"])
    failed_back = False
    if _writer(c, t) != s["writer"]:
        _failover_to(c, t, s["writer"])
        failed_back = True
    _done(t, "fs-15")
    return {"writer": s["writer"], "failed_back": failed_back}


def fs16_inject(c, t):
    _guard_db(c, t)
    _guard(c, t, "lambda", t.reconciler)
    indexdef = _sql_scalar(c, "SELECT indexdef FROM pg_indexes WHERE indexname = %s", (t.slow_index,))
    if not indexdef:
        raise OpError(f"index {t.slow_index} does not exist - the stack is not at baseline")
    env = _lambda_env(_lambda_cfg(c, t.reconciler))
    _save(t, "fs-16", {"indexdef": indexdef, "fn": t.reconciler, "env": env})
    _sql_scalar(c, f"DROP INDEX CONCURRENTLY IF EXISTS {_quote_ident(t.slow_index)}")
    c.lam.update_function_configuration(FunctionName=t.reconciler,
                                        Environment={"Variables": {**env, **_flag_env("fs-16")}})
    _wait_lambda(c, t, t.reconciler)
    return {"dropped_index": t.slow_index}


def _concurrently(indexdef: str) -> str:
    """`CREATE [UNIQUE] INDEX name ON ...` -> the same, CONCURRENTLY and IF NOT EXISTS."""
    return re.sub(r"^CREATE (UNIQUE )?INDEX ", r"CREATE \1INDEX CONCURRENTLY IF NOT EXISTS ",
                  indexdef, count=1)


def fs16_revert(c, t):
    s = t.saved.get("fs-16")
    if not s:
        return {"nothing_saved": True}
    c.lam.update_function_configuration(FunctionName=s["fn"], Environment={"Variables": s["env"]})
    _wait_lambda(c, t, s["fn"])
    _sql_scalar(c, _concurrently(s["indexdef"]))
    _done(t, "fs-16")
    return {"recreated_index": t.slow_index}


def fs16_verify(c, t, seconds: int = 5):
    # The reconciler's query runs on the READER endpoint, so that is where it is timed.
    slow = int(_sql_scalar(
        c, "SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND pid <> pg_backend_pid() "
           "AND now() - query_start > make_interval(secs => %s)", (seconds,), reader=True))
    return slow == 0, f"{slow} active quer(ies) older than {seconds}s on the reader"


# fs-17..21 ecs / alb / secret ----------------------------------------------------------------------

def fs17_inject(c, t):
    def bad_image(spec):
        cd = spec["containerDefinitions"][0]
        cd["image"] = cd["image"].rsplit(":", 1)[0] + ":does-not-exist-" + secrets.token_hex(3)
    return _ecs_deploy_variant(c, t, "fs-17", bad_image)


def fs17_verify(c, t):
    return _ecs_steady(c, t, not_td=(t.saved.get("fs-17") or {}).get("fault_task_definition", ""))


def _iam_ecs_inject(c, t, fid: str, role: str, action: str) -> dict:
    """Remove one action from an orders-api role, then force a deployment onto the change."""
    _guard(c, t, "ecs", t.ecs_service)
    out = _iam_remove_action(c, t, fid, role, action)
    c.ecs.update_service(cluster=t.ecs_cluster, service=t.ecs_service, forceNewDeployment=True)
    return out


def _iam_ecs_revert(c, t, fid: str) -> dict:
    out = _iam_restore(c, t, fid)
    if not out.get("nothing_saved"):
        c.ecs.update_service(cluster=t.ecs_cluster, service=t.ecs_service, forceNewDeployment=True)
        _done(t, fid)
    return out


def fs18_inject(c, t):
    return _iam_ecs_inject(c, t, "fs-18", t.ecs_exec_role, "secretsmanager:GetSecretValue")


def fs18_revert(c, t):
    return _iam_ecs_revert(c, t, "fs-18")


def ecs_steady(c, t):
    return _ecs_steady(c, t)


def _tg(c, t) -> dict:
    return c.elbv2.describe_target_groups(Names=[t.target_group])["TargetGroups"][0]


def fs19_inject(c, t):
    _guard(c, t, "tg", t.target_group)
    tg = _tg(c, t)
    _save(t, "fs-19", {"path": tg["HealthCheckPath"]})
    c.elbv2.modify_target_group(TargetGroupArn=tg["TargetGroupArn"], HealthCheckPath="/healthz")
    return {"health_path_from": tg["HealthCheckPath"], "to": "/healthz"}


def fs19_revert(c, t):
    s = t.saved.get("fs-19")
    if not s:
        return {"nothing_saved": True}
    c.elbv2.modify_target_group(TargetGroupArn=_tg(c, t)["TargetGroupArn"], HealthCheckPath=s["path"])
    _done(t, "fs-19")
    return {"health_path": s["path"]}


def alb_healthy(c, t):
    return _alb_healthy(c, t)


def fs20_inject(c, t):
    name, _base, bad = FLAGS["fs-20"]

    def oom(spec):
        cd = spec["containerDefinitions"][0]
        cd["memory"] = 256
        env = [e for e in cd.get("environment") or [] if e.get("name") != name]
        cd["environment"] = [*env, {"name": name, "value": bad}]
    return _ecs_deploy_variant(c, t, "fs-20", oom)


def fs20_verify(c, t):
    ok, detail = _ecs_steady(c, t)
    stopped = c.ecs.list_tasks(cluster=t.ecs_cluster, serviceName=t.ecs_service,
                               desiredStatus="STOPPED").get("taskArns") or []
    recent_oom = 0
    if stopped:
        since = _now() - dt.timedelta(minutes=3)
        for task in c.ecs.describe_tasks(cluster=t.ecs_cluster, tasks=stopped[:100]).get("tasks") or []:
            at = task.get("stoppedAt")
            if at and (at if isinstance(at, dt.datetime) else dt.datetime.fromisoformat(str(at))) >= since:
                recent_oom += any(ct.get("exitCode") == 137 for ct in task.get("containers") or [])
    return ok and not recent_oom, f"{detail}; {recent_oom} OOM exit(s) in 3 min"


def fs21_inject(c, t):
    """db_iam_auth_revoked (redesigned 2026-09-26, before any fault ran: Aurora express has no
    passwords to rotate). orders-api's task role loses rds-db:connect; every new login as `app` is
    refused with `PAM authentication failed for user "app"` while the task itself stays healthy."""
    return _iam_ecs_inject(c, t, "fs-21", t.ecs_task_role, "rds-db:connect")


def fs21_revert(c, t):
    return _iam_ecs_revert(c, t, "fs-21")


def fs21_verify(c, t):
    ok, detail = _ecs_steady(c, t)
    healthy, hd = _alb_healthy(c, t)
    tg = _tg(c, t)
    lb = (tg.get("LoadBalancerArns") or [""])[0].split(":loadbalancer/", 1)[-1]
    errors = _cw(c, "AWS/ApplicationELB", "HTTPCode_Target_5XX_Count",
                 {"TargetGroup": tg["TargetGroupArn"].split(":", 5)[-1], "LoadBalancer": lb}, 3) or 0
    return ok and healthy and errors == 0, f"{detail}; {hd}; target 5xx in 3 min={errors:g}"


# fs-22..26 kubernetes ------------------------------------------------------------------------------

def _dep(c, t, name) -> dict:
    return _to_dict(c.apps.read_namespaced_deployment(name=name, namespace=t.namespace))


def _cidx(dep: dict, name: str) -> int:
    containers = dep["spec"]["template"]["spec"]["containers"]
    return next((i for i, ct in enumerate(containers) if ct.get("name") == name), 0)


def _restart(c, t, name) -> None:
    c.apps.patch_namespaced_deployment(name=name, namespace=t.namespace, body={"spec": {"template": {
        "metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": _now().isoformat()}}}}})


# Argo CD marks what it syncs (v3 tracks by annotation; the label is the older method). A direct change to such an
# object is undone by its self-heal within seconds, so a fault injected that way would heal itself before WARDEN saw
# it - and the run would prove nothing. Such a fault is a commit to manifests/ instead (owner decision pending,
# 2026-10-16); until then it is refused, said plainly.
_ARGO_MARKS = ("argocd.argoproj.io/tracking-id", "argocd.argoproj.io/instance")


def _not_argo_managed(obj: dict, what: str) -> None:
    meta = obj.get("metadata") or {}
    if any(k in (meta.get("annotations") or {}) or k in (meta.get("labels") or {}) for k in _ARGO_MARKS):
        raise OpError(f"{what} is synced by Argo CD, whose self-heal undoes a direct change within seconds: this fault "
                      "is injected as a commit to manifests/, not as a patch on the cluster")


def _jp(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def fs22_inject(c, t):
    _guard(c, t, "k8s", t.namespace)
    cm = _to_dict(c.core.read_namespaced_config_map(name=t.configmap, namespace=t.namespace))
    _not_argo_managed(cm, f"configmap/{t.configmap}")
    data = dict(cm.get("data") or {})
    _save(t, "fs-22", {"data": data})
    c.core.patch_namespaced_config_map(name=t.configmap, namespace=t.namespace, body=[
        {"op": "replace", "path": "/data", "value": {**data, t.config_key: "not-a-number"}}])
    _restart(c, t, t.catalog)
    return {"configmap": t.configmap, "key": t.config_key}


def fs22_revert(c, t):
    s = t.saved.get("fs-22")
    if not s:
        return {"nothing_saved": True}
    c.core.patch_namespaced_config_map(name=t.configmap, namespace=t.namespace,
                                       body=[{"op": "replace", "path": "/data", "value": s["data"]}])
    _restart(c, t, t.catalog)
    _done(t, "fs-22")
    return {"configmap": "restored verbatim"}


def _secret_key_refs(dep: dict, secret: str) -> list[str]:
    keys = []
    for ct in dep["spec"]["template"]["spec"]["containers"]:
        for env in ct.get("env") or []:
            ref = ((env.get("valueFrom") or {}).get("secretKeyRef") or {})
            if ref.get("name") == secret:
                keys.append(ref["key"])
    return keys


def fs23_inject(c, t):
    _guard(c, t, "k8s", t.namespace)
    keys = _secret_key_refs(_dep(c, t, t.catalog), t.k8s_secret)
    data = dict(_to_dict(c.core.read_namespaced_secret(name=t.k8s_secret, namespace=t.namespace))
                .get("data") or {})
    key = next((k for k in keys if k in data), None)
    if key is None:
        raise OpError(f"{t.catalog} references no key of {t.k8s_secret} that exists")
    _save(t, "fs-23", {"data": data})
    c.core.patch_namespaced_secret(name=t.k8s_secret, namespace=t.namespace,
                                   body=[{"op": "remove", "path": f"/data/{_jp(key)}"}])
    _restart(c, t, t.catalog)
    return {"secret": t.k8s_secret, "removed_key": key}


def fs23_revert(c, t):
    s = t.saved.get("fs-23")
    if not s:
        return {"nothing_saved": True}
    c.core.patch_namespaced_secret(name=t.k8s_secret, namespace=t.namespace,
                                   body=[{"op": "replace", "path": "/data", "value": s["data"]}])
    _restart(c, t, t.catalog)
    _done(t, "fs-23")
    return {"secret": "restored verbatim"}


def _patch_container_field(c, t, fid: str, dep_name: str, key: str, new_value: Any) -> dict:
    """JSON-patch one container field, saving the exact prior value (None = it was absent)."""
    _guard(c, t, "k8s", t.namespace)
    dep = _dep(c, t, dep_name)
    _not_argo_managed(dep, f"deployment/{dep_name}")
    i = _cidx(dep, dep_name)
    prior = dep["spec"]["template"]["spec"]["containers"][i].get(key)
    _save(t, fid, {"deployment": dep_name, "key": key, "value": copy.deepcopy(prior)})
    op = "replace" if prior is not None else "add"
    c.apps.patch_namespaced_deployment(name=dep_name, namespace=t.namespace, body=[
        {"op": op, "path": f"/spec/template/spec/containers/{i}/{key}", "value": new_value}])
    return {"deployment": dep_name, "field": key}


def _restore_container_field(c, t, fid: str) -> dict:
    s = t.saved.get(fid)
    if not s:
        return {"nothing_saved": True}
    dep = _dep(c, t, s["deployment"])
    i = _cidx(dep, s["deployment"])
    path = f"/spec/template/spec/containers/{i}/{s['key']}"
    present = s["key"] in dep["spec"]["template"]["spec"]["containers"][i]
    if s["value"] is None:
        body = [{"op": "remove", "path": path}] if present else []
    else:
        body = [{"op": "replace" if present else "add", "path": path, "value": s["value"]}]
    if body:
        c.apps.patch_namespaced_deployment(name=s["deployment"], namespace=t.namespace, body=body)
    _done(t, fid)
    return {"deployment": s["deployment"], "field": s["key"], "restored": True}


def fs24_inject(c, t):
    probe = _dep(c, t, t.catalog)["spec"]["template"]["spec"]["containers"][
        _cidx(_dep(c, t, t.catalog), t.catalog)].get("readinessProbe")
    if not probe:
        raise OpError(f"{t.catalog} has no readinessProbe to break")
    wrong = copy.deepcopy(probe)
    handler = wrong.get("httpGet") or wrong.get("tcpSocket")
    if handler is None:
        raise OpError("the readinessProbe is neither httpGet nor tcpSocket")
    handler["port"] = 9999
    return _patch_container_field(c, t, "fs-24", t.catalog, "readinessProbe", wrong)


def fs25_inject(c, t):
    return _patch_container_field(c, t, "fs-25", t.cart_worker, "resources",
                                  {"requests": {"cpu": "8"}, "limits": {"cpu": "8"}})


def fs26_inject(c, t):
    dep = _dep(c, t, t.catalog)
    image = dep["spec"]["template"]["spec"]["containers"][_cidx(dep, t.catalog)]["image"]
    return _patch_container_field(c, t, "fs-26", t.catalog, "image",
                                  image.rsplit(":", 1)[0] + ":does-not-exist-" + secrets.token_hex(3))


def _dep_ready(c, t, name) -> tuple[bool, str]:
    dep = _dep(c, t, name)
    want = int(t.k8s_replicas.get(name, (dep.get("spec") or {}).get("replicas") or 1))
    st = dep.get("status") or {}
    ready, updated = int(st.get("readyReplicas") or 0), int(st.get("updatedReplicas") or 0)
    unavailable = int(st.get("unavailableReplicas") or 0)
    ok = ready == want and updated == want and not unavailable
    return ok, f"{name}: {ready}/{want} ready, {updated} updated, {unavailable} unavailable"


def catalog_ready(c, t):
    return _dep_ready(c, t, t.catalog)


def cart_worker_ready(c, t):
    return _dep_ready(c, t, t.cart_worker)


# fs-27 eventbridge ---------------------------------------------------------------------------------

def fs27_inject(c, t):
    _guard(c, t, "rule", t.rule)
    state = c.events.describe_rule(Name=t.rule)["State"]
    _save(t, "fs-27", {"state": state})
    c.events.disable_rule(Name=t.rule)
    return {"rule": t.rule, "from": state, "to": "DISABLED"}


def fs27_revert(c, t):
    s = t.saved.get("fs-27")
    if not s:
        return {"nothing_saved": True}
    (c.events.enable_rule if s["state"] == "ENABLED" else c.events.disable_rule)(Name=t.rule)
    _done(t, "fs-27")
    return {"rule": t.rule, "state": s["state"]}


def fs27_verify(c, t):
    state = c.events.describe_rule(Name=t.rule)["State"]
    calls = _cw(c, "AWS/Lambda", "Invocations", {"FunctionName": t.reconciler}, 6) or 0
    return state == "ENABLED" and calls > 0, f"rule {state}, reconciler invocations in 6 min={calls:g}"


# =========================================================================== baseline, per area


def _b_checkout(c, t) -> list[str]:
    p = []
    cfg = c.lam.get_function_configuration(FunctionName=t.checkout, Qualifier=t.alias)
    env = _lambda_env(cfg)
    if cfg.get("Timeout", 0) < 3:
        p.append(f"checkout:{t.alias} timeout is {cfg.get('Timeout')}s")
    if env.get("TABLE_NAME") != t.table:
        p.append(f"checkout:{t.alias} TABLE_NAME is {env.get('TABLE_NAME')!r}")
    for fid in ("fs-01", "fs-02"):
        name, base, _bad = FLAGS[fid]
        if env.get(name) != base:
            p.append(f"checkout:{t.alias} {name}={env.get(name)!r}, baseline {base!r}")
    reserved = c.lam.get_function_concurrency(FunctionName=t.checkout).get("ReservedConcurrentExecutions")
    if reserved == 0:
        p.append("checkout reserved concurrency is 0")
    docs = [c.iam.get_role_policy(RoleName=t.checkout_role, PolicyName=n)["PolicyDocument"]
            for n in c.iam.list_role_policies(RoleName=t.checkout_role).get("PolicyNames") or []]
    if "dynamodb:PutItem" not in json.dumps(docs) and "dynamodb:*" not in json.dumps(docs):
        p.append(f"{t.checkout_role} no longer grants dynamodb:PutItem")
    return p


def _b_processor(c, t) -> list[str]:
    p = []
    env = _lambda_env(_lambda_cfg(c, t.processor))
    # "" is the baseline (the code then uses the metadata secret's host = the cluster endpoint).
    if env.get("DB_HOST") not in ("", t.writer_endpoint):
        p.append(f"processor DB_HOST is {env.get('DB_HOST')!r}, not the cluster writer endpoint")
    state = _orders_esm(c, t).get("State")
    if state != "Enabled":
        p.append(f"orders event source mapping is {state}")
    return p


def _b_queues(c, t) -> list[str]:
    n = _visible(c, t.orders_dlq)
    return [f"{t.orders_dlq} holds {n} message(s)"] if n else []


def _b_sns(c, t) -> list[str]:
    policy = c.sqs.get_queue_attributes(QueueUrl=_queue_url(c, t.notifications_queue),
                                        AttributeNames=["Policy"])["Attributes"].get("Policy") or ""
    return [] if t.topic in policy else [f"{t.notifications_queue} policy no longer names {t.topic}"]


def _b_table(c, t) -> list[str]:
    pt = _table(c, t).get("ProvisionedThroughput") or {}
    got = (pt.get("ReadCapacityUnits"), pt.get("WriteCapacityUnits"))
    return [] if got == (t.table_rcu, t.table_wcu) else [f"{t.table} capacity is {got}"]


def _b_redis(c, t) -> list[str]:
    p = []
    if t.redis_sg_id and not [r for r in _sg(c, t.redis_sg_id).get("IpPermissions") or []
                              if r.get("UserIdGroupPairs")]:
        p.append("the Redis security group has no ingress from the app groups")
    try:
        pct = _redis_pct(c, t)
        if pct >= t.redis_max_pct:
            p.append(f"redis memory at {pct:.0f}%")
    except Exception as exc:  # noqa: BLE001  # a failed check is a problem and never a pass
        p.append(f"redis info failed: {type(exc).__name__}: {exc}")
    return p


def _b_aurora(c, t) -> list[str]:
    p = []
    cluster = _cluster(c, t)
    if cluster.get("Status") != "available":
        p.append(f"aurora cluster is {cluster.get('Status')}")
    if _writer(c, t) != t.writer_instance:
        p.append(f"aurora writer is {_writer(c, t)}, baseline {t.writer_instance}")
    conn = c.sql()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pg_stat_activity WHERE application_name LIKE %s",
                        (HOLD_APP_PREFIX + "%",))
            if int(cur.fetchone()[0]):
                p.append("sessions held by a previous fault are still open")
            cur.execute("SELECT count(*) FROM pg_locks WHERE NOT granted")
            if int(cur.fetchone()[0]):
                p.append("lock waiters are queued")
            cur.execute("SELECT to_regclass(%s)", (t.slow_index,))
            if cur.fetchone()[0] is None:
                p.append(f"index {t.slow_index} is missing")
    finally:
        conn.close()
    name, base, _bad = FLAGS["fs-16"]
    if _lambda_env(_lambda_cfg(c, t.reconciler)).get(name) != base:
        p.append(f"reconciler {name} is not {base!r}")
    return p


def _b_ecs(c, t) -> list[str]:
    ok, detail = _ecs_steady(c, t)
    p = [] if ok else [f"orders-api not steady: {detail}"]
    current = _ecs_service(c, t).get("taskDefinition", "")
    if t.ecs_baseline_td and current.split("/")[-1] != t.ecs_baseline_td.split("/")[-1]:
        p.append(f"orders-api is on {current.split('/')[-1]}, baseline {t.ecs_baseline_td.split('/')[-1]}")
    docs = [c.iam.get_role_policy(RoleName=t.ecs_exec_role, PolicyName=n)["PolicyDocument"]
            for n in c.iam.list_role_policies(RoleName=t.ecs_exec_role).get("PolicyNames") or []]
    if "secretsmanager:GetSecretValue" not in json.dumps(docs):
        p.append(f"{t.ecs_exec_role} no longer grants secretsmanager:GetSecretValue")
    docs = [c.iam.get_role_policy(RoleName=t.ecs_task_role, PolicyName=n)["PolicyDocument"]
            for n in c.iam.list_role_policies(RoleName=t.ecs_task_role).get("PolicyNames") or []]
    if "rds-db:connect" not in json.dumps(docs):
        p.append(f"{t.ecs_task_role} no longer grants rds-db:connect")
    return p


def _b_alb(c, t) -> list[str]:
    p = []
    if _tg(c, t).get("HealthCheckPath") != t.health_path:
        p.append(f"target group health path is {_tg(c, t).get('HealthCheckPath')}")
    ok, detail = _alb_healthy(c, t)
    return p if ok else [*p, f"ALB {detail}"]


def _b_k8s(c, t) -> list[str]:
    p = [d for ok, d in (_dep_ready(c, t, n) for n in t.k8s_replicas) if not ok]
    data = _to_dict(c.core.read_namespaced_config_map(name=t.configmap, namespace=t.namespace)).get("data") or {}
    if data.get(t.config_key) == "not-a-number":
        p.append(f"{t.configmap} still carries the fs-22 value")
    keys = _secret_key_refs(_dep(c, t, t.catalog), t.k8s_secret)
    have = _to_dict(c.core.read_namespaced_secret(name=t.k8s_secret, namespace=t.namespace)).get("data") or {}
    p += [f"{t.k8s_secret} is missing key {k}" for k in keys if k not in have]
    return p


def _b_rule(c, t) -> list[str]:
    state = c.events.describe_rule(Name=t.rule)["State"]
    return [] if state == "ENABLED" else [f"{t.rule} is {state}"]


BASELINES: dict[str, Callable[[Clients, Target], list[str]]] = {
    "checkout": _b_checkout, "processor": _b_processor, "queues": _b_queues, "sns": _b_sns,
    "table": _b_table, "redis": _b_redis, "aurora": _b_aurora, "ecs": _b_ecs, "alb": _b_alb,
    "k8s": _b_k8s, "rule": _b_rule,
}


def check_baseline(c: Clients, t: Target, areas: list[str] | None = None) -> list[str]:
    """Every component at its baseline? Empty list means yes. A failed check is a problem, never
    a pass - an unreadable component is not a healthy one."""
    problems: list[str] = []
    for area in areas or list(BASELINES):
        try:
            problems += BASELINES[area](c, t)
        except Exception as exc:  # noqa: BLE001  # a failed check is a problem and never a pass
            problems.append(f"{area}: cannot check ({type(exc).__name__}: {str(exc)[:160]})")
    return problems


# =========================================================================== the registry


@dataclass(frozen=True)
class Fault:
    inject: Callable[[Clients, Target], dict]
    revert: Callable[[Clients, Target], dict]
    verify: Callable[[Clients, Target], tuple[bool, str]]
    area: str


def _pub_revert(fid):
    return lambda c, t: _lambda_publish_revert(c, t, fid)


def _env_revert(fid):
    return lambda c, t: _lambda_env_revert(c, t, fid)


def _held(fid):
    return (lambda c, t: _inject_held(c, t, fid)), (lambda c, t: _revert_held(c, t, fid))


def _field_revert(fid):
    return lambda c, t: _restore_container_field(c, t, fid)


def _ecs_revert(fid):
    return lambda c, t: _ecs_restore(c, t, fid)


def _baseline_verify(area):
    def verify(c, t):
        problems = check_baseline(c, t, [area])
        return not problems, "; ".join(problems) or f"{area} at baseline"
    return verify


FAULTS: dict[str, Fault] = {
    "fs-00": Fault(_noop, _noop, lambda c, t: (not (p := check_baseline(c, t)), "; ".join(p) or "baseline"), "rule"),
    "fs-01": Fault(fs01_inject, _pub_revert("fs-01"), fs01_verify, "checkout"),
    "fs-02": Fault(fs02_inject, _pub_revert("fs-02"), checkout_clean, "checkout"),
    "fs-03": Fault(fs03_inject, fs03_revert, checkout_clean, "checkout"),
    "fs-04": Fault(fs04_inject, _pub_revert("fs-04"), checkout_clean, "checkout"),
    "fs-05": Fault(fs05_inject, fs05_revert, checkout_clean, "checkout"),
    "fs-06": Fault(fs06_inject, fs06_revert, fs06_verify, "queues"),
    "fs-07": Fault(fs07_inject, fs07_revert, fs07_verify, "processor"),
    "fs-08": Fault(fs08_inject, fs08_revert, fs08_verify, "sns"),
    "fs-09": Fault(fs09_inject, fs09_revert, fs09_verify, "table"),
    "fs-10": Fault(fs10_inject, fs10_revert, fs10_verify, "redis"),
    "fs-11": Fault(fs11_inject, fs11_revert, fs11_verify, "redis"),
    "fs-12": Fault(*_held("fs-12"), fs12_verify, "aurora"),
    "fs-13": Fault(*_held("fs-13"), fs13_verify, "aurora"),
    "fs-14": Fault(fs14_inject, _env_revert("fs-14"), processor_clean, "processor"),
    "fs-15": Fault(fs15_inject, fs15_revert, processor_clean, "aurora"),
    "fs-16": Fault(fs16_inject, fs16_revert, fs16_verify, "aurora"),
    "fs-17": Fault(fs17_inject, _ecs_revert("fs-17"), fs17_verify, "ecs"),
    "fs-18": Fault(fs18_inject, fs18_revert, ecs_steady, "ecs"),
    "fs-19": Fault(fs19_inject, fs19_revert, alb_healthy, "alb"),
    "fs-20": Fault(fs20_inject, _ecs_revert("fs-20"), fs20_verify, "ecs"),
    "fs-21": Fault(fs21_inject, fs21_revert, fs21_verify, "ecs"),
    "fs-22": Fault(fs22_inject, fs22_revert, catalog_ready, "k8s"),
    "fs-23": Fault(fs23_inject, fs23_revert, catalog_ready, "k8s"),
    "fs-24": Fault(fs24_inject, _field_revert("fs-24"), catalog_ready, "k8s"),
    "fs-25": Fault(fs25_inject, _field_revert("fs-25"), cart_worker_ready, "k8s"),
    "fs-26": Fault(fs26_inject, _field_revert("fs-26"), catalog_ready, "k8s"),
    "fs-27": Fault(fs27_inject, fs27_revert, fs27_verify, "rule"),
}


def fault_of(scenario_or_id: Any) -> str:
    """`fs-07-sqs-consumer-disabled` or `fs-07` -> `fs-07`."""
    sid = scenario_or_id["id"] if isinstance(scenario_or_id, dict) else str(scenario_or_id)
    fid = sid[:5]
    if fid not in FAULTS:
        raise OpError(f"unknown Wave 4 fault {sid!r}")
    return fid


def op_fs_inject(clients: Clients, target: Target, *, fault: str, account: str = "", **_: Any) -> dict:
    return FAULTS[fault_of(fault)].inject(clients, target)


def op_fs_revert(clients: Clients, target: Target, *, fault: str, account: str = "", **_: Any) -> dict:
    return FAULTS[fault_of(fault)].revert(clients, target)


# ⛔ The registry a catalog's `op:` names are looked up in (tests/test_scenario_ops.py checks it).
OPS: dict[str, Callable[..., dict]] = {"fs_inject": op_fs_inject, "fs_revert": op_fs_revert}
_VARIANTS: dict[str, dict[str, Any]] = {}


# =========================================================================== running a fix


def decide_fix(verdict: str | None) -> str:
    """The fix outcome of one run, from the gate's verdict alone.

    ⛔ THE HARNESS RUNS NO FIX COMMAND (2026-09-27 security audit). It used to run an approved fix's
    printed commands through an allow-list, with the operator's full environment. The allow-list
    matched banned flags by exact name, and the AWS CLI accepts abbreviations: `--prof admin` ran
    as another profile, and `--regio us-east-1` in another region. A deny-list of flags cannot be
    made complete, so the capability is gone rather than patched. Since 2026-10-16 the report prints
    no command at all (a fix is a catalogue plan for an approver), so there is nothing to count or
    check: an approved fix is recorded as `execution_disabled`. `no_fix_printed` and
    `fix_not_allowed` stay valid outcomes for older run records (score.FIX_OUTCOMES).
    """
    if verdict == "rejected":
        return "blocked_by_gate"
    if verdict != "approved_for_human":
        return "not_approved"
    return "execution_disabled"
