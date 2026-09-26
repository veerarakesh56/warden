"""Who does what next - the follow-up an incident report owes each team, by failure pattern.

The runbook (runbook.py) is the on-call engineer's next ten minutes. This is everything after: what the
developers should look at in the code, what the platform/DevOps team should change so it cannot
recur the same way, what the DBA should check, and what to put in place to catch it earlier.

⛔ DETECTED, NOT DIAGNOSED. Patterns are matched by fixed checks on the evidence - a count in a metric,
a Kubernetes event reason, a line WARDEN itself wrote - never by the model. Each is listed with the
evidence that triggered it, so the reader can check the match before trusting the guidance. The
model's hypothesis is shown separately; when the two disagree, that disagreement is itself worth
reading.

⛔ NO PLACEHOLDERS. Names come from the alert and the evidence. Where the evidence contains a number
the advice needs (a memory limit, an allocation it logged), it is quoted; where it does not, the
advice says how to measure it rather than inventing one.
"""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, field

from .models import Alert, ContextBundle


@dataclass
class Pattern:
    key: str
    title: str
    seen: str                                   # the evidence that triggered it, quoted
    likely_cause: str
    oncall: list[str] = field(default_factory=list)
    developers: list[str] = field(default_factory=list)
    platform: list[str] = field(default_factory=list)
    dba: list[str] = field(default_factory=list)
    prevention: list[str] = field(default_factory=list)
    # The commands that remove this pattern's cause (contract E) - exact, aimed at names from the
    # evidence, never a placeholder. Empty when the evidence cannot aim one; the text then says why.
    fix: list[str] = field(default_factory=list)


def _has(ctx: ContextBundle, *needles: str) -> str | None:
    """The first evidence line containing any needle, trimmed - so the report can quote it."""
    for line in ctx.logs:
        if any(n in line for n in needles):
            return line[:160]
    return None


_MIB = re.compile(r"(\d{2,6})\s?(MiB|MB|Mi|GiB|GB|Gi)\b")


def _peak_mib(ctx: ContextBundle) -> int | None:
    """The largest memory figure the application itself logged, in MiB, if any."""
    best = None
    for line in ctx.logs:
        for num, unit in _MIB.findall(line):
            mib = int(num) * (1024 if unit.startswith("G") else 1)
            best = mib if best is None else max(best, mib)
    return best


def detect(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    m = ctx.metrics
    svc = alert.labels.get("deployment", alert.service)
    # The same namespace the runbook uses: the label, or the $NS its first check sets.
    k = f"kubectl -n {alert.labels['namespace']}" if "namespace" in alert.labels else 'kubectl -n "$NS"'
    # The full stack labels several Deployments: the one to name is the one whose lines show trouble.
    tagged = _k8s_target(alert, next((ln for ln in ctx.logs if ln.startswith("LOG k8s/")
                                      and "ROLLOUT revision" not in ln), None))
    if tagged:
        k, svc = f"kubectl -n {tagged[0]}", tagged[1]
    out: list[Pattern] = []

    oom_line = _has(ctx, "OOMKilled", "OOMKilling")
    if m.get("oom_killed_containers", 0) > 0 or oom_line:
        limit = m.get("memory_limit_mib")
        peak = _peak_mib(ctx)
        seen = oom_line or f"oom_killed_containers = {m.get('oom_killed_containers', 0):.0f}"
        sizing = []
        if limit and peak and peak > limit:
            suggested = int(math.ceil(peak * 1.25 / 128.0) * 128)
            sizing.append(f"The container limit is {limit:.0f} MiB and the application logged {peak} MiB. "
                          f"A limit below what the code allocates can never hold: set it above the peak "
                          f"(e.g. {suggested} MiB = logged peak + 25%, rounded to 128 MiB) or cut the allocation.")
        elif limit:
            sizing.append(f"The container limit is {limit:.0f} MiB. Measure real usage before changing it: "
                          f"{k} top pod -l app={svc} --containers")
        out.append(Pattern(
            "oom", "Containers OOM-killed", seen,
            "The process used more memory than its container limit and the kernel killed it. Either the "
            "limit is below what the workload needs, or the application's memory use grew (a leak, an "
            "unbounded cache, a large request).",
            oncall=[(f"Confirm the kill reason (`Last State: Terminated, Reason: OOMKilled`): "
                    f"{k} describe pods -l app={svc} | grep -B2 -A3 OOMKilled"),
                    "If it started with a deploy, rolling back is the fastest safe mitigation."],
            developers=[("Profile memory at startup and under load; look for unbounded caches, buffers "
                        "sized from input, and objects retained across requests."),
                        "Check what changed in the last release that touches allocation."],
            platform=[*sizing, ("Set memory requests = limits for predictable scheduling, and alert on "
                      "OOMKilled and restart rate, not only on the symptom.")],
            prevention=["Load-test memory to find the real peak before setting limits.",
                        "Add a memory-usage metric per pod so the next report shows usage, not just kills."],
        ))

    crash_line = _has(ctx, "CrashLoopBackOff", "Back-off restarting failed container")
    fatal_line = _has(ctx, "fatal", "FATAL", "panic", "Traceback", "Exception")
    # When containers are being OOM-killed, the back-off IS the OOM kills restarting: listing a
    # separate crash-loop pattern would add advice about configuration errors that does not apply.
    if (m.get("crashloop_containers", 0) > 0 or crash_line) and not any(q.key == "oom" for q in out):
        out.append(Pattern(
            "crashloop", "Containers crash-looping", crash_line or "crashloop_containers > 0",
            "The container starts and exits repeatedly. The exit reason is in the container's own last "
            "log lines" + (f" - here: `{fatal_line}`" if fatal_line else "") + ".",
            oncall=[f"Read the crashed container's output: {k} logs deploy/{svc} --previous --tail=100",
                    "If a deploy preceded it, roll back; a restart alone restarts the same failure.",
                    ("No command: the cause is in the image, its configuration or a dependency, and a rollout "
                     "undo does not restore a ConfigMap or Secret - the crashed output names which to fix.")],
            developers=[("Fix the startup failure the logs name; make startup errors explicit and "
                        "non-zero with a clear message.")],
            platform=[("Validate configuration and secrets at deploy time (a pre-deploy check or init "
                      "container), not at first start in production.")],
            prevention=["A smoke test in the pipeline that starts the container with production-shaped config."],
        ))

    pull_line = _has(ctx, "ErrImagePull", "ImagePullBackOff", "Failed to pull image")
    if pull_line:
        out.append(Pattern(
            "image_pull", "Image cannot be pulled", pull_line,
            "The image reference in the pod spec cannot be pulled: the tag does not exist, the registry "
            "is unreachable, or the node lacks pull credentials.",
            oncall=["Roll back to the previous revision - its image is known to pull.",
                    "Check the exact reference in the event: a typo in the tag is the most common cause."],
            developers=["Deploy immutable digests (image@sha256:...) produced by the build, not hand-typed tags."],
            platform=["Gate deploys on the image existing in the registry (a pipeline check or an admission policy).",
                      "If it is credentials: check the node role / imagePullSecrets, and registry rate limits."],
            prevention=["Alert on ImagePullBackOff events directly - they are unambiguous."],
            fix=_rollout_undo(alert, ctx, pull_line),
        ))

    probe_line = _has(ctx, "Liveness probe failed", "Readiness probe failed", "failed liveness probe")
    if probe_line:
        out.append(Pattern(
            "probe", "Health check failing", probe_line,
            "Kubernetes is killing (liveness) or unrouting (readiness) pods whose health check fails. "
            "Either the application is unhealthy, or the probe is wrong - a bad path or port, a timeout "
            "shorter than the real response time, or no startup grace.",
            oncall=[f"Compare the probe with the app: {k} get deploy/{svc} -o jsonpath='{{.spec.template.spec.containers[*].livenessProbe}}'",
                    "If the probe changed in the last deploy, roll back."],
            developers=["Make the health endpoint cheap and independent of downstream dependencies."],
            platform=["Use a startupProbe for slow starts; set liveness timeouts from measured latency."],
            prevention=["Review probe changes like code changes - a wrong probe takes a healthy service down."],
            fix=_rollout_undo(alert, ctx, probe_line),
        ))

    if "replicas_desired" in m and m["replicas_desired"] == 0:
        out.append(Pattern(
            "scaled_to_zero", "Scaled to zero", "replicas_desired = 0",
            "The Deployment asks for zero replicas - a manual scale, an autoscaler, or an automation "
            "set it. Nothing is failing; nothing is running.",
            oncall=[f"Find who scaled it: {k} get events --field-selector involvedObject.name={svc} | grep -i scal",
                    "Restore the previous count if the scale-down was not intended."],
            platform=[("Protect production workloads from scale-to-zero: an HPA minReplicas, or a "
                      "policy that blocks replicas: 0 in prod.")],
            prevention=["Alert on 'desired replicas = 0' for services that must always run."],
        ))
    elif "pods_total" in m and m.get("pods_ready", m["pods_total"]) < m["pods_total"] and not out:
        out.append(Pattern(
            "unready", "Pods not ready",
            f"pods_ready = {m.get('pods_ready', 0):.0f} of {m['pods_total']:.0f}",
            "Some pods are not passing readiness. The events and the pods' own logs say why.",
            oncall=[f"{k} describe pods -l app={svc} | grep -A5 Events"],
        ))

    stuck_line = _has(ctx, "stuck connection:")
    if stuck_line or m.get("idle_in_transaction", 0) >= 5:
        out.append(Pattern(
            "db_idle_tx", "Sessions stuck idle inside transactions",
            stuck_line or f"idle_in_transaction = {m.get('idle_in_transaction', 0):.0f}",
            "Application code opened a transaction and stopped using it without committing or rolling "
            "back - usually an exception path that skips cleanup, or a slow external call made inside "
            "the transaction. Each one holds a connection and its locks until it is closed.",
            oncall=[("Terminate only the sessions that are idle in a transaction (see the runbook), then "
                    "watch whether they come back - if they do, the leak is still live.")],
            developers=[("Find the code path running the query shown in the evidence; make commit/rollback "
                        "unconditional (context managers / try-finally)."),
                        "Never call external services while holding a transaction open."],
            dba=[("Set idle_in_transaction_session_timeout (the runbook has the statement) so a leak "
                 "costs one connection for minutes, not the pool forever.")],
            prevention=["Alert on idle-in-transaction count and age, not just on pool exhaustion."],
        ))

    blocked_line = _has(ctx, "blocked session:")
    if blocked_line or m.get("locks_waiting", 0) > 0:
        out.append(Pattern(
            "db_lock", "Sessions blocked on a lock",
            blocked_line or f"locks_waiting = {m.get('locks_waiting', 0):.0f}",
            "One session holds a lock others need. If the holder is idle in a transaction, it will never "
            "release it by itself.",
            oncall=[("Identify the blocker (the runbook's blocked-sessions query names it) before "
                    "terminating anything - terminate the BLOCKER, not the waiters.")],
            developers=[("Keep transactions short; take locks in a consistent order; avoid explicit "
                        "table locks in request paths.")],
            dba=["Set lock_timeout for application roles so waiters fail fast instead of piling up."],
            prevention=["Alert on lock wait time and on blocking chains."],
            fix=_terminate_blockers(ctx),
        ))

    long_line = _has(ctx, "long-running query:")
    if long_line or m.get("long_running_queries", 0) > 0:
        out.append(Pattern(
            "db_long_query", "Long-running query",
            long_line or f"long_running_queries = {m.get('long_running_queries', 0):.0f}",
            "A query has been actively running for over a minute. It may be legitimate (a report, a "
            "migration, a backfill) or a runaway (a missing index, a bad plan) - WARDEN cannot tell which.",
            oncall=[("Do NOT terminate it until its owner is known: it is doing work, and terminating "
                    "loses that work. Check who runs it (user, application in the evidence).")],
            developers=[("If it is a runaway: EXPLAIN (ANALYZE, BUFFERS) the query; check for a missing "
                        "index or a changed plan.")],
            dba=[("Set statement_timeout per role so runaway queries end themselves; move reporting "
                 "to a replica.")],
            prevention=["Log slow queries (log_min_duration_statement) so the next incident has the history."],
            fix=_index_for(long_line),
        ))

    used = m.get("connections_used_pct")
    pool_used, pool_size = m.get("connection_pool_used"), m.get("connection_pool_size")
    if (used is not None and used >= 0.7) or (pool_used and pool_size and pool_used >= pool_size * 0.9):
        seen = (f"connections_used_pct = {used:.2f}" if used is not None
                else f"connection pool {pool_used:.0f}/{pool_size:.0f}")
        out.append(Pattern(
            "db_pool", "Connection capacity nearly exhausted", _has(ctx, "connections held:") or seen,
            "Connections are close to the limit. If most are idle (not in a transaction), clients are "
            "holding connections they are not using - pool sizes too large, or connections not returned.",
            oncall=[("Check who holds them (the runbook's pool query groups by application, client, state) "
                    "before raising max_connections or scaling - either can hide a leak.")],
            developers=[("Return connections to the pool promptly; size each service's pool to its real "
                        "concurrency.")],
            dba=["Put a pooler (PgBouncer / RDS Proxy) in front if many services connect directly."],
            platform=[("Scaling the application out multiplies connections - check pool size x replicas "
                      "against max_connections before scaling.")],
            prevention=["Alert at 70% of max_connections, with a per-application breakdown."],
        ))

    if m.get("replica_lag_seconds", 0) >= 30:
        out.append(Pattern(
            "replica_lag", "Replica lagging", f"replica_lag_seconds = {m['replica_lag_seconds']:.0f}",
            "The replica is behind the primary: heavy write load, long queries on the replica blocking "
            "replay, or an undersized replica.",
            oncall=["Stop routing reads that need fresh data to the replica until it catches up."],
            dba=[("Check for long queries on the replica (they can pause replay); compare replica and "
                 "primary instance sizes.")],
            prevention=["Alert on lag before it reaches the application's staleness budget."],
        ))

    if ctx.tool_errors and not m:
        out.append(Pattern(
            "evidence_unreachable", "WARDEN could not read the system", ctx.tool_errors[0][:160],
            "Every read failed, so nothing here is known about the service itself. A network change "
            "(security group, network policy), revoked credentials or the system being down all look "
            "like this.",
            oncall=[("Check reachability from where WARDEN runs, then the service itself directly - "
                    "the incident may be the outage WARDEN could not see.")],
            platform=["Check recent security-group / network-policy / IAM changes for this path."],
            prevention=["Monitor the monitoring: alert when an evidence source stops answering."],
        ))

    out += _stack(alert, ctx)

    # A secret changing is not a code deploy (contract D): rolling it back is not the fix.
    code_deploys = [d for d in ctx.recent_deploys if d.get("kind") != "secret"]
    if code_deploys and (out or _has(ctx, "ERROR", "error", " 500 ", "Exception")):
        d = code_deploys[0]
        what = (d.get("sha") or d.get("image") or d.get("task_definition") or d.get("revision")
                or d.get("version"))
        out.append(Pattern(
            "deploy", "A deploy preceded the failure", f"deploy -> {what} at {d.get('at', '?')}",
            "A change shipped shortly before the symptoms. Correlation is not cause - but it is the "
            "cheapest hypothesis to test, because rolling back is reversible.",
            oncall=["Compare the timeline: did the first error follow the deploy?"],
            developers=[f"Diff the release ({what}) against the previous one for the failing code path."],
            prevention=[("Progressive delivery (canary / automatic rollback on error rate) so a bad deploy "
                        "reaches a fraction of traffic.")],
        ))

    er = m.get("error_rate")
    if er is not None and er >= 0.02 and not any(p.key == "deploy" for p in out):
        out.append(Pattern(
            "errors", "Elevated error rate", f"error_rate = {er:.3f}",
            "Requests are failing. The key log lines name the failing code path; the timeline shows "
            "whether anything changed first.",
            oncall=["Find the first error in the timeline and what preceded it."],
            developers=["Start from the exception in the key log lines."],
        ))
    return out


# --------------------------------------------------------------------------- the full stack (Wave 4)
#
# Built against docs/WAVE4-CONTRACT.md: the tagged lines of section C (LOG/CONFIG/ESM/CODE/SOURCE/
# QUEUE/POLICY/TABLE/EVENT/CLUSTER/TARGET/TARGETGROUP/SECRET/RULE), the metrics of section B (with the
# `__<short>` suffix when several resources of a kind are labelled) and the deploy records of D.
# Every `fix` command is aimed at a name taken from those lines or the alert's labels; a value it
# needs (a version, a timeout, a capacity) is computed from the evidence and the computation is said
# in the text. When the evidence cannot aim a command, none is printed and the text says what is
# missing.

# WARDEN's own structured lines (contract C) - facts about configuration, not application output.
_STRUCTURED = ("CONFIG ", "ESM ", "CODE ", "SOURCE ", "QUEUE ", "POLICY ", "TABLE ", "CLUSTER ", "TARGET",
               "RULE ", "SECRET ", "EVENT elasticache ", "EVENT aurora ", "TOOL-PARTIAL ",
               "REPLGROUP ", "SG ", "APPSG ", "TASKROLE ")


def _sg_list(text: str) -> list[str]:
    return [g for g in text.strip("[]").split(",") if g.startswith("sg-")]


def _missing_cache_ingress(ctx: ContextBundle) -> tuple[str, str, list[str]] | None:
    """(cache SG, port, app SGs with no ingress to it) from REPLGROUP / SG / APPSG / CONFIG sgs lines.

    None when the evidence does not carry the network path. The application SGs are every security
    group an application component in this service map runs in (in-VPC Lambdas, the ECS service,
    the EKS cluster) - the ones that must reach the cache.
    """
    rg = next((ln for ln in ctx.logs if ln.startswith("REPLGROUP ")), None)
    m = re.search(r"sgs=(\[[^\]]*\])", rg or "")
    cache_sgs = _sg_list(m.group(1)) if m else []
    if not cache_sgs:
        return None
    allowed: set[str] = set()
    port = ""
    for ln in ctx.logs:
        mt = re.match(r"SG (sg-\S+) ingress tcp/(\d+) from=(\[[^\]]*\])", ln)
        if mt and mt.group(1) in cache_sgs:
            port = mt.group(2)
            allowed |= set(_sg_list(mt.group(3)))
    apps: list[str] = []
    for ln in ctx.logs:
        mt = (re.match(r"APPSG \S+ sgs=(\[[^\]]*\])", ln)
              or (re.search(r" sgs=(\[[^\]]*\])", ln) if ln.startswith("CONFIG lambda ") else None))
        for g in _sg_list(mt.group(1)) if mt else []:
            if g not in apps and g not in cache_sgs:
                apps.append(g)
    if not port or not apps:
        return None
    return cache_sgs[0], port, [g for g in apps if g not in allowed]


def region() -> str:
    """The region WARDEN read (the harness gives AWS_REGION, contract A) - never a guessed default."""
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or ""


def regioned(cmd: str) -> str:
    """Put `--region` on every aws invocation in `cmd`, nested ones included. No region known: unchanged."""
    r = region()
    if not r or "--region" in cmd:
        return cmd
    start = cmd.find("$(aws ")
    while start != -1:   # each nested `$(aws ...)`: the region goes before its closing parenthesis
        depth, end = 0, start + 1
        for end in range(start + 1, len(cmd)):
            depth += {"(": 1, ")": -1}.get(cmd[end], 0)
            if depth == 0:
                break
        cmd = f"{cmd[:end]} --region {r}{cmd[end:]}"
        start = cmd.find("$(aws ", end)
    if cmd.startswith("aws "):
        body, sep, comment = cmd.partition("   #")
        cmd = f"{body} --region {r}{sep}{comment}"
    return cmd


def _kv(line: str) -> dict[str, str]:
    return dict(re.findall(r"(\w+)=(\[[^\]]*\]|\S+)", line))


def _first(ctx: ContextBundle, prefix: str, *needles: str) -> str | None:
    return next((ln for ln in ctx.logs if ln.startswith(prefix) and all(n in ln for n in needles)), None)


def _source_of(line: str) -> tuple[str, str] | None:
    """('lambda', fn) / ('ecs', svc) / ('k8s', 'ns/dep') from a `LOG <kind>/<name>` tag, or a CODE line."""
    mt = re.match(r"LOG (lambda|ecs|k8s)/(\S+)", line)
    if mt:
        return mt.group(1), mt.group(2)
    mt = re.match(r"CODE (\S+) ", line)
    return ("lambda", mt.group(1)) if mt else None


def _per(m: dict[str, float], base: str) -> list[tuple[str | None, float]]:
    """(short name or None, value) for `base` and every `base__<short>` metric (contract B suffix rule)."""
    return [(k.split("__", 1)[1] if "__" in k else None, v) for k, v in m.items()
            if k == base or k.startswith(base + "__")]


def _named(alert: Alert, label: str, short: str | None) -> str | None:
    """The labelled resource a metric suffix names; with no suffix, the one labelled resource."""
    names = [n.strip() for n in alert.labels.get(label, "").split(",") if n.strip()]
    if short is None:
        return names[0] if len(names) == 1 else None
    return next((n for n in names if n == short or n.endswith("-" + short)), None)


def _metric(m: dict[str, float], base: str, alert: Alert, label: str, name: str) -> float | None:
    for short, v in _per(m, base):
        if _named(alert, label, short) == name:
            return v
    return None


def _config(ctx: ContextBundle, fn: str) -> dict[str, str]:
    line = _first(ctx, f"CONFIG lambda {fn} ")
    return _kv(line) if line else {}


def _env(cfg: dict[str, str]) -> tuple[list[str], dict[str, str] | None]:
    """(env var names, {name: value} when the CONFIG line carries every value, else None)."""
    items = [i.strip() for i in cfg.get("env", "[]").strip("[]").split(",") if i.strip()]
    names = [i.split("=", 1)[0] for i in items]
    values = dict(i.split("=", 1) for i in items) if items and all("=" in i for i in items) else None
    return names, values


def _deploy(ctx: ContextBundle, kind: str, service: str | None = None) -> dict | None:
    return next((d for d in ctx.recent_deploys
                 if d.get("kind") == kind and (service is None or d.get("service") == service)), None)


def _alias(cfg: dict[str, str]) -> str | None:
    # `alias_live=-` is how the stack backend says the function has no such alias.
    return next((k[len("alias_"):] for k, v in cfg.items() if k.startswith("alias_") and v != "-"), None)


def _alias_rollback(ctx: ContextBundle, fn: str) -> tuple[list[str], str]:
    """update-alias back to the version the alias left, from the deploy record (contract D)."""
    d = _deploy(ctx, "lambda", fn)
    alias = _alias(_config(ctx, fn)) or (d or {}).get("alias")
    prev = str((d or {}).get("previous", ""))
    if d and alias and prev.isdigit():
        return ([regioned(f"aws lambda update-alias --function-name {fn} --name {alias} --function-version {prev}")],
                (f"Alias `{alias}` of {fn} moved to version {d.get('version', '?')} at {d.get('at', '?')}; "
                f"the fix points it back at version {prev}, the version it served before."))
    return [], (f"No command: WARDEN saw no alias move with a previous version for {fn} (deploy record "
                "and CONFIG alias), so there is no known-good version to point at.")


def _lambda_config_fix(ctx: ContextBundle, fn: str, args: str) -> tuple[list[str], str]:
    """A configuration change on a Lambda. When the alias moved in the window, the change came with a
    published version: pointing the alias back restores that version's configuration AND code, and
    avoids publishing $LATEST, whose code may not be what the alias served."""
    cmds, why = _alias_rollback(ctx, fn)
    if cmds:
        return cmds, why
    cfg = _config(ctx, fn)
    alias = _alias(cfg)
    pinned = cfg.get(f"alias_{alias}", "") if alias else ""
    note = (f"Alias `{alias}` points at version {pinned}, a published version: this changes $LATEST only. "
            f"Publish and move `{alias}` once $LATEST's code is confirmed to be what version {pinned} runs."
            if pinned.isdigit() else "")
    return [regioned(f"aws lambda update-function-configuration --function-name {fn} {args}")], note


def _grant(line: str) -> tuple[list[str], str]:
    """put-role-policy granting exactly the action an AccessDenied line names, on the resource it names."""
    action = re.search(r"not authorized to perform:? ([a-z0-9-]+:[A-Za-z0-9*]+)", line)
    role = re.search(r"assumed-role/([\w+=,.@-]+)/", line)
    res = re.search(r"on resource:? (arn:aws:[^\s\"']+)", line)
    if not (action and role and res):
        missing = [n for n, v in (("the action", action), ("the role", role), ("the resource", res)) if not v]
        return [], f"No command: the denial line does not name {', '.join(missing)}."
    # The account id is masked in every report, so the resource is written with `*` for it.
    resource = re.sub(r"^(arn:aws:[a-z0-9-]*:[a-z0-9-]*:)\d{12}:", r"\1*:", res.group(1))
    if action.group(1).startswith("secretsmanager:"):
        resource = re.sub(r"-[A-Za-z0-9]{6}$", "-*", resource)   # Secrets Manager's random ARN suffix
    doc = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": action.group(1), "Resource": resource}]}, separators=(",", ":"))
    # ⚠ The report's redaction masks the text after `secret:` / `secretsmanager:` (it looks like a
    # credential), and then every other occurrence of that text (its literal sweep) - so the action
    # name too. The colons and the name's first letter are written as JSON escapes (backslash-u);
    # IAM parses the document to exactly the same action and resource.
    svc, _, verb = action.group(1).partition(":")
    if svc == "secretsmanager":
        doc = doc.replace(f'"{action.group(1)}"', f'"secretsmanager\\u003a\\u{ord(verb[0]):04x}{verb[1:]}"')
        doc = doc.replace("secretsmanager:", "secretsmanager\\u003a").replace(":secret:", "\\u003asecret\\u003a")
    name = "warden-restore-" + re.sub(r"[^A-Za-z0-9]+", "-", action.group(1)).lower()
    return ([regioned(f"aws iam put-role-policy --role-name {role.group(1)} --policy-name {name} "
                      f"--policy-document '{doc}'")],
            f"Grants {action.group(1)} on {resource} to role {role.group(1)} - exactly what the denial names.")


def db_iam_grant(ctx: ContextBundle, line: str) -> tuple[list[str], str]:
    """put-role-policy giving back rds-db:connect for the refused database user, to the role that
    signs the workload's tokens - only when the evidence NAMES that role (a TASKROLE line)."""
    user = re.search(r'PAM authentication failed for user "?([A-Za-z0-9_]+)', line)
    src = _source_of(line)
    tline = _first(ctx, f"TASKROLE ecs/{src[1]} ") if src and src[0] == "ecs" else None
    role = _kv(tline).get("role") if tline else None
    if not (user and role):
        needed = ([] if user else ["the refused user in the PAM line"]) + ([] if role else [
            "a `TASKROLE ecs/<service> role=<name>` line for the failing ECS service" if src and src[0] == "ecs"
            else "the identity that signs the tokens (WARDEN names it only for an ECS service, from its "
                 "task definition: a `TASKROLE ecs/<service> role=<name>` line)"])
        return [], f"No command: the evidence does not carry {' and '.join(needed)}."
    # The cluster's resource id (the ARN's middle) and the account are masked in reports: `*`.
    resource = f"arn:aws:rds-db:{region() or '*'}:*:dbuser:*/{user.group(1)}"
    doc = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "rds-db:connect", "Resource": resource}]}, separators=(",", ":"))
    return ([regioned(f"aws iam put-role-policy --role-name {role} --policy-name warden-restore-rds-db-connect "
                      f"--policy-document '{doc}'")],
            (f"Grants rds-db:connect as database user {user.group(1)} to {role}, the task role of {src[1]} "
             "(its TASKROLE line) - the identity that signs its database tokens. New connections succeed at "
             "once; nothing needs a restart."))


def _k8s_target(alert: Alert, line: str | None) -> tuple[str, str] | None:
    src = _source_of(line or "")
    if src and src[0] == "k8s" and "/" in src[1]:
        ns, dep = src[1].split("/", 1)
        return ns, dep
    deps = [d.strip() for d in alert.labels.get("deployment", "").split(",") if d.strip()]
    if "namespace" in alert.labels and len(deps) == 1:
        return alert.labels["namespace"], deps[0]
    return None


def _rollout_undo(alert: Alert, ctx: ContextBundle, line: str | None) -> list[str]:
    """`rollout undo` when WARDEN read a current revision AND an earlier one for that Deployment:
    the failure is in the pod template (image, probe, requests), and the previous template ran."""
    target = _k8s_target(alert, line)
    if not target:
        return []
    ns, dep = target
    tag = f"LOG k8s/{ns}/{dep} "
    revs = [ln for ln in ctx.logs if "ROLLOUT revision" in ln and (ln.startswith(tag) or not ln.startswith("LOG "))]
    if not any("(current)" in r for r in revs) or len(revs) < 2:
        return []
    # ⛔ Only while the CURRENT revision is failing. Wave 4's healthy control (2026-09-26) had 2/2
    # pods Ready, matched start-up readiness failures, and printed this undo - which rolled
    # catalog-api back onto the previous revision: a broken image from an earlier fault.
    m = ctx.metrics
    ready = m.get(f"pods_ready__{dep}", m.get("pods_ready"))
    total = m.get(f"pods_total__{dep}", m.get("pods_total"))
    if ready is not None and total and ready >= total:
        return []
    return [f"kubectl -n {ns} rollout undo deploy/{dep}"]


def _terminate_blockers(ctx: ContextBundle) -> list[str]:
    blockers: set[int] = set()
    for ln in ctx.logs:
        mt = re.search(r"blocked session:.* on pid\(s\) ([\d,]+)", ln)
        if mt:
            blockers.update(int(p) for p in mt.group(1).split(",") if p)
    if not blockers:
        return []
    return [("SELECT b.pid, pg_terminate_backend(b.pid) FROM pg_stat_activity b "
             f"WHERE b.pid IN ({', '.join(map(str, sorted(blockers)))}) "
             "AND b.pid IN (SELECT unnest(pg_blocking_pids(w.pid)) FROM pg_stat_activity w);"
             "   -- the blocker(s) named in the evidence, only while still blocking someone")]


_SCAN = re.compile(r"(?i)\bFROM\s+([A-Za-z_][\w.]*)(?:\s+(?:AS\s+)?(?!WHERE\b)[A-Za-z_]\w*)?\s+WHERE\s+"
                   r"(?:[A-Za-z_]\w*\.)?([A-Za-z_]\w*)\s*(?:=|<|>|\bIN\b|\bLIKE\b|\bBETWEEN\b)")


def _index_for(long_line: str | None) -> list[str]:
    """CREATE INDEX CONCURRENTLY on the column the long query filters by - only when its text shows it."""
    mt = _SCAN.search((long_line or "").split(": ", 2)[-1])
    if not mt:
        return []
    table, col = mt.group(1), mt.group(2)
    name = f"warden_{table.replace('.', '_')}_{col}_idx"[:63]
    return [f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {table} ({col});"]


def _queue_url(name: str) -> str:
    # The URL carries the account id, which every report masks: looked up at run time instead.
    return f'"$(aws sqs get-queue-url --queue-name {name} --query QueueUrl --output text)"'


def _next_node_type(node_type: str) -> str | None:
    ladder = ["micro", "small", "medium", "large", "xlarge", "2xlarge", "4xlarge"]
    mt = re.fullmatch(r"(cache\.[a-z0-9]+)\.([0-9a-z]+)", node_type)
    if not mt or mt.group(2) not in ladder[:-1]:
        return None
    return f"{mt.group(1)}.{ladder[ladder.index(mt.group(2)) + 1]}"


def _writer_host(host: str, cluster: str, instances: list[str]) -> str | None:
    """The cluster (writer) endpoint for a reader or instance endpoint, by Aurora's naming scheme."""
    if ".cluster-ro-" in host:
        return host.replace(".cluster-ro-", ".cluster-", 1)
    head, _, rest = host.partition(".")
    if head in instances and cluster and rest:
        return f"{cluster}.cluster-{rest}"
    return None


def _db_host_fix(ctx: ContextBundle, fn: str, cluster: str, instances: list[str]) -> tuple[list[str], str]:
    names, values = _env(_config(ctx, fn))
    if values is None:
        return [], (f"No command: the CONFIG line for {fn} names its environment variables "
                    f"({', '.join(names) or 'none'}) but not their values, and update-function-configuration "
                    "replaces the WHOLE environment - printing it without every value would wipe the others.")
    for var, val in values.items():
        new = _writer_host(val, cluster, instances) if ".rds.amazonaws.com" in val else None
        if new:
            env = json.dumps({"Variables": {**values, var: new}}, separators=(",", ":"))
            cmds, note = _lambda_config_fix(ctx, fn, f"--environment '{env}'")
            return cmds, f"{var} is `{val}`; the fix points it at the cluster writer endpoint `{new}`. {note}".strip()
    return [], f"No command: no environment variable of {fn} holds a reader or instance endpoint of {cluster}."


def lambda_concurrency(alert: Alert, ctx: ContextBundle, fn: str) -> tuple[list[str], str, list[str]]:
    """(fix, why, undo) raising `fn`'s reserved concurrency to what the evidence says the demand needs."""
    from .aws_backend import METRIC_WINDOW  # lazy: keeps boto3 out of the playbook's import

    m, window_s = ctx.metrics, METRIC_WINDOW.total_seconds()
    reserved = _metric(m, "lambda_reserved_concurrency", alert, "lambda", fn)
    if reserved is None:
        return [], (f"No command: {fn} has no reserved concurrency, so any throttling is the account's regional "
                    "concurrency limit - a quota increase or lower concurrency elsewhere, not a function setting."), []
    thr = _metric(m, "lambda_throttles", alert, "lambda", fn) or 0.0
    inv = _metric(m, "lambda_invocations", alert, "lambda", fn) or 0.0
    timeout = _metric(m, "lambda_timeout_s", alert, "lambda", fn)
    if not timeout:
        return [], f"No command: {fn}'s timeout is not in the evidence, so the concurrency it needs cannot be computed.", []
    new = max(math.ceil(2 * (inv + thr) / window_s * timeout), 2, int(reserved) * 2)
    put = "aws lambda put-function-concurrency --function-name {} --reserved-concurrent-executions {}"
    return ([regioned(put.format(fn, new))],
            (f"Reserved concurrency is {reserved:.0f}. {new} = max(2, 2 x current, 2 x the concurrency the demand "
             f"needs: ({inv:.0f} invocations + {thr:.0f} throttles) / {window_s:.0f}s x {timeout:.0f}s timeout, the "
             "longest a call can take). The account keeps 10 unreserved: if AWS refuses the value, lower other "
             "functions' reservations."),
            [regioned(put.format(fn, int(reserved)))])


def _ddb_throttles(m: dict[str, float]) -> dict[str, float]:
    return {b: sum(v for _, v in _per(m, b)) for b in
            ("ddb_write_throttle_events", "ddb_read_throttle_events", "ddb_throttled_requests")}


def ddb_capacity(ctx: ContextBundle) -> tuple[list[str], str, list[str]]:
    """(fix, why, undo) for the TABLE line's provisioned throughput, sized from consumed + throttled."""
    from .aws_backend import METRIC_WINDOW  # lazy: keeps boto3 out of the playbook's import

    m, window_s = ctx.metrics, METRIC_WINDOW.total_seconds()
    tline = _first(ctx, "TABLE ")
    tk = _kv(tline) if tline else {}
    if tk.get("billing") != "PROVISIONED" or not (tk.get("rcu", "").isdigit() and tk.get("wcu", "").isdigit()):
        return [], (f"No command: the table bills {tk['billing']}, so there is no provisioned throughput to raise."
                    if tk.get("billing") and tk["billing"] != "PROVISIONED" else
                    "No command: no TABLE line gives the table's billing mode and provisioned capacity."), []
    table, rcu, wcu = tline.split()[1], int(tk["rcu"]), int(tk["wcu"])
    thr = _ddb_throttles(m)

    def need(cur: int, consumed: float | None, events: float) -> int:
        if events <= 0:
            return cur
        return max(math.ceil(((consumed if consumed is not None else cur) + events / window_s) * 2), cur * 2)

    reads = thr["ddb_read_throttle_events"]
    writes = thr["ddb_write_throttle_events"] or (thr["ddb_throttled_requests"] if not reads else 0)
    new_r, new_w = need(rcu, m.get("ddb_consumed_rcu"), reads), need(wcu, m.get("ddb_consumed_wcu"), writes)
    if (new_r, new_w) == (rcu, wcu):
        new_r, new_w = rcu * 2, wcu * 2   # scale_up asked with no throttling measured: one doubling
    upd = "aws dynamodb update-table --table-name {} --provisioned-throughput ReadCapacityUnits={},WriteCapacityUnits={}"
    return ([regioned(upd.format(table, new_r, new_w))],
            (f"Provisioned {rcu} RCU / {wcu} WCU. New = max(2 x current, 2 x demand), demand = consumed units/s "
             f"+ throttle events / {window_s:.0f}s: {new_r} RCU / {new_w} WCU. Decreases are limited per day - "
             "raise with care."),
            [regioned(upd.format(table, rcu, wcu))])


def _fn_of(alert: Alert, line: str) -> str | None:
    src = _source_of(line)
    return src[1] if src and src[0] == "lambda" else _named(alert, "lambda", None)


def _stack(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    m, L = ctx.metrics, alert.labels
    out: list[Pattern] = []

    def add(key, title, seen, cause, fix=(), why="", **teams):
        oncall = list(teams.pop("oncall", []))
        if why:
            oncall.insert(0, why)
        out.append(Pattern(key, title, seen[:200], cause, oncall=oncall, fix=list(fix), **teams))

    # ---- Lambda: code regression - a traceback frame in code that shipped in the window.
    infra = ("ResourceNotFoundException", "AccessDenied", "read-only transaction", "password authentication",
             "PAM authentication failed", "too many clients", "Timeout", "timed out")
    for code in (ln for ln in ctx.logs if ln.startswith("CODE ")):
        mt = re.match(r"CODE (\S+) (\S+):(\d+) in (\S+): (.*)", code)
        if not mt or any(i in code for i in infra) or not _deploy(ctx, "lambda", mt.group(1)):
            continue
        fn, path, lineno, func, exc = mt.groups()
        failing = next((ln.split(">|", 1)[1].strip() for ln in ctx.logs
                        if ln.startswith(f"SOURCE {fn} {path}:{lineno} ") and ">|" in ln), "")
        cmds, why = _alias_rollback(ctx, fn)
        add("code_error_after_deploy", f"Code regression in {fn}", code,
            f"{fn} raises {exc} at {path}:{lineno} in {func}, in the version shipped in the window.",
            cmds, why,
            developers=[f"Fix {path}:{lineno} in {func} ({fn}): {exc}"
                        + (f" - the failing line is `{failing}`." if failing else "."),
                        "Add a test with the real payload shape that reached this line."],
            platform=["Canary the alias (weighted routing) with automatic rollback on the Errors metric."],
            prevention=["Contract-test the API payload so a field the code needs cannot go missing silently."])

    # ---- Lambda: timeout too low
    t_line = _has(ctx, "Task timed out after")
    if t_line:
        fn = _fn_of(alert, t_line)
        timeout = _metric(m, "lambda_timeout_s", alert, "lambda", fn) if fn else None
        cfg_t = re.match(r"(\d+)", _config(ctx, fn).get("timeout", "")) if fn else None
        timeout = timeout or (float(cfg_t.group(1)) if cfg_t else None)
        dur = _metric(m, "lambda_duration_max_ms", alert, "lambda", fn) if fn else None
        cmds, why = [], "No command: the function or its current timeout is not in the evidence."
        if fn and timeout:
            capped = dur is None or dur >= timeout * 1000 * 0.95
            new = math.ceil(timeout * 3) if capped else math.ceil(dur * 2 / 1000)
            new = min(max(new, int(timeout) + 1), 900)
            basis = (f"every invocation hit the {timeout:.0f}s limit, so the real duration is unknown: "
                     f"{new}s = 3 x the current timeout" if capped else
                     f"{new}s = 2 x the longest observed duration ({dur:.0f} ms), rounded up")
            cmds, note = _lambda_config_fix(ctx, fn, f"--timeout {new}")
            why = f"New timeout {basis}. {note}".strip() if "--timeout" in " ".join(cmds) else note
        add("fn_timeout", "Lambda timing out", t_line,
            "The function runs longer than its configured timeout: the timeout is below what the code path "
            "needs, or a dependency slowed down.", cmds, why,
            developers=["Find the slow call (a dependency inside the handler) and give it its own shorter timeout."],
            platform=["Set the timeout from measured p99 duration with headroom, below the API's integration timeout."],
            prevention=["Alarm on Duration approaching the timeout, not only on timeouts."])

    # ---- Lambda: throttled
    throttled = {_named(alert, "lambda", s) for s, v in _per(m, "lambda_throttles") if v > 0}
    throttled |= {_named(alert, "lambda", s) for s, v in _per(m, "lambda_reserved_concurrency") if v == 0}
    for fn in sorted(f for f in throttled if f):
        reserved = _metric(m, "lambda_reserved_concurrency", alert, "lambda", fn)
        thr = _metric(m, "lambda_throttles", alert, "lambda", fn) or 0.0
        cmds, why, _ = lambda_concurrency(alert, ctx, fn)
        add("fn_throttled", f"Lambda throttled: {fn}",
            f"lambda_throttles = {thr:.0f}" + (f", lambda_reserved_concurrency = {reserved:.0f}"
                                               if reserved is not None else ""),
            "Invocations are rejected for lack of concurrency"
            + (" - reserved concurrency 0 rejects every call." if reserved == 0 else "."),
            cmds, why,
            platform=["Treat reserved concurrency as reviewed configuration; alarm on Throttles > 0."],
            prevention=["Alert on Throttles directly - they are unambiguous."])

    # ---- Lambda: bad environment
    rnf = _has(ctx, "ResourceNotFoundException")
    fn = _fn_of(alert, rnf) if rnf else None
    cfg = _config(ctx, fn) if fn else {}
    if rnf and cfg:
        names, values = _env(cfg)
        cmds, why = _alias_rollback(ctx, fn)
        table = L.get("dynamodb_table", "")
        wrong = {k: v for k, v in (values or {}).items() if "TABLE" in k.upper() and table and v != table}
        if not cmds and values and len(wrong) == 1:
            var = next(iter(wrong))
            env = json.dumps({"Variables": {**values, var: table}}, separators=(",", ":"))
            cmds, note = _lambda_config_fix(ctx, fn, f"--environment '{env}'")
            why = f"{var} is `{wrong[var]}`, the labelled table is `{table}`. {note}".strip()
        elif not cmds:
            why = (f"No command: {fn}'s environment names {', '.join(names) or 'no variables'}"
                   + ("" if values else " without their values") + "; WARDEN cannot tell which value is wrong or "
                   "print a whole environment (update-function-configuration replaces all of it).")
        add("missing_resource", f"{fn} calls a resource that does not exist", rnf,
            f"A resource {fn} calls does not exist; its configuration names resources through the environment "
            f"({', '.join(names)}).", cmds, why,
            developers=["Validate configured resource names at cold start and fail with the name in the message."],
            platform=["Generate resource names in environment variables from the infrastructure code, not by hand."],
            prevention=["A post-deploy smoke call that exercises each dependency."])

    # ---- IAM: a denied action 
    denied = next((ln for ln in ctx.logs if "not authorized to perform" in ln
                   and "ResourceInitializationError" not in ln), None)
    if denied:
        cmds, why = _grant(denied)
        action = (re.search(r"perform:? (\S+)", denied) or [None, "an action"])[1]
        add("access_denied", f"Permission denied: {action}", denied,
            f"The role is not allowed {action}: a policy change removed it, or it was never granted.",
            cmds, why,
            platform=["Keep the role's policy in infrastructure code and review diffs that remove actions."],
            prevention=["Alarm on AccessDenied in application logs; it never fixes itself."])

    # ---- SQS: poison message
    dlq = [v for _, v in _per(m, "dlq_visible") if v > 0]
    # A traceback that is a dependency failing (denied, missing, read-only, ...) is not a message
    # the consumer cannot process: those have their own patterns.
    # A CODE line is the parsed traceback; a raw "Traceback" line counts only when none was parsed.
    codes = [ln for ln in ctx.logs if ln.startswith("CODE ")]
    trace = next((ln for ln in codes if not any(i in ln for i in infra)), None) if codes else next(
        (ln for ln in ctx.logs if "Traceback" in ln and ln.startswith("LOG lambda/")), None)
    if dlq and trace:
        q = _first(ctx, "QUEUE ", "dlq_visible=")
        dname = _kv(q).get("dlq", "") if q else ""
        peek = (f"Read what is in the DLQ before deciding (read-only, messages stay): aws sqs receive-message "
                f"--queue-url {_queue_url(dname)} --max-number-of-messages 5 --visibility-timeout 0"
                if dname else "Read the DLQ's messages before deciding what to do with them.")
        add("dead_letters", "Messages failing to the dead-letter queue", q or f"dlq_visible = {dlq[0]:.0f}",
            "The consumer raises on some messages; after the queue's max receives they move to the DLQ. The "
            "traceback names the code that cannot process them.", [],
            "No command: redriving messages the consumer cannot parse sends them straight back to the DLQ, and "
            "purging them destroys data. Decide per message once the consumer handles them.",
            oncall=[regioned(peek)],
            developers=[f"Handle the input that fails at `{trace[:160]}`; reject bad messages explicitly."],
            platform=["After the consumer is fixed, redrive the DLQ (SQS start-message-move-task)."],
            prevention=["Alarm on DLQ depth > 0."])

    # ---- SQS: consumer disabled
    esm = _first(ctx, "ESM ", "State=Disabled")
    if esm or any(v == 0 for _, v in _per(m, "lambda_esm_enabled")):
        cmds, why = [], "No command: no ESM line names the function and the queue."
        if esm:
            fn, queue = esm.split()[1], esm.split()[3]
            cmds = [regioned(f"aws lambda update-event-source-mapping --uuid \"$(aws lambda list-event-source-mappings "
                             f"--function-name {fn} --query \"EventSourceMappings[?ends_with(EventSourceArn, "
                             f"':{queue}')].UUID | [0]\" --output text)\" --enabled")]
            why = f"Re-enables the mapping {queue} -> {fn}; its UUID is looked up at run time (reports mask UUIDs)."
        add("consumer_off", "Queue consumer disabled", esm or "lambda_esm_enabled = 0",
            "The event source mapping is disabled: nothing reads the queue and the backlog grows.", cmds, why,
            platform=["Alarm on ApproximateAgeOfOldestMessage, which catches a stopped consumer whatever the cause."],
            prevention=["Audit who can disable event source mappings in production."])

    # ---- SNS -> SQS delivery blocked
    pol = _first(ctx, "POLICY sqs ", ":no")
    sns_failed = [v for _, v in _per(m, "sns_notifications_failed") if v > 0]
    if pol or sns_failed:
        cmds, why = [], "No command: no POLICY line names the queue and the topic it should allow."
        if pol:
            queue = pol.split()[2]
            topic = _kv(pol).get("allows_sns_topic", "").rsplit(":", 1)[0]
            r = region() or "*"
            policy = json.dumps({"Version": "2012-10-17", "Statement": [{
                "Sid": "warden-allow-sns", "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage", "Resource": f"arn:aws:sqs:{r}:*:{queue}",
                "Condition": {"ArnLike": {"aws:SourceArn": f"arn:aws:sns:{r}:*:{topic}"}}}]},
                separators=(",", ":"))
            attrs = json.dumps({"Policy": policy}, separators=(",", ":"))
            cmds = [regioned(f"aws sqs set-queue-attributes --queue-url {_queue_url(queue)} --attributes '{attrs}'")]
            why = (f"Replaces {queue}'s access policy with one allowing topic {topic} to send. The account part "
                   "of the ARNs is `*` because reports mask account ids; tighten it to the account afterwards.")
        add("topic_delivery_refused", "SNS cannot deliver to the queue",
            pol or f"sns_notifications_failed = {sns_failed[0]:.0f}",
            "The queue's access policy does not allow the topic, so deliveries are refused.", cmds, why,
            platform=["Keep queue policies in infrastructure code with the subscription they serve."],
            prevention=["Alarm on NumberOfNotificationsFailed > 0."])

    # ---- DynamoDB throttling
    thr = _ddb_throttles(m)
    if any(v > 0 for v in thr.values()):
        tline = _first(ctx, "TABLE ")
        cmds, why, _ = ddb_capacity(ctx)
        add("table_throttled", "DynamoDB throttling", tline or f"throttles = {sum(thr.values()):.0f}",
            "Requests exceed the table's provisioned capacity and are throttled.", cmds, why,
            platform=["Use auto scaling or on-demand for tables whose load varies."],
            prevention=["Alarm on ThrottledRequests > 0 and on consumed/provisioned > 80%."])

    # ---- Redis unreachable
    rline = next((ln for ln in ctx.logs if not ln.startswith(_STRUCTURED)
                  and re.search(r"(?i)redis|cache\.amazonaws\.com|:6379", ln)
                  and re.search(r"(?i)timeout|timed out|Error 11[01]|connection refused", ln)), None)
    if rline:
        path = _missing_cache_ingress(ctx)
        if path and path[2]:
            cache_sg, port, missing = path
            cmds = [regioned(f"aws ec2 authorize-security-group-ingress --group-id {cache_sg} --protocol tcp "
                             f"--port {port} --source-group {g}") for g in missing]
            why = (f"Restores inbound tcp/{port} on the cache's security group {cache_sg} from "
                   f"{', '.join(missing)} - application security groups (from the Lambda, ECS and EKS "
                   "configuration WARDEN read) that currently have no rule to reach the cache.")
        elif path:
            cmds, why = [], ("No command: every application security group already has an ingress rule on the "
                             "cache's security group, so the break is elsewhere (subnet, route, or the cluster).")
        else:
            cmds, why = [], ("No command: the evidence does not carry the cache's security groups and the "
                             "applications' security groups (REPLGROUP / SG / APPSG lines), so no rule can be named.")
        add("cache_unreachable", "Cache unreachable from the application", rline,
            "The application cannot open connections to the Redis endpoint - a network path (security group, "
            "subnet, route) or the cluster itself.", cmds, why,
            platform=["Check recent changes to the Redis security group's inbound rules for port 6379."],
            developers=["Give cache calls a short timeout and a fallback so a cache outage degrades, not fails."],
            prevention=["Alarm on the application's cache error rate, not only on the cluster's own health."])

    # ---- Redis memory pressure. 90% is a named threshold; evictions are a count.
    ev = sum(v for _, v in _per(m, "redis_evictions"))
    mem = max((v for _, v in _per(m, "redis_memory_pct")), default=0.0)
    if ev > 0 or mem >= 90:
        group = L.get("elasticache", "")
        nt = next((mt.group(1) for ln in ctx.logs for mt in [re.search(r"node_type=(\S+)", ln)] if mt), None)
        bigger = _next_node_type(nt) if nt else None
        cmds = ([regioned(f"aws elasticache modify-replication-group --replication-group-id {group} "
                          f"--cache-node-type {bigger} --apply-immediately")] if group and bigger else [])
        why = (f"Scales {group} from {nt} to {bigger}, the next size: more memory, no data dropped. Takes minutes."
               if cmds else "No command: no evidence line gives the node type, so the next size cannot be named "
               "(and flushing keys needs Redis access WARDEN does not have).")
        add("cache_memory", "Cache memory pressure", f"redis_memory_pct = {mem:.0f}, redis_evictions = {ev:.0f}",
            "The cache is near its memory limit and evicting (or refusing writes): keys without TTLs, or a working "
            "set larger than the node.", cmds, why,
            developers=["Set TTLs on every cache key; find what wrote the keys that fill memory."],
            platform=["Choose maxmemory-policy deliberately (allkeys-lru for a pure cache)."],
            prevention=["Alarm on DatabaseMemoryUsagePercentage > 80% and Evictions > 0."])

    # ---- Aurora: connections exhausted
    full = _has(ctx, "too many clients", "remaining connection slots are reserved")
    if full:
        add("db_connections_refused", "Database refusing new connections", full,
            "Every connection slot is taken; new clients are refused. Idle sessions held open are the usual cause.",
            [("SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle' "
              "AND backend_type = 'client backend' AND usename <> 'rdsadmin' "
              "AND now() - state_change > interval '120 seconds' AND pid <> pg_backend_pid();"
              "   -- idle (not in a transaction) for over 2 min: nothing is lost, clients reconnect")],
            dba=["Set idle_session_timeout for application roles; put a pooler (RDS Proxy) in front of Lambdas."],
            developers=["Close or return connections; one pool per process, sized to its concurrency."],
            prevention=["Alarm at 80% of max_connections with a per-application breakdown."])

    # ---- Aurora: writes reaching a read-only instance
    ro = _has(ctx, "read-only transaction")
    if ro:
        fn = _fn_of(alert, ro)
        cl = _first(ctx, "CLUSTER aurora ")
        ck = _kv(cl) if cl else {}
        cluster = cl.split()[2] if cl else L.get("aurora_cluster", "")
        readers = [r for r in ck.get("readers", "[]").strip("[]").split(",") if r]
        failover = next((ln for ln in ctx.logs if ln.startswith("EVENT aurora ") and "failover" in ln.lower()), None)
        cmds, why = (_db_host_fix(ctx, fn, cluster, [ck.get("writer", ""), *readers]) if fn
                     else ([], "No command: the failing function is not identified."))
        if failover and not cmds and cluster and len(readers) == 1:
            cmds = [regioned(f"aws rds failover-db-cluster --db-cluster-identifier {cluster} "
                             f"--target-db-instance-identifier {readers[0]}")]
            why = (f"{why} Instead: fail back so {readers[0]} - the former writer the application is pinned to - is "
                   "the writer again. Writes pause for the switch; the lasting fix is the cluster endpoint.").strip()
        common = dict(developers=["Connect writers to the cluster (writer) endpoint, never an instance or -ro endpoint."],
                      prevention=["A startup check: `SHOW transaction_read_only` must be off for a writer."])
        if failover:
            add("db_pinned_after_failover", "Writes fail after an Aurora failover",
                f"{failover[:120]} | {ro[:80]}",
                "The cluster failed over; the application is pinned to an instance endpoint that is now a reader.",
                cmds, why, **common)
        else:
            add("db_write_on_reader", "Writes sent to a read-only Aurora endpoint", ro,
                "The application's database host is a reader: every write fails.", cmds, why, **common)

    # ---- ECS: image cannot be pulled, task OOM
    def ecs_rollback() -> tuple[list[str], str]:
        d = _deploy(ctx, "ecs")
        cluster, svc = L.get("ecs_cluster") or L.get("cluster"), L.get("ecs_service")
        prev = str((d or {}).get("previous", ""))
        if d and cluster and svc and re.fullmatch(r"[\w-]+:\d+", prev):
            return ([regioned(f"aws ecs update-service --cluster {cluster} --service {svc} --task-definition {prev}")],
                    f"Returns {svc} to task definition {prev}, the revision it ran before the deploy at {d.get('at', '?')}.")
        return [], ("No command: no ECS deploy record gives the previous task definition (family:revision) "
                    "together with the cluster and service labels.")

    pull = _has(ctx, "CannotPullContainerError")
    if pull:
        add("task_image_pull", "ECS tasks cannot pull their image", pull,
            "The task definition references an image that cannot be pulled - usually a tag that does not exist.",
            *ecs_rollback(),
            platform=["Deploy image digests from the build; gate deploys on the image existing in ECR."],
            prevention=["Alarm on failed task starts for the service."])
    task_oom_line = next((ln for ln in ctx.logs if (ln.startswith("LOG ecs/") or "OutOfMemory" in ln)
                    and re.search(r"(?i)OutOfMemory|exit code:? 137|exitCode[=:] ?137", ln)), None)
    if task_oom_line:
        add("task_oom", "ECS tasks killed for memory", task_oom_line,
            "A container exceeded its task memory and was killed (exit 137).", *ecs_rollback(),
            developers=["Measure the service's peak memory; find the allocation that grew."],
            platform=["Size task memory from measured peak + headroom; alarm on MemoryUtilization."])

    # ---- ECS: secret cannot be read at task start
    init = next((ln for ln in ctx.logs if "ResourceInitializationError" in ln and re.search(r"(?i)secret", ln)), None)
    if init:
        cmds, why = _grant(init)
        cluster, svc = L.get("ecs_cluster") or L.get("cluster"), L.get("ecs_service")
        if cmds and cluster and svc:
            cmds.append(regioned(f"aws ecs update-service --cluster {cluster} --service {svc} --force-new-deployment"))
        add("task_secret_denied", "ECS tasks cannot read their secret", init,
            "The task execution role cannot read the secret the task definition injects, so no task starts.",
            cmds, why,
            platform=["Keep secretsmanager:GetSecretValue for the task's secrets in the execution role's policy."],
            prevention=["Alarm on tasks stopped with ResourceInitializationError."])

    # ---- ALB health check path wrong
    tgt = _first(ctx, "TARGET ", "ResponseCodeMismatch")
    if tgt:
        tg = tgt.split()[1]
        tgl = _first(ctx, f"TARGETGROUP {tg} ")
        bad = _kv(tgl).get("health_path") if tgl else None
        good = next((mt.group(1) for ln in ctx.logs if ln.startswith("LOG ecs/")
                     for mt in [re.search(r"GET (/[\w./-]*health[\w./-]*)[\s?\"].*\b200\b", ln)]
                     if mt and mt.group(1) != bad), None)
        cmds, why = [], ("No command: the application's working health path is not in the evidence (no 200 "
                         f"response to a health path in its logs); the target group checks `{bad}`.")
        if good:
            cmds = [regioned(f"aws elbv2 modify-target-group --target-group-arn \"$(aws elbv2 describe-target-groups "
                             f"--names {tg} --query 'TargetGroups[0].TargetGroupArn' --output text)\" "
                             f"--health-check-path {good}")]
            why = (f"The target group checks `{bad}`, which the targets answer with an error; the application "
                   f"answers `{good}` with 200 in its own logs.")
        add("lb_health_check", "Load balancer health check failing", tgt,
            "Targets fail the target group's health check with an unexpected status code: the check's path or "
            "port does not match the application.", cmds, why,
            platform=["Keep the health check path next to the route definition in infrastructure code."],
            prevention=["Alarm on UnHealthyHostCount > 0."])

    # ---- Stale credentials after a secret rotation
    auth = _has(ctx, "password authentication failed")
    changed = _first(ctx, "SECRET ", "changed") or ("secret changed in the window" if _deploy(ctx, "secret") else None)
    if auth and changed:
        src = _source_of(auth)
        cluster, svc = L.get("ecs_cluster") or L.get("cluster"), L.get("ecs_service")
        cmds, why = [], "No command: the failing workload is not an ECS service or Deployment WARDEN can name."
        if src and src[0] == "ecs" and cluster and svc:
            cmds = [regioned(f"aws ecs update-service --cluster {cluster} --service {svc} --force-new-deployment")]
            why = "New tasks read the secret at start, so they get the current password."
        elif src and src[0] == "k8s" and "/" in src[1]:
            ns, dep = src[1].split("/", 1)
            cmds, why = [f"kubectl -n {ns} rollout restart deploy/{dep}"], "New pods read the current secret."
        add("stale_credentials", "Stale database credentials after a secret change",
            f"{auth[:110]} | {changed[:80]}",
            "The database password changed (the secret changed in the window) but the running workload still "
            "uses the one it read at start.", cmds, why,
            developers=["Re-read the secret on authentication failure instead of only at start."],
            platform=["Make rotation restart its consumers (or use dual-user rotation)."])

    # ---- IAM database authentication refused (Aurora: the signing identity lost rds-db:connect)
    pam = next((ln for ln in ctx.logs if "PAM authentication failed for user" in ln), None)
    if pam:
        cmds, why = db_iam_grant(ctx, pam)
        add("db_iam_auth_refused", "Database refuses the application's IAM login", pam[-160:],
            "Aurora refused an IAM database token: the identity that signed it is no longer allowed "
            "rds-db:connect for that database user (a policy change removed it), or the user lost rds_iam.",
            cmds, why,
            platform=["Keep rds-db:connect in the workload role's policy in infrastructure code; review diffs that remove it."],
            prevention=["Alarm on `PAM authentication failed` in application logs; it never fixes itself."])

    # ---- Kubernetes: missing secret key, unschedulable
    cfgerr = _has(ctx, "CreateContainerConfigError", "couldn't find key")
    if cfgerr:
        add("secret_key_missing", "Pod references a secret key that does not exist", cfgerr,
            "A container's env references a key the Secret no longer has, so the container cannot be created.", [],
            "No command: the missing key's value is not something WARDEN reads (it never reads secret values).",
            platform=["Restore the key in the Secret from its source of truth; the pods then start on their own."],
            prevention=["Check that every referenced secret key exists before applying a Secret change."])
    sched = next((ln for ln in ctx.logs if "FailedScheduling" in ln and "Insufficient" in ln), None)
    if sched:
        undo = _rollout_undo(alert, ctx, sched)
        add("unschedulable", "Pods cannot be scheduled", sched,
            "No node has the resources the pod requests - the requests exceed what any node can offer.", undo,
            "Returns the Deployment to its previous template, whose requests were schedulable." if undo else
            "No command: WARDEN read no earlier revision of the Deployment to return to.",
            platform=["Set requests from measured usage; a LimitRange caps what one pod can request."],
            prevention=["Alert on Pending pods older than a few minutes."])

    # ---- EventBridge rule disabled
    rule = _first(ctx, "RULE ", "State=DISABLED")
    off = [s for s, v in _per(m, "rule_enabled") if v == 0]
    if rule or off:
        name = rule.split()[1] if rule else _named(alert, "eventbridge_rule", off[0])
        add("schedule_off", "Scheduled rule disabled", rule or "rule_enabled = 0",
            "The EventBridge rule is disabled, so its target is never invoked.",
            [regioned(f"aws events enable-rule --name {name}")] if name else [],
            "" if name else "No command: the disabled rule is not named in the evidence.",
            platform=["Alarm on the target's Invocations dropping to zero for scheduled work."])

    # The k8s crash loop is the `crashloop` pattern above. It gets no command: the bad value is
    # in a ConfigMap, which a rollout undo does not restore and whose previous value WARDEN never saw.
    return out
