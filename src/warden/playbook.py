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

import math
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
                    "If a deploy preceded it, roll back; a restart alone restarts the same failure."],
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

    if ctx.recent_deploys and (out or _has(ctx, "ERROR", "error", " 500 ", "Exception")):
        d = ctx.recent_deploys[0]
        what = d.get("sha") or d.get("image") or d.get("task_definition") or d.get("revision")
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
