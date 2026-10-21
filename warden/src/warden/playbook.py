"""Who does what next - the follow-up an incident report owes each team, by failure pattern.

What the on-call engineer should look at now, what the developers should look at in the code, what the
platform/DevOps team should change so it cannot recur the same way, what the DBA should check, and what
to put in place to catch it earlier.

⛔ ADVICE IN WORDS, NEVER A COMMAND (2026-10-16). Each pattern used to carry a `fix` of exact aws, kubectl
and SQL commands, printed even under a rejected verdict, some with masked values written back into
them. A change now goes only through a catalogue plan and a signed approval, which WARDEN applies
itself; nothing here is a command for anyone to paste.

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
    """The patterns the evidence shows, each with what triggered it; the full stack's after the cluster's."""
    out = _oom(ctx)
    out += _crashloop(ctx, out)
    out += _image_pull(ctx)
    out += _probe(ctx)
    out += _replicas(ctx, out)
    out += _db_idle_tx(ctx)
    out += _db_lock(ctx)
    out += _db_long_query(ctx)
    out += _db_pool(ctx)
    out += _replica_lag(ctx)
    out += _evidence_unreachable(ctx)
    out += _stack(alert, ctx)
    out += _deploy_preceded(ctx, out)
    out += _errors(ctx, out)
    return out


def _oom(ctx: ContextBundle) -> list[Pattern]:
    """Containers OOM-killed: the kill reason, and the limit against the peak the application logged."""
    m = ctx.metrics
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
            # A8 (2026-10-16): the advice used to end in a `kubectl top pod` to paste; it says what to measure.
            sizing.append(f"The container limit is {limit:.0f} MiB. Measure each container's real memory use "
                          "under load before changing it.")
        out.append(Pattern(
            "oom", "Containers OOM-killed", seen,
            "The process used more memory than its container limit and the kernel killed it. Either the "
            "limit is below what the workload needs, or the application's memory use grew (a leak, an "
            "unbounded cache, a large request).",
            oncall=["Confirm the kill reason is OOMKilled in the container status.",
                    "If it started with a deploy, rolling back is the fastest safe mitigation."],
            developers=[("Profile memory at startup and under load; look for unbounded caches, buffers "
                        "sized from input, and objects retained across requests."),
                        "Check what changed in the last release that touches allocation."],
            platform=[*sizing, ("Set memory requests = limits for predictable scheduling, and alert on "
                      "OOMKilled and restart rate, not only on the symptom.")],
            prevention=["Load-test memory to find the real peak before setting limits.",
                        "Add a memory-usage metric per pod so the next report shows usage, not just kills."],
        ))
    return out


def _crashloop(ctx: ContextBundle, found: list[Pattern]) -> list[Pattern]:
    """Containers crash-looping - unless they are being OOM-killed (`found` holds the oom pattern then)."""
    m = ctx.metrics
    out: list[Pattern] = []
    crash_line = _has(ctx, "CrashLoopBackOff", "Back-off restarting failed container")
    fatal_line = _has(ctx, "fatal", "FATAL", "panic", "Traceback", "Exception")
    # When containers are being OOM-killed, the back-off IS the OOM kills restarting: listing a
    # separate crash-loop pattern would add advice about configuration errors that does not apply.
    if (m.get("crashloop_containers", 0) > 0 or crash_line) and not any(q.key == "oom" for q in found):
        out.append(Pattern(
            "crashloop", "Containers crash-looping", crash_line or "crashloop_containers > 0",
            "The container starts and exits repeatedly. The exit reason is in the container's own last "
            "log lines" + (f" - here: `{fatal_line}`" if fatal_line else "") + ".",
            oncall=["Read the crashed container's own last output: it names why it exits.",
                    "If a deploy preceded it, roll back; a restart alone restarts the same failure.",
                    ("The cause is in the image, its configuration or a dependency, and a rollout undo does not "
                     "restore a ConfigMap or Secret - the crashed output names which to fix.")],
            developers=[("Fix the startup failure the logs name; make startup errors explicit and "
                        "non-zero with a clear message.")],
            platform=[("Validate configuration and secrets at deploy time (a pre-deploy check or init "
                      "container), not at first start in production.")],
            prevention=["A smoke test in the pipeline that starts the container with production-shaped config."],
        ))
    return out


def _image_pull(ctx: ContextBundle) -> list[Pattern]:
    """The image cannot be pulled."""
    out: list[Pattern] = []
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
    return out


def _probe(ctx: ContextBundle) -> list[Pattern]:
    """A health check failing."""
    out: list[Pattern] = []
    probe_line = _has(ctx, "Liveness probe failed", "Readiness probe failed", "failed liveness probe")
    if probe_line:
        out.append(Pattern(
            "probe", "Health check failing", probe_line,
            "Kubernetes is killing (liveness) or unrouting (readiness) pods whose health check fails. "
            "Either the application is unhealthy, or the probe is wrong - a bad path or port, a timeout "
            "shorter than the real response time, or no startup grace.",
            oncall=["Compare the Deployment's probe (path, port, timeout) with what the application serves.",
                    "If the probe changed in the last deploy, roll back."],
            developers=["Make the health endpoint cheap and independent of downstream dependencies."],
            platform=["Use a startupProbe for slow starts; set liveness timeouts from measured latency."],
            prevention=["Review probe changes like code changes - a wrong probe takes a healthy service down."],
        ))
    return out


def _replicas(ctx: ContextBundle, found: list[Pattern]) -> list[Pattern]:
    """Scaled to zero, or pods not ready when nothing above explains it (`found`)."""
    m = ctx.metrics
    out: list[Pattern] = []
    if "replicas_desired" in m and m["replicas_desired"] == 0:
        out.append(Pattern(
            "scaled_to_zero", "Scaled to zero", "replicas_desired = 0",
            "The Deployment asks for zero replicas - a manual scale, an autoscaler, or an automation "
            "set it. Nothing is failing; nothing is running.",
            oncall=["Find who scaled it: the Deployment's events and the cluster's audit log name the change.",
                    "Restore the previous count if the scale-down was not intended."],
            platform=[("Protect production workloads from scale-to-zero: an HPA minReplicas, or a "
                      "policy that blocks replicas: 0 in prod.")],
            prevention=["Alert on 'desired replicas = 0' for services that must always run."],
        ))
    elif "pods_total" in m and m.get("pods_ready", m["pods_total"]) < m["pods_total"] and not found:
        out.append(Pattern(
            "unready", "Pods not ready",
            f"pods_ready = {m.get('pods_ready', 0):.0f} of {m['pods_total']:.0f}",
            "Some pods are not passing readiness. The events and the pods' own logs say why.",
            oncall=["Read the pods' events and their own logs: they say why readiness fails."],
        ))
    return out


def _db_idle_tx(ctx: ContextBundle) -> list[Pattern]:
    """Sessions stuck idle inside transactions."""
    m = ctx.metrics
    out: list[Pattern] = []
    stuck_line = _has(ctx, "stuck connection:")
    if stuck_line or m.get("idle_in_transaction", 0) >= 5:
        out.append(Pattern(
            "db_idle_tx", "Sessions stuck idle inside transactions",
            stuck_line or f"idle_in_transaction = {m.get('idle_in_transaction', 0):.0f}",
            "Application code opened a transaction and stopped using it without committing or rolling "
            "back - usually an exception path that skips cleanup, or a slow external call made inside "
            "the transaction. Each one holds a connection and its locks until it is closed.",
            oncall=[("Terminate only the sessions that are idle in a transaction, then watch whether they come "
                    "back - if they do, the leak is still live.")],
            developers=[("Find the code path running the query shown in the evidence; make commit/rollback "
                        "unconditional (context managers / try-finally)."),
                        "Never call external services while holding a transaction open."],
            dba=[("Set idle_in_transaction_session_timeout through a reviewed change, so a leak costs one "
                 "connection for minutes, not the pool forever.")],
            prevention=["Alert on idle-in-transaction count and age, not just on pool exhaustion."],
        ))
    return out


def _db_lock(ctx: ContextBundle) -> list[Pattern]:
    """Sessions blocked on a lock."""
    m = ctx.metrics
    out: list[Pattern] = []
    blocked_line = _has(ctx, "blocked session:")
    if blocked_line or m.get("locks_waiting", 0) > 0:
        out.append(Pattern(
            "db_lock", "Sessions blocked on a lock",
            blocked_line or f"locks_waiting = {m.get('locks_waiting', 0):.0f}",
            "One session holds a lock others need. If the holder is idle in a transaction, it will never "
            "release it by itself.",
            oncall=[("Identify the blocker (the blocked-session lines in the evidence name it) before "
                    "terminating anything - terminate the BLOCKER, not the waiters.")],
            developers=[("Keep transactions short; take locks in a consistent order; avoid explicit "
                        "table locks in request paths.")],
            dba=["Set lock_timeout for application roles so waiters fail fast instead of piling up."],
            prevention=["Alert on lock wait time and on blocking chains."],
        ))
    return out


def _db_long_query(ctx: ContextBundle) -> list[Pattern]:
    """A long-running query."""
    m = ctx.metrics
    out: list[Pattern] = []
    long_line = _has(ctx, "long-running query:")
    if long_line or m.get("long_running_queries", 0) > 0:
        out.append(Pattern(
            "db_long_query", "Long-running query",
            long_line or f"long_running_queries = {m.get('long_running_queries', 0):.0f}",
            "A query has been actively running for over a minute. It may be legitimate (a report, a "
            "migration, a backfill) or a runaway (a missing index, a bad plan) - WARDEN cannot tell which.",
            oncall=[("Do NOT terminate it until its owner is known: it is doing work, and terminating "
                    "loses that work. Check who runs it (user, application in the evidence)."),
                    # WARDEN never changes a schema (owner decision 2026-09-27), and the table and column come
                    # from query TEXT, which whoever issues the query controls: a hint for a DBA, never more.
                    ("WARDEN never changes a schema. "
                     + (f"The query filters by {index_hint(long_line)}: a DBA decides whether an index helps."
                        if index_hint(long_line) else "A DBA decides whether an index helps."))],
            developers=[("If it is a runaway: read the query's plan with its real run time; check for a missing "
                        "index or a changed plan.")],
            dba=[("Set statement_timeout per role so runaway queries end themselves; move reporting "
                 "to a replica.")],
            prevention=["Log slow queries (log_min_duration_statement) so the next incident has the history."],
        ))
    return out


def _db_pool(ctx: ContextBundle) -> list[Pattern]:
    """Connection capacity nearly exhausted."""
    m = ctx.metrics
    out: list[Pattern] = []
    used = m.get("connections_used_pct")
    pool_used, pool_size = m.get("connection_pool_used"), m.get("connection_pool_size")
    if (used is not None and used >= 0.7) or (pool_used and pool_size and pool_used >= pool_size * 0.9):
        seen = (f"connections_used_pct = {used:.2f}" if used is not None
                else f"connection pool {pool_used:.0f}/{pool_size:.0f}")
        out.append(Pattern(
            "db_pool", "Connection capacity nearly exhausted", _has(ctx, "connections held:") or seen,
            "Connections are close to the limit. If most are idle (not in a transaction), clients are "
            "holding connections they are not using - pool sizes too large, or connections not returned.",
            oncall=[("Check who holds them (by application, client and state) before raising max_connections "
                    "or scaling - either can hide a leak.")],
            developers=[("Return connections to the pool promptly; size each service's pool to its real "
                        "concurrency.")],
            dba=["Put a pooler (PgBouncer / RDS Proxy) in front if many services connect directly."],
            platform=[("Scaling the application out multiplies connections - check pool size x replicas "
                      "against max_connections before scaling.")],
            prevention=["Alert at 70% of max_connections, with a per-application breakdown."],
        ))
    return out


def _replica_lag(ctx: ContextBundle) -> list[Pattern]:
    """A replica lagging."""
    m = ctx.metrics
    out: list[Pattern] = []
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
    return out


def _evidence_unreachable(ctx: ContextBundle) -> list[Pattern]:
    """Every read failed: WARDEN could not read the system."""
    m = ctx.metrics
    out: list[Pattern] = []
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
    return out


def _deploy_preceded(ctx: ContextBundle, found: list[Pattern]) -> list[Pattern]:
    """A code deploy preceded the failure (`found`: the patterns so far)."""
    out: list[Pattern] = []
    # A secret changing is not a code deploy (contract D): rolling it back is not the fix.
    code_deploys = [d for d in ctx.recent_deploys if d.get("kind") != "secret"]
    if code_deploys and (found or _has(ctx, "ERROR", "error", " 500 ", "Exception")):
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
    return out


def _errors(ctx: ContextBundle, found: list[Pattern]) -> list[Pattern]:
    """An elevated error rate no deploy explains (`found`: the patterns so far)."""
    m = ctx.metrics
    out: list[Pattern] = []
    er = m.get("error_rate")
    if er is not None and er >= 0.02 and not any(p.key == "deploy" for p in found):
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
# Built against the evidence contract in demo-app/docs/FULLSTACK-LAB.md section 4: the tagged lines of C (LOG/CONFIG/ESM/CODE/SOURCE/
# QUEUE/POLICY/TABLE/EVENT/CLUSTER/TARGET/TARGETGROUP/SECRET/RULE), the metrics of B (with the
# `__<short>` suffix when several resources of a kind are labelled) and the deploy records of D.
# Each pattern's advice names what the evidence shows (a version, a value, a missing rule) in words; a
# value it suggests (a timeout, a capacity) is worked out from the evidence and the working is said. It
# prints no command (2026-10-16): the change itself is a catalogue plan for an approver.

# The prefixes of a parsed traceback frame and of a DynamoDB table's read (contract C).
_CODE = "CODE "
_TABLE = "TABLE "
# WARDEN's own structured lines (contract C) - facts about configuration, not application output.
_STRUCTURED = ("CONFIG ", "ESM ", _CODE, "SOURCE ", "QUEUE ", "POLICY ", _TABLE, "CLUSTER ", "TARGET",
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
    port, allowed = _cache_ingress(ctx, cache_sgs)
    apps = _app_sgs(ctx, cache_sgs)
    if not port or not apps:
        return None
    return cache_sgs[0], port, [g for g in apps if g not in allowed]


def _cache_ingress(ctx: ContextBundle, cache_sgs: list[str]) -> tuple[str, set[str]]:
    """(the port, the security groups allowed in) from the SG lines' ingress rules on the cache's groups."""
    allowed: set[str] = set()
    port = ""
    for ln in ctx.logs:
        mt = re.match(r"SG (sg-\S+) ingress tcp/(\d+) from=(\[[^\]]*\])", ln)
        if mt and mt.group(1) in cache_sgs:
            port = mt.group(2)
            allowed |= set(_sg_list(mt.group(3)))
    return port, allowed


def _app_sgs(ctx: ContextBundle, cache_sgs: list[str]) -> list[str]:
    """The application's security groups (APPSG lines and in-VPC Lambdas' CONFIG lines), the cache's own left out."""
    apps: list[str] = []
    for ln in ctx.logs:
        mt = (re.match(r"APPSG \S+ sgs=(\[[^\]]*\])", ln)
              or (re.search(r" sgs=(\[[^\]]*\])", ln) if ln.startswith("CONFIG lambda ") else None))
        for g in _sg_list(mt.group(1)) if mt else []:
            if g not in apps and g not in cache_sgs:
                apps.append(g)
    return apps


def _kv(line: str) -> dict[str, str]:
    # From the start of a word: a long word with no `=` was searched again from each of its letters (Sonar python:S8786, 2026-10-16).
    return dict(re.findall(r"\b(\w+)=(\[[^\]]*\]|\S+)", line))


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
    values = {k: v for k, _, v in (i.partition("=") for i in items)} if items and all("=" in i for i in items) else None
    return names, values


def _deploy(ctx: ContextBundle, kind: str, service: str | None = None) -> dict | None:
    return next((d for d in ctx.recent_deploys
                 if d.get("kind") == kind and (service is None or d.get("service") == service)), None)


def _alias(cfg: dict[str, str]) -> str | None:
    # `alias_live=-` is how the stack backend says the function has no such alias.
    return next((k[len("alias_"):] for k, v in cfg.items() if k.startswith("alias_") and v != "-"), None)


def _alias_moved(ctx: ContextBundle, fn: str) -> str:
    """Which version `fn`'s alias moved from in the window, by the deploy record (contract D) - or ""."""
    d = _deploy(ctx, "lambda", fn)
    alias = _alias(_config(ctx, fn)) or (d or {}).get("alias")
    prev = str((d or {}).get("previous", ""))
    if d and alias and prev.isdigit():
        return (f"Alias `{alias}` of {fn} moved to version {d.get('version', '?')} at {d.get('at', '?')}; "
                f"it served version {prev} before.")
    return ""


def _denied(line: str) -> str:
    """What an AccessDenied line names, as advice.

    ⛔ The action, the role and the resource all come from a LOG LINE, and whoever can write a log line could
    shape an IAM grant (a line naming the admin role and `iam:*` is all it takes). A missing permission is
    restored from the role's DECLARED policy (Terraform), through a reviewed change - never re-derived from
    runtime text."""
    action = re.search(r"not authorized to perform:? ([a-z0-9-]+:[A-Za-z0-9*]+)", line)
    role = re.search(r"assumed-role/([\w+=,.@-]+)/", line)
    res = re.search(r"on resource:? (arn:aws:[^\s\"']+)", line)
    if not (action and role and res):
        missing = [n for n, v in (("the action", action), ("the role", role), ("the resource", res)) if not v]
        return f"The denial line does not name {', '.join(missing)}."
    # The account id is masked in every report, so the resource is written with `*` for it.
    resource = re.sub(r"^(arn:aws:[a-z0-9-]*:[a-z0-9-]*:)\d{12}:", r"\1*:", res.group(1))
    if action.group(1).startswith("secretsmanager:"):
        resource = re.sub(r"-[A-Za-z0-9]{6}$", "-*", resource)   # Secrets Manager's random ARN suffix
    return (f"The denial names {action.group(1)} on {resource} for role {role.group(1)}. Compare the role's "
            "declared policy (Terraform) with what is attached, and restore the declared one through a reviewed "
            "change - WARDEN never writes IAM from a log line.")


def _db_iam_refused(ctx: ContextBundle, line: str) -> str:
    """Which role lost rds-db:connect for the refused database user - only when the evidence NAMES that role
    (a TASKROLE line). Advice for a reviewed change, for the reason _denied gives."""
    user = re.search(r'PAM authentication failed for user "?(\w+)', line, re.ASCII)
    src = _source_of(line)
    tline = _first(ctx, f"TASKROLE ecs/{src[1]} ") if src and src[0] == "ecs" else None
    role = _kv(tline).get("role") if tline else None
    if not (user and role):
        needed = [] if user else ["the refused user in the PAM line"]
        if not role and src and src[0] == "ecs":
            needed.append("a `TASKROLE ecs/<service> role=<name>` line for the failing ECS service")
        elif not role:
            needed.append("the identity that signs the tokens (WARDEN names it only for an ECS service, from its "
                          "task definition: a `TASKROLE ecs/<service> role=<name>` line)")
        return f"The evidence does not carry {' and '.join(needed)}."
    return (f"{role}, the task role of {src[1]} (its TASKROLE line), is refused as database user {user.group(1)}. "
            "Compare its declared policy (Terraform) for rds-db:connect on that user and restore it through a "
            "reviewed change - WARDEN never writes IAM from runtime text.")


_SCAN = re.compile(r"(?i)\bFROM\s+([A-Za-z_][\w.]*)(?:\s+(?:AS\s+)?(?!WHERE\b)[A-Za-z_]\w*)?\s+WHERE\s+"
                   r"(?:[A-Za-z_]\w*\.)?([A-Za-z_]\w*)\s*(?:=|<|>|\bIN\b|\bLIKE\b|\bBETWEEN\b)")


def index_hint(long_line: str | None) -> str:
    """The table.column the long query filters by, as ADVICE for a DBA - never a command."""
    mt = _SCAN.search((long_line or "").split(": ", 2)[-1])
    return f"{mt.group(1)}.{mt.group(2)}" if mt else ""


def _next_node_type(node_type: str) -> str | None:
    ladder = ["micro", "small", "medium", "large", "xlarge", "2xlarge", "4xlarge"]
    mt = re.fullmatch(r"(cache\.[a-z0-9]+)\.([0-9a-z]+)", node_type)
    if not mt or mt.group(2) not in ladder[:-1]:
        return None
    return f"{mt.group(1)}.{ladder[ladder.index(mt.group(2)) + 1]}"


_RDS_HOST = re.compile(r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.rds\.amazonaws\.com")


def _writer_host(host: str, cluster: str, instances: list[str]) -> str | None:
    """The cluster (writer) endpoint for a reader or instance endpoint, by Aurora's naming scheme."""
    if ".cluster-ro-" in host:
        return host.replace(".cluster-ro-", ".cluster-", 1)
    head, _, rest = host.partition(".")
    if head in instances and cluster and rest:
        return f"{cluster}.cluster-{rest}"
    return None


def _db_host(ctx: ContextBundle, fn: str, cluster: str, instances: list[str]) -> str:
    """Which of `fn`'s environment variables holds a reader or instance endpoint of `cluster` - or ""."""
    _, values = _env(_config(ctx, fn))
    for var, val in (values or {}).items():
        # The whole value an RDS hostname, not one that merely contains the suffix: `....rds.amazonaws.com.evil.example`
        # made the advice point the database at another domain (CodeQL, 2026-10-02).
        new = _writer_host(val, cluster, instances) if _RDS_HOST.fullmatch(val) else None
        if new:
            return f"{var} is `{val}`, not the cluster writer endpoint `{new}`."
    return ""


def _concurrency(alert: Alert, ctx: ContextBundle, fn: str) -> str:
    """The reserved concurrency the evidence says `fn`'s demand needs, and how that was worked out."""
    from .aws_backend import METRIC_WINDOW  # lazy: keeps boto3 out of the playbook's import

    m, window_s = ctx.metrics, METRIC_WINDOW.total_seconds()
    reserved = _metric(m, "lambda_reserved_concurrency", alert, "lambda", fn)
    if reserved is None:
        return (f"{fn} has no reserved concurrency, so any throttling is the account's regional concurrency limit - "
                "a quota increase or lower concurrency elsewhere, not a function setting.")
    thr = _metric(m, "lambda_throttles", alert, "lambda", fn) or 0.0
    inv = _metric(m, "lambda_invocations", alert, "lambda", fn) or 0.0
    timeout = _metric(m, "lambda_timeout_s", alert, "lambda", fn)
    if not timeout:
        return f"{fn}'s timeout is not in the evidence, so the concurrency it needs cannot be worked out."
    new = max(math.ceil(2 * (inv + thr) / window_s * timeout), 2, int(reserved) * 2)
    return (f"Reserved concurrency is {reserved:.0f}; the demand needs about {new} = max(2, 2 x current, 2 x the "
            f"concurrency the demand needs: ({inv:.0f} invocations + {thr:.0f} throttles) / {window_s:.0f}s x "
            f"{timeout:.0f}s timeout, the longest a call can take). The account keeps 10 unreserved: a raise may need "
            "other functions' reservations lowered.")


def _ddb_throttles(m: dict[str, float]) -> dict[str, float]:
    return {b: sum(v for _, v in _per(m, b)) for b in
            ("ddb_write_throttle_events", "ddb_read_throttle_events", "ddb_throttled_requests")}


def _capacity(ctx: ContextBundle) -> str:
    """The provisioned throughput the TABLE line's table needs, sized from consumed + throttled - or why not."""
    from .aws_backend import METRIC_WINDOW  # lazy: keeps boto3 out of the playbook's import

    m, window_s = ctx.metrics, METRIC_WINDOW.total_seconds()
    tline = _first(ctx, _TABLE)
    tk = _kv(tline) if tline else {}
    if tk.get("billing") != "PROVISIONED" or not (tk.get("rcu", "").isdigit() and tk.get("wcu", "").isdigit()):
        return (f"The table bills {tk['billing']}, so there is no provisioned throughput to raise."
                if tk.get("billing") and tk["billing"] != "PROVISIONED" else "")
    rcu, wcu = int(tk["rcu"]), int(tk["wcu"])
    thr = _ddb_throttles(m)

    def need(cur: int, consumed: float | None, events: float) -> int:
        if events <= 0:
            return cur
        return max(math.ceil(((consumed if consumed is not None else cur) + events / window_s) * 2), cur * 2)

    reads = thr["ddb_read_throttle_events"]
    writes = thr["ddb_write_throttle_events"] or (thr["ddb_throttled_requests"] if not reads else 0)
    new_r, new_w = need(rcu, m.get("ddb_consumed_rcu"), reads), need(wcu, m.get("ddb_consumed_wcu"), writes)
    if (new_r, new_w) == (rcu, wcu):
        new_r, new_w = rcu * 2, wcu * 2   # throttling with no measured excess: one doubling
    return (f"Provisioned {rcu} RCU / {wcu} WCU; the demand needs about {new_r} RCU / {new_w} WCU = max(2 x current, "
            f"2 x demand), demand = consumed units/s + throttle events / {window_s:.0f}s. Decreases are limited per "
            "day - raise with care.")


def _fn_of(alert: Alert, line: str) -> str | None:
    src = _source_of(line)
    return src[1] if src and src[0] == "lambda" else _named(alert, "lambda", None)


# A traceback that names one of these is a dependency failing, not the code: those have their own patterns.
_INFRA = ("ResourceNotFoundException", "AccessDenied", "read-only transaction", "password authentication",
          "PAM authentication failed", "too many clients", "Timeout", "timed out")


def _stack(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    """The full stack's patterns (contract C), in the order a report lists them."""
    # The k8s crash loop is the `crashloop` pattern above. It names no rollback: the bad value is in a
    # ConfigMap, which a rollout undo does not restore and whose previous value WARDEN never saw.
    return [
        *_code_regression(ctx),
        *_fn_timeout(alert, ctx),
        *_fn_throttled(alert, ctx),
        *_bad_environment(alert, ctx),
        *_access_denied(ctx),
        *_dead_letters(ctx),
        *_consumer_off(ctx),
        *_topic_delivery_refused(ctx),
        *_table_throttled(ctx),
        *_cache_unreachable(ctx),
        *_cache_memory(alert, ctx),
        *_db_connections_refused(ctx),
        *_db_read_only(alert, ctx),
        *_ecs_tasks(alert, ctx),
        *_task_secret_denied(ctx),
        *_lb_health_check(ctx),
        *_stale_credentials(alert, ctx),
        *_db_iam_auth_refused(ctx),
        *_k8s_pods(ctx),
        *_schedule_off(alert, ctx),
    ]


def _add(out: list[Pattern], key: str, title: str, seen: str, cause: str, why: str = "", **teams: list[str]) -> None:
    """Append one pattern: `why`, the evidence-specific advice, leads the on-call list."""
    oncall = list(teams.pop("oncall", []))
    if why:
        oncall.insert(0, why)
    out.append(Pattern(key, title, seen[:200], cause, oncall=oncall, **teams))


def _ecs_before(alert: Alert, ctx: ContextBundle) -> str:
    """The task definition the ECS service ran before the deploy in the window - or ""."""
    d = _deploy(ctx, "ecs")
    svc = alert.labels.get("ecs_service")
    prev = str((d or {}).get("previous", ""))
    if d and svc and re.fullmatch(r"[\w-]+:\d+", prev):
        return f"{svc} ran task definition {prev} before the deploy at {d.get('at', '?')}."
    return ""


def _code_regression(ctx: ContextBundle) -> list[Pattern]:
    # ---- Lambda: code regression - a traceback frame in code that shipped in the window.
    out: list[Pattern] = []
    for code in (ln for ln in ctx.logs if ln.startswith(_CODE)):
        mt = re.match(r"CODE (\S+) (\S+):(\d+) in (\S+): (.*)", code)
        if not mt or any(i in code for i in _INFRA) or not _deploy(ctx, "lambda", mt.group(1)):
            continue
        fn, path, lineno, func, exc = mt.groups()
        failing = next((ln.split(">|", 1)[1].strip() for ln in ctx.logs
                        if ln.startswith(f"SOURCE {fn} {path}:{lineno} ") and ">|" in ln), "")
        _add(out, "code_error_after_deploy", f"Code regression in {fn}", code,
            f"{fn} raises {exc} at {path}:{lineno} in {func}, in the version shipped in the window.",
            _alias_moved(ctx, fn),
            developers=[f"Fix {path}:{lineno} in {func} ({fn}): {exc}"
                        + (f" - the failing line is `{failing}`." if failing else "."),
                        "Add a test with the real payload shape that reached this line."],
            platform=["Canary the alias (weighted routing) with automatic rollback on the Errors metric."],
            prevention=["Contract-test the API payload so a field the code needs cannot go missing silently."])
    return out


def _fn_timeout(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    # ---- Lambda: timeout too low
    m = ctx.metrics
    out: list[Pattern] = []
    t_line = _has(ctx, "Task timed out after")
    if t_line:
        fn = _fn_of(alert, t_line)
        timeout = _metric(m, "lambda_timeout_s", alert, "lambda", fn) if fn else None
        cfg_t = re.match(r"(\d+)", _config(ctx, fn).get("timeout", "")) if fn else None
        timeout = timeout or (float(cfg_t.group(1)) if cfg_t else None)
        dur = _metric(m, "lambda_duration_max_ms", alert, "lambda", fn) if fn else None
        why = _timeout_advice(ctx, fn, timeout, dur) if fn and timeout else ""
        _add(out, "fn_timeout", "Lambda timing out", t_line,
            "The function runs longer than its configured timeout: the timeout is below what the code path "
            "needs, or a dependency slowed down.", why,
            developers=["Find the slow call (a dependency inside the handler) and give it its own shorter timeout."],
            platform=["Set the timeout from measured p99 duration with headroom, below the API's integration timeout."],
            prevention=["Alarm on Duration approaching the timeout, not only on timeouts."])
    return out


def _timeout_advice(ctx: ContextBundle, fn: str, timeout: float, dur: float | None) -> str:
    """A timeout that fits `fn`, worked out from its longest observed duration, and where its alias moved."""
    capped = dur is None or dur >= timeout * 1000 * 0.95
    new = math.ceil(timeout * 3) if capped else math.ceil(dur * 2 / 1000)
    new = min(max(new, int(timeout) + 1), 900)
    basis = (f"every invocation hit the {timeout:.0f}s limit, so the real duration is unknown: "
             f"{new}s = 3 x the current timeout" if capped else
             f"{new}s = 2 x the longest observed duration ({dur:.0f} ms), rounded up")
    return " ".join(s for s in (f"A timeout that fits: {basis}.", _alias_moved(ctx, fn)) if s)


def _fn_throttled(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    # ---- Lambda: throttled
    m = ctx.metrics
    out: list[Pattern] = []
    throttled = {_named(alert, "lambda", s) for s, v in _per(m, "lambda_throttles") if v > 0}
    throttled |= {_named(alert, "lambda", s) for s, v in _per(m, "lambda_reserved_concurrency") if v == 0}
    for fn in sorted(f for f in throttled if f):
        reserved = _metric(m, "lambda_reserved_concurrency", alert, "lambda", fn)
        thr = _metric(m, "lambda_throttles", alert, "lambda", fn) or 0.0
        _add(out, "fn_throttled", f"Lambda throttled: {fn}",
            f"lambda_throttles = {thr:.0f}" + (f", lambda_reserved_concurrency = {reserved:.0f}"
                                               if reserved is not None else ""),
            "Invocations are rejected for lack of concurrency"
            + (" - reserved concurrency 0 rejects every call." if reserved == 0 else "."),
            _concurrency(alert, ctx, fn),
            platform=["Treat reserved concurrency as reviewed configuration; alarm on Throttles > 0."],
            prevention=["Alert on Throttles directly - they are unambiguous."])
    return out


def _bad_environment(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    # ---- Lambda: bad environment
    labels = alert.labels
    out: list[Pattern] = []
    rnf = _has(ctx, "ResourceNotFoundException")
    fn = _fn_of(alert, rnf) if rnf else None
    cfg = _config(ctx, fn) if fn else {}
    if rnf and cfg:
        names, values = _env(cfg)
        table = labels.get("dynamodb_table", "")
        wrong = {k: v for k, v in (values or {}).items() if "TABLE" in k.upper() and table and v != table}
        said = [_alias_moved(ctx, fn)]
        if values and len(wrong) == 1:
            var = next(iter(wrong))
            said.append(f"{var} is `{wrong[var]}`, the labelled table is `{table}`.")
        elif not said[0]:
            said.append(f"{fn}'s environment names {', '.join(names) or 'no variables'}"
                        + ("" if values else " without their values") + "; WARDEN cannot tell which value is wrong.")
        _add(out, "missing_resource", f"{fn} calls a resource that does not exist", rnf,
            f"A resource {fn} calls does not exist; its configuration names resources through the environment "
            f"({', '.join(names)}).", " ".join(s for s in said if s),
            developers=["Validate configured resource names at cold start and fail with the name in the message."],
            platform=["Generate resource names in environment variables from the infrastructure code, not by hand."],
            prevention=["A post-deploy smoke call that exercises each dependency."])
    return out


def _access_denied(ctx: ContextBundle) -> list[Pattern]:
    # ---- IAM: a denied action
    out: list[Pattern] = []
    denied = next((ln for ln in ctx.logs if "not authorized to perform" in ln
                   and "ResourceInitializationError" not in ln), None)
    if denied:
        action = (re.search(r"perform:? (\S+)", denied) or [None, "an action"])[1]
        _add(out, "access_denied", f"Permission denied: {action}", denied,
            f"The role is not allowed {action}: a policy change removed it, or it was never granted.",
            _denied(denied),
            platform=["Keep the role's policy in infrastructure code and review diffs that remove actions."],
            prevention=["Alarm on AccessDenied in application logs; it never fixes itself."])
    return out


def _dead_letters(ctx: ContextBundle) -> list[Pattern]:
    # ---- SQS: poison message
    m = ctx.metrics
    out: list[Pattern] = []
    dlq = [v for _, v in _per(m, "dlq_visible") if v > 0]
    # A traceback that is a dependency failing (denied, missing, read-only, ...) is not a message
    # the consumer cannot process: those have their own patterns.
    # A CODE line is the parsed traceback; a raw "Traceback" line counts only when none was parsed.
    codes = [ln for ln in ctx.logs if ln.startswith(_CODE)]
    trace = next((ln for ln in codes if not any(i in ln for i in _INFRA)), None) if codes else next(
        (ln for ln in ctx.logs if "Traceback" in ln and ln.startswith("LOG lambda/")), None)
    if dlq and trace:
        q = _first(ctx, "QUEUE ", "dlq_visible=")
        dname = _kv(q).get("dlq", "") if q else ""
        _add(out, "dead_letters", "Messages failing to the dead-letter queue", q or f"dlq_visible = {dlq[0]:.0f}",
            "The consumer raises on some messages; after the queue's max receives they move to the DLQ. The "
            "traceback names the code that cannot process them.",
            "Redriving messages the consumer cannot parse sends them straight back to the DLQ, and purging them "
            "destroys data. Decide per message once the consumer handles them.",
            oncall=[(f"Read the messages in the DLQ{f' ({dname})' if dname else ''} before deciding what to do "
                     "with them.")],
            developers=[f"Handle the input that fails at `{trace[:160]}`; reject bad messages explicitly."],
            platform=["After the consumer is fixed, redrive the DLQ (SQS's dead-letter queue redrive)."],
            prevention=["Alarm on DLQ depth > 0."])
    return out


def _consumer_off(ctx: ContextBundle) -> list[Pattern]:
    # ---- SQS: consumer disabled
    m = ctx.metrics
    out: list[Pattern] = []
    esm = _first(ctx, "ESM ", "State=Disabled")
    if esm or any(v == 0 for _, v in _per(m, "lambda_esm_enabled")):
        _add(out, "consumer_off", "Queue consumer disabled", esm or "lambda_esm_enabled = 0",
            "The event source mapping is disabled: nothing reads the queue and the backlog grows.",
            platform=["Alarm on ApproximateAgeOfOldestMessage, which catches a stopped consumer whatever the cause."],
            prevention=["Audit who can disable event source mappings in production."])
    return out


def _topic_delivery_refused(ctx: ContextBundle) -> list[Pattern]:
    # ---- SNS -> SQS delivery blocked
    m = ctx.metrics
    out: list[Pattern] = []
    pol = _first(ctx, "POLICY sqs ", ":no")
    sns_failed = [v for _, v in _per(m, "sns_notifications_failed") if v > 0]
    if pol or sns_failed:
        why = ""
        if pol:
            queue = pol.split()[2]
            topic = _kv(pol).get("allows_sns_topic", "").rsplit(":", 1)[0]
            # Beside the statements the policy has: a whole-policy replace dropped them (audit A6, 2026-10-16).
            why = (f"Allow topic {topic} in {queue}'s access policy, beside the statements it already has, in the "
                   "infrastructure code that declares the queue.")
        _add(out, "topic_delivery_refused", "SNS cannot deliver to the queue",
            pol or f"sns_notifications_failed = {sns_failed[0]:.0f}",
            "The queue's access policy does not allow the topic, so deliveries are refused.", why,
            platform=["Keep queue policies in infrastructure code with the subscription they serve."],
            prevention=["Alarm on NumberOfNotificationsFailed > 0."])
    return out


def _table_throttled(ctx: ContextBundle) -> list[Pattern]:
    # ---- DynamoDB throttling
    m = ctx.metrics
    out: list[Pattern] = []
    thr = _ddb_throttles(m)
    if any(v > 0 for v in thr.values()):
        tline = _first(ctx, _TABLE)
        _add(out, "table_throttled", "DynamoDB throttling", tline or f"throttles = {sum(thr.values()):.0f}",
            "Requests exceed the table's provisioned capacity and are throttled.", _capacity(ctx),
            platform=["Use auto scaling or on-demand for tables whose load varies."],
            prevention=["Alarm on ThrottledRequests > 0 and on consumed/provisioned > 80%."])
    return out


def _cache_unreachable(ctx: ContextBundle) -> list[Pattern]:
    # ---- Redis unreachable
    out: list[Pattern] = []
    rline = next((ln for ln in ctx.logs if not ln.startswith(_STRUCTURED)
                  and re.search(r"(?i)redis|cache\.amazonaws\.com|:6379", ln)
                  and re.search(r"(?i)timeout|timed out|Error 11[01]|connection refused", ln)), None)
    if rline:
        path = _missing_cache_ingress(ctx)
        why = ""
        if path and path[2]:
            cache_sg, port, missing = path
            why = (f"The cache's security group {cache_sg} has no inbound tcp/{port} rule from "
                   f"{', '.join(missing)} - application security groups (from the Lambda, ECS and EKS "
                   "configuration WARDEN read) that must reach the cache.")
        elif path:
            why = ("Every application security group already has an ingress rule on the cache's security group, "
                   "so the break is elsewhere (subnet, route, or the cluster).")
        _add(out, "cache_unreachable", "Cache unreachable from the application", rline,
            "The application cannot open connections to the Redis endpoint - a network path (security group, "
            "subnet, route) or the cluster itself.", why,
            platform=["Check recent changes to the Redis security group's inbound rules for port 6379."],
            developers=["Give cache calls a short timeout and a fallback so a cache outage degrades, not fails."],
            prevention=["Alarm on the application's cache error rate, not only on the cluster's own health."])
    return out


def _cache_memory(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    # ---- Redis memory pressure. 90% is a named threshold; evictions are a count.
    m = ctx.metrics
    labels = alert.labels
    out: list[Pattern] = []
    ev = sum(v for _, v in _per(m, "redis_evictions"))
    mem = max((v for _, v in _per(m, "redis_memory_pct")), default=0.0)
    if ev > 0 or mem >= 90:
        group = labels.get("elasticache", "")
        # ⛔ Audit A-C-14: the node type comes only from WARDEN's own REPLGROUP read, never from any
        # line that mentions one - an application can log `node_type=` too.
        rg = _first(ctx, f"REPLGROUP {group} ") if group else None
        nt = _kv(rg).get("node_type") if rg else None
        bigger = _next_node_type(nt) if nt else None
        _add(out, "cache_memory", "Cache memory pressure", f"redis_memory_pct = {mem:.0f}, redis_evictions = {ev:.0f}",
            "The cache is near its memory limit and evicting (or refusing writes): keys without TTLs, or a working "
            "set larger than the node.",
            (f"{group} runs {nt}; the next size, {bigger}, has more memory and drops no data (the change takes "
             "minutes).") if group and bigger else "",
            developers=["Set TTLs on every cache key; find what wrote the keys that fill memory."],
            platform=["Choose maxmemory-policy deliberately (allkeys-lru for a pure cache)."],
            prevention=["Alarm on DatabaseMemoryUsagePercentage > 80% and Evictions > 0."])
    return out


def _db_connections_refused(ctx: ContextBundle) -> list[Pattern]:
    # ---- Aurora: connections exhausted
    out: list[Pattern] = []
    full = _has(ctx, "too many clients", "remaining connection slots are reserved")
    if full:
        _add(out, "db_connections_refused", "Database refusing new connections", full,
            "Every connection slot is taken; new clients are refused. Idle sessions held open are the usual cause.",
            ("Sessions idle outside a transaction can be ended without losing work - their clients reconnect. "
             "Find which application holds them first."),
            dba=["Set idle_session_timeout for application roles; put a pooler (RDS Proxy) in front of Lambdas."],
            developers=["Close or return connections; one pool per process, sized to its concurrency."],
            prevention=["Alarm at 80% of max_connections with a per-application breakdown."])
    return out


def _db_read_only(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    # ---- Aurora: writes reaching a read-only instance
    labels = alert.labels
    out: list[Pattern] = []
    ro = _has(ctx, "read-only transaction")
    if ro:
        fn = _fn_of(alert, ro)
        cl = _first(ctx, "CLUSTER aurora ")
        ck = _kv(cl) if cl else {}
        cluster = cl.split()[2] if cl else labels.get("aurora_cluster", "")
        readers = [r for r in ck.get("readers", "[]").strip("[]").split(",") if r]
        failover = next((ln for ln in ctx.logs if ln.startswith("EVENT aurora ") and "failover" in ln.lower()), None)
        why = _db_host(ctx, fn, cluster, [ck.get("writer", ""), *readers]) if fn else ""
        if failover and not why and cluster and len(readers) == 1:
            why = (f"Failing back would make {readers[0]} - the former writer the application is pinned to - the "
                   "writer again. Writes pause for the switch; the lasting fix is the cluster endpoint.")
        common = {"developers": ["Connect writers to the cluster (writer) endpoint, never an instance or -ro endpoint."],
                  "prevention": ["A startup check: `SHOW transaction_read_only` must be off for a writer."]}
        if failover:
            _add(out, "db_pinned_after_failover", "Writes fail after an Aurora failover",
                f"{failover[:120]} | {ro[:80]}",
                "The cluster failed over; the application is pinned to an instance endpoint that is now a reader.",
                why, **common)
        else:
            _add(out, "db_write_on_reader", "Writes sent to a read-only Aurora endpoint", ro,
                "The application's database host is a reader: every write fails.", why, **common)
    return out


def _ecs_tasks(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    # ---- ECS: image cannot be pulled, task OOM
    out: list[Pattern] = []
    pull = _has(ctx, "CannotPullContainerError")
    if pull:
        _add(out, "task_image_pull", "ECS tasks cannot pull their image", pull,
            "The task definition references an image that cannot be pulled - usually a tag that does not exist.",
            _ecs_before(alert, ctx),
            platform=["Deploy image digests from the build; gate deploys on the image existing in ECR."],
            prevention=["Alarm on failed task starts for the service."])
    task_oom_line = next((ln for ln in ctx.logs if (ln.startswith("LOG ecs/") or "OutOfMemory" in ln)
                    and re.search(r"(?i)OutOfMemory|exit code:? 137|exitCode[=:] ?137", ln)), None)
    if task_oom_line:
        _add(out, "task_oom", "ECS tasks killed for memory", task_oom_line,
            "A container exceeded its task memory and was killed (exit 137).", _ecs_before(alert, ctx),
            developers=["Measure the service's peak memory; find the allocation that grew."],
            platform=["Size task memory from measured peak + headroom; alarm on MemoryUtilization."])
    return out


def _task_secret_denied(ctx: ContextBundle) -> list[Pattern]:
    # ---- ECS: secret cannot be read at task start
    out: list[Pattern] = []
    init = next((ln for ln in ctx.logs if "ResourceInitializationError" in ln and re.search(r"(?i)secret", ln)), None)
    if init:
        _add(out, "task_secret_denied", "ECS tasks cannot read their secret", init,
            "The task execution role cannot read the secret the task definition injects, so no task starts.",
            _denied(init),
            platform=["Keep secretsmanager:GetSecretValue for the task's secrets in the execution role's policy."],
            prevention=["Alarm on tasks stopped with ResourceInitializationError."])
    return out


def _lb_health_check(ctx: ContextBundle) -> list[Pattern]:
    # ---- ALB health check path wrong
    out: list[Pattern] = []
    tgt = _first(ctx, "TARGET ", "ResponseCodeMismatch")
    if tgt:
        tg = tgt.split()[1]
        tgl = _first(ctx, f"TARGETGROUP {tg} ")
        bad = _kv(tgl).get("health_path") if tgl else None
        # ⛔ Audit A-C-14: the working path used to be read from the application's access log, which
        # any client writes by requesting a path. It is restored from where it is declared.
        _add(out, "lb_health_check", "Load balancer health check failing", tgt,
            "Targets fail the target group's health check with an unexpected status code: the check's path or "
            "port does not match the application.",
            ("The target group checks `" + str(bad) + "`, and the working health path is not in WARDEN's own "
             "reads. Restore it from the infrastructure code that declares the target group (never from the "
             "application's logs)."),
            platform=["Keep the health check path next to the route definition in infrastructure code."],
            prevention=["Alarm on UnHealthyHostCount > 0."])
    return out


def _stale_credentials(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    # ---- Stale credentials after a secret rotation
    labels = alert.labels
    out: list[Pattern] = []
    auth = _has(ctx, "password authentication failed")
    changed = _first(ctx, "SECRET ", "changed") or ("secret changed in the window" if _deploy(ctx, "secret") else None)
    if auth and changed:
        src = _source_of(auth)
        svc = labels.get("ecs_service")
        why = ""
        if src and src[0] == "ecs" and svc:
            why = f"New tasks of {svc} read the secret at start, so they get the current password."
        elif src and src[0] == "k8s" and "/" in src[1]:
            why = f"New pods of {src[1]} read the current secret."
        _add(out, "stale_credentials", "Stale database credentials after a secret change",
            f"{auth[:110]} | {changed[:80]}",
            "The database password changed (the secret changed in the window) but the running workload still "
            "uses the one it read at start.", why,
            developers=["Re-read the secret on authentication failure instead of only at start."],
            platform=["Make rotation restart its consumers (or use dual-user rotation)."])
    return out


def _db_iam_auth_refused(ctx: ContextBundle) -> list[Pattern]:
    # ---- IAM database authentication refused (Aurora: the signing identity lost rds-db:connect)
    out: list[Pattern] = []
    pam = next((ln for ln in ctx.logs if "PAM authentication failed for user" in ln), None)
    if pam:
        _add(out, "db_iam_auth_refused", "Database refuses the application's IAM login", pam[-160:],
            "Aurora refused an IAM database token: the identity that signed it is no longer allowed "
            "rds-db:connect for that database user (a policy change removed it), or the user lost rds_iam.",
            _db_iam_refused(ctx, pam),
            platform=["Keep rds-db:connect in the workload role's policy in infrastructure code; review diffs that remove it."],
            prevention=["Alarm on `PAM authentication failed` in application logs; it never fixes itself."])
    return out


def _k8s_pods(ctx: ContextBundle) -> list[Pattern]:
    # ---- Kubernetes: missing secret key, unschedulable
    out: list[Pattern] = []
    cfgerr = _has(ctx, "CreateContainerConfigError", "couldn't find key")
    if cfgerr:
        _add(out, "secret_key_missing", "Pod references a secret key that does not exist", cfgerr,
            "A container's env references a key the Secret no longer has, so the container cannot be created.",
            "WARDEN never reads secret values, so it cannot say what the missing key held.",
            platform=["Restore the key in the Secret from its source of truth; the pods then start on their own."],
            prevention=["Check that every referenced secret key exists before applying a Secret change."])
    sched = next((ln for ln in ctx.logs if "FailedScheduling" in ln and "Insufficient" in ln), None)
    if sched:
        _add(out, "unschedulable", "Pods cannot be scheduled", sched,
            "No node has the resources the pod requests - the requests exceed what any node can offer.",
            "If the last deploy raised the pods' requests, rolling it back returns them to what fitted.",
            platform=["Set requests from measured usage; a LimitRange caps what one pod can request."],
            prevention=["Alert on Pending pods older than a few minutes."])
    return out


def _schedule_off(alert: Alert, ctx: ContextBundle) -> list[Pattern]:
    # ---- EventBridge rule disabled
    m = ctx.metrics
    out: list[Pattern] = []
    rule = _first(ctx, "RULE ", "State=DISABLED")
    off = [s for s, v in _per(m, "rule_enabled") if v == 0]
    if rule or off:
        _add(out, "schedule_off", "Scheduled rule disabled", rule or "rule_enabled = 0",
            "The EventBridge rule is disabled, so its target is never invoked.",
            # Not where the alert IS such an alarm (live, 2026-10-12: the follow-up asked for the alarm that fired).
            platform=[] if alert.labels.get("alarm") else [
                "Alarm on the target's Invocations dropping to zero for scheduled work."])
    return out
