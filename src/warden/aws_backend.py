"""A real evidence backend: read a live AWS account — CloudWatch Logs, CloudWatch metrics, ECS.

Drops into `gather(alert, backend=AwsBackend())` with no change above it — the three-method
contract (`logs` / `metrics` / `deploys`) is the one `FixtureBackend` and `KubernetesBackend`
already satisfy.

Why this module exists at all: `terraform/main.tf` granted the task role ten read actions and,
until this file, **nothing in the package called any of them**. The IAM policy described a
capability the code did not have. This module makes exactly four calls, the policy now grants
exactly those four, and a test asserts set equality in both directions:

    cloudwatch:GetMetricData   ecs:DescribeServices
    ecs:DescribeTaskDefinition logs:FilterLogEvents

The other six were removed rather than used: a standing grant on a production account that no code
path calls is the finding every least-privilege review actually produces.

Things that are deliberate, most of them carried over from what an adversarial review and a live
cluster taught the Kubernetes backend:

1. **Read-only.** Every call above is a read. A test greps this module for write-shaped API names —
   but that grep is a tripwire, not the boundary. **The task role is the boundary**: the role in
   `terraform/` cannot mutate anything, so a bug here cannot either. Run it locally with an admin
   profile and the boundary is whatever that profile allows — say so rather than pretend otherwise.

2. **Every client call carries connect and read timeouts, and retries are capped at one attempt.**
   botocore's default is up to three tries with exponential backoff, which turns one stalled API
   read into a multiple of the tool budget. `gather()` stops waiting after its deadline and the
   abandoned thread then blocks the interpreter at exit — the failure mode reproduced live against
   Kubernetes. ⚠ Connect + read (2 s + 3 s) sum to the whole default 5 s tool budget in the worst
   case; a single very slow call can therefore consume the whole budget for that tool. That is a
   real limit, not a hidden one — raise `WARDEN_TOOL_TIMEOUT` for large log groups.

3. **Metrics are real utilisation here, unlike the Kubernetes backend.** CloudWatch actually has
   CPU and memory for an ECS service, so `cpu_utilization_pct` means what it says. Task counts come
   from `DescribeServices`, which is exact rather than sampled. Keys are named for what they hold.

4. **No matching service is an ERROR, not a clean bill of health.** A typo in the cluster or
   service name would otherwise yield zeroed metrics that the verifier reads as "inspected, fine".
   It raises, which lands in `tool_errors` and fires the partial-context policy P8.

5. **Log reads are scoped to this service's log group**, and bounded by both an event limit and a
   time window. An unbounded `FilterLogEvents` on a busy group returns megabytes and blows the
   budget in step 2.

6. **A deploy is a TASK DEFINITION IMAGE CHANGE, not a new deployment record.**
   `aws ecs update-service --force-new-deployment` is the exact ECS analogue of
   `kubectl rollout restart`: it creates a fresh deployment with the *same* task definition. Taking
   any deployment record as a deploy would satisfy policy P5's "a recent deploy exists" evidence
   for a rollback that cannot possibly help. So the running revision's images are compared with the
   previous revision's, fetched by `family:revision-1` — which is why `ecs:DescribeTaskDefinition`
   is in the policy and `ecs:ListTaskDefinitions` is not needed.

7. **Task counts come from the service, not from a task listing.** `DescribeServices` already
   reports running / desired / pending exactly, so `ecs:ListTasks` buys nothing and is not granted.

8. **A partial failure is reported as a partial failure.** A log group that does not exist, or a
   previous task definition that cannot be read, is emitted with the `TOOL-PARTIAL` prefix that
   `gather()` routes into `tool_errors`. ⭐ In particular, when the previous revision cannot be
   read the deploy is **not** reported: an unprovable template change must not become evidence for
   a rollback. Partial context is visible; a fabricated deploy is not.

Mapping from an alert to a workload:
    cluster    = alert.labels["cluster"]     or $WARDEN_AWS_CLUSTER   (required — no default)
    service    = alert.labels["ecs_service"] or alert.service
    log group  = alert.labels["log_group"]   or $WARDEN_AWS_LOG_GROUP or f"/ecs/{service}"
    region     = alert.labels["region"]      or $WARDEN_AWS_REGION    or boto3's own chain

`boto3` is an optional extra (`pip install -e ".[aws]"`), imported lazily.
"""

from __future__ import annotations

import functools
import os
import re
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from .models import Alert
from .tools import PARTIAL_PREFIX, Metrics, ToolError, alert_time, deploy_in_window, failure

# (connect, read) seconds. See note 2 in the module docstring about the budget.
CONNECT_TIMEOUT = float(os.environ.get("WARDEN_AWS_CONNECT_TIMEOUT", "2.0"))
READ_TIMEOUT = float(os.environ.get("WARDEN_AWS_READ_TIMEOUT", "3.0"))

# How far back a task-definition change counts as "recent" — this window IS the evidence policy P5
# asks for before permitting a rollback.
RECENT_DEPLOY_WINDOW = timedelta(hours=float(os.environ.get("WARDEN_AWS_DEPLOY_WINDOW_H", "6")))
# How far back to read logs and metrics from the alert's own start time.
LOG_LOOKBACK = timedelta(minutes=float(os.environ.get("WARDEN_AWS_LOG_LOOKBACK_M", "15")))
METRIC_WINDOW = timedelta(minutes=float(os.environ.get("WARDEN_AWS_METRIC_WINDOW_M", "10")))
# Hard caps. FilterLogEvents pages; without a cap one busy group eats the whole tool budget.
LOG_EVENT_LIMIT = int(os.environ.get("WARDEN_AWS_LOG_LIMIT", "200"))
LOG_MAX_LINES = int(os.environ.get("WARDEN_AWS_LOG_MAX_LINES", "120"))
LOG_MAX_PAGES = int(os.environ.get("WARDEN_AWS_LOG_MAX_PAGES", "10"))
# Read first: the minutes before the alert up to the window's end. Pages run oldest-first, so a window larger than
# the page budget lost exactly the alert-time lines (audit A-B-M5); the earlier part takes the pages left.
LOG_NEAR = timedelta(minutes=float(os.environ.get("WARDEN_AWS_LOG_NEAR_M", "5")))
# Older error-looking events kept on top of the newest LOG_MAX_LINES when a window is truncated.
LOG_ERROR_EXTRA = 30
_ERRORISH = re.compile(r"(?i)error|exception|traceback|denied|not authorized|fail|timed out|refused|throttl")
# CloudWatch period in seconds. 60 is the finest granularity ECS service metrics are published at.
METRIC_PERIOD_S = int(os.environ.get("WARDEN_AWS_METRIC_PERIOD_S", "60"))



def _in_environment(read: Any) -> Any:
    """A read of one incident, in its environment's reader role when the runtime names one (AwsBackend._bind)."""
    @functools.wraps(read)
    def wrapper(self: AwsBackend, alert: Alert, *args: Any, **kwargs: Any) -> Any:
        self._bind(alert)
        return read(self, alert, *args, **kwargs)
    return wrapper


class _LazyClients(dict):
    """boto3 clients made when first used: the stack backend reads up to forty services, and an incident needs a few."""

    def __init__(self, session: Any, cfg: Any, services: tuple[str, ...] = ()) -> None:
        super().__init__()
        self.session, self.cfg = session, cfg  # public names: the client-call scans read self._<client> as a call
        self.lock = threading.Lock()  # readers run in parallel threads, and a boto3 session is not thread-safe
        for n in services:
            self[n] = session.client(n, config=cfg)

    def __missing__(self, name: str) -> Any:
        with self.lock:
            if name not in self:
                self[name] = self.session.client(name, config=self.cfg)
            return dict.__getitem__(self, name)


def _reader_clients(session: Any, cfg: Any, template: str,
                    services: tuple[str, ...] = ("logs", "cloudwatch", "ecs")) -> Any:
    """Per (environment, incident): `services`' clients in `warden-<env>-platform-reader`, assumed with the worker's
    own credentials and the incident as SourceIdentity; kept 10 minutes of the 15-minute session."""
    import boto3

    from . import identity
    from .environments import default_environment_policies

    known = set(default_environment_policies().known_environments)
    sts = session.client("sts", config=cfg)
    held: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
    lock = threading.Lock()

    def clients(env: str, incident: str) -> dict[str, Any]:
        if env not in known:
            raise ToolError(f"{env!r} is not a configured environment: nothing was read")
        # The watched environments' reader roles trust SourceIdentity inc-* only (iam/templates/platform-reader-
        # trust.json): the bare alert id was refused (2026-10-09). One correlation id, `inc-<alert id>`.
        key = (env, (incident if incident.startswith("inc-") else f"inc-{incident}")[:64])
        with lock:
            hit = held.get(key)
            if hit and hit[0] > time.monotonic():
                return hit[1]
        try:
            creds = identity.reader_session(sts, role_arn=template.format(env=env, role="platform-reader"),
                                            incident=key[1])
        except Exception as exc:
            raise ToolError(f"could not read {env}: its reader role was refused ({_one_line(exc)})") from exc
        s = boto3.session.Session(**creds, region_name=session.region_name)
        made = _LazyClients(s, cfg, services)
        with lock:
            now = time.monotonic()
            for k in [k for k, (until, _) in held.items() if until <= now]:  # an expired session is let go (M7)
                del held[k]
            held[key] = (now + 600, made)
        return made

    return clients


class AwsBackend:
    """Reads logs, metrics and rollout history for the ECS service an alert points at."""
    reads_live_store = True  # its store receives log lines late: evidence waits for them (R23)


    name = "aws"

    def __init__(self, *, logs=None, cloudwatch=None, ecs=None, region: str | None = None) -> None:
        own = logs is None and cloudwatch is None and ecs is None  # nothing injected: this backend makes its clients
        # Injectable clients so the unit tests can stub the API without an AWS account.
        if logs is None or cloudwatch is None or ecs is None:
            try:
                import boto3
                from botocore.config import Config
            except ImportError as exc:  # boto3 is an optional extra
                raise ToolError(
                    "WARDEN_BACKEND=aws needs the AWS SDK: pip install -e '.[aws]'"
                ) from exc

            cfg = Config(
                connect_timeout=CONNECT_TIMEOUT,
                read_timeout=READ_TIMEOUT,
                # One attempt, no backoff. See note 2: botocore's default of three would multiply
                # a stalled read past the tool deadline.
                retries={"max_attempts": 1, "mode": "standard"},
                user_agent_extra="warden",
            )
            region = region or os.environ.get("WARDEN_AWS_REGION") or None
            try:
                session = boto3.session.Session(region_name=region)
                logs = logs or session.client("logs", config=cfg)
                cloudwatch = cloudwatch or session.client("cloudwatch", config=cfg)
                ecs = ecs or session.client("ecs", config=cfg)
            except Exception as exc:
                raise ToolError(
                    "WARDEN_BACKEND=aws but no usable AWS credentials or region were found "
                    f"(task role, profile or environment): {_one_line(exc)}"
                ) from exc
        self._base = {"logs": logs, "cloudwatch": cloudwatch, "ecs": ecs}
        self._bound = threading.local()  # the incident's own clients, per worker thread (_bind)
        template = os.environ.get("WARDEN_AWS_ROLE_ARN_TEMPLATE", "").strip()
        self._per_env = _reader_clients(session, cfg, template) if template and own else None

    def _client(self, name: str) -> Any:
        """The clients of the incident being read (_bind), else the ones this backend was made with or given."""
        bound = vars(self).get("_bound")
        return ((vars(bound).get("clients") if bound is not None else None) or vars(self).setdefault("_base", {}))[name]

    def _give(self, name: str, client: Any) -> None:
        vars(self).setdefault("_base", {})[name] = client

    _logs = property(lambda self: self._client("logs"), lambda self, c: self._give("logs", c))
    _cw = property(lambda self: self._client("cloudwatch"), lambda self, c: self._give("cloudwatch", c))
    _ecs = property(lambda self: self._client("ecs"), lambda self, c: self._give("ecs", c))

    def _bind(self, alert: Alert) -> None:
        """In the cloud runtime (WARDEN_AWS_ROLE_ARN_TEMPLATE) every read of an incident runs in its own environment's
        reader role, `warden-<env>-platform-reader`, under the incident's name (SourceIdentity) - never the worker's
        own role, which may read no watched environment (2026-10-09: the evidence reader used the worker's
        credentials). An environment the policy does not know is refused before any call."""
        if vars(self).get("_per_env") is not None:
            self._bound.clients = self._per_env(alert.environment, alert.alert_id)

    # ------------------------------------------------------------------ alert -> workload

    @staticmethod
    def _cluster(alert: Alert) -> str:
        cluster = alert.labels.get("cluster") or os.environ.get("WARDEN_AWS_CLUSTER", "")
        if not cluster:
            # No default. "default" is a real ECS cluster name, so guessing it would point the
            # whole investigation at the wrong account-shaped thing and still return data.
            raise ToolError(
                "WARDEN_BACKEND=aws needs a cluster: set WARDEN_AWS_CLUSTER or the alert label "
                "'cluster'"
            )
        return cluster

    @staticmethod
    def _service(alert: Alert) -> str:
        return alert.labels.get("ecs_service") or alert.service

    @classmethod
    def _log_group(cls, alert: Alert) -> str:
        return (
            alert.labels.get("log_group")
            or os.environ.get("WARDEN_AWS_LOG_GROUP")
            or f"/ecs/{cls._service(alert)}"
        )

    @staticmethod
    def _started_at(alert: Alert) -> datetime:
        """The alert's own start time, or now if it cannot be parsed.

        Never raises: an unparseable timestamp must not lose the logs, and `now` is the honest
        fallback — it reads the most recent window rather than a window from 1970.
        """
        return alert_time(alert)

    def _describe_service(self, alert: Alert) -> dict:
        """The one ECS read every method needs. Missing service raises — see note 4."""
        cluster, service = self._cluster(alert), self._service(alert)
        resp = self._ecs.describe_services(cluster=cluster, services=[service])
        services = resp.get("services") or []
        # ECS answers a missing service with HTTP 200 and a `failures` entry, not an exception.
        # Treating that as "no data" would hand the verifier six zeroes that look like health.
        live = [s for s in services if s.get("status") != "INACTIVE"]
        if not live:
            failures = "; ".join(
                f"{f.get('arn', '?')}: {f.get('reason', '?')}" for f in resp.get("failures") or []
            )
            raise ToolError(
                f"no active ECS service '{service}' in cluster '{cluster}'"
                + (f" ({failures})" if failures else ""),
                outcome="not found",
            )
        return live[0]

    # ------------------------------------------------------------------ the three tools

    @_in_environment
    def logs(self, alert: Alert) -> list[str]:
        """Recent log events for this service's log group, newest window first."""
        group = self._log_group(alert)
        started = self._started_at(alert)
        start_ms = int((started - LOG_LOOKBACK).timestamp() * 1000)
        end_ms = int((started + LOG_LOOKBACK).timestamp() * 1000)

        base: dict[str, object] = {"logGroupName": group, "limit": LOG_EVENT_LIMIT}
        prefix = alert.labels.get("log_stream_prefix")
        if prefix:
            base["logStreamNamePrefix"] = prefix
        near_ms = int((started - LOG_NEAR).timestamp() * 1000)
        windows = [(near_ms, end_ms), (start_ms, near_ms - 1)] if start_ms < near_ms < end_ms else [(start_ms, end_ms)]

        # ⛔ The WHOLE window, then the NEWEST lines. filter_log_events pages oldest-first, and this
        # used to keep the first page's first 120 lines: in Wave 4 (fs-05, 2026-09-26) every kept line
        # predated the fault, and the AccessDenied lines that named the cause were the ones dropped.
        events: list[dict] = []
        partial: list[str] = []
        pages = LOG_MAX_PAGES
        try:
            for lo, hi in windows:
                kwargs: dict[str, object] = {**base, "startTime": lo, "endTime": hi}
                while pages > 0:
                    pages -= 1
                    resp = self._logs.filter_log_events(**kwargs)
                    events += resp.get("events") or []
                    token = resp.get("nextToken")
                    if not token:
                        break
                    kwargs["nextToken"] = token
                else:
                    partial.append(f"{PARTIAL_PREFIX}logs: [output truncated] stopped after {LOG_MAX_PAGES} pages, "
                                   f"{'before reaching the alert time' if lo == start_ms and len(windows) == 1 else 'the alert-time lines read first'} "
                                   "(raise WARDEN_AWS_LOG_MAX_PAGES to read the rest of the window)")
                    break
        except Exception as exc:  # noqa: BLE001 - a missing group is data, not a crash
            if not events:
                return [f"{PARTIAL_PREFIX}logs: {group}: {failure(exc)}"]
            partial.append(f"{PARTIAL_PREFIX}logs: {group}: {failure(exc)}")

        lines: list[str] = []
        for event in sorted(events, key=lambda e: e.get("timestamp") or 0):
            message = str(event.get("message", "")).rstrip()
            if message:
                # ⛔ "LOG " first (2026-09-27 audit). The line used to START with the stream name, and
                # anyone holding logs:CreateLogStream (every task and function role) chooses that
                # name - spaces allowed. A stream named "CONFIG payments-api ..." became a TRUSTED C
                # item, and one named "TOOL-PARTIAL ..." a failed-read T item, both citable.
                lines.append(f"LOG {_stream(event.get('logStreamName'))} {_ms_to_iso(event.get('timestamp'))} {message}")
        if len(lines) > LOG_MAX_LINES:
            cut = len(lines) - LOG_MAX_LINES
            older_errors = [ln for ln in lines[:cut] if _ERRORISH.search(ln)][-LOG_ERROR_EXTRA:]
            dropped = cut - len(older_errors)
            lines = older_errors + lines[cut:]
            partial.append(f"{PARTIAL_PREFIX}logs: [output truncated] kept the newest {LOG_MAX_LINES} lines and "
                           f"{len(older_errors)} older error line(s), dropped {dropped} "
                           "(raise WARDEN_AWS_LOG_MAX_LINES to see more)")
        return lines + partial

    @_in_environment
    def metrics(self, alert: Alert) -> dict[str, float]:
        """Task counts from ECS (exact) and utilisation from CloudWatch (sampled).

        Utilisation keys are omitted rather than zeroed when CloudWatch has no datapoint: a service
        that has published nothing yet is not a service at 0% CPU, and the difference decides
        whether the verifier sees evidence or an absence.
        """
        service = self._describe_service(alert)

        out: dict[str, float] = {
            "tasks_running": float(service.get("runningCount") or 0),
            "tasks_desired": float(service.get("desiredCount") or 0),
            "tasks_pending": float(service.get("pendingCount") or 0),
        }
        deployments = service.get("deployments") or []
        out["deployments_in_flight"] = float(len(deployments))
        # rolloutState FAILED means ECS gave up rolling forward — the strongest single signal here.
        out["deployments_failed"] = float(
            sum(1 for d in deployments if d.get("rolloutState") == "FAILED")
        )
        # ⛔ THE SIGNAL A REAL ACCOUNT PROVED WAS MISSING. `deployments_failed` above counts
        # deployments ECS has marked FAILED — and ECS only ever sets that when the deployment
        # circuit breaker is enabled, which the proving ground does not enable. So it was
        # structurally always 0, while tasks that start, crash and are replaced forever leave
        # `runningCount == desiredCount`, nothing pending and no failed deployment.
        #
        # The result: on a benchmark wave against a live account, two fault classes whose new tasks
        # were dying in a loop (a bad secret reference, a failing container health check) were
        # answered "no action needed" in all three runs each — because the evidence handed to the
        # model said the service was at its desired count and nothing had failed.
        #
        # `failedTasks` rides in the SAME DescribeServices response this method already reads, so
        # there is no extra API call and no extra IAM action. It is the number an operator reads off
        # the console first. See docs/bench/wave1-2026-09-11T155744Z.
        out["deployment_failed_tasks"] = float(
            sum(int(d.get("failedTasks") or 0) for d in deployments)
        )

        started = self._started_at(alert)
        stats, partial = self._utilisation(alert, started)
        out.update(stats)
        return Metrics(out, partial=partial)

    def _utilisation(self, alert: Alert, started: datetime) -> tuple[dict[str, float], list[str]]:
        """CPU and memory for the service over the window around the alert, and what could not be read."""
        cluster, service = self._cluster(alert), self._service(alert)
        dimensions = [
            {"Name": "ClusterName", "Value": cluster},
            {"Name": "ServiceName", "Value": service},
        ]
        queries = [
            {
                "Id": f"m{i}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/ECS",
                        "MetricName": metric,
                        "Dimensions": dimensions,
                    },
                    "Period": METRIC_PERIOD_S,
                    "Stat": "Maximum",
                },
                "ReturnData": True,
            }
            for i, metric in enumerate(("CPUUtilization", "MemoryUtilization"))
        ]
        try:
            resp = self._cw.get_metric_data(
                MetricDataQueries=queries,
                StartTime=started - METRIC_WINDOW,
                EndTime=started + METRIC_WINDOW,
                ScanBy="TimestampDescending",
            )
        except Exception as exc:  # noqa: BLE001
            # Utilisation is supporting evidence; the exact task counts above are the load-bearing
            # part. Losing it must not lose them, and an omitted key reads as absent, not as zero -
            # but the failure is said (audit A-B-M18), so absent is not mistaken for "not elevated".
            return {}, [f"utilisation: {failure(exc)}"]

        keys = {"m0": "cpu_utilization_pct", "m1": "memory_utilization_pct"}
        out: dict[str, float] = {}
        partial: list[str] = []
        for result in resp.get("MetricDataResults") or []:
            values = result.get("Values") or []
            key = keys.get(result.get("Id", ""))
            if key and result.get("StatusCode") not in (None, "Complete"):
                partial.append(f"utilisation: {key} {result['StatusCode']} (the series may be incomplete)")
            if key and values:
                out[key] = float(max(values))
        return out, partial

    @_in_environment
    def deploys(self, alert: Alert) -> list[dict[str, str]]:
        """A recent TASK DEFINITION IMAGE CHANGE for this service, or nothing.

        See note 6: a `--force-new-deployment` bumps the deployment without changing an image and
        is therefore NOT a deploy.
        """
        service = self._describe_service(alert)
        deployments = service.get("deployments") or []
        primary = next(
            (d for d in deployments if d.get("status") == "PRIMARY"),
            deployments[0] if deployments else None,
        )
        if primary is None:
            return []

        created = _aware(primary.get("createdAt"))
        if not deploy_in_window(alert, created, RECENT_DEPLOY_WINDOW):
            return []  # nothing changed in the window before the alert; P5 then refuses a rollback

        task_def_arn = primary.get("taskDefinition") or service.get("taskDefinition") or ""
        family, revision = _family_revision(task_def_arn)
        if not family:
            return [f"{PARTIAL_PREFIX}deploys: [failed (unclassified)] unparseable task definition '{task_def_arn}'"]

        try:
            current = self._task_definition(f"{family}:{revision}")
        except Exception as exc:  # noqa: BLE001
            return [f"{PARTIAL_PREFIX}deploys: {family}:{revision}: {failure(exc)}"]
        current_images = _images_of(current)

        # ⛔ WHAT TO COMPARE AGAINST, AND WHY revision-1 IS WRONG.
        #
        # This used to compare revision N against revision N-1, assuming the previously REGISTERED
        # revision is the previously DEPLOYED one. A real account breaks that assumption constantly:
        # CI registers revisions that are never rolled out, a rollback leaves a gap, and a benchmark
        # wave registers one variant per scenario. Measured against a live account, seven scenarios
        # in a row deployed checkout:7 through checkout:13, so each was compared with the PREVIOUS
        # SCENARIO's variant rather than with what was actually running - identical images, so
        # WARDEN reported NO DEPLOY for a genuine deploy, and P5-NO-DEPLOY-TO-ROLL-BACK then
        # rejected the correct rollback.
        #
        # ECS already answers this properly: during a rollout `describe_services` returns the
        # PRIMARY deployment alongside the ACTIVE one it is replacing. Use that, and fall back to
        # revision-1 only when there is nothing else to compare with.
        previous_arn = next(
            (d.get("taskDefinition") for d in deployments
             if d is not primary and d.get("taskDefinition")),
            "",
        )
        previous_ref = ""
        rolled_back_from = ""
        if previous_arn:
            prev_family, prev_revision = _family_revision(previous_arn)
            if prev_family == family and prev_revision > revision:
                # A ROLLBACK: the revision being replaced is newer than the one going live - ECS's circuit breaker or a
                # person stepping back. Reported as a change, but with nothing to roll back to: the "previous" here is
                # the broken revision, and a rollback aimed at it redeployed it (audit A-B-M6).
                rolled_back_from = f"{prev_family}:{prev_revision}"
            elif prev_family:
                # ⛔ Used, even when it is the SAME revision as PRIMARY. That is exactly what a
                # `--force-new-deployment` looks like — a new deployment record pointing at the
                # unchanged task definition — and the images then compare equal, so it is correctly
                # not a deploy. Skipping it here and falling through to revision-1 would report a
                # restart as a deploy, which is the single defect this whole comparison exists to
                # prevent. A test asserts it.
                previous_ref = f"{prev_family}:{prev_revision}"
        if not previous_ref and not rolled_back_from and revision > 1:
            previous_ref = f"{family}:{revision - 1}"

        previous_images: list[str] = []
        if previous_ref:
            try:
                previous_images = _images_of(self._task_definition(previous_ref))
            except Exception as exc:  # noqa: BLE001
                # ⭐ The important branch. Without the previous revision we cannot tell a real
                # deploy from a force-new-deployment, and reporting it anyway would let policy P5
                # approve a rollback on a restart. Report the gap; report no deploy.
                # Tagged at the source like every tool error: the model reads only the tag.
                gap = (
                    f"{PARTIAL_PREFIX}deploys: {failure(exc)} (previous revision {previous_ref} "
                    "unreadable, cannot prove a template change)"
                )
                return [gap]
            if previous_images == current_images:
                return []  # deployment moved, task definition did not: a restart, not a deploy

        if rolled_back_from:
            try:
                previous_images = _images_of(self._task_definition(rolled_back_from))
            except Exception:  # noqa: BLE001 - the images are context only; the rollback is reported either way
                previous_images = []
        out = {
            "service": self._service(alert),
            "revision": str(revision),
            "image": ",".join(current_images),
            "previous_image": ",".join(previous_images),
            # family:revision of both sides, so a rollback command can be aimed without a lookup.
            "task_definition": f"{family}:{revision}",
            "previous_task_definition": previous_ref,
            # WHEN IT REACHED PRODUCTION. Deliberately the deployment's creation, not the task
            # definition's registration: the question policy P5 asks is "did something change in
            # front of users near this alert?", and a revision can sit registered for weeks.
            "at": created.isoformat(),
            "by": "ecs",
        }
        # ...but the registration time is worth carrying beside it, because the two being far
        # apart is itself a signal: a revision built long ago and rolled out now is a different
        # kind of event from one built and shipped in the same minute.
        if rolled_back_from:
            out["rolled_back_from"] = rolled_back_from
        registered = _aware((current or {}).get("registeredAt"))
        if registered is not None:
            out["registered_at"] = registered.isoformat()
        return [out]

    def _task_definition(self, task_definition: str) -> dict:
        resp = self._ecs.describe_task_definition(taskDefinition=task_definition)
        return resp.get("taskDefinition") or {}


# --------------------------------------------------------------------------- helpers


def _images_of(task_definition: dict) -> list[str]:
    """Every container image in a task definition, sorted.

    Sorted so the comparison in `deploys()` is order-independent: ECS preserves the order the
    definition was registered in, and a re-registration that only reorders containers is not a
    deploy.

    ⚠ **Images only, deliberately, and this is a real limit.** A revision that changes a command,
    an environment variable or a memory reservation while keeping the same image is NOT reported as
    a deploy. That matches the Kubernetes backend, and it matches what the remediation is: the
    rollback action WARDEN proposes swaps the image. A config-only change is a real change and this
    will not see it.
    """
    containers = task_definition.get("containerDefinitions") or []
    return sorted(str(c.get("image") or "") for c in containers)


def _aware(dt: datetime | None) -> datetime | None:
    """boto3 returns tz-aware datetimes; a stub might not. Never let that raise."""
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _family_revision(arn: str) -> tuple[str, int]:
    """Split `arn:aws:ecs:eu-west-1:123:task-definition/web:7` into ("web", 7).

    Returns ("", 0) rather than raising: an unrecognised ARN shape is reported as a partial
    failure by the caller, which is more useful than a traceback during an incident.
    """
    tail = arn.rsplit("/", 1)[-1]
    family, _, rev = tail.rpartition(":")
    if not family:
        return "", 0
    try:
        return family, int(rev)
    except ValueError:
        return "", 0


_STREAM_UNSAFE = re.compile(r"[^A-Za-z0-9_./#$\[\]:-]")


def _stream(name) -> str:
    """A log stream name as one token (audit A-C-3): whoever can create a stream chooses its name,
    spaces included, and the name sits where WARDEN's own line structure is."""
    return _STREAM_UNSAFE.sub("_", str(name or "?"))[:256] or "?"


def _ms_to_iso(timestamp) -> str:
    try:
        return datetime.fromtimestamp(int(timestamp) / 1000, tz=UTC).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return "?"


def _one_line(value) -> str:
    """botocore's ClientError str() carries the whole response. One line, no headers."""
    text = str(value).strip()
    first = text.splitlines()[0] if text else ""
    return first[:200]
