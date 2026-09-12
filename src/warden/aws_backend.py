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
   Kubernetes. ⚠ Connect + read still sum to slightly over the default 5s tool budget in the worst
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

import os
from datetime import UTC, datetime, timedelta

from .models import Alert
from .tools import PARTIAL_PREFIX, ToolError

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
# CloudWatch period in seconds. 60 is the finest granularity ECS service metrics are published at.
METRIC_PERIOD_S = int(os.environ.get("WARDEN_AWS_METRIC_PERIOD_S", "60"))


class AwsBackend:
    """Reads logs, metrics and rollout history for the ECS service an alert points at."""

    name = "aws"

    def __init__(self, *, logs=None, cloudwatch=None, ecs=None, region: str | None = None) -> None:
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
        self._logs = logs
        self._cw = cloudwatch
        self._ecs = ecs

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
        raw = (alert.started_at or "").strip()
        if raw:
            try:
                parsed = datetime.fromisoformat(raw)  # 3.11+ parses a trailing Z natively
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
            except ValueError:
                pass
        return datetime.now(UTC)

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
                + (f" ({failures})" if failures else "")
            )
        return live[0]

    # ------------------------------------------------------------------ the three tools

    def logs(self, alert: Alert) -> list[str]:
        """Recent log events for this service's log group, newest window first."""
        group = self._log_group(alert)
        started = self._started_at(alert)
        start_ms = int((started - LOG_LOOKBACK).timestamp() * 1000)
        end_ms = int((started + LOG_LOOKBACK).timestamp() * 1000)

        kwargs: dict[str, object] = {
            "logGroupName": group,
            "startTime": start_ms,
            "endTime": end_ms,
            "limit": LOG_EVENT_LIMIT,
        }
        prefix = alert.labels.get("log_stream_prefix")
        if prefix:
            kwargs["logStreamNamePrefix"] = prefix

        try:
            resp = self._logs.filter_log_events(**kwargs)
        except Exception as exc:  # noqa: BLE001 - a missing group is data, not a crash
            return [f"{PARTIAL_PREFIX}logs: {group}: {_one_line(exc)}"]

        lines: list[str] = []
        for event in resp.get("events") or []:
            message = str(event.get("message", "")).rstrip()
            if not message:
                continue
            stream = event.get("logStreamName", "?")
            stamp = _ms_to_iso(event.get("timestamp"))
            lines.append(f"{stream} {stamp} {message}")
            if len(lines) >= LOG_MAX_LINES:
                lines.append(
                    f"{PARTIAL_PREFIX}logs: truncated at {LOG_MAX_LINES} lines "
                    f"(raise WARDEN_AWS_LOG_MAX_LINES to see more)"
                )
                break
        return lines

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
        stats = self._utilisation(alert, started)
        out.update(stats)
        return out

    def _utilisation(self, alert: Alert, started: datetime) -> dict[str, float]:
        """CPU and memory for the service over the window around the alert."""
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
        except Exception:  # noqa: BLE001
            # Utilisation is supporting evidence; the exact task counts above are the load-bearing
            # part. Losing it must not lose them, and an omitted key reads as absent, not as zero.
            return {}

        keys = {"m0": "cpu_utilization_pct", "m1": "memory_utilization_pct"}
        out: dict[str, float] = {}
        for result in resp.get("MetricDataResults") or []:
            values = result.get("Values") or []
            key = keys.get(result.get("Id", ""))
            if key and values:
                out[key] = float(max(values))
        return out

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
        if created is None or (datetime.now(UTC) - created) > RECENT_DEPLOY_WINDOW:
            return []  # nothing changed recently; P5 then refuses a rollback

        task_def_arn = primary.get("taskDefinition") or service.get("taskDefinition") or ""
        family, revision = _family_revision(task_def_arn)
        if not family:
            return [f"{PARTIAL_PREFIX}deploys: unparseable task definition '{task_def_arn}'"]

        try:
            current = self._task_definition(f"{family}:{revision}")
        except Exception as exc:  # noqa: BLE001
            return [f"{PARTIAL_PREFIX}deploys: {family}:{revision}: {_one_line(exc)}"]
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
        if previous_arn:
            prev_family, prev_revision = _family_revision(previous_arn)
            if prev_family:
                # ⛔ Used, even when it is the SAME revision as PRIMARY. That is exactly what a
                # `--force-new-deployment` looks like — a new deployment record pointing at the
                # unchanged task definition — and the images then compare equal, so it is correctly
                # not a deploy. Skipping it here and falling through to revision-1 would report a
                # restart as a deploy, which is the single defect this whole comparison exists to
                # prevent. A test asserts it.
                previous_ref = f"{prev_family}:{prev_revision}"
        if not previous_ref and revision > 1:
            previous_ref = f"{family}:{revision - 1}"

        previous_images: list[str] = []
        if previous_ref:
            try:
                previous_images = _images_of(self._task_definition(previous_ref))
            except Exception as exc:  # noqa: BLE001
                # ⭐ The important branch. Without the previous revision we cannot tell a real
                # deploy from a force-new-deployment, and reporting it anyway would let policy P5
                # approve a rollback on a restart. Report the gap; report no deploy.
                gap = (
                    f"{PARTIAL_PREFIX}deploys: previous revision {previous_ref} "
                    f"unreadable, cannot prove a template change: {_one_line(exc)}"
                )
                return [gap]
            if previous_images == current_images:
                return []  # deployment moved, task definition did not: a restart, not a deploy

        out = {
            "service": self._service(alert),
            "revision": str(revision),
            "image": ",".join(current_images),
            "previous_image": ",".join(previous_images),
            # WHEN IT REACHED PRODUCTION. Deliberately the deployment's creation, not the task
            # definition's registration: the question policy P5 asks is "did something change in
            # front of users near this alert?", and a revision can sit registered for weeks.
            "at": created.isoformat(),
            "by": "ecs",
        }
        # ...but the registration time is worth carrying beside it, because the two being far
        # apart is itself a signal: a revision built long ago and rolled out now is a different
        # kind of event from one built and shipped in the same minute.
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
