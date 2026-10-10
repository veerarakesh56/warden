"""AWS behind the RemediationWorkflow: Lambda, EventBridge, DynamoDB and ECS entries (decision D16, G6).

The workflow decides whether to act; this carries out one approved entry on one resource. The same rules as the
Kubernetes platform:
- reads go through the incident's reader session; a write goes through an actor session minted for that one
  plan (identity.actor_session): 900 s, SourceIdentity the incident, session tags naming the approvers and the
  plan, and a session policy allowing only that entry's actions on that resource (audit A-P-5);
- every write re-reads first and refuses, changing nothing, when the resource moved since the plan was
  approved - and re-checks its bounds against that read;
- a rollback restores exactly what the plan's snapshot recorded;
- health is a positive signal (traffic served without errors, a rollout completed, a state enabled); unknown is
  not healthy.

Entries: lambda_move_alias (to the version that served the alias's traffic before the current one - never "the
numerically previous version", Wave 4), lambda_set_reserved_concurrency (raise an existing reservation, never
create one: a new reservation caps the function), lambda_enable_esm, events_enable_rule,
dynamodb_raise_capacity (the table's provisioned WRITE capacity; read capacity is untouched), and
ecs_rollback_service (to the task definition of the service's last successful deployment before the current
one, from ECS's own deployment history), and aurora_failover (T3: promote one available reader the approver named,
only while the writer is still the one they saw; irreversible - a person decides what comes after). lambda_restore_config
is not carried out here: restoring a
configuration copies environment values, which WARDEN does not read (audit A-B-M9).

G9-D (2026-10-10; AWS's own documentation read that day, verify-fix-apis.md): lambda_disable_esm (pause a mapping that
reads an SQS queue - never a stream, whose records age out while paused), events_disable_rule (pause a SCHEDULED rule -
never an event-pattern rule, which drops what it matches), ecs_restart_service (only digest-pinned images: a forced
deployment pulls whatever a tag points to now), ecs_scale_service (at most two more tasks, never under Application Auto
Scaling), sqs_redrive_dlq (to the dead-letter queue's one source queue, at most 50 a second; the session holds each
queue's own actions only), athena_stop_query (the one query running past RUNAWAY_QUERY) and apigw_raise_stage_throttle
(an existing all-methods throttle, at most double, within the account's).
"""

from __future__ import annotations

import itertools
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from .. import catalog
from ..aws_stack import SERVED_LOOKBACK

ENV_TAG = os.environ.get("WARDEN_AWS_ENV_TAG", "Environment")
HEALTH_WINDOW = timedelta(minutes=5)
# Register C8: a revision WARDEN restores must have been healthy this long when it last served - known-good, not
# merely older. A version that served for a minute before being replaced is no fallback.
KNOWN_GOOD = timedelta(minutes=30)
_PERIOD = 300  # CloudWatch's period for the served-version reads, seconds
# G9-D: an Athena query running longer than this is a runaway a person may cancel.
RUNAWAY_QUERY = timedelta(minutes=15)
# Register C17: a Lambda alias moves through a canary - this share of its traffic to the version first, for this long,
# then all of it only if that share was served without an error. (An ECS service canaries by its own deployment
# strategy, CANARY or LINEAR, which the plan shows; WARDEN does not change a service's strategy.)
CANARY_WEIGHT = 0.1
CANARY_FOR = timedelta(minutes=2)
_KINDS = {"lambda_move_alias": "lambda", "lambda_set_reserved_concurrency": "lambda", "lambda_enable_esm": "lambda",
          "lambda_disable_esm": "lambda", "events_enable_rule": "events", "events_disable_rule": "events",
          "dynamodb_raise_capacity": "dynamodb", "ecs_rollback_service": "ecs", "ecs_restart_service": "ecs",
          "ecs_scale_service": "ecs", "sqs_redrive_dlq": "sqs", "athena_stop_query": "athena",
          "apigw_raise_stage_throttle": "apigw", "aurora_failover": "rds"}
AWS_RESERVED_UNRESERVED = 100  # AWS keeps this much account concurrency unreserved (catalog._raise_concurrency)

Clients = Callable[[str], Any]
# (who, actions, resources, condition[, also]) -> a client factory whose clients hold that one actor session; `also`
# holds further exact (actions, resources) statements (identity.session_policy).
Actor = Callable[[dict[str, Any], list[str], list[str], dict[str, Any] | None], Clients]


class AwsPlatformError(RuntimeError):
    pass


class AwsPlatformRefused(AwsPlatformError):
    """Refused before anything was written: the workflow reports "nothing was changed"."""

    nothing_changed = True


def _code(exc: BaseException) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def _never_written(exc: BaseException) -> bool:
    """AWS refused the call (authorization, validation, a precondition) or it never left: nothing was written."""
    if type(exc).__name__ in ("EndpointConnectionError", "ConnectTimeoutError", "NoCredentialsError"):
        return True
    code = _code(exc)
    return code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "ValidationException",
                    "InvalidParameterValueException", "PreconditionFailedException", "ResourceNotFoundException",
                    "ResourceConflictException", "ClientException", "InvalidParameterException",
                    "LimitExceededException")


def _one_line(value: Any) -> str:
    text = str(value).strip()
    return (text.splitlines()[0] if text else "")[:200]


class AwsPlatform:
    def __init__(self, *, reader: Clients, actor: Actor, clock: Callable[[], datetime] | None = None,
                 per_environment: Callable[[str], AwsPlatform] | None = None,
                 sleep: Callable[[float], None] | None = None) -> None:
        self._read = reader
        self._actor = actor
        self._now = clock or (lambda: datetime.now(UTC))
        self._sleep = sleep or time.sleep
        self._per_environment = per_environment
        self._instances: dict[str, AwsPlatform] = {}

    def for_environment(self, environment: str) -> AwsPlatform:
        """This platform as one environment sees it: its reader and actor roles (a runtime watching several
        environments); itself when it serves one."""
        if self._per_environment is None:
            return self
        if environment not in self._instances:
            self._instances[environment] = self._per_environment(environment)
        return self._instances[environment]

    # ------------------------------------------------------------------ the shape every platform has

    def live(self, entry: str, params: dict[str, Any]) -> dict[str, Any]:
        """What WARDEN read for this entry: the allowed values of each `ref` parameter, the current values its
        bounds need, the resource's own environment tag, a rollout state, and a snapshot that changes with any
        change that matters. Nothing read means nothing allowed."""
        read = {"lambda_move_alias": self._live_alias, "lambda_set_reserved_concurrency": self._live_concurrency,
                "lambda_enable_esm": self._live_esm, "lambda_disable_esm": self._live_esm_pause,
                "events_enable_rule": self._live_rule, "events_disable_rule": self._live_rule_pause,
                "dynamodb_raise_capacity": self._live_table, "ecs_rollback_service": self._live_ecs,
                "ecs_restart_service": self._live_ecs_tasks, "ecs_scale_service": self._live_ecs_tasks,
                "sqs_redrive_dlq": self._live_dlq, "athena_stop_query": self._live_query,
                "apigw_raise_stage_throttle": self._live_stage,
                "aurora_failover": self._live_cluster}.get(entry)
        if read is None:
            return {}
        try:
            return read(params)
        except Exception:  # noqa: BLE001 - absent or unreadable allows nothing; the catalogue refuses
            return {}

    def changes(self, since: datetime, until: datetime, environment: str) -> list[dict[str, Any]]:
        """Write events on this environment's resources in CloudTrail (requirement R38): when, what, by whom. Read-only
        events are left out; at most four pages are read."""
        out, token, mark = [], None, f"warden-{environment}-"
        trail = self._read("cloudtrail")
        for _ in range(4):
            page = trail.lookup_events(LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
                                       StartTime=since, EndTime=until, MaxResults=50,
                                       **({"NextToken": token} if token else {}))
            for e in page.get("Events") or []:
                names = [str(r.get("ResourceName", "")) for r in e.get("Resources") or []]
                hit = next((n for n in names if mark in n), None)
                if hit:
                    out.append({"at": _when(e.get("EventTime")) or since, "source": "cloudtrail",
                                "what": f"{e.get('EventName', '?')} on {hit.rsplit(':', 1)[-1].rsplit('/', 1)[-1]}",
                                "who": str(e.get("Username") or "?")})
            token = page.get("NextToken")
            if not token:
                break
        return out

    def knows(self, service: str) -> bool:
        return False  # health is asked by entry (healthy_for), never by a bare name that two kinds could share

    def healthy(self, service: str, entry: str | None = None, params: dict[str, Any] | None = None) -> bool:
        check = {"lambda_move_alias": self._lambda_healthy, "lambda_set_reserved_concurrency": self._lambda_healthy,
                 "lambda_enable_esm": self._esm_healthy, "events_enable_rule": self._rule_healthy,
                 "lambda_disable_esm": self._esm_paused, "events_disable_rule": self._rule_paused,
                 "dynamodb_raise_capacity": self._table_healthy, "ecs_rollback_service": self._ecs_healthy,
                 "ecs_restart_service": self._ecs_healthy, "ecs_scale_service": self._ecs_healthy,
                 "sqs_redrive_dlq": self._redrive_done, "athena_stop_query": self._query_cancelled,
                 "apigw_raise_stage_throttle": self._stage_healthy,
                 "aurora_failover": self._cluster_healthy}.get(entry or "")
        if check is None:
            return False
        try:
            return bool(check(service, params or {}))
        except Exception:  # noqa: BLE001 - unknown is not healthy
            return False

    def apply(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any] | None = None,
              who: dict[str, Any] | None = None) -> str:
        if entry not in _KINDS:
            raise AwsPlatformRefused(f"{entry} is not something the AWS platform does "
                                     f"(it does {', '.join(sorted(_KINDS))})")
        if not who or not who.get("approvers"):
            raise AwsPlatformRefused("no approvers were handed to the AWS platform: an actor session names them")
        return self._change(entry, params, snapshot or {}, who, back=False)

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any],
                 who: dict[str, Any] | None = None) -> str:
        if entry not in _KINDS:
            raise AwsPlatformError(f"{entry} is not something the AWS platform does")
        if entry == "athena_stop_query":
            return "nothing to roll back: a cancelled query is not resumed; it can be run again"
        if entry == "ecs_restart_service":
            # The same task definition runs again: there is nothing to return to.
            return "nothing to roll back: a restart replaced tasks with the same task definition"
        if entry == "aurora_failover":
            # Irreversible (the catalogue's T3): failing back is another failover, a new decision for a person.
            return "nothing to roll back: a failover is not undone automatically; a person decides whether to fail back"
        if not who or not who.get("approvers"):
            raise AwsPlatformError("no approvers were handed to the AWS platform for the rollback")
        return self._change(entry, params, snapshot, who, back=True)

    def _change(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any], who: dict[str, Any],
                back: bool) -> str:
        now = self.live(entry, params).get("state")
        if not now:
            raise AwsPlatformRefused(f"could not read the target of {entry}; nothing was changed")
        write = {"lambda_move_alias": self._move_alias, "lambda_set_reserved_concurrency": self._set_concurrency,
                 "lambda_enable_esm": self._esm, "events_enable_rule": self._rule,
                 "lambda_disable_esm": self._esm_off, "events_disable_rule": self._rule_off,
                 "dynamodb_raise_capacity": self._capacity, "ecs_rollback_service": self._ecs,
                 "ecs_restart_service": self._ecs_restart, "ecs_scale_service": self._ecs_scale,
                 "sqs_redrive_dlq": self._redrive, "athena_stop_query": self._stop_query,
                 "apigw_raise_stage_throttle": self._stage_throttle,
                 "aurora_failover": self._failover}[entry]
        try:
            return write(params, snapshot, now, who, back)
        except AwsPlatformError:
            raise
        except Exception as exc:
            if _never_written(exc):
                raise AwsPlatformRefused(f"AWS refused {entry} ({_code(exc) or type(exc).__name__}: "
                                         f"{_one_line(exc)}); nothing was changed") from exc
            raise AwsPlatformError(f"{entry} failed and may be half-made: {_one_line(exc)}") from exc

    @staticmethod
    def _expect(now: dict[str, Any], snapshot: dict[str, Any], keys: tuple[str, ...], what: str) -> None:
        """The resource is still as the approver saw it, field by field; else nothing is written."""
        moved = [k for k in keys if now.get(k) != snapshot.get(k)]
        if moved:
            raise AwsPlatformRefused(f"{what} changed since the plan was approved ({', '.join(moved)}); "
                                     "nothing was changed")

    def _tags(self, service: str, arn: str) -> dict[str, str]:
        c = self._read(service)
        if service == "lambda":
            return c.list_tags(Resource=arn).get("Tags") or {}
        if service == "events":
            return {t["Key"]: t["Value"] for t in c.list_tags_for_resource(ResourceARN=arn).get("Tags") or []}
        if service == "dynamodb":
            return {t["Key"]: t["Value"] for t in c.list_tags_of_resource(ResourceArn=arn).get("Tags") or []}
        if service == "sqs":
            return c.list_queue_tags(QueueUrl=arn).get("Tags") or {}  # SQS tags by the queue's URL
        if service == "athena":
            return {t["Key"]: t["Value"] for t in c.list_tags_for_resource(ResourceARN=arn).get("Tags") or []}
        raise AwsPlatformError(f"no tag reader for {service}")

    @staticmethod
    def _where(arn: str) -> str:
        """The account and Region a write goes to, in the plan the approver signs: dev's plan and prod's do not
        look the same. No credential is in it."""
        parts = arn.split(":")
        return f"{parts[4]}/{parts[3]}" if len(parts) > 4 else ""

    # ------------------------------------------------------------------ lambda: move the alias

    def _live_alias(self, params: dict[str, Any]) -> dict[str, Any]:
        fn, alias = params.get("function"), params.get("alias")
        if not isinstance(fn, str) or not isinstance(alias, str):
            return {}
        lam = self._read("lambda")
        conf = lam.get_function_configuration(FunctionName=fn)
        arn, name = conf["FunctionArn"], conf["FunctionName"]
        got = lam.get_alias(FunctionName=name, Name=alias)
        current = got["FunctionVersion"]
        weights = (got.get("RoutingConfig") or {}).get("AdditionalVersionWeights") or {}
        versions = [v for v in self._versions(name) if v["Version"].isdigit()]
        published = {v["Version"]: v for v in versions}
        to = set()
        if current in published:
            older = [v["Version"] for v in versions if int(v["Version"]) < int(current)]
            served = self._served_before(name, alias, older, _when(published[current].get("LastModified")))
            to = {served} if served else set()
        return {"function": {name}, "alias": {alias}, "to_version": to,
                "environment": self._tags("lambda", arn).get(ENV_TAG),
                "rollout": "progressing" if weights else "complete",
                "state": {"function": name, "alias": alias, "version": current,
                          "revision": got.get("RevisionId"), "where": self._where(arn)}}

    def _versions(self, fn: str) -> list[dict[str, Any]]:
        out, marker = [], None
        for _ in range(50):  # bounded: 50 pages of 50
            page = self._read("lambda").list_versions_by_function(FunctionName=fn, **({"Marker": marker} if marker else {}))
            out += page.get("Versions") or []
            marker = page.get("NextMarker")
            if not marker:
                return out
        raise AwsPlatformError(f"{fn} has more versions than WARDEN reads; the newest were not read")

    def _served_before(self, fn: str, alias: str, candidates: list[str], before: datetime | None) -> str:
        """The version that served the alias's traffic most in the lookback before the current version was
        published - Lambda keeps no alias history; its ExecutedVersion metric does (Wave 4, fs-01/fs-02) - and only
        if it was known-good there: KNOWN_GOOD of unbroken five-minute periods with invocations and no error (C8)."""
        if not candidates or before is None:
            return ""
        cands = candidates[-20:]
        specs = [{"Id": f"v{i}", "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": "AWS/Lambda", "MetricName": "Invocations", "Dimensions": [
                {"Name": "FunctionName", "Value": fn}, {"Name": "Resource", "Value": f"{fn}:{alias}"},
                {"Name": "ExecutedVersion", "Value": v}]}, "Period": _PERIOD, "Stat": "Sum"}} for i, v in enumerate(cands)]
        specs += [{"Id": f"e{i}", "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": "AWS/Lambda", "MetricName": "Errors", "Dimensions": [
                {"Name": "FunctionName", "Value": fn}, {"Name": "Resource", "Value": f"{fn}:{alias}"},
                {"Name": "ExecutedVersion", "Value": v}]}, "Period": _PERIOD, "Stat": "Sum"}} for i, v in enumerate(cands)]
        resp = self._read("cloudwatch").get_metric_data(MetricDataQueries=specs, StartTime=before - SERVED_LOOKBACK,
                                                        EndTime=before)
        results = resp.get("MetricDataResults") or []
        series = {(r["Id"][0], cands[int(r["Id"][1:])]): dict(zip(r.get("Timestamps") or [], r.get("Values") or [],
                                                                  strict=False))
                  for r in results if str(r.get("Id", ""))[:1] in ("v", "e")}
        served = {v: sum(series.get(("v", v), {}).values()) for v in cands}
        best, calls = max(served.items(), key=lambda kv: (kv[1], int(kv[0])), default=("", 0.0))
        if calls <= 0:
            return ""
        calls_at, errors_at = series.get(("v", best), {}), series.get(("e", best), {})
        good = sorted(_when(t) for t, n in calls_at.items() if n > 0 and not errors_at.get(t) and _when(t))
        run = longest = 1 if good else 0
        for a, b in itertools.pairwise(good):
            run = run + 1 if (b - a).total_seconds() == _PERIOD else 1
            longest = max(longest, run)
        return best if longest * _PERIOD >= KNOWN_GOOD.total_seconds() else ""

    def _move_alias(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("function", "alias"), f"lambda {p['function']}:{p['alias']}")
        want_now, to = (snapshot.get("version"), p["to_version"]) if not back else (p["to_version"], snapshot.get("version"))
        if now.get("version") != want_now:
            raise AwsPlatformRefused(f"alias {p['alias']} serves version {now.get('version')}, not the {want_now} the "
                                     "plan expected; nothing was changed")
        arn = self._read("lambda").get_function_configuration(FunctionName=p["function"])["FunctionArn"]
        lam = self._actor(who, ["lambda:UpdateAlias"], [arn], None)("lambda")  # the function: the service reference
        # RevisionId: Lambda refuses the update if the alias changed after this read (PreconditionFailed).
        if back:  # back to the version the alias served before: no canary for a return
            lam.update_alias(FunctionName=p["function"], Name=p["alias"], FunctionVersion=to,
                             RevisionId=now.get("revision"))
            return f"moved lambda {p['function']} alias {p['alias']} from version {want_now} to {to}"
        return self._canary(lam, p["function"], p["alias"], want_now, to, now.get("revision"))

    def _canary(self, lam: Any, fn: str, alias: str, current: str, to: str, revision: Any) -> str:
        """Register C17: CANARY_WEIGHT of the alias's traffic to `to` for CANARY_FOR, then all of it - or, if `to`
        erred there, the alias back on `current` and nothing changed."""
        got = lam.update_alias(FunctionName=fn, Name=alias, FunctionVersion=current, RevisionId=revision,
                               RoutingConfig={"AdditionalVersionWeights": {to: CANARY_WEIGHT}}) or {}
        start = self._now()
        self._sleep(CANARY_FOR.total_seconds())
        calls, errors = self._version_sums(fn, alias, to, start, self._now())
        if errors:
            try:
                lam.update_alias(FunctionName=fn, Name=alias, FunctionVersion=current, RevisionId=got.get("RevisionId"),
                                 RoutingConfig={"AdditionalVersionWeights": {}})
            except Exception as exc:
                raise AwsPlatformError(f"the canary of version {to} erred and the alias {alias} could not be put "
                                       f"back on {current}: {_one_line(exc)}") from exc
            raise AwsPlatformRefused(f"canary: version {to} erred {errors:g} time(s) in {calls:g} call(s) on "
                                     f"{CANARY_WEIGHT:.0%} of alias {alias}'s traffic; the alias is back on {current}, "
                                     "nothing was changed")
        lam.update_alias(FunctionName=fn, Name=alias, FunctionVersion=to, RevisionId=got.get("RevisionId"),
                         RoutingConfig={"AdditionalVersionWeights": {}})
        return (f"moved lambda {fn} alias {alias} from version {current} to {to}, after a {CANARY_WEIGHT:.0%} canary "
                f"for {CANARY_FOR.total_seconds() / 60:g} min ({calls:g} call(s), no error)")

    def _version_sums(self, fn: str, alias: str, version: str, start: datetime, end: datetime) -> tuple[float, float]:
        """(invocations, errors) of one version behind the alias, start..end."""
        specs = [{"Id": m[0].lower(), "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": "AWS/Lambda", "MetricName": m, "Dimensions": [
                {"Name": "FunctionName", "Value": fn}, {"Name": "Resource", "Value": f"{fn}:{alias}"},
                {"Name": "ExecutedVersion", "Value": version}]}, "Period": 60, "Stat": "Sum"}}
                 for m in ("Invocations", "Errors")]
        resp = self._read("cloudwatch").get_metric_data(MetricDataQueries=specs, StartTime=start, EndTime=end)
        sums = {r["Id"]: sum(r.get("Values") or []) for r in resp.get("MetricDataResults") or []}
        return sums.get("i", 0.0), sums.get("e", 0.0)

    def _lambda_healthy(self, fn: str, params: dict[str, Any]) -> bool:
        """Traffic served without errors or throttles in the last five minutes: at least one invocation (a request
        floor - a dead function serves nothing and errs nothing), no error, no throttle."""
        sums = self._metric_sums("AWS/Lambda", [{"Name": "FunctionName", "Value": fn}],
                                 ("Invocations", "Errors", "Throttles"))
        return sums is not None and sums["Invocations"] >= 1 and sums["Errors"] == 0 and sums["Throttles"] == 0

    def _metric_sums(self, namespace: str, dims: list[dict[str, str]], metrics: tuple[str, ...]) -> dict | None:
        end = self._now()
        resp = self._read("cloudwatch").get_metric_data(StartTime=end - HEALTH_WINDOW, EndTime=end, MetricDataQueries=[
            {"Id": f"m{i}", "ReturnData": True, "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": m,
                                                                          "Dimensions": dims},
                                                               "Period": 60, "Stat": "Sum"}}
            for i, m in enumerate(metrics)])
        results = {r["Id"]: r for r in resp.get("MetricDataResults") or []}
        if any(results.get(f"m{i}", {}).get("StatusCode") not in ("Complete", None) for i in range(len(metrics))):
            return None  # a partial read is unknown, and unknown is not healthy
        return {m: sum(results.get(f"m{i}", {}).get("Values") or []) for i, m in enumerate(metrics)}

    # ------------------------------------------------------------------ lambda: reserved concurrency

    def _live_concurrency(self, params: dict[str, Any]) -> dict[str, Any]:
        fn = params.get("function")
        if not isinstance(fn, str):
            return {}
        lam = self._read("lambda")
        conf = lam.get_function_configuration(FunctionName=fn)
        arn, name = conf["FunctionArn"], conf["FunctionName"]
        reserved = lam.get_function_concurrency(FunctionName=name).get("ReservedConcurrentExecutions")
        free = (lam.get_account_settings().get("AccountLimit") or {}).get("UnreservedConcurrentExecutions")
        return {"function": {name}, "environment": self._tags("lambda", arn).get(ENV_TAG),
                # None when nothing is reserved: a new reservation would cap the function, so none is created.
                "current_concurrency": reserved if isinstance(reserved, int) else None,
                "unreserved_account_concurrency": free,
                "state": {"function": name, "reserved": reserved, "where": self._where(arn)}}

    def _set_concurrency(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("function",), f"lambda {p['function']}")
        if back:
            if now.get("reserved") != p["concurrency"]:
                raise AwsPlatformRefused(f"lambda {p['function']} no longer reserves {p['concurrency']}; nothing was "
                                         "changed")
            to = snapshot.get("reserved")
        else:
            self._expect(now, snapshot, ("reserved",), f"lambda {p['function']}'s reserved concurrency")
            cur, to = now.get("reserved"), p["concurrency"]
            free = self.live("lambda_set_reserved_concurrency", p).get("unreserved_account_concurrency")
            if not isinstance(cur, int) or not isinstance(to, int) or to <= cur or not isinstance(free, int) \
                    or to - cur > free - AWS_RESERVED_UNRESERVED:
                raise AwsPlatformRefused(f"raising lambda {p['function']} from {cur} to {to} is outside the bound; "
                                         "nothing was changed")
        if not isinstance(to, int):
            raise AwsPlatformError("the plan holds no reserved concurrency to return to")
        arn = self._read("lambda").get_function_configuration(FunctionName=p["function"])["FunctionArn"]
        lam = self._actor(who, ["lambda:PutFunctionConcurrency"], [arn], None)("lambda")
        lam.put_function_concurrency(FunctionName=p["function"], ReservedConcurrentExecutions=to)
        return f"set lambda {p['function']} reserved concurrency from {now.get('reserved')} to {to}"

    # ------------------------------------------------------------------ lambda: event source mapping

    def _live_esm(self, params: dict[str, Any], pause: bool = False) -> dict[str, Any]:
        """The function's mappings that can be turned on (or, to pause, off). With no mapping named, the allowed set is
        every such mapping of the function - the resolver takes it only when there is exactly one."""
        fn, uuid = params.get("function"), params.get("mapping")
        if not isinstance(fn, str):
            return {}
        lam = self._read("lambda")
        conf = lam.get_function_configuration(FunctionName=fn)
        fn_arn, name = _unqualified(conf["FunctionArn"]), conf["FunctionName"]
        if isinstance(uuid, str):
            mappings = [lam.get_event_source_mapping(UUID=uuid)]
        else:
            mappings, marker = [], None
            for _ in range(5):
                page = lam.list_event_source_mappings(FunctionName=name, **({"Marker": marker} if marker else {}))
                mappings += page.get("EventSourceMappings") or []
                marker = page.get("NextMarker")
                if not marker:
                    break
        mine = [m for m in mappings if _unqualified(str(m.get("FunctionArn", ""))) == fn_arn]
        want = "Enabled" if pause else "Disabled"
        # A pause only for a queue that keeps its messages a day or more: they wait there. A stream's records expire
        # while a mapping is paused, and so do a short-retention queue's (review H2).
        allowed = {m["UUID"] for m in mine if m.get("State") == want
                   and (not pause or self._keeps(str(m.get("EventSourceArn", ""))))}
        out = {"function": {name}, "mapping": allowed, "environment": self._tags("lambda", fn_arn).get(ENV_TAG)}
        if isinstance(uuid, str) and mine:
            m = mine[0]
            state = m.get("State")
            out["rollout"] = "progressing" if state in ("Enabling", "Disabling", "Updating", "Creating") else "complete"
            out["state"] = {"mapping": uuid, "function": fn_arn, "enabled": state == "Enabled",
                            "source": m.get("EventSourceArn"), "where": self._where(fn_arn)}
            if pause:  # in the plan the approver signs: how long the waiting messages are kept
                out["state"]["retention_s"] = self._retention(str(m.get("EventSourceArn", "")))
        return out

    def _retention(self, queue_arn: str) -> int | None:
        """How long an SQS queue keeps a message, in seconds; None when it is not a queue or cannot be read."""
        if not queue_arn.startswith("arn:aws:sqs:"):
            return None
        sqs = self._read("sqs")
        url = sqs.get_queue_url(QueueName=queue_arn.rsplit(":", 1)[-1])["QueueUrl"]
        got = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["MessageRetentionPeriod"])["Attributes"]
        value = str(got.get("MessageRetentionPeriod", ""))
        return int(value) if value.isdigit() else None

    def _keeps(self, source_arn: str) -> bool:
        retention = self._retention(source_arn)
        return retention is not None and retention >= catalog.MIN_PAUSE_RETENTION_S

    def _live_esm_pause(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._live_esm(params, pause=True)

    def _esm_off(self, p, snapshot, now, who, back) -> str:
        return self._esm(p, snapshot, now, who, not back)

    def _esm(self, p, snapshot, now, who, back) -> str:
        """Enable the mapping (back: disable it). The pause entry is the same write the other way round."""
        self._expect(now, snapshot, ("mapping", "function", "source"), f"event source mapping {p['mapping']}")
        if now.get("enabled") != back:  # enabling needs it disabled; the rollback needs it enabled
            raise AwsPlatformRefused(f"event source mapping {p['mapping']} is already "
                                     f"{'enabled' if now.get('enabled') else 'disabled'}; nothing was changed")
        # The mapping's own ARN, and its function's as a condition (lambda:FunctionArn): AWS's service reference
        # (read 2026-10-03) names both for UpdateEventSourceMapping.
        fn = _unqualified(now["function"])
        mapping_arn = fn.split(":function:")[0] + f":event-source-mapping:{p['mapping']}"
        lam = self._actor(who, ["lambda:UpdateEventSourceMapping"], [mapping_arn],
                          {"ArnEquals": {"lambda:FunctionArn": fn}})("lambda")
        lam.update_event_source_mapping(UUID=p["mapping"], Enabled=not back)
        return f"{'disabled' if back else 'enabled'} event source mapping {p['mapping']}"

    def _esm_healthy(self, uuid: str, params: dict[str, Any]) -> bool:
        return self._read("lambda").get_event_source_mapping(UUID=uuid).get("State") == "Enabled"

    def _esm_paused(self, uuid: str, params: dict[str, Any]) -> bool:
        return self._read("lambda").get_event_source_mapping(UUID=uuid).get("State") == "Disabled"

    # ------------------------------------------------------------------ eventbridge: enable a rule

    def _live_rule(self, params: dict[str, Any], pause: bool = False) -> dict[str, Any]:
        name = params.get("rule")
        if not isinstance(name, str):
            return {}
        rule = self._read("events").describe_rule(Name=name)
        state = rule.get("State")
        # A pause only for a scheduled rule (it misses ticks); an event-pattern rule would drop the events it matches.
        # Only the plain ENABLED state: a rule on all CloudTrail management events may not come back the same way.
        can = state == "ENABLED" and bool(rule.get("ScheduleExpression")) and not rule.get("EventPattern") \
            if pause else state == "DISABLED"
        return {"rule": {rule["Name"]} if can else set(),
                "environment": self._tags("events", rule["Arn"]).get(ENV_TAG),
                "state": {"rule": rule["Name"], "arn": rule["Arn"], "enabled": state == "ENABLED",
                          "where": self._where(rule["Arn"])}}

    def _live_rule_pause(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._live_rule(params, pause=True)

    def _rule_off(self, p, snapshot, now, who, back) -> str:
        return self._rule(p, snapshot, now, who, not back)

    def _rule(self, p, snapshot, now, who, back) -> str:
        """Enable the rule (back: disable it). The pause entry is the same write the other way round."""
        self._expect(now, snapshot, ("rule", "arn"), f"rule {p['rule']}")
        if now.get("enabled") != back:
            raise AwsPlatformRefused(f"rule {p['rule']} is already {'enabled' if now.get('enabled') else 'disabled'}; "
                                     "nothing was changed")
        action = "events:DisableRule" if back else "events:EnableRule"
        ev = self._actor(who, [action], [now["arn"]], None)("events")
        (ev.disable_rule if back else ev.enable_rule)(Name=p["rule"])
        return f"{'disabled' if back else 'enabled'} rule {p['rule']}"

    def _rule_healthy(self, name: str, params: dict[str, Any]) -> bool:
        return self._read("events").describe_rule(Name=name).get("State") == "ENABLED"

    def _rule_paused(self, name: str, params: dict[str, Any]) -> bool:
        return self._read("events").describe_rule(Name=name).get("State") == "DISABLED"

    # ------------------------------------------------------------------ dynamodb: raise write capacity

    def _live_table(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("table")
        if not isinstance(name, str):
            return {}
        t = self._read("dynamodb").describe_table(TableName=name)["Table"]
        mode = (t.get("BillingModeSummary") or {}).get("BillingMode", "PROVISIONED")
        tp = t.get("ProvisionedThroughput") or {}
        write = tp.get("WriteCapacityUnits") if mode == "PROVISIONED" else None
        scaled = self._read("application-autoscaling").describe_scalable_targets(
            ServiceNamespace="dynamodb", ResourceIds=[f"table/{t['TableName']}"],
            ScalableDimension="dynamodb:table:WriteCapacityUnits").get("ScalableTargets")
        return {"table": {t["TableName"]}, "environment": self._tags("dynamodb", t["TableArn"]).get(ENV_TAG),
                "current_capacity": write if isinstance(write, int) and write > 0 else None,
                "autoscaled": bool(scaled), "rollout": "complete" if t.get("TableStatus") == "ACTIVE" else "progressing",
                "state": {"table": t["TableName"], "arn": t["TableArn"], "write": write, "read": tp.get("ReadCapacityUnits"),
                          "where": self._where(t["TableArn"])}}

    def _capacity(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("table", "arn", "read"), f"table {p['table']}")
        if back:
            if now.get("write") != p["capacity"]:
                raise AwsPlatformRefused(f"table {p['table']} no longer has {p['capacity']} write units; nothing was "
                                         "changed")
            to = snapshot.get("write")
        else:
            self._expect(now, snapshot, ("write",), f"table {p['table']}'s write capacity")
            cur, to = now.get("write"), p["capacity"]
            if not isinstance(cur, int) or not isinstance(to, int) or not cur < to <= 2 * cur:
                raise AwsPlatformRefused(f"raising table {p['table']} from {cur} to {to} write units is outside the "
                                         "bound (above the current, at most double); nothing was changed")
        db = self._actor(who, ["dynamodb:UpdateTable"], [now["arn"]], None)("dynamodb")
        db.update_table(TableName=p["table"], ProvisionedThroughput={"ReadCapacityUnits": now["read"],
                                                                      "WriteCapacityUnits": to})
        return f"set table {p['table']} write capacity from {now.get('write')} to {to}"

    def _table_healthy(self, name: str, params: dict[str, Any]) -> bool:
        t = self._read("dynamodb").describe_table(TableName=name)["Table"]
        sums = self._metric_sums("AWS/DynamoDB", [{"Name": "TableName", "Value": name}],
                                 ("ConsumedWriteCapacityUnits", "WriteThrottleEvents"))
        return t.get("TableStatus") == "ACTIVE" and sums is not None and sums["ConsumedWriteCapacityUnits"] > 0 \
            and sums["WriteThrottleEvents"] == 0

    # ------------------------------------------------------------------ ecs: roll a service back

    def _live_ecs(self, params: dict[str, Any]) -> dict[str, Any]:
        cluster, service = params.get("cluster"), params.get("service")
        if not isinstance(cluster, str) or not isinstance(service, str):
            return {}
        ecs = self._read("ecs")
        [svc] = ecs.describe_services(cluster=cluster, services=[service], include=["TAGS"])["services"]
        current = svc["taskDefinition"]
        deployments = svc.get("deployments") or []
        busy = len(deployments) > 1 or any(d.get("rolloutState") == "IN_PROGRESS" for d in deployments)
        previous = self._previous_steady(cluster, service, current)
        strategy = (svc.get("deploymentConfiguration") or {}).get("strategy") or "ROLLING"
        return {"cluster": {cluster}, "service": {svc["serviceName"]}, "to_task_definition": {previous} if previous else set(),
                "environment": {t["key"]: t["value"] for t in svc.get("tags") or []}.get(ENV_TAG),
                "rollout": "progressing" if busy else "complete",
                "state": {"cluster": cluster, "service": svc["serviceName"], "arn": svc["serviceArn"],
                          "task_definition": current, "where": self._where(svc["serviceArn"]),
                          # C17, in the plan the approver signs: a CANARY or LINEAR service canaries the rollback
                          # itself; a ROLLING one replaces its tasks a batch at a time.
                          "strategy": strategy}}

    def _previous_steady(self, cluster: str, service: str, current: str) -> str:
        """The task definition of the service's last successful deployment before the one now running, from ECS's
        own deployment history (ListServiceDeployments) - never "revision minus one", which CI-registered and
        rolled-back revisions break (audit A-B-M6)."""
        ecs = self._read("ecs")
        done = ecs.list_service_deployments(cluster=cluster, service=service, status=["SUCCESSFUL"],
                                            maxResults=20).get("serviceDeployments") or []
        done = sorted(done, key=lambda d: _when(d.get("finishedAt")) or datetime.min.replace(tzinfo=UTC), reverse=True)
        done = [d for d in done if d.get("targetServiceRevisionArn")]
        arns = [d["targetServiceRevisionArn"] for d in done]
        if not arns:
            return ""
        revisions = {r["serviceRevisionArn"]: r.get("taskDefinition", "")
                     for r in ecs.describe_service_revisions(serviceRevisionArns=arns).get("serviceRevisions") or []}
        tds = [revisions.get(a, "") for a in arns]
        # The newest success is the running one; the steady one before it is the next with another task definition.
        if not tds or tds[0] != current:
            return ""  # the running task definition is not the last success: a person reads the history
        i = next((i for i, td in enumerate(tds) if i and td and td != current), None)
        if i is None:
            return ""
        # Register C8: known-good - it served, steady, for KNOWN_GOOD: from its deployment finishing to the next one
        # starting. A revision replaced minutes after it settled is no fallback.
        served_from, until = _when(done[i].get("finishedAt")), _when(done[i - 1].get("startedAt") or done[i - 1].get("createdAt"))
        return tds[i] if served_from and until and until - served_from >= KNOWN_GOOD else ""

    def _ecs(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("cluster", "service", "arn"), f"service {p['service']}")
        want_now, to = ((snapshot.get("task_definition"), p["to_task_definition"]) if not back
                        else (p["to_task_definition"], snapshot.get("task_definition")))
        if now.get("task_definition") != want_now:
            raise AwsPlatformRefused(f"service {p['service']} runs {now.get('task_definition')}, not the {want_now} the "
                                     "plan expected; nothing was changed")
        ecs = self._actor(who, ["ecs:UpdateService"], [now["arn"]], None)("ecs")
        ecs.update_service(cluster=p["cluster"], service=p["service"], taskDefinition=to)
        return f"rolled service {p['service']} from {want_now} to {to}"

    def _live_ecs_tasks(self, params: dict[str, Any]) -> dict[str, Any]:
        """A service's task count and rollout settings, for a restart or a bounded scale-up (G9-D)."""
        cluster, service = params.get("cluster"), params.get("service")
        if not isinstance(cluster, str) or not isinstance(service, str):
            return {}
        ecs = self._read("ecs")
        [svc] = ecs.describe_services(cluster=cluster, services=[service], include=["TAGS"])["services"]
        td = ecs.describe_task_definition(taskDefinition=svc["taskDefinition"])["taskDefinition"]
        pinned = all("@sha256:" in str(c.get("image", "")) for c in td.get("containerDefinitions") or [{}])
        desired = svc.get("desiredCount")
        conf = svc.get("deploymentConfiguration") or {}
        min_healthy = conf.get("minimumHealthyPercent")
        deployments = svc.get("deployments") or []
        busy = len(deployments) > 1 or any(d.get("rolloutState") == "IN_PROGRESS" for d in deployments)
        scaled = self._read("application-autoscaling").describe_scalable_targets(
            ServiceNamespace="ecs", ResourceIds=[f"service/{cluster}/{svc['serviceName']}"],
            ScalableDimension="ecs:service:DesiredCount").get("ScalableTargets")
        return {"cluster": {cluster}, "service": {svc["serviceName"]} if pinned else set(),
                "environment": {t["key"]: t["value"] for t in svc.get("tags") or []}.get(ENV_TAG),
                "current_replicas": desired if isinstance(desired, int) and desired >= 1 else None,
                # Register C10: how many tasks a new deployment may stop together, from the service's own setting.
                "at_once": desired - -(-desired * min_healthy // 100) if isinstance(desired, int)
                and isinstance(min_healthy, int) else None,
                "autoscaled": bool(scaled), "rollout": "progressing" if busy else "complete",
                "state": {"cluster": cluster, "service": svc["serviceName"], "arn": svc["serviceArn"],
                          "task_definition": svc["taskDefinition"], "desired": desired,
                          "where": self._where(svc["serviceArn"])}}

    def _ecs_restart(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("cluster", "service", "arn", "task_definition"), f"service {p['service']}")
        if p["service"] not in self.live("ecs_restart_service", p).get("service", set()):
            raise AwsPlatformRefused(f"service {p['service']} runs an image not pinned by digest; a restart could "
                                     "roll out new code; nothing was changed")
        ecs = self._actor(who, ["ecs:UpdateService"], [now["arn"]], None)("ecs")
        ecs.update_service(cluster=p["cluster"], service=p["service"], forceNewDeployment=True)
        return f"restarted service {p['service']}'s tasks on {now['task_definition']}"

    def _ecs_scale(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("cluster", "service", "arn"), f"service {p['service']}")
        if back:
            if now.get("desired") != p["replicas"]:
                raise AwsPlatformRefused(f"service {p['service']} no longer wants {p['replicas']} tasks; nothing was "
                                         "changed")
            to = snapshot.get("desired")
        else:
            self._expect(now, snapshot, ("desired",), f"service {p['service']}'s task count")
            cur, to = now.get("desired"), p["replicas"]
            if not isinstance(cur, int) or not isinstance(to, int) or not cur < to <= cur + 2:
                raise AwsPlatformRefused(f"scaling service {p['service']} from {cur} to {to} tasks is outside the "
                                         "bound (above the current, at most two more); nothing was changed")
        if not isinstance(to, int):
            raise AwsPlatformError("the plan holds no task count to return to")
        ecs = self._actor(who, ["ecs:UpdateService"], [now["arn"]], None)("ecs")
        ecs.update_service(cluster=p["cluster"], service=p["service"], desiredCount=to)
        return f"set service {p['service']} desired tasks from {now.get('desired')} to {to}"

    def _ecs_healthy(self, service: str, params: dict[str, Any]) -> bool:
        """One deployment, its rollout completed, every desired task running - a positive signal."""
        [svc] = self._read("ecs").describe_services(cluster=params.get("cluster", ""), services=[service])["services"]
        deps = svc.get("deployments") or []
        return len(deps) == 1 and deps[0].get("rolloutState") == "COMPLETED" \
            and svc.get("desiredCount", 0) >= 1 and svc.get("runningCount") == svc.get("desiredCount")


    # ------------------------------------------------------------------ rds: fail an Aurora cluster over

    # ------------------------------------------------------------------ sqs: redrive a dead-letter queue (G9-D)

    def _live_dlq(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("queue")
        if not isinstance(name, str):
            return {}
        sqs = self._read("sqs")
        url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn", "ApproximateNumberOfMessages",
                                                                        "KmsMasterKeyId"])["Attributes"]
        arn = attrs["QueueArn"]
        head = arn.rsplit(":", 1)[0]
        sources = []
        for u in (sqs.list_dead_letter_source_queues(QueueUrl=url, MaxResults=10).get("queueUrls") or [])[:10]:
            # https://sqs.<region>.amazonaws.com/<account>/<name>: a source in this account and Region only.
            parts = u.rstrip("/").split("/")
            acct, qname = (parts[-2], parts[-1]) if len(parts) >= 5 else ("", "")
            if acct == head.rsplit(":", 1)[-1] and qname:
                sources.append(qname)
        running = [t for t in sqs.list_message_move_tasks(SourceArn=arn, MaxResults=10).get("Results") or []
                   if t.get("Status") == "RUNNING"]
        waiting = attrs.get("ApproximateNumberOfMessages")
        env = self._tags("sqs", url).get(ENV_TAG)
        ok = not attrs.get("KmsMasterKeyId")  # SSE-KMS needs key permissions the actor does not hold
        # The destination: the dead-letter queue's ONLY source (with several, a move would hand one queue's messages
        # to another's consumer - review M3), of the same environment (M2) and not KMS-encrypted either (L7).
        dest = sources[0] if len(sources) == 1 else ""
        if dest:
            durl = sqs.get_queue_url(QueueName=dest)["QueueUrl"]
            dattrs = sqs.get_queue_attributes(QueueUrl=durl, AttributeNames=["KmsMasterKeyId"])["Attributes"]
            if dattrs.get("KmsMasterKeyId") or self._tags("sqs", durl).get(ENV_TAG) != env:
                dest = ""
        return {"queue": {name} if ok else set(), "to_queue": {dest} if ok and dest else set(),
                "waiting": int(waiting) if str(waiting).isdigit() else None,
                "environment": env,
                "rollout": "progressing" if running else "complete",
                # In the plan the approver signs: how many messages would move, and from where to where.
                "state": {"queue": name, "arn": arn, "url": url, "sources": sorted(sources),
                          "waiting": int(waiting) if str(waiting).isdigit() else None, "where": self._where(arn)}}

    def _redrive(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("queue", "arn", "sources"), f"queue {p['queue']}")
        if p["to_queue"] not in self.live("sqs_redrive_dlq", p).get("to_queue", set()):
            raise AwsPlatformRefused(f"{p['to_queue']} is not the one same-environment source of {p['queue']} now; "
                                     "nothing was changed")
        dlq, dest = now["arn"], now["arn"].rsplit(":", 1)[0] + ":" + p["to_queue"]
        sqs_read = self._read("sqs")
        if back:
            running = [t for t in sqs_read.list_message_move_tasks(SourceArn=dlq, MaxResults=10).get("Results") or []
                       if t.get("Status") == "RUNNING"]
            if not running:
                return f"nothing to roll back: the move from {p['queue']} finished; moved messages stay in {p['to_queue']}"
            # AWS checks receive, delete and read-attributes on the dead-letter queue for a cancel too (Service
            # Authorization Reference, read 2026-10-10; review H3).
            sqs = self._actor(who, ["sqs:CancelMessageMoveTask", "sqs:ReceiveMessage", "sqs:DeleteMessage",
                                    "sqs:GetQueueAttributes"], [dlq], None)("sqs")
            sqs.cancel_message_move_task(TaskHandle=running[0]["TaskHandle"])
            return f"cancelled the move from {p['queue']}; messages already moved stay in {p['to_queue']}"
        if not isinstance(p["per_second"], int) or not 1 <= p["per_second"] <= 50:
            raise AwsPlatformRefused("the redrive rate is outside 1..50 a second; nothing was changed")
        # AWS authorizes the move against both queues (Service Authorization Reference, read 2026-10-10): receive,
        # delete and read attributes on the dead-letter queue, send on the destination - each on its own queue only.
        sqs = self._actor(who, ["sqs:StartMessageMoveTask", "sqs:ReceiveMessage", "sqs:DeleteMessage",
                                "sqs:GetQueueAttributes"], [dlq], None, also=[(["sqs:SendMessage"], [dest])])("sqs")
        sqs.start_message_move_task(SourceArn=dlq, DestinationArn=dest, MaxNumberOfMessagesPerSecond=p["per_second"])
        return (f"started moving {now.get('waiting')} messages from {p['queue']} to {p['to_queue']} at "
                f"{p['per_second']} a second")

    def _redrive_done(self, name: str, params: dict[str, Any]) -> bool:
        """The latest move finished, and the dead-letter queue is empty - a positive signal."""
        sqs = self._read("sqs")
        url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn", "ApproximateNumberOfMessages"])
        attrs = attrs["Attributes"]
        tasks = sqs.list_message_move_tasks(SourceArn=attrs["QueueArn"], MaxResults=1).get("Results") or []
        return bool(tasks) and tasks[0].get("Status") == "COMPLETED" and str(attrs.get("ApproximateNumberOfMessages")) == "0"

    # ------------------------------------------------------------------ athena: cancel the runaway query (G9-D)

    def _account(self) -> str:
        """The reader session's own account (sts:GetCallerIdentity needs no permission): an ARN for a resource whose
        API answer carries none."""
        return str(self._read("sts").get_caller_identity()["Account"])

    def _live_query(self, params: dict[str, Any]) -> dict[str, Any]:
        wg, qid = params.get("workgroup"), params.get("query")
        if not isinstance(wg, str):
            return {}
        athena = self._read("athena")
        state = athena.get_work_group(WorkGroup=wg)["WorkGroup"].get("State")
        arn = f"arn:aws:athena:{athena.meta.region_name}:{self._account()}:workgroup/{wg}"
        ids = [qid] if isinstance(qid, str) else             (athena.list_query_executions(WorkGroup=wg, MaxResults=50).get("QueryExecutionIds") or [])
        runaway, mine = set(), {}
        for q in (athena.batch_get_query_execution(QueryExecutionIds=ids).get("QueryExecutions") or []) if ids else []:
            if q.get("WorkGroup") != wg:
                continue
            st = q.get("Status") or {}
            mine[q["QueryExecutionId"]] = st.get("State")
            ran = ((q.get("Statistics") or {}).get("EngineExecutionTimeInMillis") or 0) / 1000
            # Only a SELECT: a cancelled INSERT INTO or CTAS can leave partial data (review M4). Its engine time, not
            # its time queued (L8).
            if st.get("State") == "RUNNING" and q.get("SubstatementType") == "SELECT" \
                    and ran >= RUNAWAY_QUERY.total_seconds():
                runaway.add(q["QueryExecutionId"])
        out = {"workgroup": {wg} if state == "ENABLED" else set(), "query": runaway,
               "environment": self._tags("athena", arn).get(ENV_TAG)}
        if isinstance(qid, str):
            out["state"] = {"workgroup": wg, "arn": arn, "query": qid, "query_state": mine.get(qid),
                            "where": self._where(arn)}
        return out

    def _stop_query(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("workgroup", "arn", "query"), f"query {p['query']}")
        if p["query"] not in self.live("athena_stop_query", p).get("query", set()):
            raise AwsPlatformRefused(f"query {p['query']} is no longer a runaway in {p['workgroup']}; nothing was "
                                     "changed")
        athena = self._actor(who, ["athena:StopQueryExecution"], [now["arn"]], None)("athena")
        athena.stop_query_execution(QueryExecutionId=p["query"])
        return f"cancelled query {p['query']} in workgroup {p['workgroup']}"

    def _query_cancelled(self, wg: str, params: dict[str, Any]) -> bool:
        q = self._read("athena").get_query_execution(QueryExecutionId=params.get("query", ""))["QueryExecution"]
        return q.get("WorkGroup") == wg and (q.get("Status") or {}).get("State") == "CANCELLED"

    # ------------------------------------------------------------------ api gateway: raise a stage throttle (G9-D)

    def _rest_api(self, name: str) -> tuple[str, dict[str, str]]:
        """The REST API's id and tags from its name (the metric dimension is the name); exactly one, or none."""
        apigw, found, pos = self._read("apigateway"), [], None
        for _ in range(5):
            page = apigw.get_rest_apis(limit=500, **({"position": pos} if pos else {}))
            found += [(a["id"], a.get("tags") or {}) for a in page.get("items") or [] if a.get("name") == name]
            pos = page.get("position")
            if not pos:
                break
        return found[0] if len(found) == 1 else ("", {})

    def _live_stage(self, params: dict[str, Any]) -> dict[str, Any]:
        name, stage = params.get("api"), params.get("stage")
        if not isinstance(name, str) or not isinstance(stage, str):
            return {}
        api_id, api_tags = self._rest_api(name)
        if not api_id:
            return {}
        apigw = self._read("apigateway")
        st = apigw.get_stage(restApiId=api_id, stageName=stage)
        every = (st.get("methodSettings") or {}).get("*/*") or {}
        rate, burst = every.get("throttlingRateLimit"), every.get("throttlingBurstLimit")
        acct = apigw.get_account().get("throttleSettings") or {}
        arn = f"arn:aws:apigateway:{apigw.meta.region_name}::/restapis/{api_id}/stages/{stage}"
        whole = lambda v: int(v) if isinstance(v, int | float) and v >= 1 and float(v).is_integer() else None
        return {"api": {name}, "stage": {stage} if whole(rate) and whole(burst) else set(),
                # A stage inherits its API's tags (review L6): its own, else the API's.
                "environment": (st.get("tags") or {}).get(ENV_TAG) or api_tags.get(ENV_TAG),
                "current_rate_limit": whole(rate), "current_burst_limit": whole(burst),
                "account_rate_limit": whole(acct.get("rateLimit")), "account_burst_limit": whole(acct.get("burstLimit")),
                "state": {"api": name, "api_id": api_id, "stage": stage, "arn": arn, "rate_limit": whole(rate),
                          "burst_limit": whole(burst), "where": apigw.meta.region_name}}

    def _stage_throttle(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("api", "api_id", "stage", "arn"), f"stage {p['stage']}")
        if back:
            if (now.get("rate_limit"), now.get("burst_limit")) != (p["rate_limit"], p["burst_limit"]):
                raise AwsPlatformRefused(f"stage {p['stage']}'s throttle is no longer the one WARDEN set; nothing was "
                                         "changed")
            rate, burst = snapshot.get("rate_limit"), snapshot.get("burst_limit")
        else:
            self._expect(now, snapshot, ("rate_limit", "burst_limit"), f"stage {p['stage']}'s throttle")
            problems = catalog.validate("apigw_raise_stage_throttle", p, self.live("apigw_raise_stage_throttle", p))
            if problems:
                raise AwsPlatformRefused(f"{'; '.join(problems)}; nothing was changed")
            rate, burst = p["rate_limit"], p["burst_limit"]
        if not isinstance(rate, int) or not isinstance(burst, int):
            raise AwsPlatformError("the plan holds no throttle to return to")
        apigw = self._actor(who, ["apigateway:PATCH"], [now["arn"]], None)("apigateway")
        # Only "replace", and only the all-methods key GetStage returned: AWS takes no "remove" for a throttle, and a
        # path that does not match the stage's own key makes a second setting (API Gateway reference, 2026-10-10).
        apigw.update_stage(restApiId=now["api_id"], stageName=p["stage"], patchOperations=[
            {"op": "replace", "path": "/*/*/throttling/rateLimit", "value": str(rate)},
            {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": str(burst)}])
        return (f"set stage {p['stage']} of {p['api']} throttle from {now.get('rate_limit')}/{now.get('burst_limit')} "
                f"to {rate}/{burst} (rate/burst)")

    def _stage_healthy(self, api: str, params: dict[str, Any]) -> bool:
        """The throttle WARDEN set holds and the stage serves requests - a positive signal."""
        now = self._live_stage(params).get("state") or {}
        sums = self._metric_sums("AWS/ApiGateway", [{"Name": "ApiName", "Value": api},
                                                    {"Name": "Stage", "Value": params.get("stage", "")}], ("Count",))
        return now.get("rate_limit") == params.get("rate_limit") and sums is not None and sums["Count"] > 0

    def _live_cluster(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("cluster")
        if not isinstance(name, str):
            return {}
        rds = self._read("rds")
        [c] = rds.describe_db_clusters(DBClusterIdentifier=name)["DBClusters"]
        members = c.get("DBClusterMembers") or []
        writer = next((m["DBInstanceIdentifier"] for m in members if m.get("IsClusterWriter")), None)
        readers = [m["DBInstanceIdentifier"] for m in members if not m.get("IsClusterWriter")]
        # Each reader by name: a filtered describe is authorized against every instance in the account, which the
        # reader role, held to this environment's names, may not read.
        ready = {}
        for r in readers:
            try:
                [i] = rds.describe_db_instances(DBInstanceIdentifier=r)["DBInstances"]
            except Exception:  # noqa: BLE001, S112 - a reader that cannot be read cannot be named
                continue
            if i.get("DBInstanceStatus") == "available":  # only a reader that is up can take over
                ready[r] = i["DBInstanceArn"]
        return {"cluster": {c["DBClusterIdentifier"]}, "target_instance": set(ready),
                "environment": {t["Key"]: t["Value"] for t in c.get("TagList") or []}.get(ENV_TAG),
                "rollout": "complete" if c.get("Status") == "available" and writer else "progressing",
                "state": {"cluster": c["DBClusterIdentifier"], "arn": c["DBClusterArn"], "writer": writer,
                          "readers": ready, "where": self._where(c["DBClusterArn"])}}

    def _failover(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("cluster", "arn", "writer"), f"cluster {p['cluster']}")
        target = p["target_instance"]
        arn = (now.get("readers") or {}).get(target)
        if not arn or arn != (snapshot.get("readers") or {}).get(target):
            raise AwsPlatformRefused(f"{target} is not an available reader of cluster {p['cluster']} now; nothing "
                                     "was changed")
        rds = self._actor(who, ["rds:FailoverDBCluster"], [now["arn"], arn], None)("rds")
        rds.failover_db_cluster(DBClusterIdentifier=p["cluster"], TargetDBInstanceIdentifier=target)
        return f"failed cluster {p['cluster']} over from {now['writer']} to {target}"

    def _cluster_healthy(self, name: str, params: dict[str, Any]) -> bool:
        """The cluster available, the named reader now its writer, and that instance available - a positive signal."""
        rds = self._read("rds")
        [c] = rds.describe_db_clusters(DBClusterIdentifier=name)["DBClusters"]
        writer = next((m["DBInstanceIdentifier"] for m in c.get("DBClusterMembers") or [] if m.get("IsClusterWriter")),
                      None)
        if c.get("Status") != "available" or not writer or writer != params.get("target_instance"):
            return False
        [i] = rds.describe_db_instances(DBInstanceIdentifier=writer)["DBInstances"]
        return i.get("DBInstanceStatus") == "available"


def from_environment() -> AwsPlatform:
    """The platform a worker runs (`warden worker --platform aws`): reads in the environment's reader role, each
    write in an actor session minted for that one approved plan. A runtime watching several environments names its
    roles by WARDEN_AWS_ROLE_ARN_TEMPLATE (`...:role/warden-{env}-{role}`), so each plan reads and writes through its
    own environment's roles only; one watching a single environment may name them by WARDEN_AWS_READER_ROLE_ARN and
    WARDEN_AWS_ACTOR_ROLE_ARN. The Region is WARDEN's configured one; every role is assumed with the worker's own
    credentials (its ECS task role)."""
    import boto3

    from ..environments import region

    where = region()
    sts = boto3.client("sts", region_name=where)
    template = os.environ.get("WARDEN_AWS_ROLE_ARN_TEMPLATE", "").strip()
    if template:
        # Several watched environments (the runtime module sets the template): each plan through its own
        # environment's roles, `warden-<env>-platform-reader` and `warden-<env>-actor`.
        if not template.startswith("arn:aws:iam::") or "{env}" not in template or "{role}" not in template:
            raise AwsPlatformError("WARDEN_AWS_ROLE_ARN_TEMPLATE must be an IAM role ARN with {env} and {role}")
        from ..environments import default_environment_policies

        known = set(default_environment_policies().known_environments)

        def per_environment(env: str) -> AwsPlatform:
            if env not in known:
                raise AwsPlatformRefused(f"{env!r} is not a configured environment; nothing was read or changed")
            return _platform(sts, where, template.format(env=env, role="platform-reader"),
                             template.format(env=env, role="actor"))

        def unnamed(*_a: Any) -> Any:
            raise AwsPlatformRefused("no environment was named for this AWS call; nothing was read or changed")

        return AwsPlatform(reader=unnamed, actor=unnamed, per_environment=per_environment)
    reader_arn, actor_arn = (os.environ.get("WARDEN_AWS_READER_ROLE_ARN", ""),
                             os.environ.get("WARDEN_AWS_ACTOR_ROLE_ARN", ""))
    if not reader_arn or not actor_arn:
        raise AwsPlatformError("the AWS platform needs WARDEN_AWS_ROLE_ARN_TEMPLATE, or WARDEN_AWS_READER_ROLE_ARN and "
                               "WARDEN_AWS_ACTOR_ROLE_ARN for one environment")
    return _platform(sts, where, reader_arn, actor_arn)


def _platform(sts: Any, where: str, reader_arn: str, actor_arn: str) -> AwsPlatform:
    """One environment's platform: reads in its reader role, each write in an actor session for one plan."""
    import boto3

    from .. import identity

    def session(creds: dict[str, str]) -> Clients:
        s = boto3.Session(**creds, region_name=where)
        return lambda service: s.client(service)

    held: dict[str, Any] = {}

    def reader(service: str) -> Any:
        # The reader session lasts 15 minutes; it is renewed after 10, so no read runs on one about to expire.
        import time

        if held.get("until", 0) < time.monotonic():
            held["clients"] = session(identity.reader_session(sts, role_arn=reader_arn, incident="warden-worker"))
            held["until"] = time.monotonic() + 600
        return held["clients"](service)

    def actor(who: dict[str, Any], actions: list[str], resources: list[str], condition: dict | None,
              also: tuple = ()) -> Clients:
        return session(identity.actor_session(sts, role_arn=actor_arn, incident=who["incident"],
                                              plan_hash=who["plan_hash"], approvers=who["approvers"],
                                              actions=actions, resources=resources, condition=condition, also=also))

    return AwsPlatform(reader=reader, actor=actor)


def _unqualified(function_arn: str) -> str:
    """`arn:...:function:name` from `arn:...:function:name:qualifier`."""
    head, _, rest = function_arn.partition(":function:")
    return f"{head}:function:{rest.split(':')[0]}"


def _when(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)  # Lambda writes `...000+0000`; Python 3.11+ reads it
        except ValueError:
            return None
    return None
