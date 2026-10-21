"""The runtime's Lambda entry points (G6): how alarms, Alertmanager and approvers reach WARDEN with the laptop off.

- `alarm`: an EventBridge rule on CloudWatch's "Alarm State Change" events. The event becomes an intake event and
  goes through `intake.submit` - grouped, flap-checked, capped, and a workflow started or signalled.
- `alertmanager`: Prometheus Alertmanager's webhook, behind API Gateway. `webhooks.receive` refuses a delivery
  without the bearer secret or over its caps; an alert Alertmanager itself no longer lists as active is dropped.
- `approval`: the passkey approval page, behind API Gateway on the approval domain. Its links and challenges live in
  the shared audit (AuditLinkStore), because one invocation's memory is gone by the next.
- the same `alarm` Lambda takes GuardDuty's and Security Hub's findings on the watched environments' resources
  (security_findings.py): each goes to a person on the rules alone, never to a fix.
- `actor_use`: an EventBridge rule on CloudTrail's AssumeRole of an actor role. A session the audit does not show
  approved is recorded and pages a person (actor_use.check).

Every handler reads its configuration from the environment the runtime module sets (settings.load fills it from
SSM and Secrets Manager), writes to the shared audit (runtime.open_audit) and reaches Temporal Cloud with its own
API key (runtime.connect). Nothing here decides: intake, the workflows and the gate do.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Any

from . import resources
from .intake import AlarmEvent
from .models import NAME_PATTERN, RESOURCE_LABELS, Alert, Severity

_CONFIGURED: set[str] = set()
_LOG = logging.getLogger("warden.lambda")
_LOG.setLevel(logging.INFO)  # the Lambda runtime's root logger shows warnings only: this one line is wanted


def _configure(name: str) -> None:
    """Once per Lambda container: this environment's settings, only the names this Lambda uses (settings.RESTRICTED),
    from SSM and Secrets Manager."""
    if name not in _CONFIGURED:
        from . import settings

        settings.load(only=settings.loadable_for(name))
        _CONFIGURED.add(name)

# The dimension that names what an alarm watches, most specific first (CloudWatch's own dimension names).
_SERVICE_DIMENSIONS = ("ServiceName", "FunctionName", "TableName", "QueueName", "DBClusterIdentifier",
                       "CacheClusterId", "PodName", "TargetGroup", "LoadBalancer", "ClusterName", "TopicName", "ApiId")


def alarm_event(event: dict[str, Any], default_environment: str) -> AlarmEvent | None:
    """An EventBridge CloudWatch alarm state change as an intake event; None for anything else (a configuration change,
    another source). The alarm's own text - its name and description - stays untrusted: the intake and the
    quarantine treat it as they treat any alert's."""
    if event.get("source") != "aws.cloudwatch" or event.get("detail-type") != "CloudWatch Alarm State Change":
        return None
    detail = event.get("detail") or {}
    name = str(detail.get("alarmName") or "")
    state = (detail.get("state") or {})
    when = datetime.fromisoformat(str(state.get("timestamp") or event.get("time")))
    dims, metrics = _alarm_metrics(detail)
    service = _alarm_service(dims, name)
    from .environments import env_of_name
    from .environments import region as runtime_region

    environment = env_of_name(service) or env_of_name(name) or default_environment
    # G10-F1: an alarm forwarded from another Region keeps its own `region` (EventBridge delivers it unchanged); its
    # resources are read there. Only a Region-shaped value - the label is checked as every label is.
    where = str(event.get("region") or "")
    elsewhere = {"alarm_region": where} if where and where != runtime_region() else {}
    return AlarmEvent(
        source="alarm", rule=name, state=str(state.get("value")), transitioned_at=when,
        alert=Alert(alert_id="cw", name=name[:512], severity=Severity.high, service=service, environment=environment,
                    summary=str((detail.get("configuration") or {}).get("description") or "")[:4000],
                    started_at=when.isoformat(),
                    # The alarm label last, and raw dimension names never a resource label: a dimension named
                    # `alarm` or `log_group` chose what was read (independent review 2026-10-10, L4).
                    labels={**{k: v for k, v in dims.items() if k not in RESOURCE_LABELS and k not in _OWN_LABELS},
                            **resources.labels_for(metrics), **elsewhere, "alarm": name, "via": "cloudwatch"}))


def _alarm_metrics(detail: dict[str, Any]) -> tuple[dict[str, str], list[tuple[str, dict[str, str]]]]:
    """(every dimension of the alarm's metrics, merged; each metric's (namespace, dimensions)), from the event's
    configuration."""
    dims: dict[str, str] = {}
    metrics: list[tuple[str, dict[str, str]]] = []
    for m in (detail.get("configuration") or {}).get("metrics") or []:
        metric = (m.get("metricStat") or {}).get("metric") or {}
        these = {str(k): str(v) for k, v in (metric.get("dimensions") or {}).items()}
        metrics.append((str(metric.get("namespace") or ""), these))
        dims.update(these)
    return dims, metrics


def _alarm_service(dims: dict[str, str], name: str) -> str:
    """The service an alarm watches: the most specific dimension whose value is a plain name, else the alarm's name
    when it is one, else "unknown"."""
    # Only a value that is a plain name: a hostile dimension value made the Alert invalid and the Lambda crash, losing
    # the incident (G9-A1, 2026-10-10). Its label is still dropped and reported by the Alert's own check.
    named = re.compile(NAME_PATTERN)
    return next((dims[k] for k in _SERVICE_DIMENSIONS if dims.get(k) and named.match(dims[k])),
                name if named.match(name) else "unknown")


# What a service says about itself that is an incident with no alarm on it (register G10-40). The shapes as AWS's
# own pages give them (ECS "service action events" and "service deployment state change events"; RDS "event
# categories and event messages" - read 2026-10-12).
_ECS_EVENTS = ("ECS Service Action", "ECS Deployment State Change")
_RDS_EVENTS = {"RDS DB Instance Event": "rds_instance", "RDS DB Cluster Event": "aurora_cluster"}
RDS_CATEGORIES = ("failure", "failover", "low storage")
_ECS_NAME = re.compile(r"[A-Z][A-Z0-9_]{2,63}")  # SERVICE_TASK_START_IMPAIRED, SERVICE_DEPLOYMENT_FAILED, ...
_RDS_ID = re.compile(r"RDS-EVENT-\d{4}")


def service_event(event: dict[str, Any], default_environment: str) -> AlarmEvent | None:
    """An AWS service's own event that something is wrong, as an intake event; None for anything else. Owner,
    2026-10-12: WARDEN woke only on an alarm someone had made - a service that cannot start its tasks, a deployment
    its circuit breaker failed, a database that failed over or ran out of storage were never seen without one.
    ECS: a WARN or ERROR service event. RDS: an instance's or a cluster's failure, failover or low-storage event.
    The event's own text (a reason, a message) is the alert's summary: untrusted, as an alarm's description is."""
    source, kind = event.get("source"), event.get("detail-type")
    detail = event.get("detail") if isinstance(event.get("detail"), dict) else {}
    if source == "aws.ecs" and kind in _ECS_EVENTS and detail.get("eventType") in ("WARN", "ERROR"):
        found = _ecs_event(event, detail)
    elif source == "aws.rds" and kind in _RDS_EVENTS:
        found = _rds_event(str(kind), detail)
    else:
        return None
    if found is None:
        return None
    what, text, service, labels = found
    from .environments import env_of_name

    when = datetime.fromisoformat(str(event.get("time")))
    return AlarmEvent(
        source="alarm", rule=f"{what}:{service}", state="ALARM", transitioned_at=when, stateless=True,
        alert=Alert(alert_id="ev", name=what, severity=Severity.high, service=service,
                    environment=env_of_name(service) or env_of_name(labels.get("ecs_cluster", "")) or default_environment,
                    summary=text[:4000], started_at=when.isoformat(), labels={**labels, "via": "aws-event"}))


def _ecs_event(event: dict[str, Any], detail: dict[str, Any]) -> tuple[str, str, str, dict[str, str]] | None:
    """service_event for an ECS WARN or ERROR service event: (event name, reason, service, labels); None when its name,
    cluster or service is not a plain name."""
    resources_named = event.get("resources") if isinstance(event.get("resources"), list) else []
    arn = str(resources_named[0]) if resources_named else ""
    named = re.compile(NAME_PATTERN)
    what, text = str(detail.get("eventName") or ""), str(detail.get("reason") or "")
    cluster, _, service = arn.partition(":service/")[2].partition("/")
    if not (_ECS_NAME.fullmatch(what) and named.match(cluster) and named.match(service)):
        return None
    return what, text, service, {"ecs_cluster": cluster, "ecs_service": service}


def _rds_event(kind: str, detail: dict[str, Any]) -> tuple[str, str, str, dict[str, str]] | None:
    """service_event for an RDS instance or cluster event: (event id, message, source, labels); None unless it is a
    failure, failover or low-storage event with an RDS event id and a source that is a plain name."""
    named = re.compile(NAME_PATTERN)
    categories = detail.get("EventCategories") if isinstance(detail.get("EventCategories"), list) else []
    what, text = str(detail.get("EventID") or ""), str(detail.get("Message") or "")
    service = str(detail.get("SourceIdentifier") or "")
    if not (set(RDS_CATEGORIES) & {str(c) for c in categories} and _RDS_ID.fullmatch(what) and named.match(service)):
        return None
    return what, text, service, {_RDS_EVENTS[kind]: service}


def health_event(event: dict[str, Any], default_environment: str) -> AlarmEvent | None:
    """An AWS Health notice that one of the watched environments' own resources is affected by an AWS-side issue,
    as an intake event; None for anything else (owner, 2026-10-12: triggers beyond the alarms someone made). Only an
    open `issue` scoped to this account, and only for an affected resource whose name says which watched environment
    it is in: a public notice names no resource of ours, and an instance id names no environment. It goes to a person
    on the rules alone - no change of WARDEN's mends AWS's own fault - with WARDEN's reads of the resource. The notice's
    text is the alert's summary: untrusted, as an alarm's description is. The shape is AWS's own page, "AWS Health
    events Amazon EventBridge schema" (read 2026-10-14)."""
    if event.get("source") != "aws.health" or event.get("detail-type") != "AWS Health Event":
        return None
    detail = event.get("detail") if isinstance(event.get("detail"), dict) else {}
    if (detail.get("eventTypeCategory") != "issue" or detail.get("eventScopeCode") != "ACCOUNT_SPECIFIC"
            or detail.get("statusCode") != "open"):
        return None
    what = str(detail.get("eventTypeCode") or "")
    entities = detail.get("affectedEntities") if isinstance(detail.get("affectedEntities"), list) else []
    named = re.compile(NAME_PATTERN)
    from .environments import env_of_name

    # The resource's own name: an ARN's last part (after `/` or `:`), or the value itself.
    names = [re.split(r"[/:]", str(e.get("entityValue") or ""))[-1] for e in entities if isinstance(e, dict)]
    ours = next((n for n in names if n and named.match(n) and env_of_name(n)), "")
    if not (_HEALTH_CODE.fullmatch(what) and ours):
        return None
    when = datetime.fromisoformat(str(event.get("time")))
    text = next((str(d.get("latestDescription") or "") for d in detail.get("eventDescription") or []
                 if isinstance(d, dict)), "")
    service = str(detail.get("service") or "AWS")
    return AlarmEvent(
        source="alarm", rule=f"{what}:{ours}", state="ALARM", transitioned_at=when, stateless=True,
        escalate=(f"AWS Health reports an issue with {service[:40]} affecting {ours}: an AWS-side fault, which no change "
                  "of WARDEN's mends - a person follows AWS's notice"),
        alert=Alert(alert_id="ev", name=what, severity=Severity.high, service=ours,
                    environment=env_of_name(ours) or default_environment, summary=text[:4000],
                    started_at=when.isoformat(), labels={"via": "aws-health"}))


_HEALTH_CODE = re.compile(r"AWS_[A-Z0-9_]{3,120}")  # AWS_EC2_INSTANCE_STORE_DRIVE_PERFORMANCE_DEGRADED, ...


# Labels intake writes itself; a dimension of the same name never stands in for them (L4, G10-F1).
_OWN_LABELS = ("alarm", "alarm_region", "via")


def _submit(events: list[AlarmEvent]) -> list[dict[str, Any]]:
    from . import intake, runtime

    async def go() -> list[dict[str, Any]]:
        client = await runtime.connect()
        log = runtime.open_audit()
        try:
            return [(await intake.submit(client, ev, log)).model_dump() for ev in events]
        finally:
            log.close()
    return asyncio.run(go())


def alarm(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    _configure("lambda-alarm")
    env = os.environ.get("WARDEN_ENV", "")
    from .security_findings import finding_event

    ev = alarm_event(event, env) or service_event(event, env) or health_event(event, env) or finding_event(event)
    if ev is None:
        return {"ignored": "not a CloudWatch alarm state change, nor a service event WARDEN takes"}
    decisions = _submit([ev])
    for d in decisions:
        # What intake decided, one line per alarm, where whoever operates WARDEN can see it without the database: an
        # alarm held as expected down left no sign anywhere but the audit (2026-10-14).
        _LOG.info("intake: %s %s -> %s: %s", ev.state, " ".join(ev.rule.split())[:120], d.get("action"),
                  " ".join(str(d.get("reason", "")).split())[:240])
    return {"decisions": decisions}


def _http(event: dict[str, Any]) -> tuple[str, str, dict[str, str], bytes]:
    """(method, path, headers, body) from an API Gateway HTTP API (payload 2.0) event."""
    http = (event.get("requestContext") or {}).get("http") or {}
    body = event.get("body") or ""
    raw = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode()
    headers = {str(k).lower(): str(v) for k, v in (event.get("headers") or {}).items()}
    return str(http.get("method", "GET")), str(event.get("rawPath") or http.get("path") or "/"), headers, raw


def alertmanager(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    from . import webhooks

    _configure("lambda-alertmanager")
    _, path, headers, body = _http(event)
    if path.rstrip("/") == "/datadog":
        return _datadog(headers, body)
    # The current bearer secret and, during a rotation, the previous one (register S4).
    secrets = [s for s in (os.environ.get("WARDEN_ALERTMANAGER_TOKEN", ""),
                           os.environ.get("WARDEN_ALERTMANAGER_TOKEN_PREVIOUS", "")) if s]
    got = webhooks.receive(headers, body, secrets=secrets, environment=os.environ.get("WARDEN_ENV", ""))
    if got.status != 202:
        return {"statusCode": got.status, "body": ""}
    events, dropped = got.events, list(got.refused)
    if url := os.environ.get("WARDEN_ALERTMANAGER_URL", "").strip():
        events, gone = webhooks.confirm_firing(events, webhooks.alertmanager_active(url))
        dropped += gone
    decisions = _submit(events) if events else []
    return {"statusCode": 202, "headers": {"content-type": "application/json"},
            "body": json.dumps({"accepted": len(decisions), "dropped": len(dropped)})}


def _datadog(headers: dict[str, str], body: bytes) -> dict[str, Any]:
    """A Datadog monitor's webhook (webhooks.receive_datadog): its bearer secret, then Datadog asked whether the
    monitor is alerting, then intake - as an Alertmanager alert is (register G10-53)."""
    from . import webhooks

    got = webhooks.receive_datadog(headers, body, secrets=[os.environ.get("WARDEN_DATADOG_WEBHOOK_TOKEN", "")],
                                   environment=os.environ.get("WARDEN_ENV", ""))
    if got.status != 202:
        return {"statusCode": got.status, "body": ""}
    alerting = webhooks.datadog_alerting(os.environ.get("WARDEN_DATADOG_SITE", "").strip(),
                                         os.environ.get("WARDEN_DATADOG_API_KEY", "").strip(),
                                         os.environ.get("WARDEN_DATADOG_APP_KEY", "").strip())
    events, gone = webhooks.confirm_datadog(got.events, alerting)
    decisions = _submit(events) if events else []
    return {"statusCode": 202, "headers": {"content-type": "application/json"},
            "body": json.dumps({"accepted": len(decisions), "dropped": len(got.refused) + len(gone)})}


# RemediationWorkflow's query and signals by the names it registers (workflows.py; a test holds them equal).
PLAN_QUERY, APPROVE_SIGNAL, DENY_SIGNAL, SIGNED_SIGNAL = "plan", "approve_passkey", "deny", "approve"


def approval_page() -> Any:
    """The page as the runtime runs it: links and challenges in the audit, the plan read from the workflow, the
    approval sent to it as a signal. The workflow's query and signals are called by name, so the
    worker, the activities and the workflows are never imported here: they were most of a cold start's page time
    (2.5 s, live 2026-10-14)."""
    from . import runtime_base as runtime  # runtime.py's light half
    from .approval_page import ApprovalPage, AuditLinkStore
    from .approvals import Plan

    def plan_of(workflow_id: str) -> Any:
        async def go() -> Any:
            return await (await runtime.connect()).get_workflow_handle(workflow_id).query(
                PLAN_QUERY, result_type=Plan | None)
        try:
            return asyncio.run(go())
        except Exception:  # noqa: BLE001 - a plan that cannot be read is not waiting for an approval
            return None

    def signal(workflow_id: str, assertion: Any) -> None:
        async def go() -> None:
            await (await runtime.connect()).get_workflow_handle(workflow_id).signal(
                APPROVE_SIGNAL, assertion)
        asyncio.run(go())

    def deny(workflow_id: str, denial: Any) -> None:
        async def go() -> None:
            await (await runtime.connect()).get_workflow_handle(workflow_id).signal(DENY_SIGNAL, denial)
        asyncio.run(go())

    def signed(workflow_id: str, approval: Any) -> None:
        async def go() -> None:
            await (await runtime.connect()).get_workflow_handle(workflow_id).signal(SIGNED_SIGNAL, approval)
        asyncio.run(go())

    rp_id = os.environ.get("WARDEN_APPROVAL_RP_ID", "").strip()
    if not rp_id:
        raise RuntimeError("WARDEN_APPROVAL_RP_ID is not set: the passkeys' relying party is the approval domain")
    policy = runtime.approver_policy()
    from . import paging, slack_login

    log = runtime.open_audit()
    return ApprovalPage(rp_id=rp_id, policy=policy, plan_of=plan_of, signal=signal, deny=deny,
                        store=AuditLinkStore(log), log=log, slack=slack_login.from_environment(), signed=signed,
                        pages=paging.from_environment())


def approval(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    method, path, _, body = _http(event)
    if (method.upper(), path.rstrip("/")) == ("POST", "/s/interact"):
        # Slack's note of a button click, answered before anything is loaded: Slack allows three seconds, and a cold
        # start that first read its settings and opened the audit took 6.5 (live, 2026-10-12 - "Operation timed
        # out" beside the button). Nothing is read from it and nothing is decided by it (approval_page._slack).
        return {"statusCode": 200, "headers": {"Content-Type": "text/plain", "Cache-Control": "no-store"}, "body": ""}
    cold, t0 = "lambda-approval" not in _CONFIGURED, time.perf_counter()
    _configure("lambda-approval")
    t1 = time.perf_counter()
    page = approval_page()
    t2 = time.perf_counter()
    r = page.handle(method, path, body.decode("utf-8", errors="replace"),
                    query=str(event.get("rawQueryString") or ""), cookies=event.get("cookies") or [])
    if cold:
        # Where a cold start's seconds go, measured where it happens: the first page after a quiet period took 5.6 s
        # to 9.5 s (live, 2026-10-12), and the cause is decided from these numbers, not guessed. Durations only.
        _LOG.info("approval cold start: settings=%dms page=%dms request=%dms", (t1 - t0) * 1000, (t2 - t1) * 1000,
                  (time.perf_counter() - t2) * 1000)
    return {"statusCode": r.status, "headers": r.headers, "body": r.body}


UNAPPROVED_METRIC = "UnapprovedActorUse"
APPROVERS_METRIC = "ApproverListChanged"
_LIST_WRITES = frozenset({"PutParameter", "DeleteParameter", "LabelParameterVersion", "UnlabelParameterVersion"})


def _approver_list_write(detail: dict[str, Any]) -> bool:
    """A CloudTrail record of a write - made or refused - to this runtime's approver list."""
    from .environments import names

    env = os.environ.get("WARDEN_ENV", "").strip()
    params = detail.get("requestParameters") or {}
    return (bool(env) and detail.get("eventSource") == "ssm.amazonaws.com" and detail.get("eventName") in _LIST_WRITES
            and isinstance(params, dict) and params.get("name") == names(env).ssm + "approvers")


def _approvers_changed(detail: dict[str, Any]) -> dict[str, Any]:
    """The approver list is the root of who may approve: whoever writes it can give an approver any name - or add a
    passkey of their own (owner, 2026-10-12). Every write to it, and every refused attempt, is put on the record and
    counted in `ApproverListChanged`, whose alarm pages a person. Who made it is named by kind and by the name an
    administrator set (a role's, a user's) - never a session name its caller chose."""
    from . import runtime

    who = detail.get("userIdentity") or {}
    issuer = ((who.get("sessionContext") or {}).get("sessionIssuer") or {}).get("userName")
    body = {"event": detail.get("eventName"), "by_kind": who.get("type"), "by": issuer or who.get("userName") or "",
            "event_id": detail.get("eventID"), "event_time": detail.get("eventTime"),
            "refused": detail.get("errorCode") or ""}
    try:
        runtime.open_audit().append("approvers", "approvers.changed", body)
    except Exception as e:  # noqa: BLE001 - the page below still goes out; and the log line says why
        body["audit_error"] = type(e).__name__
    import boto3

    from .environments import region

    boto3.client("cloudwatch", region_name=region()).put_metric_data(
        Namespace=f"WARDEN/{os.environ.get('WARDEN_ENV', '')}",
        MetricData=[{"MetricName": APPROVERS_METRIC, "Value": 1, "Unit": "Count"}])
    from .observability import gated

    print(gated(json.dumps({"approver_list_changed": body}, default=str)))
    return {"approver_list_changed": True, "refused": bool(body["refused"])}


def actor_use(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """An EventBridge rule on CloudTrail's AssumeRole events of the watched environments' actor roles. A session the
    audit does not show approved (actor_use.check), or one that cannot be checked because the audit cannot be read,
    is written to the audit when it can be and counted in `UnapprovedActorUse`, whose alarm pages a person."""
    from . import actor_use as au
    from . import runtime

    _configure("lambda-actor-use")
    detail = event.get("detail") or {}
    if _approver_list_write(detail):
        return _approvers_changed(detail)
    if not au.is_actor_session(detail):
        return {"ignored": "not a successful AssumeRole of an actor role"}
    log = None
    try:
        log = runtime.open_audit()
        problems = au.check(detail, log)
    except Exception as e:  # noqa: BLE001 - a session that cannot be checked is treated as unapproved
        problems = [f"the audit could not be read to check this session ({type(e).__name__})"]
    if not problems:
        return {"approved": True}
    params = detail.get("requestParameters") or {}
    body = {"role": params.get("roleArn"), "source_identity": params.get("sourceIdentity"),
            "caller": (detail.get("userIdentity") or {}).get("arn"), "event_id": detail.get("eventID"),
            "event_time": detail.get("eventTime"), "problems": problems}
    if log is not None:
        try:
            log.append(str(params.get("sourceIdentity") or "actor-use"), "actor.unapproved", body)
        except Exception as e:  # noqa: BLE001 - the page below still goes out; and the log line says why
            body["audit_error"] = type(e).__name__
    import boto3

    from .environments import region

    boto3.client("cloudwatch", region_name=region()).put_metric_data(
        Namespace=f"WARDEN/{os.environ.get('WARDEN_ENV', '')}",
        MetricData=[{"MetricName": UNAPPROVED_METRIC, "Value": 1, "Unit": "Count"}])
    from .observability import gated

    print(gated(json.dumps({"unapproved_actor_use": body}, default=str)))
    return {"approved": False, "problems": problems}


AUDIT_WRITER = "warden_audit_writer"


def migrate(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Once per deploy (runtime.yml invokes it after apply): the audit's tables and append-only triggers on the
    runtime's Aurora, and its writer login - SELECT and INSERT only, signing in with an IAM token, no password. The
    only code that reads the cluster's master secret, which RDS keeps in Secrets Manager; its role reads that secret
    and nothing else. Idempotent."""
    import boto3
    from psycopg.conninfo import make_conninfo

    from . import audit
    from .environments import region

    master = json.loads(boto3.client("secretsmanager", region_name=region()).get_secret_value(
        SecretId=os.environ["WARDEN_AUDIT_MASTER_SECRET"])["SecretString"])
    dsn = make_conninfo(host=os.environ["WARDEN_AUDIT_HOST"], port=5432, dbname=os.environ["WARDEN_AUDIT_DB"],
                        user=master["username"], password=master["password"], sslmode="require")
    audit.migrate(dsn, AUDIT_WRITER, iam_login=True)
    return {"migrated": True, "writer": AUDIT_WRITER}


# --------------------------------------------------------------------------- what reaches the Lambda's log

class HandlerFailed(RuntimeError):
    """A handler's error as the Lambda runtime is given it: its type, never its text. The runtime prints an uncaught
    error's message and traceback to the log as they are, and an exception's text can quote an alert, a request or a
    connection string; the error itself is logged first, through the log gate (observability.GatedWrap)."""


def _gated(handler: Any) -> Any:
    @functools.wraps(handler)
    def run(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
        from .observability import gate_handlers, install_log_gate

        gate_handlers()  # the runtime's own root handler, and any added since, write through the gate
        if not logging.getLogger().handlers:
            install_log_gate()  # none at all: Python's last-resort handler would print the error raw (review)
        try:
            return handler(event, context)
        except Exception as exc:
            logging.getLogger("warden.lambda").exception("%s failed", handler.__name__)
            raise HandlerFailed(f"{handler.__name__} failed ({type(exc).__name__}); the error is on the log, "
                                "gated") from None

    return run


# The entry points terraform names (frontdoor.tf, migrate.tf): each through the gate.
alarm = _gated(alarm)
alertmanager = _gated(alertmanager)
approval = _gated(approval)
actor_use = _gated(actor_use)
migrate = _gated(migrate)
