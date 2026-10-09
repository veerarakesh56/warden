"""The runtime's Lambda entry points (G6): how alarms, Alertmanager and approvers reach WARDEN with the laptop off.

- `alarm`: an EventBridge rule on CloudWatch's "Alarm State Change" events. The event becomes an intake event and
  goes through `intake.submit` - grouped, flap-checked, capped, and a workflow started or signalled.
- `alertmanager`: Prometheus Alertmanager's webhook, behind API Gateway. `webhooks.receive` refuses a delivery
  without the bearer secret or over its caps; an alert Alertmanager itself no longer lists as active is dropped.
- `approval`: the passkey approval page, behind API Gateway on the approval domain. Its links and challenges live in
  the shared audit (AuditLinkStore), because one invocation's memory is gone by the next.
- `actor_use`: an EventBridge rule on CloudTrail's AssumeRole of an actor role. A session the audit does not show
  approved is recorded and pages a person (actor_use.check).

Every handler reads its configuration from the environment the runtime module sets (settings.load fills it from
SSM and Secrets Manager), writes to the shared audit (runtime.open_audit) and reaches Temporal Cloud with its own
API key (runtime.connect). Nothing here decides: intake, the workflows and the gate do.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
from datetime import datetime
from typing import Any

from . import resources
from .intake import AlarmEvent
from .models import NAME_PATTERN, RESOURCE_LABELS, Alert, Severity

_CONFIGURED: set[str] = set()


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
    dims: dict[str, str] = {}
    metrics: list[tuple[str, dict[str, str]]] = []
    for m in (detail.get("configuration") or {}).get("metrics") or []:
        metric = (m.get("metricStat") or {}).get("metric") or {}
        these = {str(k): str(v) for k, v in (metric.get("dimensions") or {}).items()}
        metrics.append((str(metric.get("namespace") or ""), these))
        dims.update(these)
    # Only a value that is a plain name: a hostile dimension value made the Alert invalid and the Lambda crash, losing
    # the incident (G9-A1, 2026-10-10). Its label is still dropped and reported by the Alert's own check.
    named = re.compile(NAME_PATTERN)
    service = next((dims[k] for k in _SERVICE_DIMENSIONS if dims.get(k) and named.match(dims[k])),
                   name if named.match(name) else "unknown")
    from .environments import env_of_name

    environment = env_of_name(service) or env_of_name(name) or default_environment
    return AlarmEvent(
        source="alarm", rule=name, state=str(state.get("value")), transitioned_at=when,
        alert=Alert(alert_id="cw", name=name[:512], severity=Severity.high, service=service, environment=environment,
                    summary=str((detail.get("configuration") or {}).get("description") or "")[:4000],
                    started_at=when.isoformat(),
                    # The alarm label last, and raw dimension names never a resource label: a dimension named
                    # `alarm` or `log_group` chose what was read (independent review 2026-10-10, L4).
                    labels={**{k: v for k, v in dims.items() if k not in RESOURCE_LABELS and k != "alarm"},
                            **resources.labels_for(metrics), "alarm": name}))


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
    ev = alarm_event(event, os.environ.get("WARDEN_ENV", ""))
    if ev is None:
        return {"ignored": "not a CloudWatch alarm state change"}
    return {"decisions": _submit([ev])}


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
    _, _, headers, body = _http(event)
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


def approval_page() -> Any:
    """The page as the runtime runs it: links and challenges in the audit, the plan read from the workflow, the
    approval sent to it as a signal."""
    from . import runtime
    from .approval_page import ApprovalPage, AuditLinkStore
    from .workflows import RemediationWorkflow

    def plan_of(workflow_id: str) -> Any:
        async def go() -> Any:
            return await (await runtime.connect()).get_workflow_handle(workflow_id).query(RemediationWorkflow.plan)
        try:
            return asyncio.run(go())
        except Exception:  # noqa: BLE001 - a plan that cannot be read is not waiting for an approval
            return None

    def signal(workflow_id: str, assertion: Any) -> None:
        async def go() -> None:
            await (await runtime.connect()).get_workflow_handle(workflow_id).signal(
                RemediationWorkflow.approve_passkey, assertion)
        asyncio.run(go())

    def deny(workflow_id: str, denial: Any) -> None:
        async def go() -> None:
            await (await runtime.connect()).get_workflow_handle(workflow_id).signal(RemediationWorkflow.deny, denial)
        asyncio.run(go())

    rp_id = os.environ.get("WARDEN_APPROVAL_RP_ID", "").strip()
    if not rp_id:
        raise RuntimeError("WARDEN_APPROVAL_RP_ID is not set: the passkeys' relying party is the approval domain")
    policy = runtime.approver_policy()
    return ApprovalPage(rp_id=rp_id, policy=policy, plan_of=plan_of, signal=signal, deny=deny,
                        store=AuditLinkStore(runtime.open_audit()))


def approval(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    _configure("lambda-approval")
    method, path, _, body = _http(event)
    r = approval_page().handle(method, path, body.decode("utf-8", errors="replace"))
    return {"statusCode": r.status, "headers": r.headers, "body": r.body}


UNAPPROVED_METRIC = "UnapprovedActorUse"


def actor_use(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """An EventBridge rule on CloudTrail's AssumeRole events of the watched environments' actor roles. A session the
    audit does not show approved (actor_use.check), or one that cannot be checked because the audit cannot be read,
    is written to the audit when it can be and counted in `UnapprovedActorUse`, whose alarm pages a person."""
    from . import actor_use as au
    from . import runtime

    _configure("lambda-actor-use")
    detail = event.get("detail") or {}
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
        except Exception as e:  # noqa: BLE001 - the page below still goes out, and the log line says why
            body["audit_error"] = type(e).__name__
    import boto3

    from .environments import region

    boto3.client("cloudwatch", region_name=region()).put_metric_data(
        Namespace=f"WARDEN/{os.environ.get('WARDEN_ENV', '')}",
        MetricData=[{"MetricName": UNAPPROVED_METRIC, "Value": 1, "Unit": "Count"}])
    print(json.dumps({"unapproved_actor_use": body}, default=str))
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
