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
(an existing all-methods throttle, at most double, within the account's), and arc_zonal_shift (ARC moves a
load balancer's traffic away from its ONE impaired zone - no healthy host while another zone serves - for 30 to
180 minutes, only where the balancer allows zonal shifts; the rollback cancels WARDEN's own shift only), and
appconfig_revert (stop and revert the latest deployment of the ONE AppConfig environment whose monitors name the
firing alarm - AWS's own link - within 70 of AWS's 72 hours, its application, environment and deployment tagged
with one Environment; re-deploying is a new decision, so there is nothing to roll back), and
codepipeline_freeze (disable the inbound transition of the pipeline stage the service's own `warden:pipeline` tag
names - AWS has no link of its own - of the service's environment, while deploys still flow; enabled again on
rollback). A pause, a shift and a freeze end "mitigated": the page stays open (catalog.MITIGATES).
"""

from __future__ import annotations

import itertools
import json
import os
import re
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
# G9-D: the tag on a Lambda function or an ECS service naming the pipeline stage that deploys it: `<pipeline>/<stage>`.
PIPELINE_TAG = "warden:pipeline"
_PIPELINE_NAME = re.compile(r"[A-Za-z0-9.@_-]{1,100}")  # CodePipeline's own pattern for both names
# Review-e M2: a zone is judged on at least this many one-minute points of the HEALTH_WINDOW.
ZONE_POINTS = 3
# G9-D: AppConfig reverts a COMPLETED deployment for 72 hours (AWS, read 2026-10-10); WARDEN keeps a margin.
APPCONFIG_REVERT = timedelta(hours=70)
# ...and only a deployment that STARTED in the hours before its alarm went into ALARM: the change that may have caused
# it, never an unrelated one days old (review-e H1).
APPCONFIG_BEFORE_ALARM = timedelta(hours=6)
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
          "apigw_raise_stage_throttle": "apigw", "arc_zonal_shift": "elb", "appconfig_revert": "appconfig",
          "codepipeline_freeze": "codepipeline", "ec2_revert_sg_change": "ec2",
          "ecs_restore_desired": "ecs", "lambda_restore_concurrency": "lambda", "lambda_restore_settings": "lambda", "asg_restore_capacity": "asg",
          "sqs_restore_attributes": "sqs", "kinesis_restore_retention": "kinesis",
          "apigw_restore_stage": "apigw", "elb_reregister_targets": "elb", "kms_cancel_key_deletion": "kms",
          "secrets_restore_secret": "secretsmanager",
          "aurora_failover": "rds"}
AWS_RESERVED_UNRESERVED = 100  # AWS keeps this much account concurrency unreserved (catalog._raise_concurrency)

# G10-D: undoing a recorded security group change. Only a change in the hours before the alarm went into ALARM.
SG_CHANGE_BEFORE_ALARM = timedelta(hours=6)
REVERT_BEFORE_ALARM = SG_CHANGE_BEFORE_ALARM  # every revert family: the change must be this close before the alarm
_SG_ID = re.compile(r"sg-[0-9a-f]{8,17}")
_SG_EVENTS = ("RevokeSecurityGroupEgress", "RevokeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
              "AuthorizeSecurityGroupIngress")
_OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def never_revert() -> frozenset[str]:
    """Role and user names whose changes WARDEN never reverts - a security team's, a break-glass identity's. The owner
    names them (WARDEN_NEVER_REVERT_PRINCIPALS, comma-separated); a revoked rule may be the incident response."""
    return frozenset(n.strip() for n in os.environ.get("WARDEN_NEVER_REVERT_PRINCIPALS", "").split(",") if n.strip())


def _get(d: dict[str, Any], name: str) -> Any:
    """A field by name in any case: CloudTrail writes `groupId`, the EC2 API `GroupId`."""
    low = name.lower()
    return next((v for k, v in d.items() if k.lower() == low), None)


def _items(value: Any) -> list[dict[str, Any]]:
    """A CloudTrail list: `{"items": [...]}` as EC2 writes it, or a plain list."""
    if isinstance(value, dict):
        value = value.get("items") or value.get("item") or []
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _sg_group_of(request: dict[str, Any]) -> str:
    """The group a security group write names: `groupId` at the top, or in the newer APIs' request wrapper."""
    direct = _get(request, "groupId")
    if isinstance(direct, str):
        return direct
    inner = next((v for v in request.values() if isinstance(v, dict) and isinstance(_get(v, "groupId"), str)), {})
    return str(_get(inner, "groupId") or "") if inner else ""


def _sg_rule_key(r: dict[str, Any]) -> list[Any]:
    """One rule as a canonical list - [egress, protocol, from, to, kind, value] - from CloudTrail's camelCase or the
    EC2 API's PascalCase. A list, not a tuple: the plan's snapshot comes back from JSON as lists."""
    ref = _get(r, "referencedGroupId") or _get(_get(r, "referencedGroupInfo") or {}, "groupId")
    kind, value = next(((k, v) for k, v in (("cidr4", _get(r, "cidrIpv4")), ("cidr6", _get(r, "cidrIpv6")),
                                            ("prefix", _get(r, "prefixListId")), ("group", ref)) if v), ("", ""))
    port = (lambda v: int(v) if isinstance(v, (int, str)) and str(v).lstrip("-").isdigit() else None)
    return [bool(_get(r, "isEgress")), str(_get(r, "ipProtocol") or ""), port(_get(r, "fromPort")),
            port(_get(r, "toPort")), kind, str(value)]


def _sg_parse(raw: dict[str, Any], group: str) -> dict[str, Any] | None:
    """One CloudTrail security group write on `group` that succeeded, with what it changed - else None."""
    try:
        d = json.loads(raw.get("CloudTrailEvent") or "{}")
    except ValueError:
        return None
    name = str(raw.get("EventName") or d.get("eventName") or "")
    if name not in _SG_EVENTS or d.get("errorCode") or _sg_group_of(d.get("requestParameters") or {}) != group:
        return None
    kind = "revoke" if name.startswith("Revoke") else "authorize"
    response = d.get("responseElements")
    field = "revokedSecurityGroupRuleSet" if kind == "revoke" else "securityGroupRuleSet"
    items = _items(_get(response, field)) if isinstance(response, dict) else []
    who = d.get("userIdentity") or {}
    issuer = (who.get("sessionContext") or {}).get("sessionIssuer") or {}
    actor_name = str(issuer.get("userName") or who.get("userName") or "")
    at = _when(raw.get("EventTime") or d.get("eventTime"))
    return {"event": str(raw.get("EventId") or d.get("eventID") or ""), "event_name": name, "kind": kind,
            "egress": name.endswith("Egress"), "at": at, "event_time": at.strftime("%Y-%m-%dT%H:%M:%SZ") if at else "?",
            "rules": sorted((_sg_rule_key(i) for i in items), key=json.dumps), "rule_ids": sorted(str(_get(i, "securityGroupRuleId") or "")
                                                                                 for i in items),
            "who_type": str(who.get("type") or ""), "invoked_by": str(who.get("invokedBy") or ""),
            "source_identity": str((who.get("sessionContext") or {}).get("sourceIdentity") or ""),
            "actor_name": actor_name, "actor": f"{str(who.get('type') or '?').lower()}/{actor_name or '?'}",
            "truncated": not isinstance(response, dict) or not items}


def _sg_undo_text(e: dict[str, Any]) -> str:
    verb = "authorize again" if e["kind"] == "revoke" else "revoke"
    way = "to" if e["egress"] else "from"
    rules = "; ".join(f"{r[1]} {r[2]}-{r[3]} {way} {r[5]}" for r in e["rules"])
    return f"{verb} {len(e['rules'])} {'egress' if e['egress'] else 'ingress'} rule(s): {rules}"[:400]


def _sg_permission(r: list[Any]) -> dict[str, Any]:
    """The EC2 IpPermission that writes exactly one canonical rule."""
    _egress, proto, low, high, kind, value = r
    perm: dict[str, Any] = {"IpProtocol": proto}
    if proto not in ("-1", "all") and low is not None:
        perm.update(FromPort=low, ToPort=high)
    perm.update({"cidr4": {"IpRanges": [{"CidrIp": value}]}, "cidr6": {"Ipv6Ranges": [{"CidrIpv6": value}]},
                 "prefix": {"PrefixListIds": [{"PrefixListId": value}]},
                 "group": {"UserIdGroupPairs": [{"GroupId": value}]}}.get(kind, {}))
    return perm

Clients = Callable[[str], Any]
# (who, actions, resources, condition[, also]) -> a client factory whose clients hold that one actor session; `also`
# holds further exact (actions, resources) statements (identity.session_policy).
Actor = Callable[[dict[str, Any], list[str], list[str], dict[str, Any] | None], Clients]

# G10-D3: undoing a recorded change from AWS Config's record of the resource before it (owner decision 2026-10-10: a
# continuous Config recorder). Field paths from AWS's own Config resource schemas (awslabs/aws-config-resource-schema,
# read 2026-10-10): AWS::ECS::Service configuration.DesiredCount; AWS::Lambda::Function
# supplementaryConfiguration.Concurrency.reservedConcurrentExecutions.
CONFIG_LOOKBACK = timedelta(days=7)  # GetResourceConfigHistory spans at most 7 days a call


def _json(value: Any) -> dict[str, Any]:
    """A Config item's configuration: a JSON string, or already an object."""
    if isinstance(value, dict):
        return value
    try:
        out = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return out if isinstance(out, dict) else {}


def _trail_change(raw: dict[str, Any]) -> dict[str, Any] | None:
    """One CloudTrail write that succeeded, with who made it - else None."""
    try:
        d = json.loads(raw.get("CloudTrailEvent") or "{}")
    except ValueError:
        return None
    if d.get("errorCode"):
        return None
    who = d.get("userIdentity") or {}
    issuer = (who.get("sessionContext") or {}).get("sessionIssuer") or {}
    actor_name = str(issuer.get("userName") or who.get("userName") or "")
    at = _when(raw.get("EventTime") or d.get("eventTime"))
    return {"event": str(raw.get("EventId") or d.get("eventID") or ""),
            "event_name": str(raw.get("EventName") or d.get("eventName") or ""),
            "at": at, "event_time": at.strftime("%Y-%m-%dT%H:%M:%SZ") if at else "?",
            "request": d.get("requestParameters") if isinstance(d.get("requestParameters"), dict) else None,
            "who_type": str(who.get("type") or ""), "invoked_by": str(who.get("invokedBy") or ""),
            "source_identity": str((who.get("sessionContext") or {}).get("sourceIdentity") or ""),
            "actor_name": actor_name, "actor": f"{str(who.get('type') or '?').lower()}/{actor_name or '?'}",
            "user_agent": str(d.get("userAgent") or "")}


# The user agents of the infrastructure-as-code tools that call AWS's APIs themselves (CloudFormation, and so CDK and
# SAM, call as an AWS service and are refused as one).
_IAC = re.compile(r"Terraform|OpenTofu|pulumi|crossplane", re.IGNORECASE)


def _who_refusal(e: dict[str, Any], onset: datetime) -> str:
    """Why a recorded change is not WARDEN's to undo, whatever it changed - or ""."""
    if e["at"] is None or e["at"] >= onset:
        return "the change came after the alarm went off - it may be the fix"
    if e["who_type"] == "Root":
        return "the change was made by the root user: a person looks"
    if e["invoked_by"]:
        return f"the change was made by an AWS service ({e['invoked_by']}): its owner manages it"
    if e["source_identity"].startswith("inc-"):
        return "the change was WARDEN's own: its own rollback undoes it"
    if e["actor_name"] and e["actor_name"] in never_revert():
        return f"{e['actor']} is a principal whose changes WARDEN never reverts (WARDEN_NEVER_REVERT_PRINCIPALS)"
    if e["request"] is None:
        return "CloudTrail did not record the whole request (too large, or not returned)"
    iac = _IAC.search(e.get("user_agent") or "")
    if iac:
        return (f"the change was made by infrastructure as code ({iac.group(0)}): undo it in the code - its next "
                "apply would undo WARDEN's")
    return ""


# G10-D4: the settings a configuration revert may write, Lambda's bounds for each, and AWS Config's field for each
# (awslabs/aws-config-resource-schema AWS::Lambda::Function, read 2026-10-10: configuration.timeout, .memorySize,
# .ephemeralStorage.size).
_SETTINGS = {"timeout": (1, 900), "memory": (128, 10240), "storage": (512, 10240)}
_SETTINGS_REQUEST_KEYS = frozenset({"functionname", "timeout", "memorysize", "ephemeralstorage", "revisionid"})


def _setting_in_request(r: dict[str, Any], key: str) -> Any:
    if key == "timeout":
        return _get(r, "timeout")
    if key == "memory":
        return _get(r, "memorySize")
    storage = _get(r, "ephemeralStorage")
    return _get(storage, "size") if isinstance(storage, dict) else None


def _lambda_settings(conf: dict[str, Any], keys: list[str] | None = None) -> dict[str, Any]:
    """The function's timeout, memory and ephemeral storage, from GetFunctionConfiguration or a Config item."""
    storage = _get(conf, "ephemeralStorage")
    out = {"timeout": _get(conf, "timeout"), "memory": _get(conf, "memorySize"),
           "storage": _get(storage, "size") if isinstance(storage, dict) else None}
    return {k: v for k, v in out.items() if keys is None or k in keys}


# G10 v2: a queue's settings a revert may write, and SQS's bounds for each (AWS::SQS::Queue's Config schema, read
# 2026-10-10). Never Policy, RedrivePolicy, RedriveAllowPolicy, encryption or FIFO settings.
# Not MessageRetentionPeriod: setting it shorter - the restore or its automatic rollback - expires queued messages
# for good (G10 held-out re-check, 2026-10-10: g10-158 proposed undoing Terraform's longer retention).
_QUEUE_SETTINGS = {"DelaySeconds": (0, 900), "MaximumMessageSize": (1024, 1048576),
                   "ReceiveMessageWaitTimeSeconds": (0, 20), "VisibilityTimeout": (0, 43200)}


def _ints(conf: dict[str, Any], keys: list[str]) -> dict[str, int]:
    out = {}
    for k in keys:
        v = _get(conf, k)
        if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
            out[k] = int(v)
    return out


def _pairs_text(values: dict[str, Any]) -> str:
    return ",".join(f"{k}={values[k]}" for k in sorted(values))


def _pairs_parse(text: str, allowed: dict[str, tuple[int, int]]) -> dict[str, int]:
    out = {}
    for part in text.split(","):
        k, _, v = part.partition("=")
        if k not in allowed or not v.isdigit():
            return {}
        out[k] = int(v)
    return out


def _settings_text(values: dict[str, Any]) -> str:
    return ",".join(f"{k}={values[k]}" for k in sorted(values))


def _settings_parse(text: str) -> dict[str, int]:
    out = {}
    for part in text.split(","):
        k, _, v = part.partition("=")
        if k not in _SETTINGS or not v.isdigit():
            return {}
        out[k] = int(v)
    return out


def _settings_call(values: dict[str, int]) -> dict[str, Any]:
    call: dict[str, Any] = {}
    if "timeout" in values:
        call["Timeout"] = values["timeout"]
    if "memory" in values:
        call["MemorySize"] = values["memory"]
    if "storage" in values:
        call["EphemeralStorage"] = {"Size": values["storage"]}
    return call


def _last(value: Any) -> str:
    """A name from a name or an ARN: `orders` from `arn:...:service/c1/orders` or `arn:...:function:orders`."""
    return str(value or "").rsplit("/", 1)[-1].rsplit(":", 1)[-1]




def _rule_on_bus(ref: str) -> dict[str, str]:
    """`rule` or `bus/rule` (the resolver's form for a custom bus's rule) as DescribeRule/EnableRule arguments. Rule
    names hold no `/`; bus names may (a partner bus), so the bus is everything before the last one."""
    bus, _, name = ref.rpartition("/")
    return {"Name": name, **({"EventBusName": bus} if bus else {})}

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
                    "LimitExceededException",
                    # G9-D entries (review-e M6): ARC, AppConfig and CodePipeline refuse with these; throttling is a
                    # call AWS did not run. None is "half-made".
                    "ConflictException", "BadRequestException", "StageNotFoundException", "PipelineNotFoundException",
                    "ThrottlingException", "TooManyRequestsException", "Throttling", "RequestLimitExceeded")


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
                "apigw_raise_stage_throttle": self._live_stage, "arc_zonal_shift": self._live_zones,
                "appconfig_revert": self._live_appconfig, "codepipeline_freeze": self._live_pipeline,
                "ec2_revert_sg_change": self._live_sg_change, "ecs_restore_desired": self._live_ecs_desired,
                "lambda_restore_concurrency": self._live_lambda_restore,
                "lambda_restore_settings": self._live_lambda_settings,
                "sqs_restore_attributes": self._live_sqs_attributes,
                "kinesis_restore_retention": self._live_kinesis_retention,
                "asg_restore_capacity": self._live_asg_restore, "apigw_restore_stage": self._live_stage_restore,
                "elb_reregister_targets": self._live_targets, "kms_cancel_key_deletion": self._live_key_deletion,
                "secrets_restore_secret": self._live_secret_deletion,
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
                 "apigw_raise_stage_throttle": self._stage_healthy, "arc_zonal_shift": self._shift_holds,
                 "appconfig_revert": self._appconfig_reverted, "codepipeline_freeze": self._frozen,
                 "ec2_revert_sg_change": self._sg_alarm_ok, "ecs_restore_desired": self._ecs_restored,
                 "lambda_restore_concurrency": self._lambda_restored,
                 "lambda_restore_settings": self._lambda_settings_restored,
                 "sqs_restore_attributes": self._sqs_attributes_restored,
                 "kinesis_restore_retention": self._kinesis_retention_restored,
                 "asg_restore_capacity": self._asg_restored, "apigw_restore_stage": self._stage_restored,
                 "elb_reregister_targets": self._targets_healthy, "kms_cancel_key_deletion": self._key_kept,
                 "secrets_restore_secret": self._secret_restored,
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
        if entry == "appconfig_revert":
            return ("nothing to roll back: deploying the reverted configuration again is a new deployment a person "
                    "starts")
        if entry == "ecs_restart_service":
            # The same task definition runs again: there is nothing to return to.
            return "nothing to roll back: a restart replaced tasks with the same task definition"
        if entry == "kms_cancel_key_deletion":
            return ("nothing to roll back: scheduling a key's deletion again is a person's decision, never WARDEN's "
                    "undo")
        if entry == "secrets_restore_secret":
            return "nothing to roll back: deleting a secret again is a person's decision, never WARDEN's undo"
        if entry == "kinesis_restore_retention":
            return ("nothing to roll back: shortening a stream's retention deletes its older records for good; the "
                    "longer retention stays until a person decides")
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
                 "apigw_raise_stage_throttle": self._stage_throttle, "arc_zonal_shift": self._zonal_shift,
                 "appconfig_revert": self._appconfig_revert, "codepipeline_freeze": self._freeze,
                 "ec2_revert_sg_change": self._sg_revert, "ecs_restore_desired": self._ecs_restore,
                 "lambda_restore_concurrency": self._lambda_restore,
                 "lambda_restore_settings": self._lambda_settings_restore,
                 "sqs_restore_attributes": self._sqs_attributes_restore,
                 "kinesis_restore_retention": self._kinesis_retention_restore,
                 "asg_restore_capacity": self._asg_restore, "apigw_restore_stage": self._stage_restore,
                 "elb_reregister_targets": self._targets, "kms_cancel_key_deletion": self._key_cancel,
                 "secrets_restore_secret": self._secret_restore,
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
        if service == "kinesis":  # by the stream's name: the ARN's last part
            return {t["Key"]: t["Value"] for t in c.list_tags_for_stream(StreamName=_last(arn)).get("Tags") or []}
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
        rule = self._read("events").describe_rule(**_rule_on_bus(name))
        state = rule.get("State")
        # A pause only for a scheduled rule (it misses ticks); an event-pattern rule would drop the events it matches.
        # Only the plain ENABLED state: a rule on all CloudTrail management events may not come back the same way.
        can = state == "ENABLED" and bool(rule.get("ScheduleExpression")) and not rule.get("EventPattern") \
            if pause else state == "DISABLED"
        return {"rule": {name} if can and rule["Name"] == _rule_on_bus(name)["Name"] else set(),
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
        (ev.disable_rule if back else ev.enable_rule)(**_rule_on_bus(p["rule"]))
        return f"{'disabled' if back else 'enabled'} rule {p['rule']}"

    def _rule_healthy(self, name: str, params: dict[str, Any]) -> bool:
        return self._read("events").describe_rule(**_rule_on_bus(name)).get("State") == "ENABLED"

    def _rule_paused(self, name: str, params: dict[str, Any]) -> bool:
        return self._read("events").describe_rule(**_rule_on_bus(name)).get("State") == "DISABLED"

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

    # ------------------------------------------------------------------ arc: shift traffic away from a zone (G9-D)

    def _zone_health(self, lb: str, arn: str, zones: list[str]) -> dict[str, tuple[float, float]]:
        """Per zone, over the load balancer's target groups: (fewest healthy hosts, most unhealthy hosts) in the last
        HEALTH_WINDOW. A zone with no datapoint is absent: unknown is never healthy."""
        groups = self._read("elbv2").describe_target_groups(LoadBalancerArn=arn).get("TargetGroups") or []
        if len(groups) > 5:
            return {}  # review-e L3: more groups than WARDEN reads - no zone is called impaired on part of them
        tgs = [t["TargetGroupArn"].split(":", 5)[-1] for t in groups]
        queries, keys = [], {}
        # Review-e M2: every minute of the window, and the strictest view of each - no node saw a healthy host in the
        # impaired zone (Maximum 0), every node saw one in a serving zone (Minimum above 0), unhealthy ones throughout.
        for i, (tg, zone, metric, stat) in enumerate((tg, z, m, s) for tg in tgs for z in zones for m, s in
                                                      (("HealthyHostCount", "Maximum"), ("HealthyHostCount", "Minimum"),
                                                       ("UnHealthyHostCount", "Minimum"))):
            keys[f"q{i}"] = (zone, f"{metric}:{stat}")
            queries.append({"Id": f"q{i}", "ReturnData": True, "MetricStat": {"Period": 60, "Stat": stat, "Metric": {
                "Namespace": "AWS/ApplicationELB" if lb.startswith("app/") else "AWS/NetworkELB",
                "MetricName": metric, "Dimensions": [{"Name": "LoadBalancer", "Value": lb},
                                                     {"Name": "TargetGroup", "Value": tg},
                                                     {"Name": "AvailabilityZone", "Value": zone}]}}})
        if not queries:
            return {}
        end = self._now()
        got = self._read("cloudwatch").get_metric_data(MetricDataQueries=queries, StartTime=end - HEALTH_WINDOW,
                                                       EndTime=end, ScanBy="TimestampDescending")
        series: dict[tuple[str, str], list[list[float]]] = {}
        for r in got.get("MetricDataResults") or []:
            if r.get("Id") in keys:
                series.setdefault(keys[r["Id"]], []).append([float(v) for v in r.get("Values") or []])
        out = {}
        for zone in zones:
            hmax = series.get((zone, "HealthyHostCount:Maximum"), [])
            hmin = series.get((zone, "HealthyHostCount:Minimum"), [])
            umin = series.get((zone, "UnHealthyHostCount:Minimum"), [])
            if not hmax or any(len(v) < ZONE_POINTS for v in hmax + hmin + umin):
                continue  # too little data: unknown, never impaired and never serving
            healthy_never = all(x == 0 for v in hmax for x in v)
            unhealthy_always = all(sum(col) > 0 for col in zip(*umin, strict=False))
            serving_always = all(sum(col) > 0 for col in zip(*hmin, strict=False))
            if serving_always:
                out[zone] = (1.0, 0.0)  # serving: (healthy, unhealthy)
            elif healthy_never and unhealthy_always:
                out[zone] = (0.0, 1.0)  # impaired
            # anything between: unknown, neither impaired nor serving
        return out

    def _live_zones(self, params: dict[str, Any]) -> dict[str, Any]:
        """The load balancer's zones by ID, the ONE zone that is impaired (no healthy host, some unhealthy, while
        another zone serves), whether zonal shifts are allowed, and any shift already in place."""
        lb = params.get("load_balancer")
        if not isinstance(lb, str) or not lb.startswith(("app/", "net/")) or lb.count("/") != 2:
            return {}
        elb = self._read("elbv2")
        [desc] = elb.describe_load_balancers(Names=[lb.split("/")[1]])["LoadBalancers"]
        arn = desc["LoadBalancerArn"]
        if not arn.endswith(":loadbalancer/" + lb):
            return {}  # the name is another load balancer's (a different id)
        names = sorted(z["ZoneName"] for z in desc.get("AvailabilityZones") or [] if z.get("ZoneName"))
        ids = {z["ZoneName"]: z["ZoneId"] for z in self._read("ec2").describe_availability_zones(
            ZoneNames=names).get("AvailabilityZones") or [] if z.get("ZoneName") in names}
        attrs = {a.get("Key"): a.get("Value") for a in
                 elb.describe_load_balancer_attributes(LoadBalancerArn=arn).get("Attributes") or []}
        tags = {t["Key"]: t["Value"] for d in elb.describe_tags(ResourceArns=[arn]).get("TagDescriptions") or []
                for t in d.get("Tags") or []}
        health = self._zone_health(lb, arn, names)
        impaired = [z for z, (h, u) in health.items() if h == 0 and u > 0]
        serving = sorted(z for z, (h, _) in health.items() if h > 0)
        managed = self._read("arc-zonal-shift").get_managed_resource(resourceIdentifier=arn)
        active = [s.get("zonalShiftId") for s in managed.get("zonalShifts") or [] if s.get("appliedStatus") == "APPLIED"]
        # Review-e M1: ARC's own autoshift is a shift too - a manual one would override it, back into the zone AWS
        # found impaired.
        active += [f"autoshift:{a.get('awayFrom')}" for a in managed.get("autoshifts") or []
                   if a.get("appliedStatus") == "APPLIED"]
        one = len(impaired) == 1 and serving and impaired[0] in ids and attrs.get("zonal_shift.config.enabled") == "true"
        return {"load_balancer": {lb}, "away_from": {ids[impaired[0]]} if one else set(),
                "environment": tags.get(ENV_TAG), "rollout": "progressing" if active else "complete",
                "state": {"load_balancer": lb, "arn": arn, "zones": ids, "impaired_name": impaired[0] if one else None,
                          "serving": serving, "active_shifts": active, "where": self._where(arn)}}

    def _zonal_shift(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("load_balancer", "arn", "zones"), f"load balancer {p['load_balancer']}")
        arc_read = self._read("arc-zonal-shift")
        mark = f"WARDEN {who['incident']} plan "  # review-e L4: "inc-7" must not match "inc-71"
        if back:
            mine = [s for s in arc_read.get_managed_resource(resourceIdentifier=now["arn"]).get("zonalShifts") or []
                    if s.get("awayFrom") == p["away_from"] and str(s.get("comment", "")).startswith(mark)]
            if not mine:
                return f"nothing to roll back: the shift away from {p['away_from']} has already ended"
            arc = self._actor(who, ["arc-zonal-shift:CancelZonalShift"], [now["arn"]], None)("arc-zonal-shift")
            arc.cancel_zonal_shift(zonalShiftId=mine[0]["zonalShiftId"])
            return f"cancelled the shift away from {p['away_from']}; traffic returns to every zone"
        if p["away_from"] not in self.live("arc_zonal_shift", p).get("away_from", set()):
            raise AwsPlatformRefused(f"zone {p['away_from']} is no longer the one impaired zone of {p['load_balancer']} "
                                     "(or a shift is already in place); nothing was changed")
        if not isinstance(p["minutes"], int) or not 30 <= p["minutes"] <= 180:
            raise AwsPlatformRefused("a shift lasts 30 to 180 minutes; nothing was changed")
        arc = self._actor(who, ["arc-zonal-shift:StartZonalShift"], [now["arn"]], None)("arc-zonal-shift")
        arc.start_zonal_shift(resourceIdentifier=now["arn"], awayFrom=p["away_from"], expiresIn=f"{p['minutes']}m",
                              comment=f"{mark}{who['plan_hash'][:12]}"[:128])
        return f"shifted {p['load_balancer']}'s traffic away from {p['away_from']} for {p['minutes']} minutes"

    def _shift_holds(self, lb: str, params: dict[str, Any]) -> bool:
        """The shift is applied (that zone's weight 0) and another zone serves - a positive signal."""
        now = self._live_zones({"load_balancer": lb}).get("state") or {}
        managed = self._read("arc-zonal-shift").get_managed_resource(resourceIdentifier=now.get("arn", ""))
        return (managed.get("appliedWeights") or {}).get(params.get("away_from")) == 0 and bool(now.get("serving"))

    # ------------------------------------------------------------------ appconfig: revert a deployment (G9-D)

    def _live_appconfig(self, params: dict[str, Any]) -> dict[str, Any]:
        """The AppConfig environment whose monitors name the alarm, its latest deployment, and whether that one can be
        reverted: in progress, or completed within APPCONFIG_REVERT, with the application, the environment and the
        deployment all tagged with one Environment (what the actor's IAM grant is held to)."""
        from .. import aws_describe

        alarm = params.get("alarm")
        if not isinstance(alarm, str):
            return {}
        found = self._read("cloudwatch").describe_alarms(AlarmNames=[alarm], AlarmTypes=["MetricAlarm"]).get(
            "MetricAlarms") or []
        if not found:
            return {}
        ac = self._read("appconfig")
        pairs, complete = aws_describe.appconfig_for_alarm(ac, str(found[0].get("AlarmArn") or ""))
        fired = _when(found[0].get("StateTransitionedTimestamp") or found[0].get("StateUpdatedTimestamp"))
        if len(pairs) != 1 or not complete:  # review-e M3: one guard among what could NOT be read is not "the one"
            return {"alarm": {alarm}, "application": set(), "config_env": set(), "deployment": set()}
        app, env = pairs[0]
        d = aws_describe.latest_deployment(ac, app["Id"], env["Id"]) or {}
        n = d.get("DeploymentNumber")
        app_arn = f"arn:aws:appconfig:{ac.meta.region_name}:{self._account()}:application/{app['Id']}"
        env_arn = f"{app_arn}/environment/{env['Id']}"
        dep_arn = f"{env_arn}/deployment/{n}"
        tagged = {(ac.list_tags_for_resource(ResourceArn=a).get("Tags") or {}).get(ENV_TAG)
                  for a in (app_arn, env_arn, dep_arn)} if n else {None}
        done, began = _when(d.get("CompletedAt")), _when(d.get("StartedAt"))
        related = (found[0].get("StateValue") == "ALARM" and fired is not None and began is not None
                   and fired - APPCONFIG_BEFORE_ALARM <= began <= fired)
        can = bool(n) and related and len(tagged) == 1 and None not in tagged and (
            d.get("State") in ("DEPLOYING", "BAKING")
            or (d.get("State") == "COMPLETE" and done is not None and self._now() - done < APPCONFIG_REVERT))
        return {"alarm": {alarm}, "application": {app["Name"]} if can else set(),
                "config_env": {env["Name"]} if can else set(), "deployment": {str(n)} if can else set(),
                "environment": next(iter(tagged)) if len(tagged) == 1 else None,
                "state": {"alarm": alarm, "application": app["Name"], "app_id": app["Id"], "config_env": env["Name"],
                          "env_id": env["Id"], "deployment": n, "deploy_state": d.get("State"),
                          "version": d.get("VersionLabel") or d.get("ConfigurationVersion"),
                          "profile": _plain(d.get("ConfigurationName")), "started": _iso(began),
                          "completed": _iso(done), "alarm_since": _iso(fired),
                          "app_arn": app_arn, "env_arn": env_arn, "dep_arn": dep_arn, "where": self._where(app_arn)}}

    def _appconfig_revert(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("application", "app_id", "config_env", "env_id", "deployment"),
                     f"configuration {p['application']}/{p['config_env']}")
        if p["deployment"] not in self.live("appconfig_revert", p).get("deployment", set()):
            raise AwsPlatformRefused(f"deployment {p['deployment']} of {p['application']} can no longer be reverted "
                                     "(finished over 70 hours ago, superseded, or untagged); nothing was changed")
        ac = self._actor(who, ["appconfig:StopDeployment"], [now["app_arn"], now["env_arn"], now["dep_arn"]],
                         None)("appconfig")
        ac.stop_deployment(ApplicationId=now["app_id"], EnvironmentId=now["env_id"],
                           DeploymentNumber=int(p["deployment"]), AllowRevert=True)
        return f"stopped and reverted deployment {p['deployment']} of {p['application']}/{p['config_env']}"

    def _appconfig_reverted(self, config_env: str, params: dict[str, Any]) -> bool:
        """That deployment reads REVERTED or ROLLED_BACK, AND the alarm that guards it reads OK: the write landing is
        not a recovery (review-e M4)."""
        st = self._live_appconfig(params).get("state") or {}
        alarm = self._read("cloudwatch").describe_alarms(AlarmNames=[str(params.get("alarm", ""))],
                                                         AlarmTypes=["MetricAlarm"]).get("MetricAlarms") or []
        return str(st.get("deployment")) == str(params.get("deployment")) and st.get("deploy_state") in (
            "REVERTED", "ROLLED_BACK") and bool(alarm) and alarm[0].get("StateValue") == "OK"

    # ------------------------------------------------------------------ ec2: undo a recorded security group change (G10-D)

    def _live_sg_change(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE security group write CloudTrail recorded in SG_CHANGE_BEFORE_ALARM before the alarm went into ALARM,
        and exactly what undoing it writes. Allowed only when it is the group's only write from then until now (one
        after the alarm may be the fix; two are a choice WARDEN does not make), it succeeded, and nothing refuses it.
        A plan's own event is also read by its id, so a rollback and the health check see it once the alarm is OK."""
        group, alarm = params.get("group"), params.get("alarm")
        if not isinstance(group, str) or not _SG_ID.fullmatch(group) or not isinstance(alarm, str):
            return {}
        found = self._read("cloudwatch").describe_alarms(AlarmNames=[alarm], AlarmTypes=["MetricAlarm"]).get(
            "MetricAlarms") or []
        onset = _when(found[0].get("StateTransitionedTimestamp")) if found and found[0].get("StateValue") == "ALARM" \
            else None
        ec2 = self._read("ec2")
        g = (ec2.describe_security_groups(GroupIds=[group]).get("SecurityGroups") or [{}])[0]
        if g.get("GroupId") != group:
            return {}
        arn = f"arn:aws:ec2:{ec2.meta.region_name}:{g.get('OwnerId', '')}:security-group/{group}"
        tags = {t["Key"]: t["Value"] for t in g.get("Tags") or []}
        state: dict[str, Any] = {"group": group, "arn": arn, "where": self._where(arn)}
        eligible, why = None, ""
        if onset is None:
            why = "the alarm is not in ALARM"
        else:
            writes = self._sg_writes(group, onset - SG_CHANGE_BEFORE_ALARM, self._now())
            if len(writes) != 1:
                why = (f"{'no recorded write' if not writes else f'{len(writes)} writes (WARDEN does not choose one)'} "
                       f"to {group} since {onset - SG_CHANGE_BEFORE_ALARM:%Y-%m-%dT%H:%MZ}")
            else:
                eligible = writes[0]
                why = self._sg_refusal(eligible, onset)
        named = params.get("event")
        e = self._sg_event_by_id(named, group) if isinstance(named, str) else eligible
        if e is not None:
            state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor", "kind", "egress", "rules")},
                         undo=_sg_undo_text(e), present=self._sg_present(group, e))
        if not why and eligible is not None:
            if eligible["kind"] == "revoke" and self._sg_present(group, eligible):
                why = "the revoked rules are back already"
            elif eligible["kind"] == "authorize" and not self._sg_present(group, eligible):
                why = "the rules it added are gone already"
        allowed = {eligible["event"]} if eligible is not None and not why else set()
        return {"group": {group}, "alarm": {alarm}, "event": allowed, "environment": tags.get(ENV_TAG),
                "refused": why, "state": state}

    def _sg_writes(self, group: str, since: datetime, until: datetime) -> list[dict[str, Any]]:
        """Every successful security group rule write CloudTrail recorded on `group` in the window, parsed."""
        out = []
        trail = self._read("cloudtrail")
        for name in _SG_EVENTS:
            page = trail.lookup_events(LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
                                       StartTime=since, EndTime=until, MaxResults=50)
            if page.get("NextToken"):
                raise AwsPlatformRefused(f"more {name} events than WARDEN reads in the window; nothing is chosen")
            for raw in page.get("Events") or []:
                e = _sg_parse(raw, group)
                if e is not None and not (e["at"] is not None and e["at"] < since):  # the window, held here too
                    out.append(e)
        return out

    def _sg_event_by_id(self, event_id: str, group: str) -> dict[str, Any] | None:
        page = self._read("cloudtrail").lookup_events(
            LookupAttributes=[{"AttributeKey": "EventId", "AttributeValue": event_id}], MaxResults=1)
        return next((e for e in (_sg_parse(raw, group) for raw in page.get("Events") or []) if e is not None), None)

    @staticmethod
    def _sg_refusal(e: dict[str, Any], onset: datetime) -> str:
        if e["at"] is None or e["at"] >= onset:
            return "the change came after the alarm went off - it may be the fix"
        if e["who_type"] == "Root":
            return "the change was made by the root user: a person looks"
        if e["invoked_by"]:
            return f"the change was made by an AWS service ({e['invoked_by']}): its owner manages it"
        if e["source_identity"].startswith("inc-"):
            return "the change was WARDEN's own: its own rollback undoes it"
        if e["actor_name"] and e["actor_name"] in never_revert():
            return f"{e['actor']} is a principal whose changes WARDEN never reverts (WARDEN_NEVER_REVERT_PRINCIPALS)"
        if e["truncated"]:
            return "CloudTrail did not record the whole change (too large, or not returned)"
        if not e["rules"]:
            return "the event names no rule it changed"
        if e["kind"] == "revoke" and not e["egress"] and any(r[5] in _OPEN_CIDRS for r in e["rules"]):
            return "undoing it would open ingress to the whole internet: a person decides"
        return ""

    def _sg_present(self, group: str, e: dict[str, Any]) -> bool:
        """Whether the event's rules are in the group now: a revoke's re-added, an authorize's still there."""
        rules = self._read("ec2").describe_security_group_rules(
            Filters=[{"Name": "group-id", "Values": [group]}]).get("SecurityGroupRules") or []
        if e["kind"] == "authorize":
            ids = {r.get("SecurityGroupRuleId") for r in rules}
            return bool(e["rule_ids"]) and all(rid in ids for rid in e["rule_ids"])
        now = [_sg_rule_key(r) for r in rules]
        return all(r in now for r in e["rules"])

    def _sg_revert(self, p, snapshot, now, who, back) -> str:
        """Undo the recorded write (back: write it again). A revoke is undone by authorizing exactly its rules; an
        authorize by revoking exactly the rules it created. The session holds the one action on this one group."""
        self._expect(now, snapshot, ("group", "arn", "event", "kind", "egress", "rules"), f"security group {p['group']}")
        egress, kind = bool(now["egress"]), now["kind"]
        add = (kind == "revoke") != back  # a revoke's undo, or an authorize's undo rolled back: authorize
        side = "Egress" if egress else "Ingress"
        action = f"ec2:{'Authorize' if add else 'Revoke'}SecurityGroup{side}"
        region, account = now["arn"].split(":")[3], now["arn"].split(":")[4]
        resources = [now["arn"]] + ([f"arn:aws:ec2:{region}:{account}:security-group-rule/*"] if add else [])
        ec2 = self._actor(who, [action], resources, None)("ec2")
        perms = [_sg_permission(r) for r in now["rules"]]
        if add:
            (ec2.authorize_security_group_egress if egress else ec2.authorize_security_group_ingress)(
                GroupId=p["group"], IpPermissions=perms)
            return f"authorized {len(perms)} {side.lower()} rule(s) on {p['group']}"
        (ec2.revoke_security_group_egress if egress else ec2.revoke_security_group_ingress)(
            GroupId=p["group"], IpPermissions=perms)
        return f"revoked {len(perms)} {side.lower()} rule(s) on {p['group']}"

    def _sg_alarm_ok(self, group: str, params: dict[str, Any]) -> bool:
        """The undo is in place and the alarm it was for reads OK: the write landing is not a recovery."""
        st = self._live_sg_change(params).get("state") or {}
        alarm = self._read("cloudwatch").describe_alarms(AlarmNames=[str(params.get("alarm", ""))],
                                                         AlarmTypes=["MetricAlarm"]).get("MetricAlarms") or []
        undone = "kind" in st and st.get("present") is (st["kind"] == "revoke")
        return undone and bool(alarm) and alarm[0].get("StateValue") == "OK"

    # ------------------------------------------------------------------ undo a recorded change, from Config (G10-D3)

    def _alarm_onset(self, alarm: str) -> datetime | None:
        """When the alarm went into ALARM - None unless it reads ALARM now."""
        found = self._read("cloudwatch").describe_alarms(AlarmNames=[alarm], AlarmTypes=["MetricAlarm"]).get(
            "MetricAlarms") or []
        return _when(found[0].get("StateTransitionedTimestamp")) if found and found[0].get("StateValue") == "ALARM" \
            else None

    def _alarm_ok(self, alarm: str) -> bool:
        found = self._read("cloudwatch").describe_alarms(AlarmNames=[alarm], AlarmTypes=["MetricAlarm"]).get(
            "MetricAlarms") or []
        return bool(found) and found[0].get("StateValue") == "OK"

    def _trail_writes(self, key: str, value: str, since: datetime, until: datetime,
                      keep: Callable[[dict[str, Any]], bool]) -> list[dict[str, Any]]:
        """Every successful write CloudTrail recorded with this lookup attribute in the window that `keep` accepts. A
        window with more events than WARDEN reads chooses nothing: an unread one could be the change."""
        out, token = [], None
        for _ in range(4):
            page = self._read("cloudtrail").lookup_events(
                LookupAttributes=[{"AttributeKey": key, "AttributeValue": value}], StartTime=since, EndTime=until,
                MaxResults=50, **({"NextToken": token} if token else {}))
            for raw in page.get("Events") or []:
                e = _trail_change(raw)
                if e is not None and not (e["at"] is not None and e["at"] < since) and keep(e):
                    out.append(e)
            token = page.get("NextToken")
            if not token:
                return out
        raise AwsPlatformRefused(f"more CloudTrail events for {value} than WARDEN reads in the window; nothing is "
                                 "chosen")

    def _config_bracket(self, rtype: str, rid: str, e: dict[str, Any],
                        value_of: Callable[[dict[str, Any]], Any]) -> tuple[Any, Any, str]:
        """(before, after, why): the value AWS Config recorded just before the change and the one it recorded with
        it - the item whose relatedEvents names the event, else the first after it. Refused when the record is not
        continuous, when there is none before, or when the value changed again since."""
        items, token = [], None
        for _ in range(3):
            page = self._read("config").get_resource_config_history(
                resourceType=rtype, resourceId=rid, earlierTime=e["at"] - CONFIG_LOOKBACK, laterTime=self._now(),
                chronologicalOrder="Forward", limit=100, **({"nextToken": token} if token else {}))
            items += page.get("configurationItems") or []
            token = page.get("nextToken")
            if not token:
                break
        else:
            return None, None, "Config holds more records than WARDEN reads since the change"
        if any(str(i.get("recordingFrequency") or "Continuous").lower() != "continuous" for i in items):
            return None, None, "Config records this resource daily, not continuously: its value before is unknown"
        after = next((i for i in items if e["event"] in (i.get("relatedEvents") or [])), None) or next(
            (i for i in items if (_when(i.get("configurationItemCaptureTime")) or e["at"]) >= e["at"]), None)
        if after is None:
            return None, None, "Config has not recorded the change yet"
        at = items.index(after)
        before = items[at - 1] if at > 0 else None
        if before is None:
            return None, None, "Config holds no record of the resource before the change"
        if any(value_of(i) != value_of(after) for i in items[at + 1:]):
            return None, None, "the value changed again after the change"
        return value_of(before), value_of(after), ""

    def _config_id(self, rtype: str, name: str, fits: Callable[[str], bool]) -> str:
        found = self._read("config").list_discovered_resources(resourceType=rtype, resourceName=name).get(
            "resourceIdentifiers") or []
        ids = [r["resourceId"] for r in found if fits(str(r.get("resourceId", "")))]
        return ids[0] if len(ids) == 1 else ""

    def _live_ecs_desired(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE recorded UpdateService that set this service's desired count in the hours before its alarm, and the
        count AWS Config recorded before it - the one value a restore may write."""
        cluster, service, alarm = params.get("cluster"), params.get("service"), params.get("alarm")
        if not all(isinstance(v, str) for v in (cluster, service, alarm)):
            return {}
        [svc] = self._read("ecs").describe_services(cluster=cluster, services=[service], include=["TAGS"])["services"]
        name, arn = svc["serviceName"], svc["serviceArn"]
        state: dict[str, Any] = {"cluster": cluster, "service": name, "arn": arn, "desired_now": svc.get("desiredCount"),
                                 "where": self._where(arn)}
        live = {"cluster": {cluster}, "service": {name}, "alarm": {alarm}, "event": set(), "desired": set(),
                "environment": {t["key"]: t["value"] for t in svc.get("tags") or []}.get(ENV_TAG)}

        def refused(why: str) -> dict[str, Any]:
            return {**live, "refused": why, "state": state}

        scaled = self._read("application-autoscaling").describe_scalable_targets(
            ServiceNamespace="ecs", ResourceIds=[f"service/{cluster}/{name}"],
            ScalableDimension="ecs:service:DesiredCount").get("ScalableTargets")
        if scaled:
            return refused("an autoscaler owns this service's desired count")
        onset = self._alarm_onset(alarm)
        named = params.get("event")
        if onset is None and not isinstance(named, str):
            return refused("the alarm is not in ALARM")
        since = (onset or self._now()) - REVERT_BEFORE_ALARM

        def sets_count(e: dict[str, Any]) -> bool:
            r = e["request"] or {}
            return (_last(r.get("service")) == name and _last(r.get("cluster") or "default") == _last(cluster)
                    and "desiredCount" in r)

        writes = self._trail_writes("EventName", "UpdateService", since, self._now(), sets_count)
        if isinstance(named, str):
            writes = [w for w in writes if w["event"] == named] or writes
        if len(writes) != 1:
            return refused(f"{'no recorded' if not writes else len(writes)} change(s) to {name}'s desired count since "
                           f"{since:%Y-%m-%dT%H:%MZ}" + ("" if not writes else " (WARDEN does not choose one)"))
        e = writes[0]
        state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor")})
        why = _who_refusal(e, onset) if onset else "the alarm is not in ALARM"
        rid = self._config_id("AWS::ECS::Service", name, lambda rid: _last(cluster) in rid or rid.endswith(name))
        if not why and not rid:
            why = "AWS Config holds no single record of this service"
        before = after = None
        if rid and (not why or onset is None):
            before, after, bracket = self._config_bracket("AWS::ECS::Service", rid, e,
                                                          lambda i: _get(_json(i.get("configuration")), "DesiredCount"))
            why = why or bracket
        state.update(before=before, after=after)
        if not why and (not isinstance(before, int) or before < 1):
            why = f"the count before the change was {before}: nothing to restore"
        if not why and (after != (e["request"] or {}).get("desiredCount") or svc.get("desiredCount") != after):
            why = "the service's count is not what the change set: it moved since"
        return {**live, "event": set() if why else {e["event"]}, "desired": set() if why else {str(before)},
                "refused": why, "state": state}

    def _ecs_restore(self, p, snapshot, now, who, back) -> str:
        """Set the desired count back to what AWS Config recorded before the change (back: what the change set)."""
        self._expect(now, snapshot, ("cluster", "service", "arn", "event", "before", "after"), f"service {p['service']}")
        prior = int(p["desired"]) if str(p["desired"]).isdigit() else None  # a ref: what Config recorded, as text
        want_now, to = (snapshot.get("after"), prior) if not back else (prior, snapshot.get("after"))
        if now.get("desired_now") != want_now or not isinstance(to, int):
            raise AwsPlatformRefused(f"service {p['service']} wants {now.get('desired_now')} tasks, not {want_now}; "
                                     "nothing was changed")
        ecs = self._actor(who, ["ecs:UpdateService"], [now["arn"]], None)("ecs")
        ecs.update_service(cluster=p["cluster"], service=p["service"], desiredCount=to)
        return f"set service {p['service']} desired tasks from {now.get('desired_now')} to {to}"

    def _ecs_restored(self, service: str, params: dict[str, Any]) -> bool:
        """Every task of the restored count running, and the alarm reads OK."""
        [svc] = self._read("ecs").describe_services(cluster=params.get("cluster", ""), services=[service])["services"]
        want = int(params["desired"]) if str(params.get("desired", "")).isdigit() else None
        return (isinstance(want, int) and svc.get("desiredCount") == want and svc.get("runningCount") == want
                and self._alarm_ok(str(params.get("alarm", ""))))

    def _live_lambda_restore(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE recorded Put/DeleteFunctionConcurrency on this function in the hours before its alarm, and the
        reserved concurrency AWS Config recorded before it (none: unreserved)."""
        fn, alarm = params.get("function"), params.get("alarm")
        if not isinstance(fn, str) or not isinstance(alarm, str):
            return {}
        lam = self._read("lambda")
        conf = lam.get_function_configuration(FunctionName=fn)
        arn, name = conf["FunctionArn"], conf["FunctionName"]
        reserved = lam.get_function_concurrency(FunctionName=name).get("ReservedConcurrentExecutions")
        free = (lam.get_account_settings().get("AccountLimit") or {}).get("UnreservedConcurrentExecutions")
        state: dict[str, Any] = {"function": name, "arn": arn, "reserved": reserved, "where": self._where(arn)}
        live = {"function": {name}, "alarm": {alarm}, "event": set(), "concurrency": set(),
                "environment": self._tags("lambda", arn).get(ENV_TAG), "unreserved_account_concurrency": free}
        onset = self._alarm_onset(alarm)
        named = params.get("event")
        if onset is None and not isinstance(named, str):
            return {**live, "refused": "the alarm is not in ALARM", "state": state}
        since = (onset or self._now()) - REVERT_BEFORE_ALARM

        def on_this(e: dict[str, Any]) -> bool:
            return e["event_name"].startswith(("PutFunctionConcurrency", "DeleteFunctionConcurrency")) and \
                _last((e["request"] or {}).get("functionName")) == name

        # By event SOURCE: Lambda's event names carry an API version (`PutFunctionConcurrency20171031`).
        writes = self._trail_writes("EventSource", "lambda.amazonaws.com", since, self._now(), on_this)
        if isinstance(named, str):
            writes = [w for w in writes if w["event"] == named] or writes
        if len(writes) != 1:
            return {**live, "state": state, "refused": f"{'no recorded' if not writes else len(writes)} concurrency "
                    f"change(s) to {name} since {since:%Y-%m-%dT%H:%MZ}"}
        e = writes[0]
        state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor")})
        why = _who_refusal(e, onset) if onset else "the alarm is not in ALARM"

        def value_of(i: dict[str, Any]) -> Any:
            return _get(_json((i.get("supplementaryConfiguration") or {}).get("Concurrency")),
                        "reservedConcurrentExecutions")

        before = after = None
        if not why or onset is None:
            before, after, bracket = self._config_bracket("AWS::Lambda::Function", name, e, value_of)
            why = why or bracket
        state.update(before=before, after=after)
        if not why and reserved != after:
            why = "the function's reserved concurrency is not what the change set: it moved since"
        if not why and isinstance(before, int) and isinstance(free, int) and \
                before - (reserved or 0) > free - AWS_RESERVED_UNRESERVED:
            why = "the account has no room to reserve that much again"
        return {**live, "event": set() if why else {e["event"]},
                "concurrency": set() if why else {"none" if before is None else str(before)}, "refused": why,
                "state": state}

    def _lambda_restore(self, p, snapshot, now, who, back) -> str:
        """Reserved concurrency back to what Config recorded before the change - `none` deletes the reservation
        (back: what the change set)."""
        self._expect(now, snapshot, ("function", "arn", "event", "before", "after"), f"lambda {p['function']}")
        before = None if p["concurrency"] == "none" else int(p["concurrency"])
        want_now, to = (snapshot.get("after"), before) if not back else (before, snapshot.get("after"))
        if now.get("reserved") != want_now:
            raise AwsPlatformRefused(f"lambda {p['function']} reserves {now.get('reserved')}, not {want_now}; "
                                     "nothing was changed")
        action = "lambda:DeleteFunctionConcurrency" if to is None else "lambda:PutFunctionConcurrency"
        lam = self._actor(who, [action], [now["arn"]], None)("lambda")
        if to is None:
            lam.delete_function_concurrency(FunctionName=p["function"])
        else:
            lam.put_function_concurrency(FunctionName=p["function"], ReservedConcurrentExecutions=to)
        return f"set lambda {p['function']} reserved concurrency from {now.get('reserved')} to {'none' if to is None else to}"

    def _lambda_restored(self, function: str, params: dict[str, Any]) -> bool:
        want = None if params.get("concurrency") == "none" else int(params.get("concurrency", -1))
        got = self._read("lambda").get_function_concurrency(FunctionName=function).get("ReservedConcurrentExecutions")
        return got == want and self._alarm_ok(str(params.get("alarm", "")))

    def _live_lambda_settings(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE recorded UpdateFunctionConfiguration on this function in the hours before its alarm that set only its
        timeout, memory or ephemeral storage, and those values as AWS Config recorded them before it. A change that also
        set the role, environment, handler, runtime, layers or network is a person's to undo (G10-D4)."""
        fn, alarm = params.get("function"), params.get("alarm")
        if not isinstance(fn, str) or not isinstance(alarm, str):
            return {}
        conf = self._read("lambda").get_function_configuration(FunctionName=fn)
        arn, name = conf["FunctionArn"], conf["FunctionName"]
        now_values = _lambda_settings(conf)
        state: dict[str, Any] = {"function": name, "arn": arn, "now": now_values, "revision": conf.get("RevisionId"),
                                 "where": self._where(arn)}
        live = {"function": {name}, "alarm": {alarm}, "event": set(), "settings": set(),
                "environment": self._tags("lambda", arn).get(ENV_TAG)}
        onset = self._alarm_onset(alarm)
        named = params.get("event")
        if onset is None and not isinstance(named, str):
            return {**live, "refused": "the alarm is not in ALARM", "state": state}
        since = (onset or self._now()) - REVERT_BEFORE_ALARM

        def on_this(e: dict[str, Any]) -> bool:
            return e["event_name"].startswith("UpdateFunctionConfiguration") and \
                _last((e["request"] or {}).get("functionName")) == name

        writes = self._trail_writes("EventSource", "lambda.amazonaws.com", since, self._now(), on_this)
        if isinstance(named, str):
            writes = [w for w in writes if w["event"] == named] or writes
        if len(writes) != 1:
            return {**live, "state": state, "refused": f"{'no recorded' if not writes else len(writes)} configuration "
                    f"change(s) to {name} since {since:%Y-%m-%dT%H:%MZ}"}
        e = writes[0]
        state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor")})
        why = _who_refusal(e, onset) if onset else "the alarm is not in ALARM"
        other = sorted(k for k in (e["request"] or {}) if k.lower() not in _SETTINGS_REQUEST_KEYS)
        if not why and other:
            why = f"the change also set {', '.join(other)}: a person undoes it"
        changed = sorted(k for k in _SETTINGS if _setting_in_request(e["request"] or {}, k) is not None)
        if not why and not changed:
            why = "the change set none of timeout, memory or ephemeral storage"
        if not why:
            versions, marker = [], None
            for _ in range(10):  # 50 a page; a function with more than 500 versions reads its newest 500
                page = self._read("lambda").list_versions_by_function(
                    FunctionName=name, **({"Marker": marker} if marker else {}))
                versions += page.get("Versions") or []
                marker = page.get("NextMarker")
                if not marker:
                    break
            later = [v for v in versions if v.get("Version") != "$LATEST" and
                     (_when(v.get("LastModified")) or e["at"]) > e["at"]]
            if later:
                why = (f"version {later[-1].get('Version')} was published after the change and holds it: what serves "
                       "traffic is that version - a rollback, not a configuration revert")
        before = after = None
        if not why or onset is None:
            before, after, bracket = self._config_bracket(
                "AWS::Lambda::Function", name, e, lambda i: _lambda_settings(_json(i.get("configuration")), changed))
            why = why or bracket
        state.update(before=before, after=after)
        if not why and (not isinstance(before, dict) or any(not isinstance(v, int) for v in before.values())):
            why = "AWS Config recorded no value before the change"
        if not why and {k: now_values.get(k) for k in changed} != after:
            why = "the function's settings are not what the change set: they moved since"
        if not why and any(not _SETTINGS[k][0] <= v <= _SETTINGS[k][1] for k, v in before.items()):
            why = "the value before the change is outside what Lambda allows"
        return {**live, "event": set() if why else {e["event"]},
                "settings": set() if why else {_settings_text(before)}, "refused": why, "state": state}

    def _lambda_settings_restore(self, p, snapshot, now, who, back) -> str:
        """The settings back to what Config recorded before the change (back: what the change set), only while the
        function's revision is the one the plan saw."""
        self._expect(now, snapshot, ("function", "arn", "event", "before", "after"), f"lambda {p['function']}")
        before = _settings_parse(p["settings"])
        after = snapshot.get("after") or {}
        want_now, to = (after, before) if not back else (before, after)
        if {k: (now.get("now") or {}).get(k) for k in to} != want_now or not to:
            raise AwsPlatformRefused(f"lambda {p['function']} settings are {now.get('now')}, not {want_now}; "
                                     "nothing was changed")
        lam = self._actor(who, ["lambda:UpdateFunctionConfiguration"], [now["arn"]], None)("lambda")
        lam.update_function_configuration(FunctionName=p["function"], RevisionId=now.get("revision"),
                                          **_settings_call(to))
        return f"set lambda {p['function']} {_settings_text(want_now)} -> {_settings_text(to)}"

    def _lambda_settings_restored(self, function: str, params: dict[str, Any]) -> bool:
        conf = self._read("lambda").get_function_configuration(FunctionName=function)
        want = _settings_parse(str(params.get("settings", "")))
        return (bool(want) and conf.get("LastUpdateStatus") in (None, "Successful")
                and {k: _lambda_settings(conf).get(k) for k in want} == want
                and self._alarm_ok(str(params.get("alarm", ""))))

    # ------------------------------------------------------------------ G10 v2: a queue's settings, a stream's retention

    def _one_change(self, source: str, names: tuple[str, ...], since: datetime, on_this: Callable[[dict[str, Any]], bool],
                    named: Any) -> tuple[dict[str, Any] | None, str]:
        """The ONE recorded write of these names to this resource since `since`, or why there is not exactly one."""
        writes = self._trail_writes("EventSource", source, since, self._now(),
                                    lambda e: e["event_name"].startswith(names) and on_this(e))
        if isinstance(named, str):
            writes = [w for w in writes if w["event"] == named] or writes
        if len(writes) != 1:
            return None, f"{'no recorded' if not writes else len(writes)} change(s) since {since:%Y-%m-%dT%H:%MZ}"
        return writes[0], ""

    def _live_sqs_attributes(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE recorded SetQueueAttributes on this queue in the hours before its alarm that set only its timing and
        size settings, and those settings as AWS Config recorded them before it."""
        name, alarm = params.get("queue"), params.get("alarm")
        if not isinstance(name, str) or not isinstance(alarm, str):
            return {}
        sqs = self._read("sqs")
        url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
        arn = attrs["QueueArn"]
        now_values = {k: int(attrs[k]) for k in _QUEUE_SETTINGS if str(attrs.get(k, "")).isdigit()}
        state: dict[str, Any] = {"queue": name, "url": url, "arn": arn, "now": now_values, "where": self._where(arn)}
        live = {"queue": {name}, "alarm": {alarm}, "event": set(), "attributes": set(),
                "environment": self._tags("sqs", url).get(ENV_TAG)}
        onset = self._alarm_onset(alarm)
        if onset is None and not isinstance(params.get("event"), str):
            return {**live, "refused": "the alarm is not in ALARM", "state": state}
        since = (onset or self._now()) - REVERT_BEFORE_ALARM
        e, why = self._one_change("sqs.amazonaws.com", ("SetQueueAttributes",), since,
                                  lambda e: str((e["request"] or {}).get("queueUrl", "")).rstrip("/").endswith("/" + name),
                                  params.get("event"))
        if e is None:
            return {**live, "refused": why, "state": state}
        state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor")})
        why = _who_refusal(e, onset) if onset else "the alarm is not in ALARM"
        wrote = (e["request"] or {}).get("attributes")
        wrote = wrote if isinstance(wrote, dict) else {}
        other = sorted(k for k in wrote if k not in _QUEUE_SETTINGS)
        if not why and other:
            why = f"the change also set {', '.join(other)}: a person undoes it"
        changed = sorted(k for k in wrote if k in _QUEUE_SETTINGS)
        if not why and not changed:
            why = "the change set none of the queue's timing or size settings"
        before = after = None
        if not why or onset is None:
            rid = self._config_id("AWS::SQS::Queue", name, lambda rid: rid.rstrip("/").endswith(name))
            if not rid:
                why = why or "AWS Config holds no single record of this queue"
            else:
                before, after, bracket = self._config_bracket(
                    "AWS::SQS::Queue", rid, e, lambda i: _ints(_json(i.get("configuration")), changed))
                why = why or bracket
        state.update(before=before, after=after)
        if not why and (not isinstance(before, dict) or set(before) != set(changed)):
            why = "AWS Config recorded no value before the change"
        if not why and {k: now_values.get(k) for k in changed} != after:
            why = "the queue's settings are not what the change set: they moved since"
        if not why and any(not _QUEUE_SETTINGS[k][0] <= v <= _QUEUE_SETTINGS[k][1] for k, v in before.items()):
            why = "the value before the change is outside what SQS allows"
        return {**live, "event": set() if why else {e["event"]},
                "attributes": set() if why else {_pairs_text(before)}, "refused": why, "state": state}

    def _sqs_attributes_restore(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("queue", "arn", "event", "before", "after"), f"queue {p['queue']}")
        before = _pairs_parse(p["attributes"], _QUEUE_SETTINGS)
        after = snapshot.get("after") or {}
        want_now, to = (after, before) if not back else (before, after)
        if not to or {k: (now.get("now") or {}).get(k) for k in to} != want_now:
            raise AwsPlatformRefused(f"queue {p['queue']} settings are {now.get('now')}, not {want_now}; nothing was "
                                     "changed")
        sqs = self._actor(who, ["sqs:SetQueueAttributes"], [now["arn"]], None)("sqs")
        sqs.set_queue_attributes(QueueUrl=now["url"], Attributes={k: str(v) for k, v in to.items()})
        return f"set queue {p['queue']} {_pairs_text(want_now)} -> {_pairs_text(to)}"

    def _sqs_attributes_restored(self, queue: str, params: dict[str, Any]) -> bool:
        sqs = self._read("sqs")
        url = sqs.get_queue_url(QueueName=queue)["QueueUrl"]
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
        want = _pairs_parse(str(params.get("attributes", "")), _QUEUE_SETTINGS)
        return bool(want) and all(str(attrs.get(k)) == str(v) for k, v in want.items()) and \
            self._alarm_ok(str(params.get("alarm", "")))

    def _live_kinesis_retention(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE recorded DecreaseStreamRetentionPeriod on this stream in the hours before its alarm, and the
        retention AWS Config recorded before it. Records already past the shorter retention are gone either way: the
        restore keeps what is left from going too."""
        name, alarm = params.get("stream"), params.get("alarm")
        if not isinstance(name, str) or not isinstance(alarm, str):
            return {}
        s = self._read("kinesis").describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        arn, hours = s["StreamARN"], s.get("RetentionPeriodHours")
        state: dict[str, Any] = {"stream": name, "arn": arn, "hours_now": hours, "where": self._where(arn)}
        live = {"stream": {name}, "alarm": {alarm}, "event": set(), "hours": set(),
                "environment": self._tags("kinesis", arn).get(ENV_TAG)}
        onset = self._alarm_onset(alarm)
        if onset is None and not isinstance(params.get("event"), str):
            return {**live, "refused": "the alarm is not in ALARM", "state": state}
        since = (onset or self._now()) - REVERT_BEFORE_ALARM

        def on_this(e: dict[str, Any]) -> bool:
            r = e["request"] or {}
            return _last(r.get("streamName") or r.get("streamARN") or "") == name

        e, why = self._one_change("kinesis.amazonaws.com", ("DecreaseStreamRetentionPeriod",), since, on_this,
                                  params.get("event"))
        if e is None:
            return {**live, "refused": why, "state": state}
        state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor")})
        why = _who_refusal(e, onset) if onset else "the alarm is not in ALARM"
        before = after = None
        if not why or onset is None:
            rid = self._config_id("AWS::Kinesis::Stream", name, lambda rid: rid.endswith(name))
            if not rid:
                why = why or "AWS Config holds no single record of this stream"
            else:
                before, after, bracket = self._config_bracket(
                    "AWS::Kinesis::Stream", rid, e, lambda i: _get(_json(i.get("configuration")), "RetentionPeriodHours"))
                why = why or bracket
        state.update(before=before, after=after)
        if not why and not (isinstance(before, int) and isinstance(after, int) and before > after):
            why = "AWS Config recorded no longer retention before the change"
        if not why and hours != after:
            why = "the stream's retention is not what the change set: it moved since"
        if not why and not 24 <= before <= 8760:
            why = "the retention before the change is outside what Kinesis allows"
        return {**live, "event": set() if why else {e["event"]}, "hours": set() if why else {str(before)},
                "refused": why, "state": state}

    def _kinesis_retention_restore(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("stream", "arn", "event", "before", "after"), f"stream {p['stream']}")
        before = int(p["hours"]) if str(p["hours"]).isdigit() else None
        after = snapshot.get("after")
        want_now, to = (after, before) if not back else (before, after)
        if now.get("hours_now") != want_now or not isinstance(to, int):
            raise AwsPlatformRefused(f"stream {p['stream']} keeps {now.get('hours_now')} h, not {want_now} h; "
                                     "nothing was changed")
        action = "kinesis:DecreaseStreamRetentionPeriod" if back else "kinesis:IncreaseStreamRetentionPeriod"
        k = self._actor(who, [action], [now["arn"]], None)("kinesis")
        (k.decrease_stream_retention_period if back else k.increase_stream_retention_period)(
            StreamName=p["stream"], RetentionPeriodHours=to)
        return f"set stream {p['stream']} retention from {want_now} h to {to} h"

    def _kinesis_retention_restored(self, stream: str, params: dict[str, Any]) -> bool:
        s = self._read("kinesis").describe_stream_summary(StreamName=stream)["StreamDescriptionSummary"]
        return (str(s.get("RetentionPeriodHours")) == str(params.get("hours")) and s.get("StreamStatus") == "ACTIVE"
                and self._alarm_ok(str(params.get("alarm", ""))))

    def _live_asg_restore(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE recorded SetDesiredCapacity / UpdateAutoScalingGroup that set this group's desired capacity in the
        hours before its alarm, and the capacity AWS Config recorded before it. A change that also set the group's
        bounds is a person's; a scheduled action leaves no such event (AWS made it) and is not undone."""
        name, alarm = params.get("asg"), params.get("alarm")
        if not isinstance(name, str) or not isinstance(alarm, str):
            return {}
        g = (self._read("autoscaling").describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups") or [{}])[0]
        if g.get("AutoScalingGroupName") != name:
            return {}
        arn, desired = g.get("AutoScalingGroupARN", ""), g.get("DesiredCapacity")
        lo, hi = g.get("MinSize"), g.get("MaxSize")
        state: dict[str, Any] = {"asg": name, "arn": arn, "desired_now": desired, "where": self._where(arn)}
        live = {"asg": {name}, "alarm": {alarm}, "event": set(), "desired": set(),
                "environment": {t["Key"]: t["Value"] for t in g.get("Tags") or []}.get(ENV_TAG)}
        onset = self._alarm_onset(alarm)
        named = params.get("event")
        if onset is None and not isinstance(named, str):
            return {**live, "refused": "the alarm is not in ALARM", "state": state}
        since = (onset or self._now()) - REVERT_BEFORE_ALARM

        def sets_capacity(e: dict[str, Any]) -> bool:
            r = e["request"] or {}
            return _last(r.get("autoScalingGroupName")) == name and "desiredCapacity" in r

        writes = list({w["event"]: w for event in ("SetDesiredCapacity", "UpdateAutoScalingGroup")
                       for w in self._trail_writes("EventName", event, since, self._now(), sets_capacity)}.values())
        if isinstance(named, str):
            writes = [w for w in writes if w["event"] == named] or writes
        if len(writes) != 1:
            return {**live, "state": state, "refused": f"{'no recorded' if not writes else len(writes)} change(s) to "
                    f"{name}'s desired capacity since {since:%Y-%m-%dT%H:%MZ}"}
        e = writes[0]
        state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor")})
        why = _who_refusal(e, onset) if onset else "the alarm is not in ALARM"
        if not why and {"minSize", "maxSize"} & set(e["request"] or {}):
            why = "the change also set the group's bounds: a person restores them"
        rid = self._config_id("AWS::AutoScaling::AutoScalingGroup", name, lambda rid: name in rid)
        before = after = None
        if rid and (not why or onset is None):
            before, after, bracket = self._config_bracket(
                "AWS::AutoScaling::AutoScalingGroup", rid, e, lambda i: _get(_json(i.get("configuration")), "desiredCapacity"))
            why = why or bracket
        elif not why:
            why = "AWS Config holds no single record of this group"
        state.update(before=before, after=after)
        if not why and (not isinstance(before, int) or not isinstance(lo, int) or not isinstance(hi, int)
                        or not lo <= before <= hi):
            why = f"the capacity before ({before}) is outside the group's bounds now ({lo}..{hi})"
        if not why and (after != (e["request"] or {}).get("desiredCapacity") or desired != after):
            why = "the group's capacity is not what the change set: it moved since"
        return {**live, "event": set() if why else {e["event"]}, "desired": set() if why else {str(before)},
                "refused": why, "state": state}

    def _asg_restore(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("asg", "arn", "event", "before", "after"), f"group {p['asg']}")
        prior = int(p["desired"]) if str(p["desired"]).isdigit() else None
        want_now, to = (snapshot.get("after"), prior) if not back else (prior, snapshot.get("after"))
        if now.get("desired_now") != want_now or not isinstance(to, int):
            raise AwsPlatformRefused(f"group {p['asg']} wants {now.get('desired_now')} instances, not {want_now}; "
                                     "nothing was changed")
        asg = self._actor(who, ["autoscaling:SetDesiredCapacity"], [now["arn"]], None)("autoscaling")
        asg.set_desired_capacity(AutoScalingGroupName=p["asg"], DesiredCapacity=to, HonorCooldown=False)
        return f"set group {p['asg']} desired capacity from {now.get('desired_now')} to {to}"

    def _asg_restored(self, group: str, params: dict[str, Any]) -> bool:
        g = (self._read("autoscaling").describe_auto_scaling_groups(AutoScalingGroupNames=[group]).get(
            "AutoScalingGroups") or [{}])[0]
        want = int(params["desired"]) if str(params.get("desired", "")).isdigit() else None
        serving = sum(1 for i in g.get("Instances") or [] if i.get("LifecycleState") == "InService"
                      and i.get("HealthStatus") == "Healthy")
        return (isinstance(want, int) and g.get("DesiredCapacity") == want and serving == want
                and self._alarm_ok(str(params.get("alarm", ""))))

    def _live_stage_restore(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE recorded UpdateStage that only moved this REST API stage to another deployment in the hours before
        its alarm, and the deployment AWS Config recorded before it - which must still exist."""
        name, stage, alarm = params.get("api"), params.get("stage"), params.get("alarm")
        if not all(isinstance(v, str) for v in (name, stage, alarm)):
            return {}
        api_id, api_tags = self._rest_api(name)
        if not api_id:
            return {}
        apigw = self._read("apigateway")
        st = apigw.get_stage(restApiId=api_id, stageName=stage)
        arn = f"arn:aws:apigateway:{apigw.meta.region_name}::/restapis/{api_id}/stages/{stage}"
        state: dict[str, Any] = {"api": name, "api_id": api_id, "stage": stage, "arn": arn,
                                 "deployment_now": st.get("deploymentId"), "where": apigw.meta.region_name}
        live = {"api": {name}, "stage": {stage}, "alarm": {alarm}, "event": set(), "deployment": set(),
                "environment": (st.get("tags") or {}).get(ENV_TAG) or api_tags.get(ENV_TAG)}
        onset = self._alarm_onset(alarm)
        named = params.get("event")
        if onset is None and not isinstance(named, str):
            return {**live, "refused": "the alarm is not in ALARM", "state": state}
        since = (onset or self._now()) - REVERT_BEFORE_ALARM

        def moves_deployment(e: dict[str, Any]) -> bool:
            r = e["request"] or {}
            ops = r.get("patchOperations") or _get(r.get("updateStageInput") or {}, "patchOperations") or []
            return (r.get("restApiId") == api_id and r.get("stageName") == stage and len(ops) == 1
                    and isinstance(ops[0], dict) and ops[0].get("path") == "/deploymentId"
                    and ops[0].get("op") == "replace")

        writes = self._trail_writes("EventName", "UpdateStage", since, self._now(), moves_deployment)
        if isinstance(named, str):
            writes = [w for w in writes if w["event"] == named] or writes
        if len(writes) != 1:
            return {**live, "state": state, "refused": f"{'no recorded' if not writes else len(writes)} deployment "
                    f"change(s) to stage {stage} since {since:%Y-%m-%dT%H:%MZ}"}
        e = writes[0]
        state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor")})
        why = _who_refusal(e, onset) if onset else "the alarm is not in ALARM"
        rid = self._config_id("AWS::ApiGateway::Stage", stage, lambda rid: api_id in rid)
        before = after = None
        if rid and (not why or onset is None):
            before, after, bracket = self._config_bracket(
                "AWS::ApiGateway::Stage", rid, e, lambda i: _get(_json(i.get("configuration")), "deploymentId"))
            why = why or bracket
        elif not why:
            why = "AWS Config holds no single record of this stage"
        state.update(before=before, after=after)
        if not why and st.get("deploymentId") != after:
            why = "the stage's deployment is not what the change set: it moved since"
        if not why:
            try:
                apigw.get_deployment(restApiId=api_id, deploymentId=str(before))
            except Exception:  # noqa: BLE001 - gone, or unreadable: nothing to go back to
                why = f"the deployment before the change ({before}) no longer exists"
        return {**live, "event": set() if why else {e["event"]}, "deployment": set() if why else {str(before)},
                "refused": why, "state": state}

    def _stage_restore(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("api", "api_id", "stage", "arn", "event", "before", "after"), f"stage {p['stage']}")
        want_now, to = (snapshot.get("after"), p["deployment"]) if not back else (p["deployment"], snapshot.get("after"))
        if now.get("deployment_now") != want_now or not isinstance(to, str):
            raise AwsPlatformRefused(f"stage {p['stage']} serves deployment {now.get('deployment_now')}, not "
                                     f"{want_now}; nothing was changed")
        apigw = self._actor(who, ["apigateway:PATCH"], [now["arn"]], None)("apigateway")
        apigw.update_stage(restApiId=now["api_id"], stageName=p["stage"],
                           patchOperations=[{"op": "replace", "path": "/deploymentId", "value": to}])
        return f"moved stage {p['stage']} from deployment {now.get('deployment_now')} to {to}"

    def _stage_restored(self, stage: str, params: dict[str, Any]) -> bool:
        api_id, _ = self._rest_api(str(params.get("api", "")))
        st = self._read("apigateway").get_stage(restApiId=api_id, stageName=stage) if api_id else {}
        return st.get("deploymentId") == params.get("deployment") and self._alarm_ok(str(params.get("alarm", "")))

    # ------------------------------------------------------------------ undo a recorded change, from the event (G10-D2)

    def _one_write(self, event: str, keep: Callable[[dict[str, Any]], bool], params: dict[str, Any],
                   alarm: str) -> tuple[dict[str, Any] | None, datetime | None, str]:
        """(the ONE successful `event` write `keep` accepts in the hours before the alarm, the alarm's onset, why
        none). A plan's own event (params["event"]) is found again once the alarm reads OK - for the rollback and
        the health check - but is allowed again only while it reads ALARM."""
        onset = self._alarm_onset(alarm)
        named = params.get("event")
        if onset is None and not isinstance(named, str):
            return None, None, "the alarm is not in ALARM"
        since = (onset or self._now()) - REVERT_BEFORE_ALARM
        writes = list({w["event"]: w for w in self._trail_writes("EventName", event, since, self._now(), keep)}.values())
        if isinstance(named, str):
            writes = [w for w in writes if w["event"] == named] or writes
        if len(writes) != 1:
            return None, onset, (f"{'no recorded' if not writes else len(writes)} {event} since "
                                 f"{since:%Y-%m-%dT%H:%MZ}" + (" (WARDEN does not choose one)" if writes else ""))
        e = writes[0]
        return e, onset, (_who_refusal(e, onset) if onset else "the alarm is not in ALARM")

    def _live_targets(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE DeregisterTargets a person made on this target group before the alarm - an ECS service or an Auto
        Scaling group deregisters its own (AWS-made: refused) - and its targets, while none is registered again."""
        name, alarm = params.get("target_group"), params.get("alarm")
        if not isinstance(name, str) or not isinstance(alarm, str):
            return {}
        elb = self._read("elbv2")
        [tg] = elb.describe_target_groups(Names=[name])["TargetGroups"]
        arn = tg["TargetGroupArn"]
        tags = {t["Key"]: t["Value"] for d in elb.describe_tags(ResourceArns=[arn]).get("TagDescriptions") or []
                for t in d.get("Tags") or []}
        state: dict[str, Any] = {"target_group": name, "arn": arn, "where": self._where(arn)}
        live = {"target_group": {name}, "alarm": {alarm}, "event": set(), "environment": tags.get(ENV_TAG)}
        e, _onset, why = self._one_write(
            "DeregisterTargets", lambda e: _get(e["request"] or {}, "targetGroupArn") == arn, params, alarm)
        if e is not None:
            targets = sorted(([str(_get(t, "id")), _get(t, "port")] for t in _get(e["request"], "targets") or []
                              if isinstance(t, dict) and _get(t, "id")), key=json.dumps)
            state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor")}, targets=targets)
            if not why and not targets:
                why = "the event names no target it deregistered"
            if not why:
                now = elb.describe_target_health(TargetGroupArn=arn, Targets=[
                    {"Id": t, **({"Port": p} if isinstance(p, int) else {})} for t, p in targets]).get(
                    "TargetHealthDescriptions") or []
                if any(((h.get("TargetHealth") or {}).get("State")) not in (None, "unused", "draining") for h in now):
                    why = "a deregistered target is registered again already"
        return {**live, "event": set() if why else {e["event"]}, "refused": why, "state": state}

    def _targets(self, p, snapshot, now, who, back) -> str:
        """Register the targets the recorded DeregisterTargets removed (back: deregister them again)."""
        self._expect(now, snapshot, ("target_group", "arn", "event", "targets"), f"target group {p['target_group']}")
        targets = [{"Id": t, **({"Port": port} if isinstance(port, int) else {})} for t, port in now["targets"]]
        action = "elasticloadbalancing:DeregisterTargets" if back else "elasticloadbalancing:RegisterTargets"
        elb = self._actor(who, [action], [now["arn"]], None)("elbv2")
        (elb.deregister_targets if back else elb.register_targets)(TargetGroupArn=now["arn"], Targets=targets)
        return f"{'deregistered' if back else 'registered'} {len(targets)} target(s) in {p['target_group']}"

    def _targets_healthy(self, name: str, params: dict[str, Any]) -> bool:
        st = self._live_targets(params).get("state") or {}
        if not st.get("targets"):
            return False
        now = self._read("elbv2").describe_target_health(TargetGroupArn=st["arn"], Targets=[
            {"Id": t, **({"Port": p} if isinstance(p, int) else {})} for t, p in st["targets"]]).get(
            "TargetHealthDescriptions") or []
        healthy = [h for h in now if (h.get("TargetHealth") or {}).get("State") == "healthy"]
        return len(healthy) == len(st["targets"]) and self._alarm_ok(str(params.get("alarm", "")))

    def _live_key_deletion(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE ScheduleKeyDeletion on this customer managed key before the alarm, while the key is still pending
        deletion. Cancelling keeps the key but leaves it disabled: enabling it is a person's (a key may be disabled
        because it is compromised)."""
        key, alarm = params.get("key"), params.get("alarm")
        if not isinstance(key, str) or not isinstance(alarm, str):
            return {}
        kms = self._read("kms")
        meta = kms.describe_key(KeyId=key)["KeyMetadata"]
        kid, arn = meta["KeyId"], meta["Arn"]
        tags = {t["TagKey"]: t["TagValue"] for t in kms.list_resource_tags(KeyId=kid).get("Tags") or []}
        state: dict[str, Any] = {"key": key, "arn": arn, "key_state": meta.get("KeyState"), "where": self._where(arn)}
        live = {"key": {key}, "alarm": {alarm}, "event": set(), "environment": tags.get(ENV_TAG)}
        e, _onset, why = self._one_write(
            "ScheduleKeyDeletion", lambda e: _last(_get(e["request"] or {}, "keyId")) in (kid, _last(arn)), params, alarm)
        if e is not None:
            state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor")})
        if not why and meta.get("KeyManager") != "CUSTOMER":
            why = "an AWS managed key is AWS's to manage"
        if not why and meta.get("KeyState") != "PendingDeletion":
            why = f"the key is {meta.get('KeyState')}, not pending deletion"
        return {**live, "event": set() if why or e is None else {e["event"]}, "refused": why, "state": state}

    def _key_cancel(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("key", "arn", "event"), f"key {p['key']}")
        if now.get("key_state") != "PendingDeletion":
            raise AwsPlatformRefused(f"key {p['key']} is {now.get('key_state')}, not pending deletion; nothing was "
                                     "changed")
        kms = self._actor(who, ["kms:CancelKeyDeletion"], [now["arn"]], None)("kms")
        kms.cancel_key_deletion(KeyId=now["arn"])
        return f"cancelled the deletion of key {p['key']} (it stays disabled until a person enables it)"

    def _key_kept(self, key: str, params: dict[str, Any]) -> bool:
        return self._read("kms").describe_key(KeyId=key)["KeyMetadata"].get("KeyState") == "Disabled"

    def _live_secret_deletion(self, params: dict[str, Any]) -> dict[str, Any]:
        """The ONE DeleteSecret with a recovery window on this secret before the alarm, while it is still
        recoverable. One deleted without recovery is gone: nothing to restore."""
        name, alarm = params.get("secret"), params.get("alarm")
        if not isinstance(name, str) or not isinstance(alarm, str):
            return {}
        sm = self._read("secretsmanager")
        d = sm.describe_secret(SecretId=name)
        arn = d["ARN"]
        tags = {t["Key"]: t["Value"] for t in d.get("Tags") or []}
        state: dict[str, Any] = {"secret": d.get("Name", name), "arn": arn, "deleted": bool(d.get("DeletedDate")),
                                 "where": self._where(arn)}
        live = {"secret": {name}, "alarm": {alarm}, "event": set(), "environment": tags.get(ENV_TAG)}

        def on_this(e: dict[str, Any]) -> bool:
            r = e["request"] or {}
            return str(_get(r, "secretId") or "") in (arn, d.get("Name"), name) and not _get(
                r, "forceDeleteWithoutRecovery")

        e, _onset, why = self._one_write("DeleteSecret", on_this, params, alarm)
        if e is not None:
            state.update({k: e[k] for k in ("event", "event_name", "event_time", "actor")})
        if not why and not d.get("DeletedDate"):
            why = "the secret is not deleted (restored already)"
        return {**live, "event": set() if why or e is None else {e["event"]}, "refused": why, "state": state}

    def _secret_restore(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("secret", "arn", "event"), f"secret {p['secret']}")
        if not now.get("deleted"):
            raise AwsPlatformRefused(f"secret {p['secret']} is not deleted; nothing was changed")
        sm = self._actor(who, ["secretsmanager:RestoreSecret"], [now["arn"]], None)("secretsmanager")
        sm.restore_secret(SecretId=now["arn"])
        return f"restored secret {p['secret']}"

    def _secret_restored(self, name: str, params: dict[str, Any]) -> bool:
        d = self._read("secretsmanager").describe_secret(SecretId=name)
        return not d.get("DeletedDate") and self._alarm_ok(str(params.get("alarm", "")))

    # ------------------------------------------------------------------ codepipeline: freeze deploys (G9-D)

    def _resource_tags(self, resource: str) -> dict[str, str]:
        """The tags of a Lambda function (`name`) or an ECS service (`cluster/service`)."""
        if "/" in resource:
            cluster, service = resource.split("/", 1)
            [svc] = self._read("ecs").describe_services(cluster=cluster, services=[service], include=["TAGS"])["services"]
            return {t["key"]: t["value"] for t in svc.get("tags") or []}
        arn = self._read("lambda").get_function_configuration(FunctionName=resource)["FunctionArn"]
        return self._tags("lambda", _unqualified(arn))

    def _live_pipeline(self, params: dict[str, Any]) -> dict[str, Any]:
        resource = params.get("resource")
        if not isinstance(resource, str):
            return {}
        tags = self._resource_tags(resource)
        pipeline, _, stage = str(tags.get(PIPELINE_TAG, "")).partition("/")
        if not (_PIPELINE_NAME.fullmatch(pipeline) and _PIPELINE_NAME.fullmatch(stage)):
            return {"resource": {resource}, "pipeline": set(), "stage": set(), "environment": tags.get(ENV_TAG)}
        cp = self._read("codepipeline")
        st = cp.get_pipeline_state(name=pipeline)
        stages = {s.get("stageName"): s for s in st.get("stageStates") or []}
        arn = f"arn:aws:codepipeline:{cp.meta.region_name}:{self._account()}:{pipeline}"
        p_env = {t["key"]: t["value"] for t in cp.list_tags_for_resource(resourceArn=arn).get("tags") or []}.get(ENV_TAG)
        flowing = (stages.get(stage, {}).get("inboundTransitionState") or {}).get("enabled")
        # Freezable: the stage exists, deploys still flow into it, and the pipeline is the service's environment's.
        can = stage in stages and flowing is True and p_env == tags.get(ENV_TAG)
        return {"resource": {resource}, "pipeline": {pipeline} if can else set(), "stage": {stage} if can else set(),
                "environment": tags.get(ENV_TAG) if p_env == tags.get(ENV_TAG) else None,
                "state": {"resource": resource, "pipeline": pipeline, "stage": stage, "arn": f"{arn}/{stage}",
                          "enabled": flowing, "where": self._where(arn)}}

    def _freeze(self, p, snapshot, now, who, back) -> str:
        self._expect(now, snapshot, ("resource", "pipeline", "stage", "arn"), f"pipeline {p['pipeline']}")
        if back and now.get("enabled") is True:
            return f"nothing to roll back: deploys into {p['pipeline']} stage {p['stage']} were enabled again already"
        if now.get("enabled") is back:  # freezing needs deploys flowing; the rollback needs them frozen
            raise AwsPlatformRefused(f"stage {p['stage']} of {p['pipeline']} is already "
                                     f"{'enabled' if now.get('enabled') else 'frozen'}; nothing was changed")
        action = "codepipeline:EnableStageTransition" if back else "codepipeline:DisableStageTransition"
        cp = self._actor(who, [action], [now["arn"]], None)("codepipeline")
        if back:
            cp.enable_stage_transition(pipelineName=p["pipeline"], stageName=p["stage"], transitionType="Inbound")
            return f"enabled deploys into {p['pipeline']} stage {p['stage']} again"
        # The reason: CodePipeline's own character set only (letters, digits, spaces and ! @ ( ) . * ? -).
        reason = re.sub(r"[^A-Za-z0-9!@ ().*?-]", "-", f"WARDEN {who['incident']} froze deploys for a person")[:300]
        cp.disable_stage_transition(pipelineName=p["pipeline"], stageName=p["stage"], transitionType="Inbound",
                                    reason=reason)
        return f"froze deploys into {p['pipeline']} stage {p['stage']}"

    def _frozen(self, stage: str, params: dict[str, Any]) -> bool:
        st = self._read("codepipeline").get_pipeline_state(name=params.get("pipeline", ""))
        found = [s for s in st.get("stageStates") or [] if s.get("stageName") == stage]
        return bool(found) and (found[0].get("inboundTransitionState") or {}).get("enabled") is False

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


def _iso(t: datetime | None) -> str | None:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


_PLAIN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _plain(name: Any) -> str:
    """A name AWS lets its owner write freely, shown only when it is a plain name (review-e L8)."""
    return str(name) if isinstance(name, str) and _PLAIN_NAME.fullmatch(name) else "(name withheld: not a plain name)"


def _when(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)  # Lambda writes `...000+0000`; Python 3.11+ reads it
        except ValueError:
            return None
    return None
