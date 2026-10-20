"""Service quotas as evidence (B14): how close the alert's services are to their AWS limits, read-only.

A Lambda that throttles at its account's concurrency, a Fargate service that cannot start tasks for want of vCPU, an
EC2 fleet at its instance limit - each looks like an application failure in the logs, and the cause is a number AWS
holds: the quota, and its usage. For the services the alert names (its resource labels, or an AWS/Usage alarm's own
Service), WARDEN lists the account's quotas that have a usage metric (Service Quotas ListServiceQuotas: each quota's
UsageMetric), reads those metrics' maximum around the alarm (CloudWatch GetMetricData, AWS/Usage and the services' own
namespaces) and states each quota's value, its peak usage and the share used.

Read in the incident's environment's reader role (servicequotas:ListServiceQuotas, cloudwatch:GetMetricData), every
read bounded: at most MAX_SERVICES services, LIST_PAGES pages of quotas each, MAX_METRICS usage metrics in ONE
GetMetricData call. Cost: Service Quotas' API has no charge; GetMetricData is $0.01 per 1,000 metrics requested
(AWS Price List API, AmazonCloudWatch ap-south-1, published 2026-10-07) - at most $0.0004 an incident.

Only usage AWS recommends reading as a Maximum (a count: concurrent executions, running vCPUs, instances) is compared
with its quota; a rate quota's per-second limit is not a per-minute sum, so it is never compared and never claimed.
The lines are WARDEN's own reads of AWS's numbers (STATE quota ...); a quota with no usage data in the window is said to
be unread, never to have headroom.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from .grafana import PARTIAL, _alert_time, _iso
from .models import Alert

LOOKBACK = timedelta(minutes=15)
PERIOD_S = 60
MAX_SERVICES = 2
LIST_PAGES = 2
PAGE_SIZE = 100
MAX_METRICS = 40
MAX_LINES = 6
NEAR = 0.8  # a quota at 80% or more of its value is named as near its limit

# The Service Quotas service code of each resource label WARDEN reads (resources.py), most specific first. An ECS service
# runs on Fargate or on EC2 capacity: Fargate's quotas are the ones an ECS service meets first.
_LABEL_SERVICES = (("lambda", "lambda"), ("ecs_service", "fargate"), ("ecs_cluster", "fargate"),
                   ("dynamodb_table", "dynamodb"), ("eks_cluster", "ec2"), ("asg", "ec2"), ("instance_id", "ec2"),
                   ("aurora_cluster", "rds"), ("rds_instance", "rds"), ("elasticache_node", "elasticache"),
                   ("kinesis_stream", "kinesis"), ("state_machine", "states"), ("apigw_id", "apigateway"),
                   ("apigw_rest", "apigateway"), ("nat_gateway", "vpc"), ("ebs_volume", "ebs"))
# An AWS/Usage alarm's Service dimension (resources.py: quota_service) as a Service Quotas code.
_USAGE_SERVICES = {"lambda": "lambda", "fargate": "fargate", "ec2": "ec2", "dynamodb": "dynamodb", "rds": "rds",
                   "elasticache": "elasticache", "kinesis": "kinesis", "states": "states", "apigateway": "apigateway",
                   "ecs": "ecs", "ebs": "ebs", "vpc": "vpc", "logs": "logs", "cloudwatch": "monitoring",
                   "sqs": "sqs", "sns": "sns", "eks": "eks"}
# A quota name as AWS writes it ("Concurrent executions", "Fargate On-Demand vCPU resource count"): anything else is cut.
_TEXT = re.compile(r"[^A-Za-z0-9 ()._/,-]")
_CODE = re.compile(r"^[A-Za-z0-9-]{1,40}$")


def service_codes(alert: Alert) -> list[str]:
    """The Service Quotas codes to read for this alert: an AWS/Usage alarm's own service first, then each resource
    label's, without repeats, at most MAX_SERVICES. Only from the alert's labels - never from evidence text."""
    labels = alert.labels or {}
    found: list[str] = []
    usage = _USAGE_SERVICES.get(str(labels.get("quota_service") or "").strip().lower())
    if usage:
        found.append(usage)
    for key, code in _LABEL_SERVICES:
        if labels.get(key) and code not in found:
            found.append(code)
    return found[:MAX_SERVICES]


def _metric(quota: dict[str, Any]) -> dict[str, Any] | None:
    """The quota's usage metric as a GetMetricData MetricStat, when AWS gives one and recommends its Maximum."""
    usage = quota.get("UsageMetric") or {}
    if str(usage.get("MetricStatisticRecommendation") or "") != "Maximum":
        return None
    namespace, name = str(usage.get("MetricNamespace") or ""), str(usage.get("MetricName") or "")
    if not namespace or not name:
        return None
    dims = [{"Name": str(k), "Value": str(v)} for k, v in sorted((usage.get("MetricDimensions") or {}).items())]
    return {"Metric": {"Namespace": namespace, "MetricName": name, "Dimensions": dims}, "Period": PERIOD_S,
            "Stat": "Maximum"}


class QuotaReader:
    """Quotas and their usage for the alert's services. `clients` makes the boto3 clients for an alert - in the
    runtime, the ones over the incident's environment's reader role (the stack backend's)."""

    source = "quotas"

    def __init__(self, clients: Any) -> None:
        self._clients = clients

    def logs(self, alert: Alert) -> list[str]:
        codes = service_codes(alert)
        if not codes:
            return []
        try:
            made = self._clients(alert)
            quotas_client, cloudwatch = made["service-quotas"], made["cloudwatch"]
        except Exception as exc:  # noqa: BLE001 - no client is a read that did not happen, never headroom
            return [f"{PARTIAL}quotas: {type(exc).__name__} - not read"]
        out: list[str] = []
        listed: list[tuple[str, dict[str, Any]]] = []
        for code in codes:
            got, problem = self._list(quotas_client, code)
            if problem:
                out.append(problem)
            listed += [(code, q) for q in got]
        return out + self._usage(cloudwatch, alert, listed)

    def traces(self, alert: Alert) -> list[str]:
        return []

    def metrics(self, alert: Alert) -> dict[str, float]:
        return {}

    @staticmethod
    def _list(client: Any, code: str) -> tuple[list[dict[str, Any]], str]:
        """The service's quotas that have a usage metric, up to LIST_PAGES pages."""
        quotas: list[dict[str, Any]] = []
        token = ""
        for _ in range(LIST_PAGES):
            try:
                page = client.list_service_quotas(ServiceCode=code, MaxResults=PAGE_SIZE,
                                                  **({"NextToken": token} if token else {}))
            except Exception as exc:  # noqa: BLE001 - one service unread never hides another
                return quotas, f"{PARTIAL}quotas {code}: {type(exc).__name__} - not read"
            quotas += [q for q in page.get("Quotas") or [] if q.get("UsageMetric")]
            token = str(page.get("NextToken") or "")
            if not token:
                break
        return quotas, ""

    def _usage(self, cloudwatch: Any, alert: Alert, listed: list[tuple[str, dict[str, Any]]]) -> list[str]:
        """Each comparable quota's peak usage around the alarm, as a share of its value: the closest first."""
        at = _alert_time(alert)
        start, end = (at - LOOKBACK).replace(second=0, microsecond=0), at + LOOKBACK
        asked: dict[str, tuple[str, dict[str, Any]]] = {}
        queries = []
        for code, q in listed:
            stat = _metric(q)
            value = q.get("Value")
            if stat is None or not isinstance(value, int | float) or value <= 0 or len(queries) >= MAX_METRICS:
                continue
            qid = f"q{len(queries)}"
            asked[qid] = (code, q)
            queries.append({"Id": qid, "MetricStat": stat, "ReturnData": True})
        if not queries:
            if not listed:
                return []
            services = ", ".join(sorted({c for c, _ in listed}))
            said = f"no quota of {services} has a count usage metric to compare - not a sign of headroom"
            return [f"{PARTIAL}quotas: {said}"]
        try:
            got = cloudwatch.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end,
                                             ScanBy="TimestampDescending")
        except Exception as exc:  # noqa: BLE001
            return [f"{PARTIAL}quotas usage: {type(exc).__name__} - not read"]
        rows = []
        for result in got.get("MetricDataResults") or []:
            code, q = asked.get(str(result.get("Id")), ("", {}))
            values = [float(v) for v in result.get("Values") or []]
            if q and values:
                peak, value = max(values), float(q["Value"])
                rows.append((peak / value, code, q, peak, value))
        unread = len(asked) - len(rows)  # no data, or no result at all: unread either way
        rows.sort(key=lambda r: (-r[0], r[1], str(r[2].get("QuotaCode"))))
        lines = []
        for share, code, q, peak, value in rows[:MAX_LINES]:
            quota_code = str(q.get("QuotaCode") or "")
            name = _TEXT.sub("", str(q.get("QuotaName") or ""))[:80].strip() or "unnamed"
            lines.append(f"STATE quota {code} {quota_code if _CODE.match(quota_code) else '?'} ({name}) "
                         f"value={value:g} usage_max={peak:g} used={round(share * 100)}%"
                         f"{' near_limit' if share >= NEAR else ''} between {_iso(start)} and {_iso(end)}")
        if unread:
            lines.append(f"{PARTIAL}quotas usage: {unread} of {len(asked)} usage metrics had no data between "
                         f"{_iso(start)} and {_iso(end)} - not a sign of headroom")
        return lines
