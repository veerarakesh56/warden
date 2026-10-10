"""What an alarm watches, as typed resource labels (G9-A1, 2026-10-10).

A CloudWatch alarm names its resource only through its metrics' namespace and dimensions - `AWS/Lambda`
`FunctionName=orders`, `AWS/RDS` `DBInstanceIdentifier=db1`. The evidence backends select their readers by resource
labels (`lambda`, `rds_instance`, ...). Without this table an alarm on anything but an ECS service named no resource,
and WARDEN read nothing (audit 2026-10-10, finding 1).

Deterministic and closed: one entry per namespace, the dimension names AWS documents for it, nothing guessed from the
alarm's name or description (those stay untrusted text). Values still pass the Alert label check (models.py: a value
that is not a plain identifier is dropped and reported). A namespace not in the table maps to nothing, and the report
says what was not read.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping

Labels = dict[str, str]


def _last(value: str) -> str:
    """`targetgroup/name/0123abcd` -> `name`; `app/name/0123abcd` -> `name`; a plain value unchanged."""
    parts = value.split("/")
    return parts[1] if len(parts) >= 3 else value


def _arn_name(value: str) -> str:
    """`arn:aws:states:r:a:stateMachine:orders` -> `orders`; `arn:aws:acm:r:a:certificate/c-1` -> `c-1`."""
    return value.rsplit(":", 1)[-1].rsplit("/", 1)[-1] if value.startswith("arn:") else value


def _one(key: str, *dims: str, fn: Callable[[str], str] = str) -> Callable[[Mapping[str, str]], Labels]:
    """`key` from the first of `dims` the metric carries (AWS documents some dimensions under two spellings)."""
    def mapper(d: Mapping[str, str]) -> Labels:
        value = next((d[x] for x in dims if d.get(x)), "")
        return {key: fn(value)} if value else {}
    return mapper


def _webacl(value: str) -> str:
    """A WAF web ACL's name from `arn:aws:wafv2:r:a:regional/webacl/<name>/<id>`; a plain value unchanged."""
    parts = value.split("/")
    return parts[-2] if value.startswith("arn:") and len(parts) >= 3 else value


def _lambda(d: Mapping[str, str]) -> Labels:
    out = {"lambda": d["FunctionName"]} if d.get("FunctionName") else {}
    if d.get("Resource") and ":" in d["Resource"]:  # FunctionName:alias or :version
        out["lambda_qualifier"] = d["Resource"].split(":", 1)[1]
    return out


def _ecs(d: Mapping[str, str]) -> Labels:
    out = {}
    if d.get("ClusterName"):
        out["ecs_cluster"] = d["ClusterName"]
    if d.get("ServiceName"):
        out["ecs_service"] = d["ServiceName"]
    return out


def _container_insights(d: Mapping[str, str]) -> Labels:
    """EKS Container Insights: ClusterName, Namespace, and a pod or service name (a Deployment's pods carry its name
    as their prefix; the k8s reader resolves it)."""
    out = {}
    if d.get("ClusterName"):
        out["eks_cluster"] = d["ClusterName"]
    if d.get("Namespace"):
        out["namespace"] = d["Namespace"]
    if d.get("PodName"):
        out["deployment"] = d["PodName"]
    if d.get("Service"):  # a Kubernetes Service, not a Deployment: kept apart (unverified that the names agree)
        out["k8s_service"] = d["Service"]
    return out


def _rds(d: Mapping[str, str]) -> Labels:
    """AWS documents both DB... and Db... spellings (e.g. `DbInstanceIdentifier, VolumeName`)."""
    return {**_one("aurora_cluster", "DBClusterIdentifier", "DbClusterIdentifier")(d),
            **_one("rds_instance", "DBInstanceIdentifier", "DbInstanceIdentifier")(d)}


def _docdb(d: Mapping[str, str]) -> Labels:
    return {**_one("docdb_cluster", "DBClusterIdentifier")(d), **_one("docdb_instance", "DBInstanceIdentifier")(d)}


def _elasticache(d: Mapping[str, str]) -> Labels:
    """Node-based caches report CacheClusterId (the reader resolves its replication group; `rg-0001-001` is not parsed
    here); serverless caches report `clusterId`, lower-case c (AWS's ElastiCache serverless metrics)."""
    return {**_one("elasticache_node", "CacheClusterId")(d), **_one("elasticache_serverless", "clusterId")(d)}


def _alb(d: Mapping[str, str]) -> Labels:
    out = {}
    if d.get("TargetGroup"):
        out["alb_target_group"] = _last(d["TargetGroup"])
    if d.get("LoadBalancer"):
        out["load_balancer"] = d["LoadBalancer"]  # app/<name>/<id>: the reader needs all three parts
    return out


def _nlb(d: Mapping[str, str]) -> Labels:
    out = {}
    if d.get("TargetGroup"):
        out["nlb_target_group"] = _last(d["TargetGroup"])
    if d.get("LoadBalancer"):
        out["load_balancer"] = d["LoadBalancer"]
    return out


def _apigw(d: Mapping[str, str]) -> Labels:
    """HTTP and WebSocket APIs report ApiId; REST APIs report ApiName (and Stage)."""
    out = {}
    if d.get("ApiId"):
        out["apigw_id"] = d["ApiId"]
    if d.get("ApiName"):
        out["apigw_rest"] = d["ApiName"]
    if d.get("Stage"):
        out["apigw_stage"] = d["Stage"]
    return out


def _ec2(d: Mapping[str, str]) -> Labels:
    out = {}
    if d.get("InstanceId"):
        out["instance_id"] = d["InstanceId"]
    if d.get("AutoScalingGroupName"):
        out["asg"] = d["AutoScalingGroupName"]
    return out


def _events(d: Mapping[str, str]) -> Labels:
    """AWS/Events: a rule, and its bus when it is not the default one (metrics with both EventBusName and RuleName are a
    custom bus's rule - EventBridge user guide, read 2026-10-10)."""
    out = {"eventbridge_rule": d["RuleName"]} if d.get("RuleName") else {}
    if out and d.get("EventBusName") and d["EventBusName"] != "default":
        out["event_bus"] = d["EventBusName"]
    return out


def _usage(d: Mapping[str, str]) -> Labels:
    """AWS/Usage: a service quota's usage (Service, Type, Resource, Class)."""
    if not d.get("Service"):
        return {}
    return {"quota_service": d["Service"], **({"quota_resource": d["Resource"]} if d.get("Resource") else {})}


# Namespace -> labels. Every main AWS service the owner named (2026-10-10) that publishes CloudWatch metrics.
NAMESPACES: dict[str, Callable[[Mapping[str, str]], Labels]] = {
    "AWS/Lambda": _lambda,
    "AWS/Logs": _one("log_group", "LogGroupName"),
    "CloudWatchSynthetics": _one("canary", "CanaryName"),
    "AWS/ECS": _ecs,
    "ECS/ContainerInsights": _ecs,
    "ContainerInsights": _container_insights,
    "AWS/EC2": _ec2,
    "AWS/AutoScaling": _one("asg", "AutoScalingGroupName"),
    "AWS/EBS": _one("ebs_volume", "VolumeId"),
    "AWS/EFS": _one("efs", "FileSystemId"),
    "AWS/FSx": _one("fsx", "FileSystemId"),
    "AWS/RDS": _rds,
    "AWS/DocDB": _docdb,
    "AWS/DynamoDB": _one("dynamodb_table", "TableName"),
    "AWS/ElastiCache": _elasticache,
    "AWS/MemoryDB": _one("memorydb", "ClusterName"),
    "AWS/SQS": _one("sqs", "QueueName"),
    "AWS/SNS": _one("sns_topic", "TopicName"),
    "AWS/AmazonMQ": _one("mq_broker", "Broker", fn=lambda v: re.sub(r"-[12]$", "", v)),  # ActiveMQ: <broker>-1/-2
    "AWS/Events": _events,
    "AWS/Scheduler": _one("schedule_group", "ScheduleGroup"),
    "AWS/States": _one("state_machine", "StateMachineArn", fn=_arn_name),
    "AWS/Kinesis": _one("kinesis_stream", "StreamName"),
    "AWS/Firehose": _one("firehose", "DeliveryStreamName"),
    "AWS/Kafka": _one("msk_cluster", "Cluster Name"),
    "AWS/ApiGateway": _apigw,
    "AWS/AppSync": lambda d: {**_one("appsync", "GraphQLAPIId", "API_Id")(d), **_one("appsync_events", "EventAPIId")(d)},
    "AWS/ApplicationELB": _alb,
    "AWS/NetworkELB": _nlb,
    "AWS/ELB": _one("clb", "LoadBalancerName"),
    "AWS/CloudFront": _one("cloudfront", "DistributionId"),
    "AWS/Route53": _one("route53_health_check", "HealthCheckId"),
    "AWS/S3": _one("s3_bucket", "BucketName"),
    "AWS/NATGateway": _one("nat_gateway", "NatGatewayId"),
    "AWS/TransitGateway": _one("transit_gateway", "TransitGateway"),
    "AWS/ES": _one("opensearch", "DomainName"),
    "AWS/Redshift": _one("redshift", "ClusterIdentifier"),
    "AWS/Cognito": _one("cognito_user_pool", "UserPool", "UserPoolId"),
    "AWS/AppRunner": _one("apprunner", "ServiceName"),
    "Glue": _one("glue_job", "JobName"),  # not AWS/Glue (Glue's own docs, 2026-10-10)
    "AWS/Athena": _one("athena_workgroup", "WorkGroup"),
    "AWS/ElasticMapReduce": _one("emr_cluster", "JobFlowId"),
    "AWS/WAFV2": _one("waf_web_acl", "WebACL", "WebACLArn", fn=_webacl),
    "AWS/KMS": _one("kms_key", "KeyId", "KeyArn", fn=_arn_name),
    "AWS/CertificateManager": _one("acm_certificate", "CertificateArn", fn=_arn_name),
    "AWS/Usage": _usage,
}


def labels_for(metrics: list[tuple[str, Mapping[str, str]]]) -> Labels:
    """The resource labels of an alarm's metrics: (namespace, dimensions) pairs, as the alarm event carries them. A
    metric-math alarm has several; each contributes, the first value for a key wins. Unknown namespaces add nothing."""
    out: Labels = {}
    for namespace, dims in metrics:
        mapper = NAMESPACES.get(namespace)
        if mapper is None:
            continue
        for key, value in mapper({str(k): str(v) for k, v in dims.items()}).items():
            if value:
                out.setdefault(key, value)
    return out


# Every label key this table can produce: the resource labels (models.RESOURCE_LABELS must hold each).
LABEL_KEYS = frozenset({
    "lambda", "lambda_qualifier", "ecs_cluster", "ecs_service", "eks_cluster", "namespace", "deployment",
    "k8s_service", "log_group", "canary", "docdb_cluster", "docdb_instance", "mq_broker", "elasticache_serverless",
    "appsync_events",
    "instance_id", "asg", "ebs_volume", "efs", "fsx", "aurora_cluster", "rds_instance", "dynamodb_table",
    "elasticache_node", "memorydb", "sqs", "sns_topic", "eventbridge_rule", "event_bus", "schedule_group",
    "state_machine", "kinesis_stream", "firehose", "msk_cluster", "apigw_id", "apigw_rest", "apigw_stage", "appsync",
    "alb_target_group", "nlb_target_group", "load_balancer", "clb", "cloudfront", "route53_health_check", "s3_bucket",
    "nat_gateway", "transit_gateway", "opensearch", "redshift", "cognito_user_pool", "apprunner", "glue_job",
    "athena_workgroup", "emr_cluster", "waf_web_acl", "kms_key", "acm_certificate", "quota_service", "quota_resource",
})
