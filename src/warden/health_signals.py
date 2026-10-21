"""Each main AWS service's key health signals, read as evidence whenever an alarm names the resource (U3-3).

The universal alarm reader (aws_stack._read_alarm) reads the alarm's own metric and up to a dozen of the resource's
recently active others, in whatever order CloudWatch lists them and always as their Maximum. A NAT gateway's alarm on
its traffic could therefore miss ErrorPortAllocation (the gateway ran out of source ports), and an EFS alarm on
throughput read BurstCreditBalance as the HIGHEST balance of the window - the opposite of what tells that the credits
ran out. This table names, per service, the one or two signals that say the resource itself is unhealthy, each with
the statistic AWS documents for it:

- `Sum`          a count over the window (port allocation errors, dropped packets, throttled records);
- `Maximum`      the worst value of the window for a figure where higher is worse (a 0/1 failed check, a percent);
- `Average`      the worst per-period average, for a rate AWS publishes as Average only (CloudFront's 5xx rate);
- `Minimum/min`  the LOWEST value of the window, for a balance where lower is worse (credits, free storage);
- `Average/min`  the lowest per-period average (a canary's success percent, which AWS publishes as Average only).

Read-only and through the reader role: every read is one CloudWatch GetMetricData call, which the reader policies
already grant (cloudwatch:GetMetricData); OpenSearch's ClientId dimension is the account, read with
sts:GetCallerIdentity like every other account lookup. A signal with no datapoint is absent, never zero - an
attached-only metric (EBS BurstBalance), a General Purpose-only one (EFS PercentIOLimit) or an opt-in one (Auto Scaling
group metrics) is simply not there when it does not apply.

Metric names, dimensions, units and statistics: AWS's own documentation sources for each service (researched
2026-10-21; see the PR). Services whose dedicated reader already reads their key signals (Lambda, SQS, DynamoDB,
ElastiCache, Aurora, ALB target groups, API Gateway, SNS, EventBridge, ECS) are not repeated here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

# Stats this table may use, and how aws_stack._cw_read folds a window of periods into one value.
STATS = frozenset({"Sum", "Maximum", "Average", "Minimum/min", "Average/min"})


@dataclass(frozen=True)
class Signal:
    key: str        # the evidence metric key (a trusted name: fixed here, never taken from CloudWatch)
    metric: str     # AWS's metric name
    stat: str       # one of STATS
    unit: str       # the unit AWS documents, so the key's meaning is plain to a reader of the evidence


@dataclass(frozen=True)
class Service:
    namespace: str
    dims: Callable[[str, Callable[[], str]], dict[str, str]]  # (label value, account()) -> dimensions
    signals: tuple[Signal, ...]


def _dim(name: str) -> Callable[[str, Callable[[], str]], dict[str, str]]:
    return lambda value, account: {name: value}


def _opensearch(value: str, account: Callable[[], str]) -> dict[str, str]:
    # Domain-level OpenSearch metrics carry the account as ClientId beside DomainName.
    return {"DomainName": value, "ClientId": account()}


def _cloudfront(value: str, account: Callable[[], str]) -> dict[str, str]:
    # "Global" is CloudFront's Region dimension value, always (CloudFront is a global service) - not an AWS Region.
    return {"DistributionId": value, "Region": "Global"}


# label (resources.LABEL_KEYS) -> the service's key health signals.
TABLE: dict[str, Service] = {
    "nat_gateway": Service("AWS/NATGateway", _dim("NatGatewayId"), (
        # > 0: the gateway could not allocate a source port - too many concurrent connections through it.
        Signal("nat_error_port_allocation", "ErrorPortAllocation", "Sum", "Count"),
        Signal("nat_packets_drop_count", "PacketsDropCount", "Sum", "Count"),
    )),
    "efs": Service("AWS/EFS", _dim("FileSystemId"), (
        # Bursting throughput: at zero credits the file system is held to its baseline throughput.
        Signal("efs_burst_credit_balance_bytes", "BurstCreditBalance", "Minimum/min", "Bytes"),
        # General Purpose performance mode only: how close the file system is to its I/O limit.
        Signal("efs_percent_io_limit", "PercentIOLimit", "Maximum", "Percent"),
    )),
    "ebs_volume": Service("AWS/EBS", _dim("VolumeId"), (
        # gp2/st1/sc1 only, and only while attached: the percent of burst credits left.
        Signal("ebs_burst_balance_pct", "BurstBalance", "Minimum/min", "Percent"),
    )),
    "instance_id": Service("AWS/EC2", _dim("InstanceId"), (
        Signal("ec2_status_check_failed_instance", "StatusCheckFailed_Instance", "Maximum", "Count (0 or 1)"),
        Signal("ec2_status_check_failed_system", "StatusCheckFailed_System", "Maximum", "Count (0 or 1)"),
    )),
    "rds_instance": Service("AWS/RDS", _dim("DBInstanceIdentifier"), (
        Signal("rds_free_storage_bytes", "FreeStorageSpace", "Minimum/min", "Bytes"),
        Signal("rds_freeable_memory_bytes", "FreeableMemory", "Minimum/min", "Bytes"),
    )),
    "kinesis_stream": Service("AWS/Kinesis", _dim("StreamName"), (
        Signal("kinesis_iterator_age_ms", "GetRecords.IteratorAgeMilliseconds", "Maximum", "Milliseconds"),
        Signal("kinesis_write_throttled_records", "WriteProvisionedThroughputExceeded", "Sum", "Count"),
    )),
    "opensearch": Service("AWS/ES", _opensearch, (
        Signal("opensearch_cluster_red", "ClusterStatus.red", "Maximum", "0 or 1"),
        Signal("opensearch_index_writes_blocked", "ClusterIndexWritesBlocked", "Maximum", "0 or 1"),
    )),
    "redshift": Service("AWS/Redshift", _dim("ClusterIdentifier"), (
        # 1 healthy, 0 unhealthy: the lowest of the window says whether it was ever unhealthy.
        Signal("redshift_health_status", "HealthStatus", "Minimum/min", "1 healthy, 0 unhealthy"),
        Signal("redshift_disk_used_pct", "PercentageDiskSpaceUsed", "Maximum", "Percent"),
    )),
    "msk_cluster": Service("AWS/Kafka", _dim("Cluster Name"), (
        # ActiveControllerCount is left out: per broker it is 1 on the controller and 0 on the others, so a fold over
        # the cluster's datapoints cannot say "no controller" without counting brokers.
        Signal("msk_offline_partitions", "OfflinePartitionsCount", "Maximum", "Count"),
    )),
    "canary": Service("CloudWatchSynthetics", _dim("CanaryName"), (
        Signal("canary_success_pct", "SuccessPercent", "Average/min", "Percent"),
    )),
    "asg": Service("AWS/AutoScaling", _dim("AutoScalingGroupName"), (
        # Published only when the group's metrics collection is enabled.
        Signal("asg_in_service_instances", "GroupInServiceInstances", "Minimum/min", "Count"),
        Signal("asg_desired_capacity", "GroupDesiredCapacity", "Maximum", "Count"),
    )),
    "cloudfront": Service("AWS/CloudFront", _cloudfront, (
        Signal("cloudfront_5xx_error_rate_pct", "5xxErrorRate", "Average", "Percent"),
    )),
}


def queries(label: str, value: str, account: Callable[[], str]) -> dict[str, tuple[str, str, dict[str, str], str]]:
    """`{key: (namespace, metric, dimensions, stat)}` for aws_stack._cw_read: the label's signals on one resource."""
    service = TABLE[label]
    dims = service.dims(value, account)
    return {s.key: (service.namespace, s.metric, dims, s.stat) for s in service.signals}
