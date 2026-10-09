"""The state of every main AWS service's resource, read one way (G9-A2c, 2026-10-10).

The universal alarm reader (aws_stack._read_alarm) gives an alarm's metric, the resource's other metrics and its
changes; this table adds what metrics do not show - a database's status and class, a stream's open shards, a NAT
gateway's failure code, a certificate's expiry. One closed table instead of thirty hand-written readers:

- each entry is ONE read-only call (a test holds every method to Describe/Get/List and the reader role to granting
  each action) addressed by the resource label resources.py gave the alarm;
- only an allowlist of AWS's own structured fields is copied - states, sizes, versions, counts, booleans, dates -
  never a description, a tag, an error message or anything else a person or an application wrote;
- every value is one token (aws_stack._safe), and the line is `STATE <label> <name> field=value ...`, a structured read
  (evidence kind C).

Services without a describe that adds to the metrics stay metric-only (WAF, KMS key use), and a resource the call
cannot find is a TOOL-PARTIAL, never silence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .aws_stack import _safe, _z


@dataclass(frozen=True)
class Describe:
    service: str                      # the boto3 client
    method: str                       # its read method
    action: str                       # the IAM action that authorises it
    params: Callable[[str, Callable[[], str], str], dict]  # (label value, account(), region) -> call arguments
    path: str                         # where the resource sits in the response (a dict, or a list to pick from)
    fields: tuple[str, ...]           # AWS's structured fields only, dotted
    match: str = ""                   # in a list: the field that must equal the label value (else the first item)


def _arg(name: str) -> Callable[[str, Callable[[], str], str], dict]:
    return lambda v, account, region: {name: v}


def _list_arg(name: str) -> Callable[[str, Callable[[], str], str], dict]:
    return lambda v, account, region: {name: [v]}


def _none(v: str, account: Callable[[], str], region: str) -> dict:
    return {}


# label -> how to read the state of the resource it names. Keys are resources.LABEL_KEYS entries.
TABLE: dict[str, Describe] = {
    "rds_instance": Describe("rds", "describe_db_instances", "rds:DescribeDBInstances", _arg("DBInstanceIdentifier"),
                             "DBInstances", ("DBInstanceStatus", "DBInstanceClass", "Engine", "EngineVersion", "MultiAZ",
                                             "AllocatedStorage", "MaxAllocatedStorage", "StorageType", "Iops",
                                             "BackupRetentionPeriod", "ReadReplicaSourceDBInstanceIdentifier",
                                             "PendingModifiedValues", "CACertificateIdentifier")),
    "docdb_cluster": Describe("docdb", "describe_db_clusters", "rds:DescribeDBClusters", _arg("DBClusterIdentifier"),
                              "DBClusters", ("Status", "Engine", "EngineVersion", "MultiAZ", "DBClusterMembers")),
    "docdb_instance": Describe("docdb", "describe_db_instances", "rds:DescribeDBInstances",
                               _arg("DBInstanceIdentifier"), "DBInstances",
                               ("DBInstanceStatus", "DBInstanceClass", "EngineVersion", "PendingModifiedValues")),
    "memorydb": Describe("memorydb", "describe_clusters", "memorydb:DescribeClusters", _arg("ClusterName"),
                         "Clusters", ("Status", "NodeType", "NumberOfShards", "EngineVersion", "AvailabilityMode")),
    "elasticache_node": Describe("elasticache", "describe_cache_clusters", "elasticache:DescribeCacheClusters",
                                 _arg("CacheClusterId"), "CacheClusters",
                                 ("CacheClusterStatus", "CacheNodeType", "Engine", "EngineVersion",
                                  "ReplicationGroupId", "NumCacheNodes")),
    "elasticache_serverless": Describe("elasticache", "describe_serverless_caches",
                                       "elasticache:DescribeServerlessCaches", _arg("ServerlessCacheName"),
                                       "ServerlessCaches", ("Status", "Engine", "MajorEngineVersion",
                                                            "CacheUsageLimits.DataStorage.Maximum",
                                                            "CacheUsageLimits.ECPUPerSecond.Maximum")),
    "kinesis_stream": Describe("kinesis", "describe_stream_summary", "kinesis:DescribeStreamSummary",
                               _arg("StreamName"), "StreamDescriptionSummary",
                               ("StreamStatus", "StreamModeDetails.StreamMode", "OpenShardCount",
                                "RetentionPeriodHours", "ConsumerCount", "EncryptionType")),
    "firehose": Describe("firehose", "describe_delivery_stream", "firehose:DescribeDeliveryStream",
                         _arg("DeliveryStreamName"), "DeliveryStreamDescription",
                         ("DeliveryStreamStatus", "DeliveryStreamType", "FailureDescription.Type")),
    "msk_cluster": Describe("kafka", "list_clusters_v2", "kafka:ListClustersV2", _arg("ClusterNameFilter"),
                            "ClusterInfoList", ("State", "ClusterType", "CurrentVersion",
                                                "Provisioned.NumberOfBrokerNodes",
                                                "Provisioned.BrokerNodeGroupInfo.InstanceType"),
                            match="ClusterName"),
    "state_machine": Describe("stepfunctions", "describe_state_machine", "states:DescribeStateMachine",
                              lambda v, account, region: {
                                  "stateMachineArn": f"arn:aws:states:{region}:{account()}:stateMachine:{v}"},
                              "", ("status", "type", "revisionId")),
    "schedule_group": Describe("scheduler", "get_schedule_group", "scheduler:GetScheduleGroup", _arg("Name"), "",
                               ("State",)),
    "mq_broker": Describe("mq", "list_brokers", "mq:ListBrokers", _none, "BrokerSummaries",
                          ("BrokerState", "DeploymentMode", "EngineType", "HostInstanceType"), match="BrokerName"),
    "apigw_id": Describe("apigatewayv2", "get_api", "apigateway:GET", _arg("ApiId"), "",
                         ("ProtocolType", "DisableExecuteApiEndpoint", "ApiGatewayManaged")),
    "apigw_rest": Describe("apigateway", "get_rest_apis", "apigateway:GET", _none, "items",
                           ("endpointConfiguration.types", "apiKeySource", "disableExecuteApiEndpoint"),
                           match="name"),
    "appsync": Describe("appsync", "get_graphql_api", "appsync:GetGraphqlApi", _arg("apiId"), "graphqlApi",
                        ("authenticationType", "xrayEnabled", "logConfig.fieldLogLevel", "apiType")),
    "load_balancer": Describe("elbv2", "describe_load_balancers", "elasticloadbalancing:DescribeLoadBalancers",
                              lambda v, account, region: {"Names": [v.split("/")[1] if v.count("/") >= 2 else v]},
                              "LoadBalancers", ("State.Code", "Type", "Scheme", "IpAddressType", "AvailabilityZones")),
    "nlb_target_group": Describe("elbv2", "describe_target_groups", "elasticloadbalancing:DescribeTargetGroups",
                                 _list_arg("Names"), "TargetGroups",
                                 ("Protocol", "Port", "TargetType", "HealthCheckProtocol", "HealthCheckPort",
                                  "HealthyThresholdCount", "UnhealthyThresholdCount", "LoadBalancerArns")),
    "clb": Describe("elb", "describe_instance_health", "elasticloadbalancing:DescribeInstanceHealth",
                    _arg("LoadBalancerName"), "", ("InstanceStates",)),
    "cloudfront": Describe("cloudfront", "get_distribution", "cloudfront:GetDistribution", _arg("Id"), "Distribution",
                           ("Status", "DistributionConfig.Enabled", "DistributionConfig.Origins.Quantity",
                            "DistributionConfig.HttpVersion", "DistributionConfig.PriceClass", "LastModifiedTime")),
    "route53_health_check": Describe("route53", "get_health_check_status", "route53:GetHealthCheckStatus",
                                     _arg("HealthCheckId"), "", ("HealthCheckObservations",)),
    "s3_bucket": Describe("s3", "get_bucket_versioning", "s3:GetBucketVersioning", _arg("Bucket"), "",
                          ("Status", "MFADelete")),
    "nat_gateway": Describe("ec2", "describe_nat_gateways", "ec2:DescribeNatGateways", _list_arg("NatGatewayIds"),
                            "NatGateways", ("State", "FailureCode", "ConnectivityType")),
    "transit_gateway": Describe("ec2", "describe_transit_gateways", "ec2:DescribeTransitGateways",
                                _list_arg("TransitGatewayIds"), "TransitGateways", ("State",)),
    "instance_id": Describe("ec2", "describe_instance_status", "ec2:DescribeInstanceStatus",
                            lambda v, account, region: {"InstanceIds": [v], "IncludeAllInstances": True},
                            "InstanceStatuses", ("InstanceState.Name", "SystemStatus.Status", "InstanceStatus.Status",
                                                 "Events")),
    "asg": Describe("autoscaling", "describe_auto_scaling_groups", "autoscaling:DescribeAutoScalingGroups",
                    _list_arg("AutoScalingGroupNames"), "AutoScalingGroups",
                    ("MinSize", "MaxSize", "DesiredCapacity", "Instances", "Status", "SuspendedProcesses")),
    "ebs_volume": Describe("ec2", "describe_volumes", "ec2:DescribeVolumes", _list_arg("VolumeIds"), "Volumes",
                           ("State", "VolumeType", "Size", "Iops", "Throughput", "Attachments")),
    "efs": Describe("efs", "describe_file_systems", "elasticfilesystem:DescribeFileSystems", _arg("FileSystemId"),
                    "FileSystems", ("LifeCycleState", "ThroughputMode", "PerformanceMode", "SizeInBytes.Value",
                                    "NumberOfMountTargets")),
    "fsx": Describe("fsx", "describe_file_systems", "fsx:DescribeFileSystems", _list_arg("FileSystemIds"),
                    "FileSystems", ("Lifecycle", "FileSystemType", "StorageCapacity", "StorageType")),
    "opensearch": Describe("opensearch", "describe_domain", "es:DescribeDomain", _arg("DomainName"), "DomainStatus",
                           ("Processing", "UpgradeProcessing", "EngineVersion", "ClusterConfig.InstanceType",
                            "ClusterConfig.InstanceCount", "ClusterConfig.DedicatedMasterEnabled",
                            "EBSOptions.VolumeSize")),
    "redshift": Describe("redshift", "describe_clusters", "redshift:DescribeClusters", _arg("ClusterIdentifier"),
                         "Clusters", ("ClusterStatus", "ClusterAvailabilityStatus", "NodeType", "NumberOfNodes",
                                      "PendingModifiedValues")),
    "cognito_user_pool": Describe("cognito-idp", "describe_user_pool", "cognito-idp:DescribeUserPool",
                                  _arg("UserPoolId"), "UserPool",
                                  ("Status", "EstimatedNumberOfUsers", "MfaConfiguration", "UserPoolTier")),
    "apprunner": Describe("apprunner", "list_services", "apprunner:ListServices", _none, "ServiceSummaryList",
                          ("Status", "UpdatedAt"), match="ServiceName"),
    "glue_job": Describe("glue", "get_job_runs", "glue:GetJobRuns", lambda v, account, region: {"JobName": v,
                                                                                             "MaxResults": 10},
                         "", ("JobRuns",)),
    "athena_workgroup": Describe("athena", "get_work_group", "athena:GetWorkGroup", _arg("WorkGroup"), "WorkGroup",
                                 ("State", "Configuration.EngineVersion.EffectiveEngineVersion",
                                  "Configuration.EnforceWorkGroupConfiguration")),
    "emr_cluster": Describe("emr", "describe_cluster", "elasticmapreduce:DescribeCluster", _arg("ClusterId"),
                            "Cluster", ("Status.State", "Status.StateChangeReason.Code", "ReleaseLabel",
                                        "InstanceCollectionType")),
    "kms_key": Describe("kms", "describe_key", "kms:DescribeKey", _arg("KeyId"), "KeyMetadata",
                        ("KeyState", "Enabled", "KeyManager", "KeySpec", "DeletionDate", "ValidTo")),
    "acm_certificate": Describe("acm", "describe_certificate", "acm:DescribeCertificate",
                                lambda v, account, region: {
                                    "CertificateArn": f"arn:aws:acm:{region}:{account()}:certificate/{v}"},
                                "Certificate", ("Status", "Type", "NotAfter", "RenewalEligibility",
                                                "RenewalSummary.RenewalStatus", "InUseBy")),
    "canary": Describe("synthetics", "get_canary", "synthetics:GetCanary", _arg("Name"), "Canary",
                       ("Status.State", "Status.StateReasonCode", "RuntimeVersion")),
}


def _get(item: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(item, Mapping):
            return None
        item = item.get(part)
    return item


def _value(v: Any) -> str:
    """One token: a list is its count (and, for a list of states, the count of each), a dict its keys, a date UTC."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, datetime):
        return _z(v)
    if isinstance(v, (list, tuple)):
        # A list of resources is its count and how many are in each state; a Route 53 checker's report counts by
        # its first word (Success / Failure), never its text.
        states = [str(_get(x, "State") or _get(x, "Status") or _get(x, "JobRunState") or _get(x, "HealthStatus")
                      or str(_get(x, "StatusReport.Status") or "").split(":")[0] or "")
                  for x in v if isinstance(x, Mapping)]
        states = [_safe(s) for s in states if s]
        if states:
            return f"{len(v)}(" + ",".join(f"{s}:{states.count(s)}" for s in sorted(set(states))) + ")"
        if v and all(isinstance(x, str) and len(x) <= 24 for x in v):  # enum values (REGIONAL, EDGE)
            return "+".join(_safe(x) for x in v)
        return str(len(v))
    if isinstance(v, Mapping):
        return "+".join(sorted(str(k) for k in v)) or "none"
    return _safe(v)


def state_line(key: str, name: str, response: Mapping[str, Any]) -> str:
    """`STATE <label> <name> field=value ...` from one describe response, the allowlisted fields only."""
    d = TABLE[key]
    item: Any = _get(response, d.path) if d.path else response
    if isinstance(item, list):
        found = [x for x in item if not d.match or _get(x, d.match) == name]
        if not found:
            raise LookupError(f"no {key} named in the response")
        item = found[0]
    if not isinstance(item, Mapping):
        raise TypeError(f"no {key} in the response")
    fields = " ".join(f"{f.split('.')[-1] if f.count('.') < 2 else f.replace('.', '_')}={_value(_get(item, f))}"
                      for f in d.fields if _get(item, f) is not None)
    return f"STATE {key} {_safe(name)} {fields}".rstrip()


def read(key: str, name: str, client: Any, account: Callable[[], str], region: str) -> str:
    """One resource's state line: the table's one read call, its allowlisted fields."""
    d = TABLE[key]
    return state_line(key, name, getattr(client, d.method)(**d.params(name, account, region)))
