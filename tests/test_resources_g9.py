"""G9-A1 (2026-10-10): an alarm on any main AWS service names its resource. CloudWatch gives only the metric's
namespace and dimensions; resources.py maps them to the evidence backends' resource labels, deterministically, and the
alarm intake applies it. Before this, only an ECS alarm named anything WARDEN could read (audit 2026-10-10)."""

from __future__ import annotations

import pytest

from warden import lambdas, resources
from warden.models import RESOURCE_LABELS

ACCT = "0" * 12  # a placeholder account id, built from parts (no real-looking literal)

# One documented example per namespace: (namespace, dimensions, the labels they must give).
CASES = [
    ("AWS/Lambda", {"FunctionName": "orders", "Resource": "orders:live"}, {"lambda": "orders", "lambda_qualifier": "live"}),
    ("AWS/ECS", {"ClusterName": "c1", "ServiceName": "api"}, {"ecs_cluster": "c1", "ecs_service": "api"}),
    ("ECS/ContainerInsights", {"ClusterName": "c1", "ServiceName": "api"}, {"ecs_cluster": "c1", "ecs_service": "api"}),
    ("ContainerInsights", {"ClusterName": "k1", "Namespace": "shop", "PodName": "cart"},
     {"eks_cluster": "k1", "namespace": "shop", "deployment": "cart"}),
    ("ContainerInsights", {"ClusterName": "k1", "Namespace": "shop", "Service": "cart-svc"},
     {"eks_cluster": "k1", "namespace": "shop", "k8s_service": "cart-svc"}),
    ("AWS/Logs", {"LogGroupName": "/ecs/orders"}, {"log_group": "/ecs/orders"}),
    ("CloudWatchSynthetics", {"CanaryName": "home"}, {"canary": "home"}),
    ("AWS/DocDB", {"DBClusterIdentifier": "docs"}, {"docdb_cluster": "docs"}),
    ("AWS/DocDB", {"DBInstanceIdentifier": "docs-1"}, {"docdb_instance": "docs-1"}),
    ("AWS/AmazonMQ", {"Broker": "mq"}, {"mq_broker": "mq"}),
    ("AWS/EC2", {"InstanceId": "i-0abc"}, {"instance_id": "i-0abc"}),
    ("AWS/EC2", {"AutoScalingGroupName": "web"}, {"asg": "web"}),
    ("AWS/AutoScaling", {"AutoScalingGroupName": "web"}, {"asg": "web"}),
    ("AWS/EBS", {"VolumeId": "vol-1"}, {"ebs_volume": "vol-1"}),
    ("AWS/EFS", {"FileSystemId": "fs-1"}, {"efs": "fs-1"}),
    ("AWS/FSx", {"FileSystemId": "fs-2"}, {"fsx": "fs-2"}),
    ("AWS/RDS", {"DBClusterIdentifier": "orders"}, {"aurora_cluster": "orders"}),
    ("AWS/RDS", {"DBInstanceIdentifier": "db1"}, {"rds_instance": "db1"}),
    ("AWS/RDS", {"DbInstanceIdentifier": "db2", "VolumeName": "v"}, {"rds_instance": "db2"}),
    ("AWS/RDS", {"DbClusterIdentifier": "c2", "EngineName": "aurora-postgresql"}, {"aurora_cluster": "c2"}),
    ("AWS/DynamoDB", {"TableName": "carts"}, {"dynamodb_table": "carts"}),
    ("AWS/ElastiCache", {"CacheClusterId": "rg-0001-001"}, {"elasticache_node": "rg-0001-001"}),
    ("AWS/ElastiCache", {"clusterId": "sl-cache"}, {"elasticache_serverless": "sl-cache"}),
    ("AWS/MemoryDB", {"ClusterName": "mem"}, {"memorydb": "mem"}),
    ("AWS/SQS", {"QueueName": "jobs"}, {"sqs": "jobs"}),
    ("AWS/SNS", {"TopicName": "alerts"}, {"sns_topic": "alerts"}),
    ("AWS/Events", {"RuleName": "nightly"}, {"eventbridge_rule": "nightly"}),
    # A custom bus's rule carries EventBusName too; the default bus names no bus.
    ("AWS/Events", {"EventBusName": "orders-bus", "RuleName": "created"}, {"eventbridge_rule": "created", "event_bus": "orders-bus"}),
    ("AWS/Events", {"EventBusName": "default", "RuleName": "nightly"}, {"eventbridge_rule": "nightly"}),
    ("AWS/Events", {"EventBusName": "orders-bus"}, {}),
    ("AWS/Scheduler", {"ScheduleGroup": "default"}, {"schedule_group": "default"}),
    ("AWS/States", {"StateMachineArn": f"arn:aws:states:r:{ACCT}:stateMachine:checkout"}, {"state_machine": "checkout"}),
    ("AWS/Kinesis", {"StreamName": "clicks"}, {"kinesis_stream": "clicks"}),
    ("AWS/Firehose", {"DeliveryStreamName": "to-s3"}, {"firehose": "to-s3"}),
    ("AWS/Kafka", {"Cluster Name": "events"}, {"msk_cluster": "events"}),
    ("AWS/ApiGateway", {"ApiId": "a1b2c3", "Stage": "prod"}, {"apigw_id": "a1b2c3", "apigw_stage": "prod"}),
    ("AWS/ApiGateway", {"ApiName": "shop"}, {"apigw_rest": "shop"}),
    ("AWS/AppSync", {"GraphQLAPIId": "g1"}, {"appsync": "g1"}),
    ("AWS/AppSync", {"API_Id": "g2"}, {"appsync": "g2"}),
    ("AWS/AppSync", {"EventAPIId": "e1"}, {"appsync_events": "e1"}),
    ("AWS/ApplicationELB", {"TargetGroup": "targetgroup/web-tg/0123", "LoadBalancer": "app/web/0456"},
     {"alb_target_group": "web-tg", "load_balancer": "app/web/0456"}),
    ("AWS/NetworkELB", {"TargetGroup": "targetgroup/tcp-tg/0123"}, {"nlb_target_group": "tcp-tg"}),
    ("AWS/ELB", {"LoadBalancerName": "classic"}, {"clb": "classic"}),
    ("AWS/CloudFront", {"DistributionId": "E123"}, {"cloudfront": "E123"}),
    ("AWS/Route53", {"HealthCheckId": "hc-1"}, {"route53_health_check": "hc-1"}),
    ("AWS/S3", {"BucketName": "assets"}, {"s3_bucket": "assets"}),
    ("AWS/NATGateway", {"NatGatewayId": "nat-1"}, {"nat_gateway": "nat-1"}),
    ("AWS/TransitGateway", {"TransitGateway": "tgw-1"}, {"transit_gateway": "tgw-1"}),
    ("AWS/ES", {"DomainName": "search", "ClientId": ACCT}, {"opensearch": "search"}),
    ("AWS/Redshift", {"ClusterIdentifier": "dw"}, {"redshift": "dw"}),
    ("AWS/Cognito", {"UserPool": "pool"}, {"cognito_user_pool": "pool"}),
    ("AWS/Cognito", {"UserPoolId": "pool2"}, {"cognito_user_pool": "pool2"}),
    ("AWS/AppRunner", {"ServiceName": "web"}, {"apprunner": "web"}),
    ("Glue", {"JobName": "etl"}, {"glue_job": "etl"}),
    ("AWS/Athena", {"WorkGroup": "primary"}, {"athena_workgroup": "primary"}),
    ("AWS/ElasticMapReduce", {"JobFlowId": "j-1"}, {"emr_cluster": "j-1"}),
    ("AWS/WAFV2", {"WebACL": "edge"}, {"waf_web_acl": "edge"}),
    ("AWS/WAFV2", {"WebACLArn": f"arn:aws:wafv2:r:{ACCT}:regional/webacl/edge2/abc"}, {"waf_web_acl": "edge2"}),
    ("AWS/KMS", {"KeyId": "k-1"}, {"kms_key": "k-1"}),
    ("AWS/KMS", {"KeyArn": f"arn:aws:kms:r:{ACCT}:key/k-2"}, {"kms_key": "k-2"}),
    ("AWS/CertificateManager", {"CertificateArn": f"arn:aws:acm:r:{ACCT}:certificate/c-1"},
     {"acm_certificate": "c-1"}),
    ("AWS/Usage", {"Service": "Lambda", "Type": "Resource", "Resource": "ConcurrentExecutions", "Class": "None"},
     {"quota_service": "Lambda", "quota_resource": "ConcurrentExecutions"}),
]


@pytest.mark.parametrize(("namespace", "dims", "want"), CASES, ids=[f"{c[0]}:{min(c[1])}" for c in CASES])
def test_each_namespace_names_its_resource(namespace, dims, want):
    assert resources.labels_for([(namespace, dims)]) == want


def test_every_namespace_in_the_table_is_exercised():
    assert {c[0] for c in CASES} == set(resources.NAMESPACES)


def test_every_label_the_table_can_give_is_a_resource_label():
    produced = {k for ns, dims, _ in CASES for k in resources.labels_for([(ns, dims)])}
    assert produced == resources.LABEL_KEYS
    assert resources.LABEL_KEYS <= RESOURCE_LABELS  # never redacted as credentials (models.py)


def test_unknown_namespaces_and_empty_values_name_nothing():
    assert resources.labels_for([("Custom/App", {"Service": "x"}), ("AWS/Lambda", {"FunctionName": ""})]) == {}


def test_a_metric_math_alarm_names_each_resource_and_the_first_value_wins():
    got = resources.labels_for([("AWS/SQS", {"QueueName": "jobs"}), ("AWS/Lambda", {"FunctionName": "worker"}),
                                ("AWS/SQS", {"QueueName": "other"})])
    assert got == {"sqs": "jobs", "lambda": "worker"}


def _event(metrics):
    return {"source": "aws.cloudwatch", "detail-type": "CloudWatch Alarm State Change", "time": "2026-10-10T00:00:00Z",
            "detail": {"alarmName": "warden-dev-orders-errors",
                       "state": {"value": "ALARM", "timestamp": "2026-10-10T00:00:00+00:00"},
                       "configuration": {"description": "d", "metrics": [
                           {"metricStat": {"metric": {"namespace": ns, "name": "Errors", "dimensions": dims}}}
                           for ns, dims in metrics]}}}


def test_the_alarm_intake_labels_the_resource_from_the_metric():
    ev = lambdas.alarm_event(_event([("AWS/Lambda", {"FunctionName": "warden-dev-orders"})]), "dev")
    assert ev.alert.labels["lambda"] == "warden-dev-orders" and ev.alert.service == "warden-dev-orders"
    ev = lambdas.alarm_event(_event([("AWS/RDS", {"DBInstanceIdentifier": "warden-dev-db"})]), "dev")
    assert ev.alert.labels["rds_instance"] == "warden-dev-db"


def test_a_hostile_dimension_value_is_dropped_and_reported_not_read():
    ev = lambdas.alarm_event(_event([("AWS/Lambda", {"FunctionName": "--profile=admin"})]), "dev")
    assert "lambda" not in ev.alert.labels and "lambda" in ev.alert.rejected_labels
