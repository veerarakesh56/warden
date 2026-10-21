"""B40: every AWS call `terraform destroy` makes for the stacks the deploy role runs is allowed - conditions included.

A dev full-stack destroy once failed. The deploy role was refused lambda:GetEventSourceMapping,
ec2:DeleteTags and ec2:DisassociateAddress. All three actions were already in the policy. Their conditions were the
problem, and the older check (tests/test_env_iam.py) compared action and resource names only:
- lambda:GetEventSourceMapping was granted only with `lambda:FunctionArn` = one of this environment's functions. The
  provider's delete waiter polls the mapping until it is gone. A mapping that no longer exists has no function to
  check the condition against, so the last poll is refused instead of answered "not found".
- ec2:DisassociateAddress was granted only on resources tagged Environment=<env>. The call is authorised on the
  address AND on the network interface it is attached to (AWS Service Reference: resource types elastic-ip and
  network-interface). A NAT gateway's interface is created by AWS and carries no tag. The runtime stack hit the
  same refusal (tests/test_runtime_iam_g6.py).
- ec2:DeleteTags: `aws_ec2_tag` puts the stack's tags, one resource per key, on the security group EKS creates for
  the cluster. Destroy removes the keys in parallel. Once `Environment` is gone the group no longer matches the
  Environment-tag grant, so the remaining keys are refused.

This file evaluates each call the way IAM does for an identity policy plus a permissions boundary. The call must be
allowed by the deploy role's policies (deploy + deploy-ec2) AND by the boundary on every resource it names, and no
Deny may match (deploy-guard, boundary). Condition keys come from a request context written for that call.

The calls come from the AWS provider's source (hashicorp/terraform-provider-aws v6.66.0, the version in the stacks'
.terraform.lock.hcl, read 2026-10-17). They cover each resource's Read function, because destroy refreshes state
first, and its Delete function with the waiters and finders it calls, plus the data sources and the S3 backend. A
call that is only reached for a setting these stacks do not use is listed in NOT_REACHED with the reason. Actions and
their resource types and condition keys come from the AWS Service Reference (servicereference.us-east-1.amazonaws.com,
read 2026-10-17). A new resource type in a stack fails test_every_resource_type_in_the_stacks_has_its_calls_listed
until its calls are listed here.

Not modelled: service control policies and session policies (none are used), and multi-valued condition keys (no
policy here uses one).
"""

from __future__ import annotations

import ast
import fnmatch
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import render_env_iam as r  # after the sys.path line above

ENVS = r.environments()
STACKS = ("fullstack", "undo-lab")  # the stacks _infra-deploy.yml runs (its `case "$STACK"` line)
ACCOUNT = "1111" + "22223333"  # AWS's documentation example account, built from parts

# --- the evaluator --------------------------------------------------------------------------------------------------


def _list(x):
    return [x] if isinstance(x, str) else list(x or [])


def _load(env, kind):
    return json.loads((ROOT / "iam" / env / f"{kind}.json").read_text(encoding="utf-8"))


def _any_like(value, patterns):
    return any(fnmatch.fnmatchcase(value, p) for p in _list(patterns))


def _condition_holds(op, key, want, ctx):
    """One condition key under one operator, as IAM's condition evaluation documents it: a positive operator is
    false when the key is absent; a negated one (Not...) is true when the key is absent; Null tests absence."""
    have = ctx.get(key)
    if op.startswith(("ForAllValues:", "ForAnyValue:")):
        # A multi-valued key (aws:TagKeys): ForAllValues is true when every value matches - and when the key is
        # absent, which is why the policies pair it with Null; ForAnyValue when at least one does.
        qualifier, base = op.split(":", 1)
        if have is None:
            return qualifier == "ForAllValues"
        hits = [_condition_holds(base, key, want, {key: v}) for v in _list(have)]
        return all(hits) if qualifier == "ForAllValues" else any(hits)
    if op.endswith("IfExists"):
        # IfExists: true when the key is absent, else the operator without the suffix.
        return have is None or _condition_holds(op.removesuffix("IfExists"), key, want, ctx)
    if op == "Null":
        return (have is None) == (str(want).lower() == "true")
    if op in ("StringEquals", "ArnEquals"):
        # ArnEquals and ArnLike behave the same: both match `*` and `?` in each ARN segment.
        return have is not None and (have in _list(want) if op == "StringEquals" else _any_like(have, want))
    if op in ("StringLike", "ArnLike"):
        return have is not None and _any_like(have, want)
    if op == "StringNotEquals":
        return have is None or have not in _list(want)
    if op in ("StringNotLike", "ArnNotLike"):
        return have is None or not _any_like(have, want)
    raise AssertionError(f"condition operator {op} is not modelled here - add it before relying on this test")


def _statement_matches(st, action, resource, ctx):
    if "Action" in st and not any(fnmatch.fnmatchcase(action.lower(), a.lower()) for a in _list(st["Action"])):
        return False
    if "NotAction" in st and any(fnmatch.fnmatchcase(action.lower(), a.lower()) for a in _list(st["NotAction"])):
        return False
    if "Resource" in st and not _any_like(resource, st["Resource"]):
        return False
    if "NotResource" in st and _any_like(resource, st["NotResource"]):
        return False
    return all(_condition_holds(op, key, want, ctx)
               for op, keys in st.get("Condition", {}).items() for key, want in keys.items())


def refusal(env, action, resources, ctx):
    """None when IAM allows the call, else why not. Every resource the call names is authorised on its own, each
    with its own request context: `ctx` is one dict for all of them, or a list with one dict per resource."""
    identity = [st for kind in ("deploy", "deploy-ec2") for st in _load(env, kind)["Statement"]]
    boundary = _load(env, "boundary")["Statement"]
    denies = [st for st in [*identity, *_load(env, "deploy-guard")["Statement"], *boundary] if st["Effect"] == "Deny"]
    ctxs = ctx if isinstance(ctx, list) else [ctx] * len(resources)
    for resource, one in zip(resources, ctxs, strict=True):
        for name, stmts in (("deploy policies", identity), ("boundary", boundary)):
            if not any(st["Effect"] == "Allow" and _statement_matches(st, action, resource, one) for st in stmts):
                return f"{action} on {resource}: no Allow in the {name}"
        hit = next((st for st in denies if _statement_matches(st, action, resource, one)), None)
        if hit:
            return f"{action} on {resource}: denied by {hit.get('Sid')}"
    return None


# --- the calls ------------------------------------------------------------------------------------------------------

# How a resource is named: (template, extra request-context keys). `{p}` is warden-<env>, `{r}` the region,
# `{a}` the account. "TAGGED" = carries the stack's default_tags (Environment=<env>).
TAGGED = "tagged"
ARNS = {
    "api": "arn:aws:apigateway:{r}::/apis/a1b2c3",
    "api-int": "arn:aws:apigateway:{r}::/apis/a1b2c3/integrations/i1",
    "api-route": "arn:aws:apigateway:{r}::/apis/a1b2c3/routes/r1",
    "api-stage": "arn:aws:apigateway:{r}::/apis/a1b2c3/stages/$default",
    "api-tags": "arn:aws:apigateway:{r}::/tags/arn%3Aaws%3Aapigateway%3A{r}%3A%3A%2Fapis%2Fa1b2c3",
    "budget": "arn:aws:budgets::{a}:budget/{p}-monthly",
    "rule": "arn:aws:events:{r}:{a}:rule/{p}-reconcile",
    "lg-lambda": "arn:aws:logs:{r}:{a}:log-group:/aws/lambda/{p}-orders",
    "lg-ecs": "arn:aws:logs:{r}:{a}:log-group:/ecs/{p}-orders-api",
    "lg-ci": "arn:aws:logs:{r}:{a}:log-group:/aws/containerinsights/{p}-eks/performance",
    "lg-vended": "arn:aws:logs:{r}:{a}:log-group:/aws/vendedlogs/{p}-api-access",
    "alarm": "arn:aws:cloudwatch:{r}:{a}:alarm:{p}-errors",
    "table": "arn:aws:dynamodb:{r}:{a}:table/{p}-orders",
    "repo": "arn:aws:ecr:{r}:{a}:repository/{p}-shop",
    "ecs-cluster": "arn:aws:ecs:{r}:{a}:cluster/{p}-apps",
    "ecs-service": "arn:aws:ecs:{r}:{a}:service/{p}-apps/{p}-orders-api",
    "taskdef": "arn:aws:ecs:{r}:{a}:task-definition/{p}-orders-api:3",
    "eks-cluster": "arn:aws:eks:{r}:{a}:cluster/{p}-eks",
    "eks-nodegroup": "arn:aws:eks:{r}:{a}:nodegroup/{p}-eks/{p}-nodes/uuid",
    "eks-addon": "arn:aws:eks:{r}:{a}:addon/{p}-eks/coredns/uuid",
    "eks-access": "arn:aws:eks:{r}:{a}:access-entry/{p}-eks/role/{a}/{p}-catalog-pod/uuid",
    "eks-podid": "arn:aws:eks:{r}:{a}:podidentityassociation/{p}-eks/a-0123456789",
    "cache-rg": "arn:aws:elasticache:{r}:{a}:replicationgroup:{p}-cache",
    "cache-cluster": "arn:aws:elasticache:{r}:{a}:cluster:{p}-cache-001",
    "cache-subnets": "arn:aws:elasticache:{r}:{a}:subnetgroup:{p}-cache",
    "role": "arn:aws:iam::{a}:role/{p}-orders-fn",
    "function": "arn:aws:lambda:{r}:{a}:function:{p}-orders",
    "alias": "arn:aws:lambda:{r}:{a}:function:{p}-orders:live",
    "esm": "arn:aws:lambda:{r}:{a}:event-source-mapping:0a1b2c3d-aaaa-bbbb-cccc-ddddeeeeffff",
    "lb": "arn:aws:elasticloadbalancing:{r}:{a}:loadbalancer/app/{p}-alb/50dc6c495c0c9188",
    "listener": "arn:aws:elasticloadbalancing:{r}:{a}:listener/app/{p}-alb/50dc6c495c0c9188/f2f7dc8efc522ab2",
    "tg": "arn:aws:elasticloadbalancing:{r}:{a}:targetgroup/{p}-orders/73e2d6bc24d8a067",
    "secret": "arn:aws:secretsmanager:{r}:{a}:secret:{p}-db-AbCdEf",
    "topic": "arn:aws:sns:{r}:{a}:{p}-alerts",
    "queue": "arn:aws:sqs:{r}:{a}:{p}-orders",
    "vpc": "arn:aws:ec2:{r}:{a}:vpc/vpc-0a1b2c3d",
    "subnet": "arn:aws:ec2:{r}:{a}:subnet/subnet-0a1b2c3d",
    "igw": "arn:aws:ec2:{r}:{a}:internet-gateway/igw-0a1b2c3d",
    "rtb": "arn:aws:ec2:{r}:{a}:route-table/rtb-0a1b2c3d",
    "eip": "arn:aws:ec2:{r}:{a}:elastic-ip/eipalloc-0a1b2c3d",
    "nat": "arn:aws:ec2:{r}:{a}:natgateway/nat-0a1b2c3d",
    "sg": "arn:aws:ec2:{r}:{a}:security-group/sg-0a1b2c3d",
    "vpce": "arn:aws:ec2:{r}:{a}:vpc-endpoint/vpce-0a1b2c3d",
    "lt": "arn:aws:ec2:{r}:{a}:launch-template/lt-0a1b2c3d",
    "param": "arn:aws:ssm:{r}:{a}:parameter/warden/{env}/tf/my_ip_cidr",
    # The ALB's imported certificate and its access-log bucket (Sonar S5332 / S6258).
    "cert": "arn:aws:acm:{r}:{a}:certificate/0a1b2c3d-aaaa-bbbb-cccc-ddddeeeeffff",
    "alb-logs": "arn:aws:s3:::{p}-alb-logs-20261021000000000000000001",
    "alb-logs-obj": "arn:aws:s3:::{p}-alb-logs-20261021000000000000000001/AWSLogs/{a}/elasticloadbalancing/x.log.gz",
    # The S3 backend keeps a workspace's state at env:/<workspace>/<key>; _infra-deploy.yml sets key=<stack>/... and
    # the workspace to the environment; use_lockfile writes <state>.tflock beside it.
    **{f"state-{stack}": f"arn:aws:s3:::{{p}}-tfstate-abc/env:/{{env}}/{stack}/terraform.tfstate" for stack in STACKS},
    **{f"lock-{stack}": f"arn:aws:s3:::{{p}}-tfstate-abc/env:/{{env}}/{stack}/terraform.tfstate.tflock"
       for stack in STACKS},
    "state-bucket": "arn:aws:s3:::{p}-tfstate-abc",
    "deploy-role": "arn:aws:iam::{a}:role/{p}-deploy",
    # Untagged, made by AWS: the NAT gateway's network interface; the cluster security group EKS made, carrying only
    # its own `aws:eks:cluster-name` tag once destroy has removed the stack's `Environment` key.
    "nat-eni": "arn:aws:ec2:{r}:{a}:network-interface/eni-0a1b2c3d",
    "eks-sg": "arn:aws:ec2:{r}:{a}:security-group/sg-0eks0a1b2",
    "*": "*",
}
UNTAGGED = {"nat-eni", "eks-sg", "*", "esm-gone", "state-bucket", "param", "deploy-role",
            *(f"{kind}-{stack}" for kind in ("state", "lock") for stack in STACKS),
            "api-tags", "alb-logs-obj"}
# IAM and Budgets are global services: their calls go to the global region (environments.yaml aws_global_region).
GLOBAL = ("iam:", "budgets:")


def call(action, *kinds, **extra):
    """One call: the action, the resources it is authorised on, and request-context keys beyond the defaults."""
    return action, kinds or ("*",), extra


# Each SDK operation as its IAM action (Service Reference). The provider's tag interceptor lists tags on Read for a
# resource with tags (`@Tags` in its source); EC2 and Secrets Manager return tags in the describe call itself.
DESTROY_CALLS = {
    # Read: DescribeCertificate and the tag interceptor; Delete retries while the listener still holds it.
    "aws_acm_certificate": [call("acm:DescribeCertificate", "cert"), call("acm:ListTagsForCertificate", "cert"),
                            call("acm:DeleteCertificate", "cert")],
    "aws_apigatewayv2_api": [call("apigateway:GET", "api"), call("apigateway:GET", "api-tags"),
                             call("apigateway:DELETE", "api")],
    "aws_apigatewayv2_integration": [call("apigateway:GET", "api-int"), call("apigateway:DELETE", "api-int")],
    "aws_apigatewayv2_route": [call("apigateway:GET", "api-route"), call("apigateway:DELETE", "api-route")],
    "aws_apigatewayv2_stage": [call("apigateway:GET", "api"), call("apigateway:GET", "api-stage"),
                               call("apigateway:GET", "api-tags"), call("apigateway:DELETE", "api-stage")],
    # DescribeBudget/DescribeNotificationsForBudget/DescribeSubscribersForNotification -> ViewBudget; DeleteBudget ->
    # ModifyBudget (Budgets authorises reads and writes of a budget with these two actions).
    "aws_budgets_budget": [call("budgets:ViewBudget", "budget"), call("budgets:ListTagsForResource", "budget"),
                           call("budgets:ModifyBudget", "budget")],
    "aws_cloudwatch_event_rule": [call("events:DescribeRule", "rule"), call("events:ListTagsForResource", "rule"),
                                  call("events:DeleteRule", "rule")],
    "aws_cloudwatch_event_target": [call("events:ListTargetsByRule", "rule"), call("events:RemoveTargets", "rule")],
    "aws_cloudwatch_log_group": [call("logs:DescribeLogGroups", "*")]
    + [call(a, k) for k in ("lg-lambda", "lg-ecs", "lg-ci", "lg-vended")
       for a in ("logs:ListTagsForResource", "logs:DeleteLogGroup")],
    "aws_cloudwatch_metric_alarm": [call("cloudwatch:DescribeAlarms", "*"), call("cloudwatch:ListTagsForResource", "alarm"),
                                    call("cloudwatch:DeleteAlarms", "alarm")],
    "aws_dynamodb_table": [call("dynamodb:DescribeTable", "table"), call("dynamodb:DescribeContinuousBackups", "table"),
                           call("dynamodb:DescribeTimeToLive", "table"), call("dynamodb:ListTagsOfResource", "table"),
                           call("dynamodb:DeleteTable", "table")],
    # One DeleteTags per key of the stack's default tags (aws_ec2_tag for_each = local.tags), in any order.
    "aws_ec2_tag": [call("ec2:DescribeTags", "*")] + [
        call("ec2:DeleteTags", "eks-sg", **{"aws:ResourceTag/aws:eks:cluster-name": "{p}-eks", "aws:TagKeys": [key]})
        for key in ("Project", "Environment", "ManagedBy", "Lifecycle")],
    "aws_ecr_lifecycle_policy": [call("ecr:GetLifecyclePolicy", "repo"), call("ecr:DeleteLifecyclePolicy", "repo")],
    "aws_ecr_repository": [call("ecr:DescribeRepositories", "repo"), call("ecr:ListTagsForResource", "repo"),
                           call("ecr:DeleteRepository", "repo")],
    "aws_ecs_cluster": [call("ecs:DescribeClusters", "ecs-cluster"), call("ecs:ListTagsForResource", "ecs-cluster"),
                        call("ecs:DeleteCluster", "ecs-cluster")],
    "aws_ecs_service": [call(a, "ecs-service", **{"ecs:cluster": ARNS["ecs-cluster"]})
                        for a in ("ecs:DescribeServices", "ecs:ListTagsForResource", "ecs:UpdateService",
                                  "ecs:DeleteService")],
    "aws_ecs_task_definition": [call("ecs:DescribeTaskDefinition", "*"), call("ecs:ListTagsForResource", "taskdef"),
                                call("ecs:DeregisterTaskDefinition", "*")],
    # DisassociateAddress is authorised on the address and on the interface it leaves (B40).
    "aws_eip": [call("ec2:DescribeAddresses", "*"), call("ec2:DescribeAddressesAttribute", "eip"),
                call("ec2:DisassociateAddress", "eip", "nat-eni"), call("ec2:ReleaseAddress", "eip")],
    "aws_eks_access_entry": [call("eks:DescribeAccessEntry", "eks-access"), call("eks:ListTagsForResource", "eks-access"),
                             call("eks:DeleteAccessEntry", "eks-access")],
    "aws_eks_access_policy_association": [call("eks:ListAssociatedAccessPolicies", "eks-access"),
                                          call("eks:DisassociateAccessPolicy", "eks-access")],
    "aws_eks_addon": [call("eks:DescribeAddon", "eks-addon"), call("eks:ListTagsForResource", "eks-addon"),
                      call("eks:DeleteAddon", "eks-addon")],
    "aws_eks_cluster": [call("eks:DescribeCluster", "eks-cluster"), call("eks:ListTagsForResource", "eks-cluster"),
                        call("eks:DeleteCluster", "eks-cluster")],
    "aws_eks_node_group": [call("eks:DescribeNodegroup", "eks-nodegroup"), call("eks:ListTagsForResource", "eks-nodegroup"),
                           call("eks:DeleteNodegroup", "eks-nodegroup")],
    "aws_eks_pod_identity_association": [call("eks:DescribePodIdentityAssociation", "eks-podid"),
                                         call("eks:ListTagsForResource", "eks-podid"),
                                         call("eks:DeletePodIdentityAssociation", "eks-podid")],
    "aws_elasticache_replication_group": [call("elasticache:DescribeReplicationGroups", "cache-rg"),
                                          call("elasticache:DescribeCacheClusters", "cache-cluster"),
                                          call("elasticache:ListTagsForResource", "cache-rg"),
                                          call("elasticache:DeleteReplicationGroup", "cache-rg")],
    "aws_elasticache_subnet_group": [call("elasticache:DescribeCacheSubnetGroups", "cache-subnets"),
                                     call("elasticache:ListTagsForResource", "cache-subnets"),
                                     call("elasticache:DeleteCacheSubnetGroup", "cache-subnets")],
    "aws_iam_role": [call(a, "role") for a in ("iam:GetRole", "iam:ListRoleTags", "iam:ListRolePolicies",
                                             "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
                                             "iam:ListInstanceProfilesForRole", "iam:DeleteRolePolicy",
                                             "iam:DetachRolePolicy", "iam:DeleteRole")],
    "aws_iam_role_policy": [call("iam:GetRolePolicy", "role"), call("iam:DeleteRolePolicy", "role")],
    "aws_iam_role_policy_attachment": [call("iam:ListAttachedRolePolicies", "role"), call("iam:DetachRolePolicy", "role")],
    "aws_internet_gateway": [call("ec2:DescribeInternetGateways", "*"), call("ec2:DetachInternetGateway", "igw", "vpc"),
                             call("ec2:DeleteInternetGateway", "igw")],
    "aws_lambda_alias": [call("lambda:GetAlias", "alias"), call("lambda:DeleteAlias", "alias")],
    # The waiter's last poll asks for a mapping that is gone: no function to bind lambda:FunctionArn to (B40).
    "aws_lambda_event_source_mapping": [
        call("lambda:GetEventSourceMapping", "esm", **{"lambda:FunctionArn": ARNS["function"]}),
        call("lambda:ListTags", "esm"),
        call("lambda:DeleteEventSourceMapping", "esm", **{"lambda:FunctionArn": ARNS["function"]}),
        call("lambda:GetEventSourceMapping", "esm-gone")],
    "aws_lambda_function": [call(a, "function") for a in ("lambda:GetFunction", "lambda:GetFunctionCodeSigningConfig",
                                                        "lambda:GetFunctionConcurrency", "lambda:ListVersionsByFunction",
                                                        "lambda:ListTags", "lambda:DeleteFunction")],
    "aws_lambda_permission": [call("lambda:GetPolicy", "function"), call("lambda:RemovePermission", "function")],
    "aws_launch_template": [call("ec2:DescribeLaunchTemplates", "*"), call("ec2:DescribeLaunchTemplateVersions", "*"),
                            call("ec2:DescribeInstanceTypes", "*"), call("ec2:DeleteLaunchTemplate", "lt")],
    "aws_lb": [call("elasticloadbalancing:DescribeLoadBalancers", "*"),
               call("elasticloadbalancing:DescribeLoadBalancerAttributes", "*"),
               call("elasticloadbalancing:DescribeCapacityReservation", "*"),
               call("elasticloadbalancing:DescribeTags", "*"), call("elasticloadbalancing:DeleteLoadBalancer", "lb")],
    "aws_lb_listener": [call("elasticloadbalancing:DescribeListeners", "*"),
                        call("elasticloadbalancing:DescribeListenerAttributes", "*"),
                        call("elasticloadbalancing:DescribeTags", "*"), call("elasticloadbalancing:DeleteListener", "listener")],
    "aws_lb_target_group": [call("elasticloadbalancing:DescribeTargetGroups", "*"),
                            call("elasticloadbalancing:DescribeTargetGroupAttributes", "*"),
                            call("elasticloadbalancing:DescribeTags", "*"),
                            call("elasticloadbalancing:DeleteTargetGroup", "tg")],
    "aws_nat_gateway": [call("ec2:DescribeNatGateways", "*"), call("ec2:DeleteNatGateway", "nat")],
    "aws_route_table": [call("ec2:DescribeRouteTables", "*"), call("ec2:DescribeNetworkInterfaces", "*"),
                        call("ec2:DisassociateRouteTable", "rtb", "subnet"), call("ec2:DeleteRouteTable", "rtb")],
    "aws_route_table_association": [call("ec2:DescribeRouteTables", "*"), call("ec2:DisassociateRouteTable", "rtb", "subnet")],
    # The ALB's log bucket (force_destroy: every object version goes first). The bucket's Read asks for each of its
    # sub-configurations; a sub-resource's Delete is a Put of the empty configuration where S3 has no Delete action.
    "aws_s3_bucket": [call(a, "alb-logs") for a in (
        "s3:ListBucket", "s3:GetBucketPolicy", "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketWebsite",
        "s3:GetBucketVersioning", "s3:GetAccelerateConfiguration", "s3:GetBucketRequestPayment", "s3:GetBucketLogging",
        "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration", "s3:GetEncryptionConfiguration",
        "s3:GetBucketObjectLockConfiguration", "s3:GetBucketTagging", "s3:ListBucketVersions", "s3:DeleteBucket")]
    + [call("s3:DeleteObjectVersion", "alb-logs-obj"), call("s3:DeleteObject", "alb-logs-obj")],
    "aws_s3_bucket_lifecycle_configuration": [call("s3:GetLifecycleConfiguration", "alb-logs"),
                                              call("s3:PutLifecycleConfiguration", "alb-logs")],
    "aws_s3_bucket_logging": [call("s3:GetBucketLogging", "alb-logs"), call("s3:PutBucketLogging", "alb-logs")],
    "aws_s3_bucket_policy": [call("s3:GetBucketPolicy", "alb-logs"), call("s3:DeleteBucketPolicy", "alb-logs")],
    "aws_s3_bucket_public_access_block": [call("s3:GetBucketPublicAccessBlock", "alb-logs"),
                                          call("s3:PutBucketPublicAccessBlock", "alb-logs")],
    "aws_s3_bucket_server_side_encryption_configuration": [call("s3:GetEncryptionConfiguration", "alb-logs"),
                                                           call("s3:PutEncryptionConfiguration", "alb-logs")],
    "aws_s3_bucket_versioning": [call("s3:GetBucketVersioning", "alb-logs"), call("s3:PutBucketVersioning", "alb-logs")],
    "aws_secretsmanager_secret": [call("secretsmanager:DescribeSecret", "secret"),
                                  call("secretsmanager:DeleteSecret", "secret")],
    "aws_secretsmanager_secret_version": [call("secretsmanager:GetSecretValue", "secret"),
                                          call("secretsmanager:ListSecretVersionIds", "secret"),
                                          call("secretsmanager:UpdateSecretVersionStage", "secret")],
    "aws_security_group": [call("ec2:DescribeSecurityGroups", "*"), call("ec2:DescribeSecurityGroupRules", "*"),
                           call("ec2:RevokeSecurityGroupIngress", "sg"), call("ec2:RevokeSecurityGroupEgress", "sg"),
                           call("ec2:DeleteSecurityGroup", "sg")],
    "aws_sns_topic": [call("sns:GetTopicAttributes", "topic"), call("sns:ListTagsForResource", "topic"),
                      call("sns:DeleteTopic", "topic")],
    "aws_sns_topic_subscription": [call("sns:GetSubscriptionAttributes", "topic"),
                                   call("sns:ListSubscriptionsByTopic", "topic"), call("sns:Unsubscribe", "topic")],
    "aws_sqs_queue": [call("sqs:GetQueueAttributes", "queue"), call("sqs:ListQueueTags", "queue"),
                      call("sqs:DeleteQueue", "queue")],
    "aws_sqs_queue_policy": [call("sqs:GetQueueAttributes", "queue"), call("sqs:SetQueueAttributes", "queue")],
    "aws_subnet": [call("ec2:DescribeSubnets", "*"), call("ec2:DescribeVpcEndpoints", "*"), call("ec2:DescribeVpcs", "*"),
                   call("ec2:DeleteSubnet", "subnet")],
    "aws_vpc": [call("ec2:DescribeVpcs", "*"), call("ec2:DescribeVpcAttribute", "vpc"), call("ec2:DescribeNetworkAcls", "*"),
                call("ec2:DescribeRouteTables", "*"), call("ec2:DescribeSecurityGroups", "*"),
                call("ec2:DescribeVpcEndpoints", "*"), call("ec2:DeleteVpc", "vpc")],
    "aws_vpc_endpoint": [call("ec2:DescribeVpcEndpoints", "*"), call("ec2:DescribePrefixLists", "*"),
                         call("ec2:DescribeNetworkInterfaces", "*"), call("ec2:DeleteVpcEndpoints", "vpce")],
    "aws_vpc_security_group_ingress_rule": [call("ec2:DescribeSecurityGroupRules", "*"),
                                            call("ec2:RevokeSecurityGroupIngress", "sg")],
}
# Read during the destroy plan; aws_iam_policy_document makes no call.
DATA_CALLS = {
    "aws_availability_zones": [call("ec2:DescribeAvailabilityZones", "*")],
    "aws_caller_identity": [call("sts:GetCallerIdentity", "*")],
    # v6.66.0 ec2_eips_data_source.go -> findEIPs: one DescribeAddresses (filtered by tag; fullstack's runtime NAT).
    "aws_eips": [call("ec2:DescribeAddresses", "*")],
    "aws_iam_policy_document": [],
    "aws_iam_session_context": [call("iam:GetRole", "deploy-role")],
    "aws_ssm_parameter": [call("ssm:GetParameter", "param")],
}
# The S3 backend with use_lockfile=true (_infra-deploy.yml): read and write the state, take and drop the lock object.
BACKEND_CALLS = [call("s3:ListBucket", "state-bucket")] + [
    call(action, f"{kind}-{stack}") for stack in STACKS
    for action, kind in (("s3:GetObject", "state"), ("s3:PutObject", "state"), ("s3:GetObject", "lock"),
                         ("s3:PutObject", "lock"), ("s3:DeleteObject", "lock"))]
# terraform/fullstack/aurora_express.py destroy runs first in the same job (the cluster is not a terraform resource).
# Its boto3 calls and waiters, as IAM actions (a waiter polls a describe call).
AURORA_CALLS = {"describe_db_clusters": "rds:DescribeDBClusters", "describe_db_instances": "rds:DescribeDBInstances",
                "delete_db_instance": "rds:DeleteDBInstance", "delete_db_cluster": "rds:DeleteDBCluster",
                "modify_db_cluster": "rds:ModifyDBCluster", "db_instance_available": "rds:DescribeDBInstances",
                "db_cluster_available": "rds:DescribeDBClusters",
                "db_instance_deleted": "rds:DescribeDBInstances", "db_cluster_deleted": "rds:DescribeDBClusters"}
AURORA_ARNS = {"rds:DescribeDBInstances": "arn:aws:rds:{r}:{a}:db:{p}-aurora-instance-1",
               "rds:DeleteDBInstance": "arn:aws:rds:{r}:{a}:db:{p}-aurora-instance-1",
               "rds:DescribeDBClusters": "arn:aws:rds:{r}:{a}:cluster:{p}-aurora",
               "rds:DeleteDBCluster": "arn:aws:rds:{r}:{a}:cluster:{p}-aurora",
               "rds:ModifyDBCluster": "arn:aws:rds:{r}:{a}:cluster:{p}-aurora"}
# B9: destroy keeps a final snapshot of the cluster, checks it exists and tags it (the delete itself is authorised on
# the snapshot too: REQUIRED_CALLS["pause"] below covers it, pause being a destroy that copies the data first).
AURORA_CALLS |= {"describe_db_cluster_snapshots": "rds:DescribeDBClusterSnapshots",
                 "add_tags_to_resource": "rds:AddTagsToResource"}
AURORA_ARNS |= {"rds:DescribeDBClusterSnapshots": "arn:aws:rds:{r}:{a}:cluster-snapshot:{p}-aurora-final-20261017t113509z",
                "rds:AddTagsToResource": "arn:aws:rds:{r}:{a}:cluster-snapshot:{p}-aurora-final-20261017t113509z"}
# Reached in the provider only for a setting these stacks do not use (v6.66.0 source).
NOT_REACHED = {
    "ec2:GetIpamPoolAllocations": "aws_eip / aws_subnet / aws_vpc: only with an IPAM pool (ipam_pool_id)",
    "ec2:ModifyVpcEndpoint": "aws_subnet: only with a VPC endpoint the subnet is in that terraform must detach",
    "dynamodb:UpdateTable": "aws_dynamodb_table: only to remove replicas (no `replica` blocks)",
    "elasticache:DisassociateGlobalReplicationGroup": "only for a member of a global datastore",
    "secretsmanager:RemoveRegionsFromReplication": "only for a replicated secret (no `replica` blocks)",
    "lambda:UpdateFunctionConfiguration": "aws_lambda_function: only with replace_security_groups_on_destroy",
    "lambda:ListDurableExecutionsByFunction": "aws_lambda_function: only for a durable function",
    "lambda:GetDurableExecution": "aws_lambda_function: only for a durable function",
    "lambda:StopDurableExecution": "aws_lambda_function: only for a durable function",
    "iam:RemoveRoleFromInstanceProfile": "aws_iam_role: only when an instance profile still holds the role (EKS "
                                         "removes the node group's own before the role is deleted)",
    "eks:DescribePodIdentityAssociation (aws_eks_addon)": "only for an add-on with pod_identity_association blocks",
}


def _context(env, action, kind, extra):
    region = r.names(env).region
    fill = {"p": f"warden-{env}", "r": region, "a": ACCOUNT, "env": env}
    ctx = {"aws:RequestedRegion": r.EnvironmentPolicies.load().aws_global_region if action.startswith(GLOBAL)
           else region}
    if kind not in UNTAGGED:
        ctx["aws:ResourceTag/Environment"] = env
    if action.startswith("iam:") and kind == "role":
        ctx["iam:PermissionsBoundary"] = f"arn:aws:iam::{ACCOUNT}:policy/WardenEnvBoundary-{env}"
    ctx.update({k: v.format(**fill) if isinstance(v, str) else v for k, v in extra.items()})
    arn = ARNS["esm"] if kind == "esm-gone" else ARNS[kind]
    return arn.format(**fill), ctx


def _rows(env, calls):
    for action, kinds, extra in calls:
        targets = [_context(env, action, kind, extra) for kind in kinds]
        yield action, [arn for arn, _ in targets], [ctx for _, ctx in targets]


# GetCallerIdentity "requires no permissions" and works under an explicit deny (STS API reference).
NEEDS_NO_PERMISSION = {"sts:GetCallerIdentity"}

# --- the tests ------------------------------------------------------------------------------------------------------


def _types(kind):
    found = set()
    for stack in STACKS:
        for tf in (ROOT / "terraform" / stack).glob("*.tf"):
            found |= set(re.findall(rf'^{kind} "(aws_[a-z0-9_]+)"', tf.read_text(encoding="utf-8"), re.MULTILINE))
    return found


def test_every_resource_type_in_the_stacks_has_its_calls_listed():
    """A new resource type, or data source, fails here until its destroy-time calls are read from the provider and
    listed above, and then checked below."""
    assert _types("resource") == set(DESTROY_CALLS), sorted(_types("resource") ^ set(DESTROY_CALLS))
    assert _types("data") == set(DATA_CALLS), sorted(_types("data") ^ set(DATA_CALLS))


def test_the_provider_version_the_calls_were_read_from_is_the_one_locked():
    for stack in STACKS:
        lock = (ROOT / "terraform" / stack / ".terraform.lock.hcl").read_text(encoding="utf-8")
        block = lock.split('provider "registry.terraform.io/hashicorp/aws"', 1)[1]
        assert re.search(r'version\s+=\s+"6\.66\.0"', block.split("}", 1)[0]), \
            f"{stack}: the AWS provider moved - re-read its Read/Delete calls and update DESTROY_CALLS"


# The calls each stack action needs, by action. Another action (e.g. pause / resume) adds its own list here and is
# checked by the same test.
REQUIRED_CALLS = {
    "destroy": [c for group in (*DESTROY_CALLS.values(), *DATA_CALLS.values(), BACKEND_CALLS) for c in group],
}
# Pause and resume: scripts/pause_resume.py and aurora_express.py's restore, beside the destroy and
# the apply. A copy being made, a cluster or table being restored and AWS's own default subnet group carry no
# Environment tag yet; a request that tags names this environment (aws:RequestTag).
ARNS |= {
    "aurora": "arn:aws:rds:{r}:{a}:cluster:{p}-aurora",
    "aurora-new": "arn:aws:rds:{r}:{a}:cluster:{p}-aurora",
    "aurora-writer": "arn:aws:rds:{r}:{a}:db:{p}-aurora-instance-1",
    "aurora-pause": "arn:aws:rds:{r}:{a}:cluster-snapshot:{p}-aurora-pause-20261017t113509z",
    "aurora-pause-by-hand": "arn:aws:rds:{r}:{a}:cluster-snapshot:{p}-aurora-pause-20261017",
    "aurora-final": "arn:aws:rds:{r}:{a}:cluster-snapshot:{p}-aurora-final-20261017t113509z",
    "default-subnets": "arn:aws:rds:{r}:{a}:subgrp:default",
    "carts": "arn:aws:dynamodb:{r}:{a}:table/{p}-carts",
    "carts-new": "arn:aws:dynamodb:{r}:{a}:table/{p}-carts",
    "carts-backup": "arn:aws:dynamodb:{r}:{a}:table/{p}-carts/backup/01760000000000-abcdef12",
    "schedule": "arn:aws:events:{r}:{a}:rule/{p}-traffic-1m",
    "orders-queue": "arn:aws:sqs:{r}:{a}:{p}-orders",
}
UNTAGGED |= {"aurora-new", "aurora-pause", "aurora-pause-by-hand", "aurora-final", "default-subnets", "carts-new",
             "carts-backup"}
_TAGGING = {"aws:RequestTag/Environment": "{env}"}
# The writers stopped before the copies, started again on resume (pause_resume.py quiesce / wake).
_WRITERS_OFF = [call("events:DisableRule", "schedule"), call("lambda:PutFunctionConcurrency", "function"),
                call("lambda:GetFunctionConfiguration", "function"),
                call("sqs:GetQueueUrl", "orders-queue"), call("sqs:GetQueueAttributes", "orders-queue")]
_WRITERS_ON = [call("events:EnableRule", "schedule"), call("lambda:DeleteFunctionConcurrency", "function")]
REQUIRED_CALLS["pause"] = REQUIRED_CALLS["destroy"] + _WRITERS_OFF + _WRITERS_ON + [
    call("rds:DescribeDBClusters", "aurora"), call("rds:DescribeDBClusterSnapshots", "*"),
    call("rds:CreateDBClusterSnapshot", "aurora", "aurora-pause", **_TAGGING),
    call("rds:AddTagsToResource", "aurora-pause", **_TAGGING),
    call("dynamodb:DescribeTable", "carts"), call("dynamodb:CreateBackup", "carts"),
    call("dynamodb:DescribeBackup", "carts-backup"), call("dynamodb:ListBackups", "*"),
    # aurora_express.py destroy: the delete names the final snapshot it makes, which is then checked and tagged.
    call("rds:DeleteDBInstance", "aurora-writer"),
    call("rds:DeleteDBCluster", "aurora", "aurora-final"), call("rds:CreateDBClusterSnapshot", "aurora", "aurora-final"),
    call("rds:AddTagsToResource", "aurora-final", **_TAGGING)]
REQUIRED_CALLS["resume"] = _WRITERS_ON + [
    call("dynamodb:DescribeTable", "carts"), call("dynamodb:ListBackups", "*"),
    call("dynamodb:RestoreTableFromBackup", "carts-backup", "carts-new"),
    # RestoreTableFromBackup writes the items into the new table (DynamoDB's restore permissions).
    *[call(a, "carts-new") for a in ("dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem",
                                       "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:BatchWriteItem")],
    call("rds:DescribeDBClusterSnapshots", "*"),
    *[call("rds:RestoreDBClusterFromSnapshot", "aurora-new", snap, "default-subnets", **_TAGGING)
      for snap in ("aurora-pause", "aurora-pause-by-hand")],
    call("rds:AddTagsToResource", "aurora-new", **_TAGGING), call("rds:ModifyDBCluster", "aurora"),
    call("rds:CreateDBInstance", "aurora", "aurora-writer", "default-subnets", **_TAGGING)]


@pytest.mark.parametrize("stack_action", sorted(REQUIRED_CALLS))
@pytest.mark.parametrize("env", ENVS)
def test_every_call_a_stack_action_makes_is_allowed(env, stack_action):
    calls = REQUIRED_CALLS[stack_action]
    refused = [why for action, resources, ctx in _rows(env, calls)
               if action not in NEEDS_NO_PERMISSION and (why := refusal(env, action, resources, ctx))]
    assert not refused, refused


def _aurora_destroy_calls():
    """The rds methods and waiters reachable from aurora_express.destroy, through the module's own functions."""
    tree = ast.parse((ROOT / "terraform" / "fullstack" / "aurora_express.py").read_text(encoding="utf-8"))
    defs = {f.name: f for f in tree.body if isinstance(f, ast.FunctionDef)}
    todo, seen, used = ["destroy"], set(), set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for node in ast.walk(defs[name]):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in defs:
                todo.append(fn.id)
            elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id == "rds":
                if fn.attr != "get_waiter":
                    used.add(fn.attr)
                elif node.args and isinstance(node.args[0], ast.Constant):
                    used.add(node.args[0].value)
    return used


@pytest.mark.parametrize("env", ENVS)
def test_the_aurora_destroy_script_calls_are_allowed(env):
    used = _aurora_destroy_calls()
    assert {"delete_db_instance", "delete_db_cluster"} <= used, "the call scan found too little"
    assert used <= set(AURORA_CALLS), sorted(used - set(AURORA_CALLS))
    fill = {"p": f"warden-{env}", "r": r.names(env).region, "a": ACCOUNT}
    ctx = {"aws:RequestedRegion": fill["r"], "aws:ResourceTag/Environment": env}
    refused = [why for action in sorted({AURORA_CALLS[m] for m in used})
               if (why := refusal(env, action, [AURORA_ARNS[action].format(**fill)], ctx))]
    assert not refused, refused


@pytest.mark.parametrize("env", ENVS)
def test_the_three_destroy_refusals_of_2026_10_17_are_allowed_now(env):
    """The exact requests the failed destroy made, each in its worst-case context."""
    rows = {action: (resources, ctx) for action, resources, ctx in _rows(env, [
        call("lambda:GetEventSourceMapping", "esm-gone"),
        call("ec2:DisassociateAddress", "eip", "nat-eni"),
        call("ec2:DeleteTags", "eks-sg", **{"aws:ResourceTag/aws:eks:cluster-name": "{p}-eks",
                                             "aws:TagKeys": ["Environment"]})])}
    for action, (resources, ctx) in rows.items():
        assert refusal(env, action, resources, ctx) is None, action


@pytest.mark.parametrize("env", ENVS)
def test_the_new_grants_stay_narrow(env):
    """B40 widened three grants and no more: a mapping read in this region only; an address taken off an interface
    (the address itself still needs this environment's tag); tags removed only from this environment's EKS
    cluster security group."""
    region = r.names(env).region
    fill = {"p": f"warden-{env}", "r": region, "a": ACCOUNT}
    other = {"aws:RequestedRegion": region, "aws:ResourceTag/Environment": "prod" if env != "prod" else "dev"}
    untagged = {"aws:RequestedRegion": region}
    # A mapping read is all that is widened: update and delete still need this environment's function.
    for action in ("lambda:UpdateEventSourceMapping", "lambda:DeleteEventSourceMapping"):
        assert refusal(env, action, [ARNS["esm"].format(**fill)], untagged)
    assert refusal(env, "lambda:GetEventSourceMapping",
                   [ARNS["esm"].format(**fill).replace(region, "us-west-2")], untagged)
    foreign = {**untagged, "lambda:FunctionArn": f"arn:aws:lambda:{region}:{ACCOUNT}:function:someone-elses"}
    assert refusal(env, "lambda:GetEventSourceMapping", [ARNS["esm"].format(**fill)], foreign)
    # Another environment's or an untagged address cannot be taken off an interface.
    for ctx in (other, untagged):
        assert refusal(env, "ec2:DisassociateAddress",
                       [ARNS["eip"].format(**fill), ARNS["nat-eni"].format(**fill)], ctx)
    # Tags come off only the security group of this environment's own cluster.
    others = [f"warden-{o}-eks" for o in ENVS if o != env] + [f"warden-{env}-lab-eks", f"warden-{env}-eks2"]
    for cluster in (*others, "warden-other-eks", "someone-elses-eks"):
        assert refusal(env, "ec2:DeleteTags", [ARNS["eks-sg"].format(**fill)],
                       {**untagged, "aws:ResourceTag/aws:eks:cluster-name": cluster, "aws:TagKeys": ["Project"]})
    assert refusal(env, "ec2:DeleteTags", [ARNS["vpc"].format(**fill)], {**untagged, "aws:TagKeys": ["Project"]})
    # Only the keys the stack sets come off: never another key, and never every tag at once - a
    # DeleteTags that names no key removes them all, and ForAllValues alone would let it through (hence Null).
    sg = {**untagged, "aws:ResourceTag/aws:eks:cluster-name": f"warden-{env}-eks"}
    own = {**untagged, "aws:ResourceTag/Environment": env}
    for target, ctx in ((ARNS["eks-sg"], sg), (ARNS["vpc"], own)):
        assert refusal(env, "ec2:DeleteTags", [target.format(**fill)], {**ctx, "aws:TagKeys": ["Owner"]})
        assert refusal(env, "ec2:DeleteTags", [target.format(**fill)], {**ctx, "aws:TagKeys": ["Project", "Owner"]})
        assert refusal(env, "ec2:DeleteTags", [target.format(**fill)], ctx)  # no key named: every tag
    assert refusal(env, "ec2:DeleteTags", [ARNS["eks-sg"].format(**fill)], {**sg, "aws:TagKeys": ["Name"]})
    assert refusal(env, "ec2:DeleteTags", [ARNS["vpc"].format(**fill)], {**own, "aws:TagKeys": ["Name"]}) is None


def test_every_tag_key_the_stack_sets_can_be_taken_off_again():
    """An update that drops a key the stack set needs DeleteTags for that key: the untag grant names every key the
    full stack's EC2 resources carry - the default tags and each resource's own - and no other."""
    tf = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "terraform" / "fullstack").glob("*.tf"))
    blocks = []
    for m in re.finditer(r"\btags\s*=\s*\{", tf):  # each map, to its own closing brace (past any ${...})
        depth, i = 1, m.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(tf[i], 0)
            i += 1
        blocks.append(tf[m.end():i - 1])
    keys = {k.strip('"') for b in blocks for k in re.findall(r'^\s*("[^"]+"|\w+)\s*=', b, re.MULTILINE)}
    assert {"Project", "Environment", "ManagedBy", "Lifecycle", "Name", "kubernetes.io/role/elb"} <= keys
    for env in ENVS:
        st = next(s for s in _load(env, "deploy-ec2")["Statement"] if s.get("Sid") == "Ec2UntagOwnEnvTaggedOnlyTheStacksKeys")
        allowed = set(st["Condition"]["ForAllValues:StringEquals"]["aws:TagKeys"])
        assert allowed == keys, (sorted(allowed - keys), sorted(keys - allowed))
        assert st["Condition"]["Null"] == {"aws:TagKeys": "false"}


def test_the_evaluator_reads_conditions_as_iam_does():
    """The checks above are only as good as this evaluator: a positive operator fails on a missing key, a negated
    one passes, Null tests presence, an unknown operator stops the test."""
    ctx = {"k": "warden-dev-x"}
    assert _condition_holds("StringLike", "k", "warden-dev-*", ctx)
    assert not _condition_holds("StringLike", "missing", "*", ctx)
    assert not _condition_holds("ArnLike", "missing", "*", ctx)
    assert _condition_holds("StringNotEquals", "missing", "x", ctx)
    assert _condition_holds("ArnNotLike", "missing", "x", ctx)
    assert not _condition_holds("StringNotLike", "k", "warden-*", ctx)
    assert _condition_holds("Null", "missing", "true", ctx)
    assert not _condition_holds("Null", "k", "true", ctx)
    assert _condition_holds("ArnLikeIfExists", "missing", "x", ctx)
    assert _condition_holds("ArnLikeIfExists", "k", "warden-dev-*", ctx)
    assert not _condition_holds("ArnLikeIfExists", "k", "warden-prod-*", ctx)
    assert _condition_holds("ForAllValues:StringEquals", "tags", ["a", "b"], {"tags": ["a"]})
    assert not _condition_holds("ForAllValues:StringEquals", "tags", ["a"], {"tags": ["a", "c"]})
    assert _condition_holds("ForAllValues:StringEquals", "tags", ["a"], {})  # absent: true - pair it with Null
    assert _condition_holds("ForAnyValue:StringEquals", "tags", ["a"], {"tags": ["c", "a"]})
    assert not _condition_holds("ForAnyValue:StringEquals", "tags", ["a"], {})
    with pytest.raises(AssertionError):
        _condition_holds("NumericLessThan", "k", "1", ctx)
