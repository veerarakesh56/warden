"""The account sweep: tags never decide what counts, a service it cannot list is BLIND, not empty, and
every resource found must carry Project=warden and a known Environment."""

from __future__ import annotations

import importlib.util
import pathlib

from botocore.exceptions import ClientError

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("account_sweep", ROOT / "scripts" / "account_sweep.py")
sweep_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sweep_mod)

DENIED = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "List")
GOOD = [{"Key": "Project", "Value": "warden"}, {"Key": "Environment", "Value": "dev"}]


class FakeClient:
    def __init__(self, answers: dict):
        self.answers = answers

    def can_paginate(self, call):
        return False

    def __getattr__(self, call):
        answer = self.answers.get(call, {})

        def method(**kwargs):
            if isinstance(answer, Exception):
                raise answer
            return answer(**kwargs) if callable(answer) else answer
        return method


class FakeSession:
    def __init__(self, per_service: dict):
        self.per_service = per_service

    def client(self, service, region_name=None):
        return FakeClient(self.per_service.get(service, {}))


def test_untagged_billable_resources_are_found_and_free_defaults_are_not():
    session = FakeSession({
        "ec2": {
            "describe_instances": {"Reservations": [{"Instances": [
                {"InstanceId": "i-live", "State": {"Name": "running"}},  # no tags at all
                {"InstanceId": "i-gone", "State": {"Name": "terminated"}}]}]},
            "describe_nat_gateways": {"NatGateways": [
                {"NatGatewayId": "nat-1", "State": "available", "Tags": GOOD},
                {"NatGatewayId": "nat-old", "State": "deleted"}]},
            "describe_vpcs": {"Vpcs": [{"VpcId": "vpc-default", "IsDefault": True},
                                       {"VpcId": "vpc-mine", "IsDefault": False, "Tags": GOOD}]},
            "describe_security_groups": {"SecurityGroups": [{"GroupId": "sg-d", "GroupName": "default"}]},
        },
        "kms": {"list_aliases": {"Aliases": [
            {"AliasName": "alias/aws/ssm", "TargetKeyId": "k1"},
            {"AliasName": "alias/mine", "TargetKeyId": "k2"}]}},
    })
    found, blind, _, _ = sweep_mod.sweep(session, ["ap-south-2"])
    assert blind == []
    assert found == {
        "ap-south-2 ec2.describe_instances": ["i-live"],
        "ap-south-2 ec2.describe_nat_gateways": ["nat-1"],
        "ap-south-2 ec2.describe_vpcs": ["vpc-mine"],
        "ap-south-2 kms.list_aliases": ["alias/mine"],
    }


def test_a_resource_without_both_tags_or_with_an_unknown_environment_is_reported():
    lambda_arns = {"arn:aws:lambda:r:a:function:ok": GOOD,
                   "arn:aws:lambda:r:a:function:typo": [{"Key": "Project", "Value": "warden"},
                                                        {"Key": "Environment", "Value": "prd"}]}
    session = FakeSession({
        "ec2": {"describe_instances": {"Reservations": [{"Instances": [
            {"InstanceId": "i-noenv", "State": {"Name": "running"},
             "Tags": [{"Key": "Project", "Value": "warden"}]}]}]},
            "describe_network_interfaces": {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-aws"}]}},
        "lambda": {"list_functions": {"Functions": [{"FunctionName": n.rsplit(":", 1)[-1], "FunctionArn": n}
                                                    for n in [*lambda_arns, "arn:aws:lambda:r:a:function:bare"]]}},
        "resourcegroupstaggingapi": {"get_resources": lambda ResourceARNList: {"ResourceTagMappingList": [
            {"ResourceARN": a, "Tags": lambda_arns[a]} for a in ResourceARNList if a in lambda_arns]}},
        "s3": {"list_buckets": {"Buckets": [{"Name": "warden-dev-tfstate-x"}]},
               "get_bucket_tagging": {"TagSet": GOOD}},
    })
    _, blind, wrong, _ = sweep_mod.sweep(session, ["ap-south-2"], "acct")
    assert blind == []
    assert sorted(wrong) == [
        "UNTAGGED ap-south-2 ec2.describe_instances i-noenv: Environment=None",
        "UNTAGGED ap-south-2 lambda.list_functions bare: Project=None, Environment=None",
        "UNTAGGED ap-south-2 lambda.list_functions typo: Environment='prd'",
    ]  # the ENI is exempt; the tagged function and bucket pass


def test_tags_it_cannot_read_are_reported_not_assumed_fine():
    session = FakeSession({
        "dynamodb": {"list_tables": {"TableNames": ["orders"]}},
        "resourcegroupstaggingapi": {"get_resources": DENIED},
    })
    _, _, wrong, _ = sweep_mod.sweep(session, ["ap-south-2"], "acct")
    assert wrong == ["TAGS-BLIND ap-south-2 dynamodb.list_tables orders: tagging API AccessDenied"]


def test_a_service_it_cannot_list_is_blind_and_the_run_is_not_clean(capsys):
    session = FakeSession({"sqs": {"list_queues": DENIED},
                           "sts": {"get_caller_identity": {"Account": "acct"}},
                           "ec2": {"describe_regions": {"Regions": [{"RegionName": "ap-south-2"}]}}})
    assert sweep_mod.main(["--no-assume"], session=session) == 2
    out = capsys.readouterr().out
    assert "BLIND ap-south-2 sqs.list_queues: AccessDenied" in out
    assert "NOT a clean result" in out and "clean - nothing" not in out


def test_every_region_is_swept_not_only_the_home_region():
    session = FakeSession({"ec2": {"describe_nat_gateways": {"NatGateways": [
        {"NatGatewayId": "nat-x", "State": "available"}]}}})
    found, _, _, _ = sweep_mod.sweep(session, ["ap-south-2", "us-east-1"])
    assert "us-east-1 ec2.describe_nat_gateways" in found


def test_the_sweep_role_policy_allows_every_call_the_sweep_makes_and_nothing_else():
    """iam/operator/sweep-policy.json is least privilege: one listing action per
    check, plus the tag reads. A check added without its action would come back BLIND."""
    import json

    prefix = {"elbv2": "elasticloadbalancing", "elb": "elasticloadbalancing", "efs": "elasticfilesystem",
              "opensearch": "es", "emr": "elasticmapreduce"}
    wanted = {"ec2:DescribeRegions", "s3:GetBucketTagging", "tag:GetResources"}
    for service, call, *_ in sweep_mod.REGIONAL + sweep_mod.GLOBAL:
        if service.startswith("apigateway"):
            continue
        action = "".join(w.capitalize() for w in call.split("_"))
        action = action.replace("Db", "DB")  # rds spells it DescribeDBInstances
        action = {"ListBuckets": "ListAllMyBuckets"}.get(action, action)  # IAM's name for the S3 call
        wanted.add(f"{prefix.get(service, service)}:{action}")
    policy = json.loads((ROOT / "iam" / "operator" / "sweep-policy.json").read_text())
    listed = set(policy["Statement"][0]["Action"])
    assert listed == wanted, (wanted - listed, listed - wanted)
    api = policy["Statement"][1]
    assert api["Action"] == "apigateway:GET" and all(r.endswith(("/restapis", "/apis")) for r in api["Resource"])



def test_a_service_the_account_is_not_signed_up_for_is_not_enabled_not_blind():
    off = ClientError({"Error": {"Code": "SubscriptionRequiredException", "Message": "no"}}, "List")
    session = FakeSession({"kinesis": {"list_streams": off}, "sqs": {"list_queues": DENIED}})
    _, blind, _, not_enabled = sweep_mod.sweep(session, ["ap-south-2", "us-east-1"])
    assert not_enabled == ["kinesis"]
    assert blind == ["ap-south-2 sqs.list_queues: AccessDenied", "us-east-1 sqs.list_queues: AccessDenied"]


def test_the_runtime_environment_is_a_valid_tag():
    """W0-now tags the runtime's secrets Environment=ops; the first sweep after it must not call
    them untagged (second review, 2026-09-30)."""
    assert sweep_mod.tag_problem({"Project": "warden", "Environment": "ops"}) is None
    assert sweep_mod.tag_problem({"Project": "warden", "Environment": "opz"})


def test_a_full_sweep_reports_every_tag_outcome_in_order():
    """Characterisation (before splitting sweep for cognitive complexity): every tag outcome - inline tags good and
    wrong, a bucket whose tags cannot be read, a bucket with none, a listing with no tags and no ARN, ARNs read through
    the tagging API good, wrong and missing, an exempt kind - per region, in the order the sweep has always written."""
    def bucket_tags(Bucket):
        if Bucket == "b-denied":
            raise DENIED
        if Bucket == "b-none":
            raise ClientError({"Error": {"Code": "NoSuchTagSet", "Message": "none"}}, "GetBucketTagging")
        return {"TagSet": GOOD}

    def resources(ResourceARNList):
        tagged = {"arn:aws:dynamodb:ap-south-2:acct:table/t-good": GOOD,
                  "arn:aws:dynamodb:ap-south-2:acct:table/t-wrong": [{"Key": "Project", "Value": "other"}],
                  "arn:aws:route53:::hostedzone/Z1": GOOD}
        return {"ResourceTagMappingList": [{"ResourceARN": a, "Tags": tagged[a]} for a in ResourceARNList
                                           if a in tagged]}

    session = FakeSession({
        "s3": {"list_buckets": {"Buckets": [{"Name": "b-denied"}, {"Name": "b-none"}, {"Name": "b-ok"}]},
               "get_bucket_tagging": bucket_tags},
        "route53": {"list_hosted_zones": {"HostedZones": [{"Name": "/hostedzone/Z1"}, {"Name": "/hostedzone/Z2"}]}},
        "ec2": {"describe_instances": {"Reservations": [{"Instances": [
                    {"InstanceId": "i-ok", "State": {"Name": "running"}, "Tags": GOOD},
                    {"InstanceId": "i-bad", "State": {"Name": "running"},
                     "Tags": [{"Key": "Environment", "Value": "dev"}]}]}]},
                "describe_addresses": {"Addresses": [{"PublicIp": "198.51.100.7"}]},
                "describe_network_interfaces": {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1"}]}},
        "dynamodb": {"list_tables": {"TableNames": ["t-good", "t-wrong", "t-missing"]}},
        "kinesis": {"list_streams": ClientError({"Error": {"Code": "OptInRequired", "Message": "no"}}, "List")},
        "sqs": {"list_queues": DENIED},
        "resourcegroupstaggingapi": {"get_resources": resources},
    })
    found, blind, wrong, off = sweep_mod.sweep(session, ["ap-south-2", "us-east-1"], "acct")
    assert found == {
        "global s3.list_buckets": ["b-denied", "b-none", "b-ok"],
        "global route53.list_hosted_zones": ["/hostedzone/Z1", "/hostedzone/Z2"],
        "ap-south-2 ec2.describe_instances": ["i-ok", "i-bad"],
        "ap-south-2 ec2.describe_addresses": ["198.51.100.7"],
        "ap-south-2 ec2.describe_network_interfaces": ["eni-1"],
        "ap-south-2 dynamodb.list_tables": ["t-good", "t-wrong", "t-missing"],
        "us-east-1 ec2.describe_instances": ["i-ok", "i-bad"],
        "us-east-1 ec2.describe_addresses": ["198.51.100.7"],
        "us-east-1 ec2.describe_network_interfaces": ["eni-1"],
        "us-east-1 dynamodb.list_tables": ["t-good", "t-wrong", "t-missing"],
    }
    assert blind == ["ap-south-2 sqs.list_queues: AccessDenied", "us-east-1 sqs.list_queues: AccessDenied"]
    assert off == ["kinesis"]
    assert wrong == [
        "TAGS-BLIND global s3.list_buckets b-denied: AccessDenied",
        "UNTAGGED global s3.list_buckets b-none: Project=None, Environment=None",
        "UNTAGGED global route53.list_hosted_zones /hostedzone/Z2: Project=None, Environment=None",
        "UNTAGGED ap-south-2 ec2.describe_instances i-bad: Project=None",
        "TAGS-BLIND ap-south-2 ec2.describe_addresses 198.51.100.7: no tags and no ARN in the listing",
        "UNTAGGED ap-south-2 dynamodb.list_tables t-wrong: Project='other', Environment=None",
        "UNTAGGED ap-south-2 dynamodb.list_tables t-missing: Project=None, Environment=None",
        "UNTAGGED us-east-1 ec2.describe_instances i-bad: Project=None",
        "TAGS-BLIND us-east-1 ec2.describe_addresses 198.51.100.7: no tags and no ARN in the listing",
        "UNTAGGED us-east-1 dynamodb.list_tables t-good: Project=None, Environment=None",
        "UNTAGGED us-east-1 dynamodb.list_tables t-wrong: Project=None, Environment=None",
        "UNTAGGED us-east-1 dynamodb.list_tables t-missing: Project=None, Environment=None",
    ]


def test_a_tagging_api_it_cannot_read_makes_every_pending_resource_blind():
    """Characterisation: the tagging API refused for a region - each resource waiting on it is TAGS-BLIND, in order."""
    session = FakeSession({"sqs": {"list_queues": {"QueueUrls": ["https://sqs/acct/q1", "https://sqs/acct/q2"]}},
                           "resourcegroupstaggingapi": {"get_resources": DENIED}})
    _, _, wrong, _ = sweep_mod.sweep(session, ["ap-south-2"], "acct")
    assert wrong == ["TAGS-BLIND ap-south-2 sqs.list_queues https://sqs/acct/q1: tagging API AccessDenied",
                     "TAGS-BLIND ap-south-2 sqs.list_queues https://sqs/acct/q2: tagging API AccessDenied"]
