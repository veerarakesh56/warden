"""List everything that can cost money in the account, in EVERY region, without trusting tags.

    python scripts/account_sweep.py                # assume warden-pg-sweep (read-only), sweep
    python scripts/account_sweep.py --no-assume    # sweep with the current credentials
    python scripts/account_sweep.py --write-trust  # write the sweep role's trust policy (local)

Read-only: it lists, it never deletes. A resource counts whatever its tags say - an untagged NAT
bills the same as a tagged one. Default VPCs, default security groups, AWS-managed keys and
AWS-managed event rules are not reported: they exist in every account and cost nothing.

TAGS: every resource found must carry Project=warden and an Environment that is a key of
environments.yaml. One that does not is reported UNTAGGED; one whose tags could not be read is
reported TAGS-BLIND - never assumed fine. Network interfaces are exempt (most are created by AWS for
the resource they attach to, and cost nothing), as are KMS aliases (the tags live on the key).

A service the account is not signed up for (SubscriptionRequired / OptInRequired - on the Free plan,
Kinesis, Redshift and EMR) cannot hold anything; it is listed once as NOT ENABLED, not as blind.

⛔ A service it could not LIST for any other reason is reported as BLIND, never as empty. Exit codes: 0 nothing found,
1 something found or a tag problem, 2 blind somewhere (the answer is incomplete, so it is not
"clean").

The role `warden-pg-sweep` may make exactly the listing calls below and read tags
(terraform/proving-ground/sweep-role-policy.json - no secret values, no object contents), and it
trusts only warden-operator. Billing -> Bills stays the ground truth for
charges; this is the resource-level view.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

import boto3
import jmespath
from botocore.exceptions import BotoCoreError, ClientError

from warden.environments import EnvironmentPolicies

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROLE = "warden-pg-sweep"
TRUST_FILE = ROOT / "terraform" / "proving-ground" / "sweep-role-trust.local.json"
ENVIRONMENTS = set(EnvironmentPolicies.load().known_environments)
NOT_ENABLED = {"SubscriptionRequiredException", "OptInRequired"}
LIVE = ("pending", "available", "running", "stopping", "stopped", "creating", "modifying")


def _not(field: str, *values: str):
    return lambda r: r.get(field) not in values


# (client, call, kwargs, JMESPath to the items, id field, keep?) - one row per resource kind that can bill.
REGIONAL: list[tuple[str, str, dict, str, str, Any]] = [
    ("ec2", "describe_instances", {}, "Reservations[].Instances[]", "InstanceId",
     lambda r: r.get("State", {}).get("Name") in LIVE),
    ("ec2", "describe_nat_gateways", {}, "NatGateways", "NatGatewayId", _not("State", "deleted", "failed")),
    ("ec2", "describe_addresses", {}, "Addresses", "PublicIp", None),
    ("ec2", "describe_volumes", {}, "Volumes", "VolumeId", None),
    ("ec2", "describe_snapshots", {"OwnerIds": ["self"]}, "Snapshots", "SnapshotId", None),
    ("ec2", "describe_images", {"Owners": ["self"]}, "Images", "ImageId", None),
    ("ec2", "describe_vpcs", {}, "Vpcs", "VpcId", lambda r: not r.get("IsDefault")),
    ("ec2", "describe_network_interfaces", {}, "NetworkInterfaces", "NetworkInterfaceId", None),
    ("ec2", "describe_vpc_endpoints", {}, "VpcEndpoints", "VpcEndpointId", _not("State", "deleted")),
    ("ec2", "describe_security_groups", {}, "SecurityGroups", "GroupId", _not("GroupName", "default")),
    ("elbv2", "describe_load_balancers", {}, "LoadBalancers", "LoadBalancerName", None),
    ("elb", "describe_load_balancers", {}, "LoadBalancerDescriptions", "LoadBalancerName", None),
    ("eks", "list_clusters", {}, "clusters", "", None),
    ("ecs", "list_clusters", {}, "clusterArns", "", None),
    ("rds", "describe_db_instances", {}, "DBInstances", "DBInstanceIdentifier", None),
    ("rds", "describe_db_clusters", {}, "DBClusters", "DBClusterIdentifier", None),
    ("rds", "describe_db_snapshots", {"SnapshotType": "manual"}, "DBSnapshots", "DBSnapshotIdentifier", None),
    ("rds", "describe_db_cluster_snapshots", {"SnapshotType": "manual"}, "DBClusterSnapshots",
     "DBClusterSnapshotIdentifier", None),
    ("elasticache", "describe_cache_clusters", {}, "CacheClusters", "CacheClusterId", None),
    ("elasticache", "describe_serverless_caches", {}, "ServerlessCaches", "ServerlessCacheName", None),
    ("lambda", "list_functions", {}, "Functions", "FunctionName", None),
    ("dynamodb", "list_tables", {}, "TableNames", "", None),
    ("sqs", "list_queues", {}, "QueueUrls", "", None),
    ("sns", "list_topics", {}, "Topics", "TopicArn", None),
    ("secretsmanager", "list_secrets", {}, "SecretList", "Name", None),
    ("ecr", "describe_repositories", {}, "repositories", "repositoryName", None),
    ("kms", "list_aliases", {}, "Aliases", "AliasName",
     lambda r: r.get("TargetKeyId") and not r["AliasName"].startswith("alias/aws/")),
    ("events", "list_rules", {}, "Rules", "Name", lambda r: not r.get("ManagedBy")),
    ("cloudwatch", "describe_alarms", {}, "MetricAlarms", "AlarmName", None),
    ("logs", "describe_log_groups", {}, "logGroups", "logGroupName", None),
    ("ssm", "describe_parameters", {}, "Parameters", "Name", None),
    ("apigateway", "get_rest_apis", {}, "items", "name", None),
    ("apigatewayv2", "get_apis", {}, "Items", "Name", None),
    ("efs", "describe_file_systems", {}, "FileSystems", "FileSystemId", None),
    ("kinesis", "list_streams", {}, "StreamNames", "", None),
    ("opensearch", "list_domain_names", {}, "DomainNames", "DomainName", None),
    ("redshift", "describe_clusters", {}, "Clusters", "ClusterIdentifier", None),
    ("sagemaker", "list_endpoints", {}, "Endpoints", "EndpointName", None),
    ("sagemaker", "list_notebook_instances", {}, "NotebookInstances", "NotebookInstanceName",
     _not("NotebookInstanceStatus", "Deleting")),
    ("emr", "list_clusters", {"ClusterStates": ["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"]},
     "Clusters", "Id", None),
]
GLOBAL: list[tuple[str, str, dict, str, str, Any]] = [
    ("s3", "list_buckets", {}, "Buckets", "Name", None),
    ("cloudfront", "list_distributions", {}, "DistributionList.Items", "Id", None),
    ("route53", "list_hosted_zones", {}, "HostedZones", "Name", None),
]


def _items(client: Any, call: str, kwargs: dict, key: str) -> list:
    """Every item under `key` (a JMESPath expression), across all pages."""
    if client.can_paginate(call):
        return [x for x in client.get_paginator(call).paginate(**kwargs).search(key) if x is not None]
    return jmespath.search(key, getattr(client, call)(**kwargs)) or []


# Listings that carry neither tags nor an ARN: the ARN is built from the id.
ARN_OF = {
    "eks.list_clusters": "arn:aws:eks:{region}:{account}:cluster/{id}",
    "dynamodb.list_tables": "arn:aws:dynamodb:{region}:{account}:table/{id}",
    "kinesis.list_streams": "arn:aws:kinesis:{region}:{account}:stream/{id}",
    "sqs.list_queues": "arn:aws:sqs:{region}:{account}:{last}",
    "elb.describe_load_balancers": "arn:aws:elasticloadbalancing:{region}:{account}:loadbalancer/{id}",
    "opensearch.list_domain_names": "arn:aws:es:{region}:{account}:domain/{id}",
    "ssm.describe_parameters": "arn:aws:ssm:{region}:{account}:parameter/{bare}",
    "route53.list_hosted_zones": "arn:aws:route53:::hostedzone/{last}",
}
NO_TAG_AUDIT = {"ec2.describe_network_interfaces", "kms.list_aliases"}


def _check(session: Any, region: str | None, row: tuple) -> tuple[list[tuple[str, Any]], str | None]:
    service, call, kwargs, key, id_field, keep = row
    try:
        client = session.client(service, region_name=region) if region else session.client(service)
        items = _items(client, call, kwargs, key)
    except (ClientError, BotoCoreError) as exc:
        return [], f"{service}.{call}: {_code(exc)}"
    kept = [x for x in items if keep is None or keep(x)]
    return [(str(x.get(id_field) if id_field else x), x) for x in kept], None


def _code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)


def _inline_tags(item: Any) -> dict | None:
    if not isinstance(item, dict):
        return None
    for key in ("Tags", "TagList", "tags"):
        if key in item:
            raw = item[key] or {}
            if isinstance(raw, dict):
                return dict(raw)
            return {t.get("Key", t.get("key")): t.get("Value", t.get("value")) for t in raw}
    return None


def _arn(item: Any, name: str, region: str | None, account: str, rid: str) -> str | None:
    if isinstance(item, str) and item.startswith("arn:"):
        return item
    if isinstance(item, dict):
        if item.get("logGroupArn"):
            return item["logGroupArn"]
        for key, value in item.items():
            if key.lower().endswith("arn") and isinstance(value, str) and value.startswith("arn:"):
                return value
    template = ARN_OF.get(name)
    return template and template.format(region=region, account=account, id=rid,
                                        last=rid.rstrip("/").rsplit("/", 1)[-1], bare=rid.lstrip("/"))


def tag_problem(tags: dict) -> str | None:
    wrong = []
    if tags.get("Project") != "warden":
        wrong.append(f"Project={tags.get('Project')!r}")
    if tags.get("Environment") not in ENVIRONMENTS:
        wrong.append(f"Environment={tags.get('Environment')!r}")
    return ", ".join(wrong) or None


def _lookup(session: Any, region: str | None, arns: list[str]) -> dict[str, dict] | str:
    """ARN -> tags through the tagging API. An ARN it does not return has no tags."""
    try:
        tagging = session.client("resourcegroupstaggingapi", region_name=region or "us-east-1")
        out: dict[str, dict] = {}
        for i in range(0, len(arns), 100):
            page = tagging.get_resources(ResourceARNList=arns[i:i + 100])
            for r in page.get("ResourceTagMappingList") or []:
                out[r["ResourceARN"]] = {t["Key"]: t["Value"] for t in r.get("Tags") or []}
        return out
    except (ClientError, BotoCoreError) as exc:
        return _code(exc)


def _bucket_tags(session: Any, bucket: str) -> dict | str:
    try:
        return {t["Key"]: t["Value"] for t in session.client("s3").get_bucket_tagging(Bucket=bucket)["TagSet"]}
    except (ClientError, BotoCoreError) as exc:
        return {} if _code(exc) == "NoSuchTagSet" else _code(exc)


def sweep(session: Any, regions: list[str], account: str = "") -> tuple[dict[str, list[str]], list[str], list[str], list[str]]:
    found: dict[str, list[str]] = {}
    blind: list[str] = []
    off: set[str] = set()
    tags_wrong: list[str] = []
    for region, rows in [(None, GLOBAL)] + [(r, REGIONAL) for r in regions]:
        place = region or "global"
        pending: dict[str, str] = {}  # arn -> "where id"
        for row in rows:
            name = f"{row[0]}.{row[1]}"
            hits, error = _check(session, region, row)
            if error and error.rsplit(": ", 1)[-1] in NOT_ENABLED:
                off.add(row[0])
                continue
            if error:
                blind.append(f"{place} {error}")
                continue
            if hits:
                found[f"{place} {name}"] = [rid for rid, _ in hits]
            if name in NO_TAG_AUDIT:
                continue
            for rid, item in hits:
                label = f"{place} {name} {rid}"
                tags = _bucket_tags(session, rid) if name == "s3.list_buckets" else _inline_tags(item)
                arn = None if tags is not None else _arn(item, name, region, account, rid)
                if isinstance(tags, str):
                    tags_wrong.append(f"TAGS-BLIND {label}: {tags}")
                elif tags is not None:
                    if problem := tag_problem(tags):
                        tags_wrong.append(f"UNTAGGED {label}: {problem}")
                elif arn:
                    pending[arn] = label
                else:
                    tags_wrong.append(f"TAGS-BLIND {label}: no tags and no ARN in the listing")
        if pending:
            looked = _lookup(session, region, list(pending))
            for arn, label in pending.items():
                if isinstance(looked, str):
                    tags_wrong.append(f"TAGS-BLIND {label}: tagging API {looked}")
                elif problem := tag_problem(looked.get(arn, {})):
                    tags_wrong.append(f"UNTAGGED {label}: {problem}")
    return found, blind, tags_wrong, sorted(off)


def _regions(session: Any) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])


def main(argv: list[str] | None = None, *, session: Any = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--no-assume", action="store_true", help="use the current credentials")
    parser.add_argument("--write-trust", action="store_true", help="write the role's trust policy")
    args = parser.parse_args(argv)
    session = session or boto3.Session()
    account = session.client("sts").get_caller_identity()["Account"]
    if args.write_trust:
        TRUST_FILE.write_text(json.dumps({"Version": "2012-10-17", "Statement": [{
            "Sid": "OnlyTheOperator", "Effect": "Allow", "Action": "sts:AssumeRole",
            "Principal": {"AWS": f"arn:aws:iam::{account}:user/warden-operator"}}]}, indent=2) + "\n",
            encoding="utf-8")
        print(f"wrote {TRUST_FILE} (gitignored: it holds the account id)")
        return 0
    if not args.no_assume:
        creds = session.client("sts").assume_role(
            RoleArn=f"arn:aws:iam::{account}:role/{ROLE}", RoleSessionName="warden-sweep",
            DurationSeconds=900)["Credentials"]
        session = boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                                aws_secret_access_key=creds["SecretAccessKey"],
                                aws_session_token=creds["SessionToken"])
    try:
        regions, no_regions = _regions(session), []
    except (ClientError, BotoCoreError) as exc:
        regions, no_regions = ["ap-south-2"], [f"regions: {_code(exc)} - only ap-south-2 was swept"]
    found, blind, tags_wrong, off = sweep(session, regions, account)
    blind = no_regions + blind
    print(f"swept {len(regions)} region(s) + global, {len(REGIONAL)} regional and {len(GLOBAL)} global checks")
    for where, ids in sorted(found.items()):
        print(f"FOUND {where}: {', '.join(ids)}")
    if off:
        print(f"NOT ENABLED on this account, so nothing can exist there: {', '.join(off)}")
    for line in tags_wrong:
        print(line)
    for line in blind:
        print(f"BLIND {line}")
    if blind:
        print("INCOMPLETE - some services could not be listed; this is NOT a clean result")
        return 2
    print("clean - nothing that can bill was found" if not found else "resources exist (above)")
    return 1 if found or tags_wrong else 0


if __name__ == "__main__":
    sys.exit(main())
