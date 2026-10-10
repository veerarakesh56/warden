"""Forward the watched environments' alarms from AWS's global-services Region to WARDEN's runtime Region (G10-F1).

    python scripts/forward_global_alarms.py            # print what would be made, change nothing
    python scripts/forward_global_alarms.py --apply    # make it (the setup role, in the live window)
    python scripts/forward_global_alarms.py --undo     # remove exactly what --apply made

CloudFront and Route 53 health checks publish their metrics - and so keep their alarms - only in AWS's global-services
Region (environments.yaml `aws_global_region`). WARDEN's intake listens in its runtime Region (`aws_region`). One rule
there sends each watched environment's alarm state change, unchanged (EventBridge delivers it identical, its `region`
kept), to the runtime Region's default event bus, where the runtime's own alarms rule takes it to intake - and drops
it while the runtime is paused. Persistent account setup like the Config recorder: the runtime's deploy role, held to
its own Region by its boundary, does not make it. Every Region and name comes from environments.yaml; the account
from STS. Cross-Region events cost about $1 a million (EventBridge pricing).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from warden.environments import EnvironmentPolicies


def plan(account: str) -> dict[str, Any]:
    """Every name and document the forwarding needs, from environments.yaml and the account."""
    cfg = EnvironmentPolicies.load()
    runtime, home, glob = cfg.runtime_environment, cfg.aws_region, cfg.aws_global_region
    if not (runtime and home and glob) or home == glob:
        raise SystemExit("environments.yaml needs runtime, aws_region and a different aws_global_region")
    bus = f"arn:aws:events:{home}:{account}:event-bus/default"
    tags = [{"Key": "Project", "Value": "warden"}, {"Key": "Environment", "Value": runtime}]
    return {
        "global_region": glob, "role": f"warden-{runtime}-forward-alarms", "rule": f"warden-{runtime}-global-alarm-changes",
        "bus": bus, "tags": tags, "boundary": f"arn:aws:iam::{account}:policy/WardenEnvBoundary-{runtime}",
        "trust": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": account}}}]},
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Sid": "OnlyTheRuntimeRegionsDefaultBus", "Effect": "Allow", "Action": "events:PutEvents", "Resource": bus}]},
        "pattern": {"source": ["aws.cloudwatch"], "detail-type": ["CloudWatch Alarm State Change"],
                    "detail": {"alarmName": [{"prefix": f"warden-{e}-"} for e in cfg.known_environments]}},
    }


def apply(p: dict[str, Any], iam: Any, events: Any, undo: bool = False) -> list[str]:
    """Make (or remove) the role and the rule; returns what it did, one line each. Safe to run again."""
    done = []
    if undo:
        if events.list_targets_by_rule(Rule=p["rule"]).get("Targets"):
            events.remove_targets(Rule=p["rule"], Ids=["runtime-bus"])
            done.append(f"removed the target of {p['rule']}")
        events.delete_rule(Name=p["rule"])
        iam.delete_role_policy(RoleName=p["role"], PolicyName="put-events")
        iam.delete_role(RoleName=p["role"])
        return [*done, f"deleted rule {p['rule']} and role {p['role']}"]
    try:
        role = iam.get_role(RoleName=p["role"])["Role"]
    except iam.exceptions.NoSuchEntityException:
        role = iam.create_role(RoleName=p["role"], AssumeRolePolicyDocument=json.dumps(p["trust"]),
                               PermissionsBoundary=p["boundary"], Tags=p["tags"],
                               Description="EventBridge forwards alarm changes to WARDEN's runtime Region")["Role"]
        done.append(f"created role {p['role']}")
    iam.put_role_policy(RoleName=p["role"], PolicyName="put-events", PolicyDocument=json.dumps(p["policy"]))
    events.put_rule(Name=p["rule"], EventPattern=json.dumps(p["pattern"]), State="ENABLED", Tags=p["tags"],
                    Description="WARDEN: the watched environments' alarm changes, to the runtime Region's bus")
    events.put_targets(Rule=p["rule"], Targets=[{"Id": "runtime-bus", "Arn": p["bus"], "RoleArn": role["Arn"]}])
    return [*done, f"put role policy, rule {p['rule']} in {p['global_region']} and its target {p['bus']}"]


def main(argv: list[str] | None = None) -> int:
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--apply", action="store_true")
    a.add_argument("--undo", action="store_true")
    args = a.parse_args(argv)
    import boto3

    account = boto3.client("sts").get_caller_identity()["Account"]
    p = plan(account)
    if not (args.apply or args.undo):
        print(json.dumps({k: v for k, v in p.items() if k != "tags"}, indent=2))
        print("dry run: nothing was changed (--apply to make it, --undo to remove it)")
        return 0
    lines = apply(p, boto3.client("iam"), boto3.client("events", region_name=p["global_region"]), undo=args.undo)
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
