"""After `terraform destroy`: remove what Terraform never knew about, then PROVE nothing is left.

    python scripts/teardown_sweep.py              # dry run: list what would be removed, remove nothing
    python scripts/teardown_sweep.py --apply      # remove it, then sweep

⛔ WHY TERRAFORM DESTROY IS NOT ENOUGH. The benchmark creates resources Terraform has never heard of.
Every scenario that deploys a variant registers a new task-definition revision, and `ecs-02`'s revert
re-creates the log group as a brand new resource. Terraform destroys what is in its state; these are
not. And until 2026-09-11 none of them were tagged, so the sweep that reported "0 tagged resources
remaining" could not see them either - it would have declared the account clean while one revision
per scenario per wave sat in it.

So this checks by TAG and by NAME, and reports both.

⛔ WHAT IT WILL NOT TOUCH. `checkout` is an ordinary family name that could exist for real in some
account. A revision carrying a `Project` tag for anything other than this proving ground is refused
outright and reported, never removed. Untagged revisions in the proving-ground region are listed by
name before anything happens, so a dry run shows exactly what `--apply` would remove.

⚠ Stated so nobody discovers it later:
  - `AWSServiceRoleForECS` is deliberately KEPT. It is account-wide, other ECS use depends on it, and
    removing it here could break something that has nothing to do with this project.
  - An ECS cluster that has been deleted stays visible as INACTIVE for a while and cannot be removed
    any further. It costs nothing and ages out on AWS's side.
  - A task-definition revision that has been deleted goes to DELETE_IN_PROGRESS and disappears on
    AWS's schedule, not immediately.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from typing import Any

PROJECT = ("Project", "warden-proving-ground")
DEFAULT_REGION = "ap-south-2"


def _revisions(ecs: Any, family: str, status: str) -> list[str]:
    arns: list[str] = []
    token = None
    while True:
        kw: dict[str, Any] = {"familyPrefix": family, "status": status}
        if token:
            kw["nextToken"] = token
        page = ecs.list_task_definitions(**kw)
        # familyPrefix is a PREFIX: "checkout" also matches "checkout-legacy". Keep the exact family.
        arns += [a for a in page.get("taskDefinitionArns") or []
                 if a.rsplit("/", 1)[-1].rsplit(":", 1)[0] == family]
        token = page.get("nextToken")
        if not token:
            return arns


def _project_tag(ecs: Any, arn: str) -> str | None:
    """The revision's Project tag, or None when it has none."""
    resp = ecs.describe_task_definition(taskDefinition=arn, include=["TAGS"])
    tags = {t["key"]: t["value"] for t in resp.get("tags") or []}
    return tags.get(PROJECT[0])


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def plan(ecs: Any, logs: Any, family: str, log_group: str) -> dict[str, list[str]]:
    """Work out what would be removed. Reads only."""
    active = _revisions(ecs, family, "ACTIVE")
    inactive = _revisions(ecs, family, "INACTIVE")
    ours: list[str] = []
    refused: list[str] = []
    for arn in active + inactive:
        tag = _project_tag(ecs, arn)
        if tag not in (None, PROJECT[1]):
            refused.append(f"{arn.rsplit('/', 1)[-1]} (Project={tag})")
        else:
            ours.append(arn)
    groups = [g["logGroupName"] for g in
              logs.describe_log_groups(logGroupNamePrefix=log_group).get("logGroups") or []
              if g["logGroupName"] == log_group]
    return {
        "deregister": [a for a in active if a in ours],
        "delete": [a for a in ours],
        "log_groups": groups,
        "refused": refused,
    }


def apply(ecs: Any, logs: Any, todo: dict[str, list[str]]) -> None:
    for arn in todo["deregister"]:
        ecs.deregister_task_definition(taskDefinition=arn)
    # DeleteTaskDefinitions takes at most 10 per call, and only INACTIVE (deregistered) revisions.
    for batch in _chunks(todo["delete"], 10):
        ecs.delete_task_definitions(taskDefinitions=batch)
    for name in todo["log_groups"]:
        logs.delete_log_group(logGroupName=name)


def sweep(ecs: Any, logs: Any, tagging: Any, family: str, log_group: str,
          cluster: str) -> dict[str, list[str]]:
    """What is still there, by tag AND by name. Empty lists everywhere means clean."""
    tagged = [r["ResourceARN"] for r in tagging.get_resources(
        TagFilters=[{"Key": PROJECT[0], "Values": [PROJECT[1]]}],
    ).get("ResourceTagMappingList") or []]
    # An INACTIVE cluster cannot be removed further and costs nothing; listing it as "left behind"
    # would make the sweep permanently red for something no action can fix.
    tagged = [a for a in tagged if not (":cluster/" in a and a.endswith(f"/{cluster}")
                                        and _cluster_inactive(ecs, cluster))]
    running: list[str] = []
    try:
        running = ecs.list_tasks(cluster=cluster).get("taskArns") or []
    except Exception:  # noqa: BLE001 - a cluster that no longer exists has no running tasks
        running = []
    return {
        "tagged": tagged,
        "revisions_active": _revisions(ecs, family, "ACTIVE"),
        "revisions_inactive": _revisions(ecs, family, "INACTIVE"),
        "log_groups": [g["logGroupName"] for g in
                       logs.describe_log_groups(logGroupNamePrefix=log_group).get("logGroups") or []
                       if g["logGroupName"] == log_group],
        "running_tasks": running,
    }


def _cluster_inactive(ecs: Any, cluster: str) -> bool:
    clusters = ecs.describe_clusters(clusters=[cluster]).get("clusters") or []
    return bool(clusters) and clusters[0].get("status") == "INACTIVE"


def main(argv: list[str] | None = None, *, session: Any = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--family", default="checkout")
    parser.add_argument("--log-group", default="/ecs/checkout")
    parser.add_argument("--cluster", required=True, help="e.g. warden-pg-068d9d")
    parser.add_argument("--apply", action="store_true", help="actually remove; default is a dry run")
    args = parser.parse_args(argv)

    sys.stdout.reconfigure(encoding="utf-8")  # a Windows console is cp1252 and cannot print ⛔
    if session is None:
        import boto3

        session = boto3.Session(region_name=args.region)
    ecs, logs = session.client("ecs"), session.client("logs")
    tagging = session.client("resourcegroupstaggingapi")

    todo = plan(ecs, logs, args.family, args.log_group)
    print(f"{'APPLYING' if args.apply else 'DRY RUN'} in {args.region}")
    print(f"  deregister {len(todo['deregister'])} ACTIVE {args.family} revision(s)")
    print(f"  delete     {len(todo['delete'])} {args.family} revision(s): "
          + (", ".join(a.rsplit(":", 1)[-1] for a in todo["delete"]) or "none"))
    print(f"  log groups {todo['log_groups'] or 'none'}")
    if todo["refused"]:
        print(f"\n⛔ REFUSED - tagged for another project, left alone: {todo['refused']}")

    if args.apply:
        apply(ecs, logs, todo)

    left = sweep(ecs, logs, tagging, args.family, args.log_group, args.cluster)
    print("\nwhat is still there:")
    for key, values in left.items():
        print(f"  {key:20s} {len(values)}" + (f"   {values[:5]}" if values else ""))
    print("\nkept on purpose: AWSServiceRoleForECS (account-wide; other ECS use depends on it)")

    if not args.apply:
        print("\ndry run - nothing was removed. Re-run with --apply.")
        return 0
    # Revisions that were just deleted linger as INACTIVE / DELETE_IN_PROGRESS on AWS's schedule,
    # so "clean" is judged on what can still cost money or confuse a later sweep.
    dirty = left["tagged"] or left["revisions_active"] or left["log_groups"] or left["running_tasks"]
    print("\n⛔ NOT CLEAN - see above." if dirty else "\nclean.")
    return 1 if dirty else 0


if __name__ == "__main__":
    raise SystemExit(main())
