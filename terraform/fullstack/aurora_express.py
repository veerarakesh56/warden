"""Aurora PostgreSQL in EXPRESS configuration for the Wave 4 stack. Part of the INFRA pipeline.

    WARDEN_ENV=<env> python terraform/fullstack/aurora_express.py create   [--stack PATH]   # after terraform apply
    WARDEN_ENV=<env> python terraform/fullstack/aurora_express.py status   [--stack PATH]
    WARDEN_ENV=<env> python terraform/fullstack/aurora_express.py destroy  [--stack PATH]   # before terraform destroy

The environment is WARDEN_ENV, and nothing else: with none set the script refuses, and a stack.json from
another environment is refused (audit A-I-23: it acted on dev unless told otherwise). The region is
AWS_REGION (or stack.json's `region`).

⛔ WHY THIS IS NOT TERRAFORM (2026-09-26, docs/WAVE4-FULLSTACK.md "Free-plan constraints"). The
account is on the AWS Free plan, which creates an Aurora cluster only "WithExpressConfiguration",
and the AWS provider (6.66.0, and main) cannot set it. Express configuration means:
  - the cluster and ONE Aurora Serverless writer instance, named by AWS - this script records the name;
  - no VPC: the only way in is the Aurora internet access gateway (PostgreSQL wire protocol, 5432,
    IPv4), which cannot be disabled;
  - IAM database authentication only: no password anywhere. The master user is `postgres` and holds
    rds_iam. Tokens come from generate_db_auth_token and need rds-db:connect;
  - the default engine version and parameter group, an AWS-owned encryption key, no RDS Proxy.

create    creates cluster warden-<env>-aurora (database shop, tag Project=warden), sets
          Serverless v2 to 0.5-2 ACU, adds reader warden-<env>-aurora-2 (promotion tier 1, another
          AZ than the writer), writes the endpoints into the metadata secret warden-<env>-db-app and
          merges the Aurora keys into stack.json. A second run on an existing cluster changes
          nothing and refreshes both.
status    prints what exists. Exit 0 when the cluster is available, 1 otherwise.
destroy   deletes the instances, then the cluster (no final snapshot), and waits until it is gone.

Standard library + boto3 only: the infra pipeline must not depend on WARDEN or the apps.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time

# One environment per process, set by use() from WARDEN_ENV in main(): never a default.
ENV = PREFIX = CLUSTER = SECRET = APP_USER = ""
TAGS: list[dict] = []
DB_NAME = "shop"
MASTER_USER = "postgres"   # express configuration's master user; it cannot be chosen
PORT = 5432
ACU = {"MinCapacity": 0.5, "MaxCapacity": 2.0}
DEFAULT_STACK = pathlib.Path.home() / "warden-fullstack-build" / "stack.json"
WAIT = {"Delay": 30, "MaxAttempts": 80}   # 40 minutes; express is fast, a reader is not


def use(env: str) -> None:
    """The names of one environment's stack: warden-<env>-aurora, warden-<env>-db-app, its tags."""
    global ENV, PREFIX, CLUSTER, SECRET, APP_USER, TAGS
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", env):
        raise SystemExit(f"refusing: {env!r} is not an environment name")
    ENV, PREFIX = env, f"warden-{env}-"
    CLUSTER, SECRET = PREFIX + "aurora", PREFIX + "db-app"
    # The application's login, as data.tf names it (db_users): the secret said "app", which no IAM grant names
    # and bootstrap.sql no longer creates (seventh review, 2026-10-01).
    APP_USER = f"warden_{env.replace('-', '_')}_app"
    TAGS = [{"Key": "Project", "Value": "warden"}, {"Key": "Environment", "Value": ENV},
            {"Key": "ManagedBy", "Value": "aurora_express.py"}, {"Key": "Lifecycle", "Value": "ephemeral"}]


def guard(cluster: str) -> None:
    """⛔ This script creates and DELETES a database cluster. Only this environment's own: a name prefix let
    WARDEN_ENV=qa delete warden-qa-prod-aurora (seventh review, 2026-10-01)."""
    if not CLUSTER or cluster != CLUSTER:
        raise SystemExit(f"refusing: {cluster!r} is not this environment's cluster ({CLUSTER or 'none set'})")


def describe(rds, cluster: str) -> dict | None:
    try:
        return rds.describe_db_clusters(DBClusterIdentifier=cluster)["DBClusters"][0]
    except rds.exceptions.DBClusterNotFoundFault:
        return None


def instances(rds, cluster: str) -> list[dict]:
    return rds.describe_db_instances(
        Filters=[{"Name": "db-cluster-id", "Values": [cluster]}]).get("DBInstances") or []


def writer_of(c: dict) -> str:
    return next((m["DBInstanceIdentifier"] for m in c.get("DBClusterMembers") or [] if m.get("IsClusterWriter")), "")


def _wait_cluster(rds, cluster: str) -> dict:
    rds.get_waiter("db_cluster_available").wait(DBClusterIdentifier=cluster, WaiterConfig=WAIT)
    return describe(rds, cluster)


def facts(rds, cluster: str) -> dict:
    """The stack.json keys this script owns, read from the live cluster."""
    c = describe(rds, cluster)
    return {
        "aurora_cluster": cluster,
        "aurora_writer_endpoint": c["Endpoint"],
        "aurora_reader_endpoint": c["ReaderEndpoint"],
        "aurora_instance_endpoints": {i["DBInstanceIdentifier"]: (i.get("Endpoint") or {}).get("Address", "")
                                      for i in instances(rds, cluster)},
        "aurora_writer_instance": writer_of(c),
        "db_name": DB_NAME,
        "db_master_username": MASTER_USER,
    }


def _read_stack(path: pathlib.Path) -> dict:
    """stack.json's values, unwrapped; empty when there is none (status and destroy need none)."""
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {k: v["value"] if isinstance(v, dict) and "value" in v else v for k, v in raw.items()}


def merge_stack(path: pathlib.Path, values: dict) -> None:
    """Add keys to stack.json in the file's own format (`terraform output -json` wraps each value)."""
    if not path.exists():
        raise SystemExit(f"no {path}: write it first with `terraform output -json` (README)")
    raw = json.loads(path.read_text(encoding="utf-8"))
    wrapped = any(isinstance(v, dict) and "value" in v for v in raw.values())
    for key, value in values.items():
        raw[key] = {"value": value, "sensitive": False,
                    "type": "string" if isinstance(value, str) else "object"} if wrapped else value
    path.write_text(json.dumps(raw, indent=1), encoding="utf-8")


def create(rds, sm, stack: pathlib.Path, cluster: str | None = None, log=print) -> dict:
    cluster = cluster or CLUSTER
    guard(cluster)
    if describe(rds, cluster) is None:
        log(f"creating {cluster} (express configuration; bootstrap-db creates database {DB_NAME})")
        rds.create_db_cluster(DBClusterIdentifier=cluster, Engine="aurora-postgresql",
                              # No DatabaseName: express refuses it (InvalidParameterCombination, seen
                              # 2026-09-26, despite the doc) - bootstrap-db creates DB_NAME instead.
                              WithExpressConfiguration=True, Tags=TAGS)
    else:
        log(f"{cluster} exists - refreshing the secret and stack.json only")
    c = _wait_cluster(rds, cluster)

    scaling = c.get("ServerlessV2ScalingConfiguration") or {}
    if (scaling.get("MinCapacity"), scaling.get("MaxCapacity")) != (ACU["MinCapacity"], ACU["MaxCapacity"]):
        log(f"serverless v2 capacity {scaling or 'default'} -> {ACU}")
        rds.modify_db_cluster(DBClusterIdentifier=cluster, ServerlessV2ScalingConfiguration=ACU,
                              ApplyImmediately=True)
        # ⛔ The "available" waiter can answer on its first poll, before the modify has even moved the
        # cluster to `modifying`; adding the reader then fails with InvalidDBClusterStateFault. Poll
        # until the capacity IS the target and the cluster is available again.
        for _ in range(120):
            c = describe(rds, cluster) or {}
            got = c.get("ServerlessV2ScalingConfiguration") or {}
            if c.get("Status") == "available" and all(got.get(k) == v for k, v in ACU.items()):
                break
            time.sleep(15)
        else:
            raise SystemExit(f"{cluster}: capacity change to {ACU} did not complete in 30 minutes")

    reader = f"{cluster}-2"  # named after THIS cluster, so --cluster never attaches a reader elsewhere
    members = {m["DBInstanceIdentifier"] for m in c.get("DBClusterMembers") or []}
    if reader not in members:
        writer_az = next((i.get("AvailabilityZone") for i in instances(rds, cluster)
                          if i["DBInstanceIdentifier"] == writer_of(c)), None)
        other = next((z for z in c.get("AvailabilityZones") or [] if z != writer_az), None)
        log(f"adding reader {reader}" + (f" in {other}" if other else ""))
        rds.create_db_instance(DBInstanceIdentifier=reader, DBClusterIdentifier=cluster,
                               Engine="aurora-postgresql", DBInstanceClass="db.serverless",
                               PromotionTier=1, Tags=TAGS, **({"AvailabilityZone": other} if other else {}))
    rds.get_waiter("db_instance_available").wait(
        Filters=[{"Name": "db-cluster-id", "Values": [cluster]}], WaiterConfig=WAIT)

    found = facts(rds, cluster)
    sm.put_secret_value(SecretId=SECRET, SecretString=json.dumps({
        "username": APP_USER, "dbname": DB_NAME, "port": PORT,
        "host": found["aurora_writer_endpoint"], "reader": found["aurora_reader_endpoint"]}))
    merge_stack(stack, found)
    log(f"writer {found['aurora_writer_instance']}, reader endpoint {found['aurora_reader_endpoint']}; "
        f"{SECRET} and {stack} updated")
    return found


def status(rds, cluster: str | None = None, log=print) -> bool:
    cluster = cluster or CLUSTER
    guard(cluster)
    c = describe(rds, cluster)
    if c is None:
        log(f"{cluster}: does not exist")
        return False
    log(f"{cluster}: {c.get('Status')}  writer={writer_of(c) or '-'}  "
        f"iam_auth={c.get('IAMDatabaseAuthenticationEnabled')}  "
        f"internet_gateway={c.get('InternetAccessGatewayEnabled')}  "
        f"acu={c.get('ServerlessV2ScalingConfiguration')}")
    log(f"  endpoint {c.get('Endpoint')}  reader {c.get('ReaderEndpoint')}")
    for i in instances(rds, cluster):
        log(f"  {i['DBInstanceIdentifier']}: {i.get('DBInstanceStatus')} {i.get('AvailabilityZone')} "
            f"{(i.get('Endpoint') or {}).get('Address', '-')}")
    return c.get("Status") == "available"


def destroy(rds, cluster: str | None = None, log=print) -> None:
    cluster = cluster or CLUSTER
    guard(cluster)
    c = describe(rds, cluster)
    if c is None:
        log(f"{cluster}: already gone")
        return
    if c.get("DeletionProtection"):
        rds.modify_db_cluster(DBClusterIdentifier=cluster, DeletionProtection=False, ApplyImmediately=True)
        _wait_cluster(rds, cluster)
    for i in instances(rds, cluster):
        name = i["DBInstanceIdentifier"]
        if i.get("DBInstanceStatus") in ("creating", "modifying", "backing-up", "configuring-enhanced-monitoring"):
            # An interrupted `create` leaves an instance mid-creation; RDS refuses to delete it until
            # it settles (InvalidDBInstanceState), so wait for it rather than fail the teardown.
            log(f"waiting for {name} ({i.get('DBInstanceStatus')}) to settle before deleting it")
            rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=name, WaiterConfig=WAIT)
        if i.get("DBInstanceStatus") != "deleting":
            log(f"deleting instance {name}")
            rds.delete_db_instance(DBInstanceIdentifier=name)
    for i in instances(rds, cluster):
        rds.get_waiter("db_instance_deleted").wait(DBInstanceIdentifier=i["DBInstanceIdentifier"],
                                                   WaiterConfig=WAIT)
    if (describe(rds, cluster) or {}).get("Status") != "deleting":
        log(f"deleting cluster {cluster} (no final snapshot)")
        rds.delete_db_cluster(DBClusterIdentifier=cluster, SkipFinalSnapshot=True)
    rds.get_waiter("db_cluster_deleted").wait(DBClusterIdentifier=cluster, WaiterConfig=WAIT)
    log(f"{cluster}: gone")


def main(argv: list[str] | None = None, *, clients=None) -> int:
    # ⛔ FIRST, before argparse can print: a Windows console is cp1252 and the help text carries ⛔.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["create", "status", "destroy"])
    ap.add_argument("--stack", type=pathlib.Path, default=DEFAULT_STACK,
                    help="stack.json to merge the Aurora keys into (create)")
    ap.add_argument("--cluster", help="default: warden-<WARDEN_ENV>-aurora")
    ap.add_argument("--region", help="default: AWS_REGION, else stack.json's region")
    args = ap.parse_args(argv)
    stack = _read_stack(args.stack.expanduser())
    env = os.environ.get("WARDEN_ENV", "")
    if not env:
        raise SystemExit("refusing: set WARDEN_ENV to the environment whose Aurora this is")
    if stack.get("environment") not in (None, env):
        raise SystemExit(f"refusing: {args.stack} is environment {stack['environment']!r}, WARDEN_ENV is {env!r}")
    use(env)
    if (stack.get("db_users") or {}).get("app", APP_USER) != APP_USER:
        raise SystemExit(f"refusing: {args.stack} names the app user {stack['db_users']['app']!r}, not {APP_USER!r}")
    args.cluster = args.cluster or CLUSTER
    guard(args.cluster)
    args.region = args.region or os.environ.get("AWS_REGION") or stack.get("region")
    if clients is None and not args.region:
        raise SystemExit("refusing: no region - set AWS_REGION or pass --region")
    if clients is None:
        import boto3

        session = boto3.Session(region_name=args.region)
        clients = {"rds": session.client("rds"), "secretsmanager": session.client("secretsmanager")}
    rds = clients["rds"]
    if args.cmd == "create":
        create(rds, clients["secretsmanager"], args.stack.expanduser(), args.cluster)
    elif args.cmd == "status":
        return 0 if status(rds, args.cluster) else 1
    else:
        destroy(rds, args.cluster)
    return 0


if __name__ == "__main__":
    sys.exit(main())
