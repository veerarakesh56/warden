"""Aurora PostgreSQL in EXPRESS configuration for the Wave 4 stack. Part of the INFRA pipeline.

    WARDEN_ENV=<env> python terraform/fullstack/aurora_express.py create   [--stack PATH]   # after terraform apply
    WARDEN_ENV=<env> python terraform/fullstack/aurora_express.py create --from-snapshot latest|<id>   # resume
    WARDEN_ENV=<env> python terraform/fullstack/aurora_express.py status   [--stack PATH]
    WARDEN_ENV=<env> python terraform/fullstack/aurora_express.py destroy  [--stack PATH]   # before terraform destroy

The environment is WARDEN_ENV, and nothing else: with none set the script refuses, and a stack.json from
another environment is refused (it must never act on dev unless told). The region is
AWS_REGION (or stack.json's `region`). --stack (default ~/warden-fullstack-build/stack.json) must lie
there, in the temp folder (RUNNER_TEMP) or in the working directory (warden.paths).

⛔ WHY THIS IS NOT TERRAFORM (docs/FULLSTACK-LAB.md section 1). The
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
          --from-snapshot latest|<id> (resume): a cluster that does not exist yet is restored from that cluster
          snapshot - `latest` is the newest `<cluster>-pause-...` one, or none on a first install (then the
          cluster is created empty, as without the option). An existing cluster is never touched by it.
status    prints what exists. Exit 0 when the cluster is available, 1 otherwise.
destroy   deletes the instances, then the cluster, and waits until it is gone. The cluster is never deleted
          without a final snapshot, <cluster>-final-<UTC time>, tagged like the cluster and checked to exist
          afterwards; the boundary denies deleting snapshots, so an operator removes old ones by hand.

Standard library + boto3 only: the infra pipeline must not depend on WARDEN or the apps.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))  # warden.paths is stdlib only: the
# infra deploy job installs boto3 and no package

from warden import paths  # after the sys.path line above, deliberately

# One environment per process, set by use() from WARDEN_ENV in main(): never a default.
# Set by use(). One per line: a chained `= ""` made one literal flow into the secret's name AND the cluster's,
# and CodeQL read every log of the cluster name as logging a secret.
ENV = ""
PREFIX = ""
CLUSTER = ""
SECRET_ID = ""
APP_USER = ""
TAGS: list[dict] = []
DB_NAME = "shop"
MASTER_USER = "postgres"   # express configuration's master user; it cannot be chosen
PORT = 5432
ACU = {"MinCapacity": 0.5, "MaxCapacity": 2.0}
DEFAULT_STACK = pathlib.Path.home() / "warden-fullstack-build" / "stack.json"
WAIT = {"Delay": 30, "MaxAttempts": 80}   # 40 minutes; express is fast, a reader is not


def use(env: str) -> None:
    """The names of one environment's stack: warden-<env>-aurora, warden-<env>-db-app, its tags."""
    global ENV, PREFIX, CLUSTER, SECRET_ID, APP_USER, TAGS
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", env):
        raise SystemExit(f"refusing: {env!r} is not an environment name")
    ENV, PREFIX = env, f"warden-{env}-"
    CLUSTER = PREFIX + "aurora"
    SECRET_ID = PREFIX + "db-app"  # the Secrets Manager secret's NAME - it holds endpoints, never a password
    # The application's login, as data.tf names it (db_users): the secret said "app", which no IAM grant names
    # and bootstrap.sql no longer creates.
    APP_USER = f"warden_{env.replace('-', '_')}_app"
    TAGS = [{"Key": "Project", "Value": "warden"}, {"Key": "Environment", "Value": ENV},
            {"Key": "ManagedBy", "Value": "aurora_express.py"}, {"Key": "Lifecycle", "Value": "ephemeral"}]


def guard(cluster: str) -> None:
    """⛔ This script creates and DELETES a database cluster. Only this environment's own: a name prefix let
    WARDEN_ENV=qa delete warden-qa-prod-aurora."""
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
        # What an rds-db:connect grant names the cluster by (render_env_iam.py --cluster-resource-id).
        "aurora_cluster_resource_id": c.get("DbClusterResourceId", ""),
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
    # Checked here too, beside the read and the write (Sonar pythonsecurity:S2083).
    real = pathlib.Path(path).expanduser().resolve()
    bases = [b for b in (pathlib.Path(r).expanduser().resolve() for r in paths.work_roots()) if b.parent != b]
    if not any(real.is_relative_to(b) for b in bases):  # the form audit.key_path uses (S8707 cleared there)
        raise SystemExit(f"refused: {path} is outside the places the tools work ({', '.join(map(str, bases))})")
    if not real.exists():
        raise SystemExit(f"no {path}: write it first with `terraform output -json` (README)")
    with open(real, encoding="utf-8") as src:
        raw = json.loads(src.read())
    wrapped = any(isinstance(v, dict) and "value" in v for v in raw.values())
    for key, value in values.items():
        if wrapped:
            raw[key] = {"value": value, "sensitive": False, "type": "string" if isinstance(value, str) else "object"}
        else:
            raw[key] = value
    with open(real, "w", encoding="utf-8") as out:
        out.write(json.dumps(raw, indent=1))


def create(rds, sm, stack: pathlib.Path, cluster: str | None = None, log=print) -> dict:
    cluster = cluster or CLUSTER
    guard(cluster)
    if describe(rds, cluster) is None:
        log(f"creating {cluster} (express configuration; bootstrap-db creates database {DB_NAME})")
        rds.create_db_cluster(DBClusterIdentifier=cluster, Engine="aurora-postgresql",
                              # No DatabaseName: express refuses it (InvalidParameterCombination, seen
                              # live, despite the doc) - bootstrap-db creates DB_NAME instead.
                              WithExpressConfiguration=True, Tags=TAGS)
    else:
        log(f"{cluster} exists - refreshing the secret and stack.json only")
    c = _wait_cluster(rds, cluster)
    # Express is IAM database authentication only (seen live) - checked, not assumed: with it off, every
    # identity's IAM-token login fails and a password would be the only way in.
    if c.get("IAMDatabaseAuthenticationEnabled") is not True:
        raise SystemExit(f"{cluster}: IAM database authentication is not enabled - refusing to go on")

    c = _set_capacity(rds, cluster, c, log)
    _add_reader(rds, cluster, c, log)
    rds.get_waiter("db_instance_available").wait(
        Filters=[{"Name": "db-cluster-id", "Values": [cluster]}], WaiterConfig=WAIT)

    found = facts(rds, cluster)
    sm.put_secret_value(SecretId=SECRET_ID, SecretString=json.dumps({
        "username": APP_USER, "dbname": DB_NAME, "port": PORT,
        "host": found["aurora_writer_endpoint"], "reader": found["aurora_reader_endpoint"]}))
    merge_stack(stack, found)
    log(f"writer {found['aurora_writer_instance']}, reader endpoint {found['aurora_reader_endpoint']}; "
        f"{SECRET_ID} and {stack} updated")
    return found


def _set_capacity(rds, cluster: str, c: dict, log) -> dict:
    """Serverless v2 at ACU: changed when it differs, then polled until it IS the target and the cluster is
    available again. The cluster as last described."""
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
    return c


def _add_reader(rds, cluster: str, c: dict, log) -> None:
    """The reader <cluster>-2 (promotion tier 1, another AZ than the writer's when there is one), unless it is
    already a member or the account's plan allows no more instances."""
    reader = f"{cluster}-2"  # named after THIS cluster, so --cluster never attaches a reader elsewhere
    members = {m["DBInstanceIdentifier"] for m in c.get("DBClusterMembers") or []}
    if reader not in members:
        writer_az = next((i.get("AvailabilityZone") for i in instances(rds, cluster)
                          if i["DBInstanceIdentifier"] == writer_of(c)), None)
        other = next((z for z in c.get("AvailabilityZones") or [] if z != writer_az), None)
        log(f"adding reader {reader}" + (f" in {other}" if other else ""))
        try:
            rds.create_db_instance(DBInstanceIdentifier=reader, DBClusterIdentifier=cluster,
                                   Engine="aurora-postgresql", DBInstanceClass="db.serverless",
                                   PromotionTier=1, Tags=TAGS, **({"AvailabilityZone": other} if other else {}))
        except Exception as exc:  # one refusal is expected and named; any other still stops the build
            # The AWS Free plan's limit on database instances (WARDEN's own audit database holds one): "You reached the
            # maximum number of instances available with free plan accounts". The cluster's reader
            # endpoint then serves the writer; the faults that need a second instance (write-to-reader, failover)
            # cannot run on this account.
            if (getattr(exc, "response", None) or {}).get("Error", {}).get("Code") != "InstanceQuotaExceeded":
                raise
            log(f"no reader {reader}: the account's plan allows no more database instances - the reader endpoint "
                "serves the writer, and the reader and failover faults (fs-14, fs-15) cannot run here")


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


def utc_stamp(now: datetime.datetime | None = None) -> str:
    """The UTC time in a snapshot's name, e.g. 20261017t113000z: lower case, as RDS stores an identifier; letters and
    digits only, so the name keeps RDS's rule (letters, digits, single hyphens) and DynamoDB's for a backup."""
    now = (now or datetime.datetime.now(datetime.UTC)).astimezone(datetime.UTC)
    return f"{now:%Y%m%dt%H%M%Sz}"


def final_snapshot_name(cluster: str, now: datetime.datetime | None = None) -> str:
    """The final snapshot's name: `<cluster>-final-<UTC time>`, e.g. warden-dev-aurora-final-20261017t113000z."""
    return f"{cluster}-final-{utc_stamp(now)}"


def pause_name(base: str, now: datetime.datetime | None = None) -> str:
    """A pause copy's name: `<data store>-pause-<UTC time>`, e.g. warden-dev-carts-pause-20261017t113000z."""
    return f"{base}-pause-{utc_stamp(now)}"


def is_pause_name(base: str, name: str) -> bool:
    """`<base>-pause-<UTC time>` as the pipelines name it, or `<base>-pause-<YYYYMMDD>` as a person made one by hand.
    Another data store whose name starts like this one (warden-dev-aurora-2) is not it."""
    return re.fullmatch(rf"{re.escape(base.lower())}-pause-\d{{8}}(t\d{{6}}z)?", (name or "").lower()) is not None


def newest_pause(items: list[dict], base: str, name_key: str, time_key: str, status_key: str) -> dict | None:
    """The newest usable pause copy of `base`: by the time AWS says it was made, not by its name - a hand-made one
    carries a date only. Only a copy whose status is available counts."""
    usable = [i for i in items if is_pause_name(base, i.get(name_key, ""))
              and str(i.get(status_key, "")).lower() == "available"]
    oldest = datetime.datetime.min.replace(tzinfo=datetime.UTC)
    return max(usable, key=lambda i: (i.get(time_key) or oldest, i.get(name_key, "")), default=None)


STALE_MARGIN = datetime.timedelta(hours=1)  # a pause's own final snapshot follows its pause snapshot within it


def refuse_a_stale_pause(snapshots: list[dict], cluster: str) -> None:
    """⛔ A `destroy` after the last pause leaves a final snapshot newer than every pause copy: `latest` would bring back
    older data, and the tables' pause backups are older still (destroy makes none). Refused, both named, so a person
    picks one. A pause makes its own final snapshot right after its pause copy: within the margin."""
    def newest(kind):
        found = [s for s in snapshots if str(s.get("Status", "")).lower() == "available"
                 and (is_pause_name(cluster, s.get("DBClusterSnapshotIdentifier", "")) if kind == "pause"
                      else s.get("DBClusterSnapshotIdentifier", "").lower().startswith(f"{cluster}-final-"))]
        return max(found, key=lambda s: s.get("SnapshotCreateTime") or datetime.datetime.min.replace(tzinfo=datetime.UTC),
                   default=None)

    pause, final = newest("pause"), newest("final")
    if final is None or not final.get("SnapshotCreateTime"):
        return
    if pause is None or final["SnapshotCreateTime"] > (pause.get("SnapshotCreateTime") or final["SnapshotCreateTime"]) \
            + STALE_MARGIN:
        raise SystemExit(f"refusing `latest`: {final['DBClusterSnapshotIdentifier']} (a destroy) is newer than the newest "
                         f"pause copy {pause['DBClusterSnapshotIdentifier'] if pause else '(none)'} - resume would bring "
                         "back older data. Pick one with --from-snapshot <id> (and restore the tables by hand).")


def cluster_snapshots(rds) -> list[dict]:
    """Every manual cluster snapshot in the region. Not by cluster: RDS filters by an EXISTING cluster only, and a
    paused one has been deleted."""
    out, marker = [], None
    while True:
        page = rds.describe_db_cluster_snapshots(SnapshotType="manual", **({"Marker": marker} if marker else {}))
        out += page.get("DBClusterSnapshots") or []
        marker = page.get("Marker")
        if not marker:
            return out


def restore(rds, cluster: str, snapshot: str, log=print) -> str | None:
    """Resume: bring a cluster that does not exist back from a cluster snapshot - `latest` is the newest pause one.
    Returns the snapshot used, or None when there is none (a first install: create() makes it empty). An existing
    cluster is left as it is: a restore never overwrites data."""
    guard(cluster)
    if describe(rds, cluster) is not None:
        log(f"{cluster} exists - not restored from any snapshot")
        return None
    if snapshot == "latest":
        snapshots = cluster_snapshots(rds)
        refuse_a_stale_pause(snapshots, cluster)
        found = newest_pause(snapshots, cluster, "DBClusterSnapshotIdentifier", "SnapshotCreateTime", "Status")
        if found is None:
            log(f"no {cluster}-pause-... snapshot: {cluster} is created empty (a first install)")
            return None
        snapshot = found["DBClusterSnapshotIdentifier"]
    elif not any(s.get("DBClusterSnapshotIdentifier") == snapshot.lower() for s in cluster_snapshots(rds)):
        raise SystemExit(f"refusing: no cluster snapshot {snapshot!r} - nothing restored")
    log(f"restoring {cluster} from {snapshot} (express: internet access gateway, IAM authentication)")
    # Express has no VPC: the restore asks for the same shape (the API's EnableVPCNetworking=False with
    # EnableInternetAccessGateway=True needs IAM authentication), then the master user signs in by IAM only.
    rds.restore_db_cluster_from_snapshot(DBClusterIdentifier=cluster, SnapshotIdentifier=snapshot,
                                         Engine="aurora-postgresql", EnableVPCNetworking=False,
                                         EnableInternetAccessGateway=True, EnableIAMDatabaseAuthentication=True,
                                         ServerlessV2ScalingConfiguration=ACU, Tags=TAGS)
    _wait_cluster(rds, cluster)
    rds.modify_db_cluster(DBClusterIdentifier=cluster, MasterUserAuthenticationType="iam-db-auth",
                          ApplyImmediately=True)
    _wait_cluster(rds, cluster)
    # A restore makes the cluster only, never its instances: the writer is added here, then create() goes on.
    rds.create_db_instance(DBInstanceIdentifier=f"{cluster}-instance-1", DBClusterIdentifier=cluster,
                           Engine="aurora-postgresql", DBInstanceClass="db.serverless", Tags=TAGS)
    rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=f"{cluster}-instance-1", WaiterConfig=WAIT)
    log(f"{cluster} restored from {snapshot}")
    return snapshot


def _keep_final_snapshot(rds, name: str, log) -> None:
    """⛔ The snapshot must exist once the cluster is gone (B9): a missing one stops the teardown loudly. It is
    tagged like the cluster so the account sweep counts it as this environment's; a failed tag is said, not fatal."""
    found = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=name).get("DBClusterSnapshots") or []
    if not found:
        raise SystemExit(f"final snapshot {name} not found after the cluster was deleted - look before going on")
    snap = found[0]
    log(f"final snapshot {name}: {snap.get('Status')}")
    try:
        rds.add_tags_to_resource(ResourceName=snap["DBClusterSnapshotArn"], Tags=TAGS)
    except rds.exceptions.ClientError as e:  # the data is safe either way; the sweep reports it untagged
        log(f"WARNING: could not tag final snapshot {name} ({type(e).__name__}): the account sweep will list it UNTAGGED")


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
    snapshot = None
    if (describe(rds, cluster) or {}).get("Status") != "deleting":
        # ⛔ Never skip the final snapshot (B9): the data is kept, under a name that says which cluster and when.
        snapshot = final_snapshot_name(cluster)
        log(f"deleting cluster {cluster}, final snapshot {snapshot}")
        rds.delete_db_cluster(DBClusterIdentifier=cluster, SkipFinalSnapshot=False,
                              FinalDBSnapshotIdentifier=snapshot)
    rds.get_waiter("db_cluster_deleted").wait(DBClusterIdentifier=cluster, WaiterConfig=WAIT)
    if snapshot:
        _keep_final_snapshot(rds, snapshot, log)
    log(f"{cluster}: gone")


def _utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)


def _use_checked(stack_arg: pathlib.Path, stack: dict) -> None:
    """use(WARDEN_ENV) - refused with none set, with another environment's stack.json, or another app user."""
    env = os.environ.get("WARDEN_ENV", "")
    if not env:
        raise SystemExit("refusing: set WARDEN_ENV to the environment whose Aurora this is")
    if stack.get("environment") not in (None, env):
        raise SystemExit(f"refusing: {stack_arg} is environment {stack['environment']!r}, WARDEN_ENV is {env!r}")
    use(env)
    if (stack.get("db_users") or {}).get("app", APP_USER) != APP_USER:
        raise SystemExit(f"refusing: {stack_arg} names the app user {stack['db_users']['app']!r}, not {APP_USER!r}")


def _clients(region: str | None) -> dict:
    if not region:
        raise SystemExit("refusing: no region - set AWS_REGION or pass --region")
    import boto3

    session = boto3.Session(region_name=region)
    return {"rds": session.client("rds"), "secretsmanager": session.client("secretsmanager")}


def main(argv: list[str] | None = None, *, clients=None) -> int:
    # ⛔ FIRST, before argparse can print: a Windows console is cp1252 and the help text carries ⛔.
    _utf8_console()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["create", "status", "destroy"])
    ap.add_argument("--from-snapshot", default="none",
                    help="create only: latest (the newest pause snapshot) or a cluster snapshot id; default none")
    ap.add_argument("--stack", type=pathlib.Path, default=DEFAULT_STACK,
                    help="stack.json to merge the Aurora keys into (create)")
    ap.add_argument("--cluster", help="default: warden-<WARDEN_ENV>-aurora")
    ap.add_argument("--region", help="default: AWS_REGION, else stack.json's region")
    args = ap.parse_args(argv)
    # --stack comes from the command line and create writes it back: it must lie where the tools work - the
    # checkout, the temp folder (RUNNER_TEMP in the deploy job) or ~/warden-fullstack-build (warden.paths; Sonar
    # pythonsecurity:S2083). It is read and written through the checked path only.
    try:
        stack_path = paths.inside(args.stack)
    except ValueError as e:
        raise SystemExit(f"refused: {e}") from None
    stack = _read_stack(stack_path)
    _use_checked(args.stack, stack)
    args.cluster = args.cluster or CLUSTER
    guard(args.cluster)
    args.region = args.region or os.environ.get("AWS_REGION") or stack.get("region")
    clients = clients if clients is not None else _clients(args.region)
    rds = clients["rds"]
    if args.cmd == "create" and args.from_snapshot != "none":
        restore(rds, args.cluster, args.from_snapshot)
    if args.cmd == "create":
        create(rds, clients["secretsmanager"], stack_path, args.cluster)
    elif args.cmd == "status":
        return 0 if status(rds, args.cluster) else 1
    else:
        destroy(rds, args.cluster)
    return 0


if __name__ == "__main__":
    sys.exit(main())
