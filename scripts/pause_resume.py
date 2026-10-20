"""Pause an environment to save money, and resume it, without losing its data (owner update 5, 2026-10-17).

    WARDEN_ENV=<env> python scripts/pause_resume.py snapshot --stack fullstack|runtime   # pause, BEFORE anything goes
    WARDEN_ENV=<env> python scripts/pause_resume.py restore-tables --imports PATH         # fullstack resume, before apply
    WARDEN_ENV=<env> python scripts/pause_resume.py stop-db                               # runtime pause, after apply
    WARDEN_ENV=<env> python scripts/pause_resume.py start-db                              # runtime resume, before apply
    WARDEN_ENV=<env> python scripts/pause_resume.py report --stack fullstack|runtime [--keep N]

What each data store is, and how it is kept:
  fullstack  the shop's Aurora (express, terraform/fullstack/aurora_express.py) - a cluster snapshot; the DynamoDB
             tables (TABLES) - an on-demand backup each. The pipeline then destroys the whole stack (it all bills
             while idle) and, on resume, restores the tables before `terraform apply` (and imports them into its
             state) and Aurora after it (`aurora_express.py create --from-snapshot latest`).
  runtime    WARDEN's audit database warden-<env>-audit (an Aurora cluster, or one RDS instance on the AWS Free plan)
             - a snapshot, then it is STOPPED, not deleted. Compute, the NAT and the self-alarms' actions go through
             SSM /warden/<env>/tf/paused and Terraform (terraform/runtime). RDS starts a stopped database again by
             itself after 7 days (AWS's rule): `report` says so.

Names: `<data store>-pause-<UTC time>` (warden-dev-carts-pause-20261017t113000z), tagged Project/Environment where AWS
allows it (a DynamoDB backup takes no tags: its name carries the environment). Resume takes the NEWEST available copy
by the time AWS made it - so the hand-made `<data store>-pause-<YYYYMMDD>` ones count too. No copy (a first install):
nothing is restored and Terraform / aurora_express.py create the data stores empty, as before.

⛔ Nothing here deletes a snapshot or a backup, ever. `report` keeps the newest --keep (default 3) and LISTS the older
ones for a person to delete by hand; the environment's boundary denies deleting a database snapshot and the deploy
guard a DynamoDB backup. ⛔ `snapshot` returns only when every copy is available, and fails otherwise - the pipeline
deletes or stops nothing after a failed step.

Standard library + boto3 only, like aurora_express.py: the pipelines install the infra-deploy group alone.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("aurora_express", ROOT / "terraform" / "fullstack" / "aurora_express.py")
ax = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ax)

# The full stack's DynamoDB tables (terraform/fullstack/*.tf), as <name suffix>: <terraform address>. A test holds this
# equal to the aws_dynamodb_table blocks there, so a new table is never left out of a pause.
TABLES = {"carts": "aws_dynamodb_table.carts"}
BACKUP_WAIT = {"Delay": 15, "MaxAttempts": 120}  # 30 minutes
# USD per GB-month in the environments' region (environments.yaml aws_region), from the AWS Price List API, read
# 2026-10-17 (RDS offer of 2026-10-06, DynamoDB offer of 2026-09-11). An estimate: Billing is the ground truth.
PRICE = {"aurora_snapshot": 0.023, "rds_snapshot": 0.095, "dynamodb_backup": 0.114, "rds_gp3_stopped": 0.131}
DAYS_PER_MONTH = 30.4


def tags() -> list[dict]:
    """A pause copy's tags: whose it is (the boundary refuses a request tagged for another environment)."""
    return [{"Key": "Project", "Value": "warden"}, {"Key": "Environment", "Value": ax.ENV},
            {"Key": "ManagedBy", "Value": "pause_resume.py"}, {"Key": "Purpose", "Value": "pause"}]


def _wait_backup(ddb, arn: str, name: str, log) -> dict:
    for _ in range(BACKUP_WAIT["MaxAttempts"]):
        desc = ddb.describe_backup(BackupArn=arn)["BackupDescription"]["BackupDetails"]
        if desc["BackupStatus"] == "AVAILABLE":
            log(f"backup {name}: available ({desc.get('BackupSizeBytes', 0)} bytes)")
            return desc
        if desc["BackupStatus"] != "CREATING":
            raise SystemExit(f"backup {name} is {desc['BackupStatus']}: nothing is deleted")
        time.sleep(BACKUP_WAIT["Delay"])
    raise SystemExit(f"backup {name} was not available in 30 minutes: nothing is deleted")


def _table(ddb, name: str) -> dict | None:
    try:
        return ddb.describe_table(TableName=name)["Table"]
    except ddb.exceptions.ResourceNotFoundException:
        return None


def backup_tables(ddb, log=print) -> list[str]:
    made = []
    for suffix in TABLES:
        table = ax.PREFIX + suffix
        if _table(ddb, table) is None:
            log(f"{table}: does not exist - nothing to keep")
            continue
        name = ax.pause_name(table)
        log(f"backing up {table} as {name}")
        arn = ddb.create_backup(TableName=table, BackupName=name)["BackupDetails"]["BackupArn"]
        _wait_backup(ddb, arn, name, log)
        made.append(name)
    return made


def _snapshot_status(rds, kind: str, name: str) -> str:
    if kind == "cluster":
        snaps = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=name)["DBClusterSnapshots"]
    else:
        snaps = rds.describe_db_snapshots(DBSnapshotIdentifier=name)["DBSnapshots"]
    return (snaps[0].get("Status") if snaps else "") or ""


def snapshot_db(rds, kind: str, ident: str, log=print) -> str:
    """A pause snapshot of a cluster or an instance; returns its name only once AWS says it is available."""
    name = ax.pause_name(ident)
    log(f"snapshot of {ident} as {name}")
    if kind == "cluster":
        rds.create_db_cluster_snapshot(DBClusterSnapshotIdentifier=name, DBClusterIdentifier=ident, Tags=tags())
        rds.get_waiter("db_cluster_snapshot_available").wait(DBClusterSnapshotIdentifier=name, WaiterConfig=ax.WAIT)
    else:
        rds.create_db_snapshot(DBSnapshotIdentifier=name, DBInstanceIdentifier=ident, Tags=tags())
        rds.get_waiter("db_snapshot_available").wait(DBSnapshotIdentifier=name, WaiterConfig=ax.WAIT)
    # ⛔ Checked, not assumed from the waiter: what is deleted or stopped next depends on this copy.
    status = _snapshot_status(rds, kind, name)
    if status != "available":
        raise SystemExit(f"snapshot {name} is {status or 'missing'}, not available: nothing is deleted or stopped")
    log(f"snapshot {name}: available")
    return name


def audit_db(rds) -> tuple[str, dict] | None:
    """WARDEN's audit database: ("cluster", it) or ("instance", it) - the module makes one or the other - or None."""
    ident = ax.PREFIX + "audit"
    c = ax.describe(rds, ident)
    if c is not None:
        return "cluster", c
    try:
        return "instance", rds.describe_db_instances(DBInstanceIdentifier=ident)["DBInstances"][0]
    except rds.exceptions.DBInstanceNotFoundFault:
        return None


def _db_status(kind: str, db: dict) -> str:
    return db.get("Status") if kind == "cluster" else db.get("DBInstanceStatus")


def _rds_snapshots(rds, kind: str) -> list[dict]:
    """Every manual snapshot of that kind in the region, as {name, time, status, gb}."""
    call, key, ident = (("describe_db_cluster_snapshots", "DBClusterSnapshots", "DBClusterSnapshotIdentifier")
                        if kind == "cluster" else ("describe_db_snapshots", "DBSnapshots", "DBSnapshotIdentifier"))
    out, marker = [], None
    while True:
        page = getattr(rds, call)(SnapshotType="manual", **({"Marker": marker} if marker else {}))
        out += [{"name": s[ident], "time": s.get("SnapshotCreateTime"), "status": s.get("Status", ""),
                 "gb": s.get("AllocatedStorage") or 0} for s in page.get(key) or []]
        marker = page.get("Marker")
        if not marker:
            return out


def _backups(ddb) -> list[dict]:
    """Every on-demand backup in the region, as {name, time, status, gb, arn, table}. Not by table: a paused table
    has been deleted."""
    out, start = [], None
    while True:
        page = ddb.list_backups(BackupType="USER", **({"ExclusiveStartBackupArn": start} if start else {}))
        out += [{"name": b["BackupName"], "time": b.get("BackupCreationDateTime"), "status": b.get("BackupStatus", ""),
                 "gb": (b.get("BackupSizeBytes") or 0) / 1e9, "arn": b["BackupArn"], "table": b.get("TableName")}
                for b in page.get("BackupSummaries") or []]
        start = page.get("LastEvaluatedBackupArn")
        if not start:
            return out


def snapshot(stack: str, clients: dict, log=print) -> list[str]:
    """Pause, first step: a copy of every data store of `stack`, each available before this returns."""
    rds = clients["rds"]
    if stack == "fullstack":
        made = []
        c = ax.describe(rds, ax.CLUSTER)
        if c is None:
            log(f"{ax.CLUSTER}: does not exist - nothing to keep")
        elif c.get("Status") != "available":
            raise SystemExit(f"{ax.CLUSTER} is {c.get('Status')}: no snapshot can be taken, so nothing is deleted")
        else:
            made.append(snapshot_db(rds, "cluster", ax.CLUSTER, log))
        return made + backup_tables(clients["dynamodb"], log)
    found = audit_db(rds)
    if found is None:
        log(f"{ax.PREFIX}audit: does not exist - nothing to keep")
        return []
    kind = found[0]
    ident, status = ax.PREFIX + "audit", _db_status(*found)
    if status == "stopped":
        # A stopped database cannot be copied, and has not changed since it stopped: the newest pause copy holds it.
        newest = ax.newest_pause(_rds_snapshots(rds, kind), ident, "name", "time", "status")
        if newest is not None:
            log(f"{ident} is stopped; its newest pause snapshot {newest['name']} is kept")
            return []
        log(f"{ident} is stopped with no pause snapshot: starting it for one")
        start_db(rds, log)
    elif status != "available":
        raise SystemExit(f"{ident} is {status}: no snapshot can be taken, so nothing is stopped")
    return [snapshot_db(rds, kind, ident, log)]


def stop_db(rds, log=print) -> None:
    """Runtime pause, last step: stop the audit database (never delete it)."""
    found = audit_db(rds)
    if found is None:
        log(f"{ax.PREFIX}audit: does not exist - nothing to stop")
        return
    kind, ident, status = found[0], ax.PREFIX + "audit", _db_status(*found)
    if status in ("stopped", "stopping"):
        log(f"{ident}: already {status}")
    elif kind == "cluster":
        rds.stop_db_cluster(DBClusterIdentifier=ident)
    else:
        rds.stop_db_instance(DBInstanceIdentifier=ident)
    log(f"{ident}: stopped - AWS starts it again by itself after 7 days; pause again then, or it bills")


def start_db(rds, log=print) -> None:
    """Runtime resume, first step: start the audit database and wait until it is available. A database that is gone
    while a pause snapshot of it exists is NOT recreated empty: that is a restore, for a person (docs/OPERATIONS.md)."""
    ident = ax.PREFIX + "audit"
    found = audit_db(rds)
    if found is None:
        kept = [s for kind in ("cluster", "instance") for s in _rds_snapshots(rds, kind)
                if ax.is_pause_name(ident, s["name"])]
        if kept:
            raise SystemExit(f"refusing: {ident} is gone but pause snapshots of it exist ({', '.join(s['name'] for s in kept)})"
                             " - restore it by hand (docs/OPERATIONS.md) so the audit is not started empty")
        log(f"{ident}: does not exist and no pause snapshot - Terraform creates it (a first install)")
        return
    kind, status = found[0], _db_status(*found)
    if status == "stopped":
        log(f"starting {ident}")
        if kind == "cluster":
            rds.start_db_cluster(DBClusterIdentifier=ident)
        else:
            rds.start_db_instance(DBInstanceIdentifier=ident)
    if kind == "cluster":
        rds.get_waiter("db_cluster_available").wait(DBClusterIdentifier=ident, WaiterConfig=ax.WAIT)
    else:
        rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=ident, WaiterConfig=ax.WAIT)
    log(f"{ident}: available")


def restore_tables(ddb, imports: pathlib.Path, log=print) -> dict[str, str]:
    """Fullstack resume, before `terraform apply`: each table that does not exist is restored from its newest pause
    backup; every table that exists is written to `imports` (<terraform address> <name>) for the pipeline to import
    into Terraform's state if it is not there yet. No backup: Terraform creates the table empty (a first install)."""
    restored, lines, backups = {}, [], None
    for suffix, address in TABLES.items():
        table = ax.PREFIX + suffix
        if _table(ddb, table) is None:
            backups = _backups(ddb) if backups is None else backups
            newest = ax.newest_pause(backups, table, "name", "time", "status")
            if newest is None:
                log(f"{table}: no pause backup - Terraform creates it empty (a first install)")
                continue
            log(f"restoring {table} from {newest['name']}")
            ddb.restore_table_from_backup(TargetTableName=table, BackupArn=newest["arn"])
            ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig=BACKUP_WAIT)
            restored[table] = newest["name"]
            log(f"{table}: restored from {newest['name']}")
        lines.append(f"{address} {table}\n")
    imports.write_text("".join(lines), encoding="utf-8")
    return restored


def _copies(stack: str, clients: dict) -> dict[str, tuple[str, list[dict]]]:
    """{data store: (its price key, every copy in the region of its kind)}."""
    rds = clients["rds"]
    if stack == "fullstack":
        backups = _backups(clients["dynamodb"])
        return {ax.CLUSTER: ("aurora_snapshot", _rds_snapshots(rds, "cluster"))} | {
            ax.PREFIX + s: ("dynamodb_backup", backups) for s in TABLES}
    found = audit_db(rds)
    kind = found[0] if found else "instance"
    return {ax.PREFIX + "audit": ("aurora_snapshot" if kind == "cluster" else "rds_snapshot", _rds_snapshots(rds, kind))}


def _report_one(base: str, price: str, items: list[dict], keep: int, out: dict, log) -> float:
    """One data store's pause and final copies, newest first; the pause copies past the newest `keep` are LISTED."""
    mine = sorted((i for i in items if ax.is_pause_name(base, i["name"]) or i["name"].startswith(f"{base}-final-")),
                  key=lambda i: (i["time"] is not None, i["time"] or 0, i["name"]), reverse=True)
    kept_pauses = [i["name"] for i in mine if ax.is_pause_name(base, i["name"])][:keep]
    daily = 0.0
    for i in mine:
        cost = i["gb"] * PRICE[price] / DAYS_PER_MONTH
        daily += cost
        older = ax.is_pause_name(base, i["name"]) and i["name"] not in kept_pauses
        out["older" if older else "kept"].append(i["name"])
        note = f" - older than the newest {keep}: a person may delete it" if older else ""
        log(f"  {i['name']}: {i['gb']:.2f} GB, about USD {cost:.4f} a day{note}")
    return daily


def _stopped_audit_cost(rds, log) -> float:
    found = audit_db(rds)
    if not found or _db_status(*found) not in ("stopped", "stopping"):
        return 0.0
    gb = found[1].get("AllocatedStorage") or 0
    # A stopped instance bills its provisioned storage; a stopped Aurora cluster its volume, counted in the snapshot.
    cost = gb * PRICE["rds_gp3_stopped"] / DAYS_PER_MONTH if found[0] == "instance" else 0.0
    log(f"  {ax.PREFIX}audit: stopped ({gb} GB of storage still billed, about USD {cost:.4f} a day); "
        "AWS starts it again by itself after 7 days")
    return cost


def report(stack: str, clients: dict, keep: int = 3, log=print) -> dict:
    """What stays while paused and what it costs a day (an estimate), the newest `keep` copies of each data store,
    and the older ones LISTED for a person - nothing is deleted."""
    out: dict = {"kept": [], "older": []}
    daily = sum(_report_one(base, price, items, keep, out, log) for base, (price, items) in _copies(stack, clients).items())
    if stack == "runtime":
        daily += _stopped_audit_cost(clients["rds"], log)
    log(f"while paused: about USD {daily:.3f} a day for the copies above, plus secrets (USD 0.40 a month each) and "
        "KMS keys (USD 1 a month each) that stay. Nothing was deleted.")
    out["daily_usd"] = round(daily, 4)
    return out


def main(argv: list[str] | None = None, *, clients=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["snapshot", "restore-tables", "stop-db", "start-db", "report"])
    ap.add_argument("--stack", choices=["fullstack", "runtime"], default="fullstack")
    ap.add_argument("--imports", type=pathlib.Path, help="restore-tables: where to write the tables to import")
    ap.add_argument("--keep", type=int, default=3, help="report: the newest copies kept per data store (default 3)")
    args = ap.parse_args(argv)
    env = os.environ.get("WARDEN_ENV", "")
    if not env:
        raise SystemExit("refusing: set WARDEN_ENV to the environment to pause or resume")
    ax.use(env)
    if args.keep < 1:
        raise SystemExit("refusing: --keep must be 1 or more")
    if args.cmd == "restore-tables" and not args.imports:
        raise SystemExit("refusing: restore-tables needs --imports PATH")
    if clients is None:
        import boto3

        session = boto3.Session(region_name=os.environ.get("AWS_REGION") or None)
        clients = {"rds": session.client("rds"), "dynamodb": session.client("dynamodb")}
    if args.cmd == "snapshot":
        print(json.dumps({"snapshots": snapshot(args.stack, clients)}))
    elif args.cmd == "restore-tables":
        restore_tables(clients["dynamodb"], args.imports)
    elif args.cmd == "stop-db":
        stop_db(clients["rds"])
    elif args.cmd == "start-db":
        start_db(clients["rds"])
    else:
        report(args.stack, clients, args.keep)
    return 0


if __name__ == "__main__":
    sys.exit(main())
