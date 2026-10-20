"""Pause and resume without losing data (owner update 5, 2026-10-17): scripts/pause_resume.py, aurora_express.py's
restore, the pipelines' order and the permissions they need. Fake AWS clients only; every guard here was plant-checked
(the PR lists them)."""

from __future__ import annotations

import datetime
import importlib.util
import json
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
FLOWS = ROOT / ".github" / "workflows"
UTC = datetime.UTC


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def pr():
    mod = _load("pause_resume", ROOT / "scripts" / "pause_resume.py")
    mod.ax.use("dev")
    mod.BACKUP_WAIT = {"Delay": 0, "MaxAttempts": 3}
    return mod


def _t(day: int, hour: int = 0) -> datetime.datetime:
    return datetime.datetime(2026, 10, day, hour, tzinfo=UTC)


class _NotFound(Exception):
    pass


class FakeRds:
    """A cluster or an instance, its snapshots, and waiters that settle at once (or never, with `stuck`)."""

    def __init__(self, cluster=None, instance=None, snapshots=(), stuck=False):
        self.cluster, self.instance, self.calls, self.stuck = cluster, instance, [], stuck
        self.cluster_snaps = {s["DBClusterSnapshotIdentifier"]: s for s in snapshots if "DBClusterSnapshotIdentifier" in s}
        self.db_snaps = {s["DBSnapshotIdentifier"]: s for s in snapshots if "DBSnapshotIdentifier" in s}
        self.exceptions = type("E", (), {"DBClusterNotFoundFault": _NotFound, "DBInstanceNotFoundFault": _NotFound,
                                         "ClientError": _NotFound})

    def _log(self, name, **kw):
        self.calls.append((name, kw))

    def describe_db_clusters(self, DBClusterIdentifier):
        if self.cluster is None or self.cluster["DBClusterIdentifier"] != DBClusterIdentifier:
            raise _NotFound(DBClusterIdentifier)
        return {"DBClusters": [self.cluster]}

    def describe_db_instances(self, DBInstanceIdentifier=None, Filters=None):
        if self.instance is None or (DBInstanceIdentifier and self.instance["DBInstanceIdentifier"] != DBInstanceIdentifier):
            if DBInstanceIdentifier:
                raise _NotFound(DBInstanceIdentifier)
            return {"DBInstances": []}
        return {"DBInstances": [self.instance]}

    def describe_db_cluster_snapshots(self, DBClusterSnapshotIdentifier=None, SnapshotType=None, Marker=None):
        self._log("describe_db_cluster_snapshots")
        snaps = list(self.cluster_snaps.values())
        if DBClusterSnapshotIdentifier:
            snaps = [s for s in snaps if s["DBClusterSnapshotIdentifier"] == DBClusterSnapshotIdentifier]
        return {"DBClusterSnapshots": snaps}

    def describe_db_snapshots(self, DBSnapshotIdentifier=None, SnapshotType=None, Marker=None):
        snaps = list(self.db_snaps.values())
        if DBSnapshotIdentifier:
            snaps = [s for s in snaps if s["DBSnapshotIdentifier"] == DBSnapshotIdentifier]
        return {"DBSnapshots": snaps}

    def create_db_cluster_snapshot(self, **kw):
        self._log("create_db_cluster_snapshot", **kw)
        name = kw["DBClusterSnapshotIdentifier"]
        self.cluster_snaps[name] = {"DBClusterSnapshotIdentifier": name, "Status": "creating",
                                    "SnapshotCreateTime": _t(20), "AllocatedStorage": 1}

    def create_db_snapshot(self, **kw):
        self._log("create_db_snapshot", **kw)
        name = kw["DBSnapshotIdentifier"]
        self.db_snaps[name] = {"DBSnapshotIdentifier": name, "Status": "creating", "SnapshotCreateTime": _t(20),
                               "AllocatedStorage": 20}

    def restore_db_cluster_from_snapshot(self, **kw):
        self._log("restore_db_cluster_from_snapshot", **kw)
        self.cluster = {"DBClusterIdentifier": kw["DBClusterIdentifier"], "Status": "creating"}

    def modify_db_cluster(self, **kw):
        self._log("modify_db_cluster", **kw)

    def create_db_instance(self, **kw):
        self._log("create_db_instance", **kw)

    def _set(self, status):
        target = self.cluster or self.instance
        target["Status" if self.cluster else "DBInstanceStatus"] = status

    def stop_db_cluster(self, **kw):
        self._log("stop_db_cluster", **kw)
        self._set("stopping")

    def stop_db_instance(self, **kw):
        self._log("stop_db_instance", **kw)
        self._set("stopping")

    def start_db_cluster(self, **kw):
        self._log("start_db_cluster", **kw)
        self._set("starting")

    def start_db_instance(self, **kw):
        self._log("start_db_instance", **kw)
        self._set("starting")

    def get_waiter(self, name):
        rds = self

        class W:
            def wait(self, **kw):
                rds._log("wait:" + name, **kw)
                if rds.stuck:
                    return
                if name == "db_cluster_snapshot_available":
                    rds.cluster_snaps[kw["DBClusterSnapshotIdentifier"]]["Status"] = "available"
                elif name == "db_snapshot_available":
                    rds.db_snaps[kw["DBSnapshotIdentifier"]]["Status"] = "available"
                elif name in ("db_cluster_available", "db_instance_available") and (rds.cluster or rds.instance):
                    rds._set("available")
        return W()


class FakeDdb:
    def __init__(self, tables=(), backups=(), fail=False):
        self.tables, self.backups, self.calls, self.fail = set(tables), list(backups), [], fail
        self.exceptions = type("E", (), {"ResourceNotFoundException": _NotFound})

    def describe_table(self, TableName):
        if TableName not in self.tables:
            raise _NotFound(TableName)
        return {"Table": {"TableName": TableName, "TableStatus": "ACTIVE"}}

    def create_backup(self, TableName, BackupName):
        self.calls.append(("create_backup", TableName, BackupName))
        arn = f"arn:aws:dynamodb:r:a:table/{TableName}/backup/0001"
        self.backups.append({"BackupName": BackupName, "BackupArn": arn, "BackupStatus": "CREATING",
                             "BackupCreationDateTime": _t(20), "TableName": TableName, "BackupSizeBytes": 2_000})
        return {"BackupDetails": {"BackupArn": arn}}

    def describe_backup(self, BackupArn):
        b = next(b for b in self.backups if b["BackupArn"] == BackupArn)
        b["BackupStatus"] = "DELETED" if self.fail else "AVAILABLE"
        return {"BackupDescription": {"BackupDetails": b}}

    def list_backups(self, BackupType, ExclusiveStartBackupArn=None):
        return {"BackupSummaries": self.backups}

    def restore_table_from_backup(self, TargetTableName, BackupArn):
        self.calls.append(("restore_table_from_backup", TargetTableName, BackupArn))
        self.tables.add(TargetTableName)

    def get_waiter(self, name):
        ddb = self

        class W:
            def wait(self, **kw):
                ddb.calls.append(("wait:" + name, kw["TableName"]))
        return W()


def _cluster(status="available"):
    return {"DBClusterIdentifier": "warden-dev-aurora", "Status": status}


def _csnap(name, day, status="available"):
    return {"DBClusterSnapshotIdentifier": name, "Status": status, "SnapshotCreateTime": _t(day), "AllocatedStorage": 1}


def _backup(name, day, status="AVAILABLE", table="warden-dev-carts"):
    return {"BackupName": name, "BackupArn": f"arn:aws:dynamodb:r:a:table/{table}/backup/{name}", "BackupStatus": status,
            "BackupCreationDateTime": _t(day), "TableName": table, "BackupSizeBytes": 1_000}


# --------------------------------------------------------------------------- names and the newest pick


def test_a_pause_copy_is_named_after_its_data_store_and_the_utc_time(pr):
    ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    when = datetime.datetime(2026, 10, 20, 11, 55, 0, tzinfo=ist)  # 06:25 UTC
    assert pr.ax.pause_name("warden-dev-carts", when) == "warden-dev-carts-pause-20261020t062500z"
    assert pr.ax.is_pause_name("warden-dev-carts", "warden-dev-carts-pause-20261020t062500z")


@pytest.mark.parametrize("name, ok", [
    ("warden-dev-aurora-pause-20261017", True),            # the laptop's, by hand: a date only
    ("warden-dev-aurora-pause-20261020t062500z", True),
    ("WARDEN-DEV-AURORA-PAUSE-20261017", True),            # RDS is case-insensitive
    ("warden-dev-aurora-final-20261017t062500z", False),   # a teardown's, not a pause
    ("warden-dev-aurora-2-pause-20261017", False),         # another data store
    ("warden-dev-aurora-pause-2026101", False),
    ("warden-dev-aurora-pause-20261017-copy", False),
])
def test_only_this_data_stores_pause_copies_count(pr, name, ok):
    assert pr.ax.is_pause_name("warden-dev-aurora", name) is ok


def test_resume_picks_the_newest_pause_copy_by_when_aws_made_it_not_by_its_name(pr):
    items = [_csnap("warden-dev-aurora-pause-20261017", 17),           # hand-made, date only
             _csnap("warden-dev-aurora-pause-20261018t090000z", 18),
             _csnap("warden-dev-aurora-pause-20261019t090000z", 19, status="creating"),  # not usable yet
             _csnap("warden-dev-aurora-final-20261020t090000z", 20)]   # not a pause copy
    got = pr.ax.newest_pause(items, "warden-dev-aurora", "DBClusterSnapshotIdentifier", "SnapshotCreateTime", "Status")
    assert got["DBClusterSnapshotIdentifier"] == "warden-dev-aurora-pause-20261018t090000z"
    # The hand-made one, alone or newer, is picked too - "20261017" sorts after "20261016t..." by name either way.
    items = [_csnap("warden-dev-aurora-pause-20261016t230000z", 16), _csnap("warden-dev-aurora-pause-20261017", 17)]
    got = pr.ax.newest_pause(items, "warden-dev-aurora", "DBClusterSnapshotIdentifier", "SnapshotCreateTime", "Status")
    assert got["DBClusterSnapshotIdentifier"] == "warden-dev-aurora-pause-20261017"
    # Made by hand at 20:00 the same day as a pipeline copy of 09:00: by name the 09:00 one sorts last, by time it
    # is older - the newer, hand-made one is picked.
    late = {**_csnap("warden-dev-aurora-pause-20261018", 18), "SnapshotCreateTime": _t(18, 20)}
    items = [_csnap("warden-dev-aurora-pause-20261018t090000z", 18) | {"SnapshotCreateTime": _t(18, 9)}, late]
    got = pr.ax.newest_pause(items, "warden-dev-aurora", "DBClusterSnapshotIdentifier", "SnapshotCreateTime", "Status")
    assert got["DBClusterSnapshotIdentifier"] == "warden-dev-aurora-pause-20261018"
    assert pr.ax.newest_pause([], "warden-dev-aurora", "a", "b", "c") is None


# --------------------------------------------------------------------------- pause: copies before anything goes


def test_pause_copies_aurora_and_every_table_and_returns_only_once_each_is_available(pr):
    rds, ddb = FakeRds(cluster=_cluster()), FakeDdb(tables={"warden-dev-carts"})
    made = pr.snapshot("fullstack", {"rds": rds, "dynamodb": ddb}, log=lambda *_: None)
    assert [re.sub(r"\d{8}t\d{6}z$", "<t>", m) for m in made] == ["warden-dev-aurora-pause-<t>",
                                                                  "warden-dev-carts-pause-<t>"]
    assert all(s["Status"] == "available" for s in rds.cluster_snaps.values())
    assert all(b["BackupStatus"] == "AVAILABLE" for b in ddb.backups)
    create = next(kw for n, kw in rds.calls if n == "create_db_cluster_snapshot")
    assert {"Key": "Environment", "Value": "dev"} in create["Tags"]


def test_pause_fails_when_the_aurora_snapshot_is_not_available(pr):
    """⛔ The pipeline destroys nothing after a failed step: the snapshot must BE available, not just waited for."""
    rds = FakeRds(cluster=_cluster(), stuck=True)
    with pytest.raises(SystemExit, match="not available: nothing is deleted"):
        pr.snapshot("fullstack", {"rds": rds, "dynamodb": FakeDdb()}, log=lambda *_: None)


def test_pause_fails_when_a_table_backup_does_not_become_available(pr):
    ddb = FakeDdb(tables={"warden-dev-carts"}, fail=True)
    with pytest.raises(SystemExit, match="is DELETED: nothing is deleted"):
        pr.snapshot("fullstack", {"rds": FakeRds(), "dynamodb": ddb}, log=lambda *_: None)


def test_pause_refuses_an_aurora_cluster_it_cannot_copy(pr):
    with pytest.raises(SystemExit, match="no snapshot can be taken, so nothing is deleted"):
        pr.snapshot("fullstack", {"rds": FakeRds(cluster=_cluster("modifying")), "dynamodb": FakeDdb()},
                    log=lambda *_: None)


def test_pause_of_a_stack_that_is_not_there_copies_nothing_and_says_so(pr):
    said = []
    assert pr.snapshot("fullstack", {"rds": FakeRds(), "dynamodb": FakeDdb()}, log=said.append) == []
    assert any("nothing to keep" in s for s in said)


def test_every_dynamodb_table_in_the_full_stack_is_paused(pr):
    tf = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "terraform" / "fullstack").glob("*.tf"))
    blocks = re.findall(r'^resource "aws_dynamodb_table" "(\w+)"', tf, re.MULTILINE)
    assert sorted(pr.TABLES.values()) == sorted(f"aws_dynamodb_table.{b}" for b in blocks)
    for suffix, address in pr.TABLES.items():
        block = tf.split(f'resource "aws_dynamodb_table" "{address.split(".")[1]}"', 1)[1]
        assert f'name           = "${{local.name}}-{suffix}"' in block.split("\n}", 1)[0]


# --------------------------------------------------------------------------- runtime: the audit database


def _audit_instance(status="available"):
    return {"DBInstanceIdentifier": "warden-ops-audit", "DBInstanceStatus": status, "AllocatedStorage": 20}


def _ops(pr):
    pr.ax.use("ops")
    return pr


def test_runtime_pause_snapshots_the_audit_database_then_stop_db_stops_it(pr):
    pr = _ops(pr)
    rds = FakeRds(instance=_audit_instance())
    [made] = pr.snapshot("runtime", {"rds": rds}, log=lambda *_: None)
    assert made.startswith("warden-ops-audit-pause-") and rds.db_snaps[made]["Status"] == "available"
    pr.stop_db(rds, log=lambda *_: None)
    assert ("stop_db_instance", {"DBInstanceIdentifier": "warden-ops-audit"}) in rds.calls
    assert not [n for n, _ in rds.calls if "delete" in n]


def test_runtime_pause_of_a_stopped_database_keeps_its_newest_pause_snapshot(pr):
    """The laptop's pause of 2026-10-17: stopped, with warden-ops-audit-pause-20261017 made by hand."""
    pr = _ops(pr)
    snap = {"DBSnapshotIdentifier": "warden-ops-audit-pause-20261017", "Status": "available",
            "SnapshotCreateTime": _t(17), "AllocatedStorage": 20}
    rds = FakeRds(instance=_audit_instance("stopped"), snapshots=[snap])
    assert pr.snapshot("runtime", {"rds": rds}, log=lambda *_: None) == []
    assert not [n for n, _ in rds.calls if n.startswith(("create", "start"))]


def test_runtime_pause_of_a_stopped_database_with_no_copy_starts_it_for_one(pr):
    pr = _ops(pr)
    rds = FakeRds(instance=_audit_instance("stopped"))
    [made] = pr.snapshot("runtime", {"rds": rds}, log=lambda *_: None)
    names = [n for n, _ in rds.calls]
    assert names.index("start_db_instance") < names.index("create_db_snapshot") and made in rds.db_snaps


def test_runtime_pause_of_an_aurora_audit_cluster(pr):
    pr = _ops(pr)
    rds = FakeRds(cluster={"DBClusterIdentifier": "warden-ops-audit", "Status": "available"})
    [made] = pr.snapshot("runtime", {"rds": rds}, log=lambda *_: None)
    assert rds.cluster_snaps[made]["Status"] == "available"
    pr.stop_db(rds, log=lambda *_: None)
    assert ("stop_db_cluster", {"DBClusterIdentifier": "warden-ops-audit"}) in rds.calls


def test_runtime_resume_starts_the_database_and_waits_for_it(pr):
    pr = _ops(pr)
    rds = FakeRds(instance=_audit_instance("stopped"))
    pr.start_db(rds, log=lambda *_: None)
    assert [n for n, _ in rds.calls] == ["start_db_instance", "wait:db_instance_available"]
    assert rds.instance["DBInstanceStatus"] == "available"


def test_runtime_resume_never_lets_a_lost_audit_database_be_recreated_empty(pr):
    """⛔ Gone, with a pause snapshot of it: refused - Terraform would make an EMPTY audit."""
    pr = _ops(pr)
    snap = {"DBSnapshotIdentifier": "warden-ops-audit-pause-20261017", "Status": "available",
            "SnapshotCreateTime": _t(17), "AllocatedStorage": 20}
    with pytest.raises(SystemExit, match="restore it by hand"):
        pr.start_db(FakeRds(snapshots=[snap]), log=lambda *_: None)


def test_runtime_resume_on_a_first_install_lets_terraform_create_the_database(pr):
    pr = _ops(pr)
    said = []
    pr.start_db(FakeRds(), log=said.append)
    assert "a first install" in said[-1]


# --------------------------------------------------------------------------- resume: the tables and Aurora


def test_resume_restores_a_missing_table_from_its_newest_pause_backup_and_lists_it_for_import(pr, tmp_path):
    ddb = FakeDdb(backups=[_backup("warden-dev-carts-pause-20261017", 17),
                           _backup("warden-dev-carts-pause-20261018t090000z", 18),
                           _backup("warden-dev-carts-pause-20261019t090000z", 19, status="CREATING"),
                           _backup("warden-dev-orders-pause-20261020t090000z", 20, table="warden-dev-orders")])
    imports = tmp_path / "imports.txt"
    restored = pr.restore_tables(ddb, imports, log=lambda *_: None)
    assert restored == {"warden-dev-carts": "warden-dev-carts-pause-20261018t090000z"}
    assert ("restore_table_from_backup", "warden-dev-carts",
            "arn:aws:dynamodb:r:a:table/warden-dev-carts/backup/warden-dev-carts-pause-20261018t090000z") in ddb.calls
    assert imports.read_text(encoding="utf-8") == "aws_dynamodb_table.carts warden-dev-carts\n"


def test_resume_picks_up_the_laptops_hand_made_backup(pr, tmp_path):
    ddb = FakeDdb(backups=[_backup("warden-dev-carts-pause-20261017", 17)])
    assert pr.restore_tables(ddb, tmp_path / "i.txt", log=lambda *_: None) == {
        "warden-dev-carts": "warden-dev-carts-pause-20261017"}


def test_resume_never_overwrites_a_table_that_exists(pr, tmp_path):
    ddb = FakeDdb(tables={"warden-dev-carts"}, backups=[_backup("warden-dev-carts-pause-20261017", 17)])
    assert pr.restore_tables(ddb, tmp_path / "i.txt", log=lambda *_: None) == {}
    assert not [c for c in ddb.calls if c[0] == "restore_table_from_backup"]
    assert (tmp_path / "i.txt").read_text(encoding="utf-8") == "aws_dynamodb_table.carts warden-dev-carts\n"


def test_resume_on_a_first_install_restores_nothing_and_terraform_creates_the_table(pr, tmp_path):
    said = []
    assert pr.restore_tables(FakeDdb(), tmp_path / "i.txt", log=said.append) == {}
    assert (tmp_path / "i.txt").read_text(encoding="utf-8") == ""
    assert any("a first install" in s for s in said)


def test_aurora_resume_restores_the_newest_pause_snapshot_as_an_express_cluster(pr):
    ax = pr.ax
    rds = FakeRds(snapshots=[_csnap("warden-dev-aurora-pause-20261017", 17),
                             _csnap("warden-dev-aurora-pause-20261016t090000z", 16)])
    assert ax.restore(rds, "warden-dev-aurora", "latest", log=lambda *_: None) == "warden-dev-aurora-pause-20261017"
    restore = next(kw for n, kw in rds.calls if n == "restore_db_cluster_from_snapshot")
    assert restore["SnapshotIdentifier"] == "warden-dev-aurora-pause-20261017"
    assert (restore["EnableVPCNetworking"], restore["EnableInternetAccessGateway"],
            restore["EnableIAMDatabaseAuthentication"]) == (False, True, True)
    assert ("modify_db_cluster", {"DBClusterIdentifier": "warden-dev-aurora", "MasterUserAuthenticationType": "iam-db-auth",
                                  "ApplyImmediately": True}) in rds.calls
    writer = next(kw for n, kw in rds.calls if n == "create_db_instance")
    assert writer["DBInstanceIdentifier"] == "warden-dev-aurora-instance-1" and writer["DBInstanceClass"] == "db.serverless"


def test_aurora_resume_on_a_first_install_creates_it_empty(pr):
    said = []
    rds = FakeRds()
    assert pr.ax.restore(rds, "warden-dev-aurora", "latest", log=said.append) is None
    assert not [n for n, _ in rds.calls if n.startswith("restore")] and "a first install" in said[-1]


def test_aurora_resume_never_touches_a_cluster_that_exists(pr):
    rds = FakeRds(cluster=_cluster(), snapshots=[_csnap("warden-dev-aurora-pause-20261017", 17)])
    assert pr.ax.restore(rds, "warden-dev-aurora", "latest", log=lambda *_: None) is None
    assert not [n for n, _ in rds.calls if n.startswith(("restore", "modify", "create"))]


def test_aurora_resume_refuses_a_named_snapshot_that_is_not_there(pr):
    with pytest.raises(SystemExit, match="no cluster snapshot"):
        pr.ax.restore(FakeRds(), "warden-dev-aurora", "warden-dev-aurora-pause-20990101", log=lambda *_: None)


def test_aurora_create_restores_only_when_asked(pr, tmp_path, monkeypatch):
    """`create` alone never restores; `--from-snapshot latest` restores before the usual create steps."""
    seen = []
    monkeypatch.setattr(pr.ax, "restore", lambda rds, cluster, snap, log=print: seen.append(snap))
    monkeypatch.setattr(pr.ax, "create", lambda *a, **k: seen.append("create"))
    monkeypatch.setenv("WARDEN_ENV", "dev")
    clients = {"rds": FakeRds(), "secretsmanager": object()}
    pr.ax.main(["create", "--stack", str(tmp_path / "s.json"), "--region", "r"], clients=clients)
    assert seen == ["create"]
    pr.ax.main(["create", "--stack", str(tmp_path / "s.json"), "--region", "r", "--from-snapshot", "latest"],
               clients=clients)
    assert seen == ["create", "latest", "create"]


# --------------------------------------------------------------------------- what stays, never deleted


def test_report_keeps_the_newest_n_and_lists_older_ones_for_a_person_deleting_nothing(pr):
    rds = FakeRds(snapshots=[_csnap(f"warden-dev-aurora-pause-202610{d}t090000z", d) for d in (14, 15, 16, 17)]
                  + [_csnap("warden-dev-aurora-final-20261013t090000z", 13)])
    ddb = FakeDdb(backups=[_backup("warden-dev-carts-pause-20261017", 17)])
    said = []
    out = pr.report("fullstack", {"rds": rds, "dynamodb": ddb}, keep=3, log=said.append)
    assert out["older"] == ["warden-dev-aurora-pause-20261014t090000z"]
    assert "warden-dev-aurora-final-20261013t090000z" in out["kept"] and "warden-dev-carts-pause-20261017" in out["kept"]
    assert any("a person may delete it" in s for s in said) and "Nothing was deleted" in said[-1]
    assert out["daily_usd"] > 0
    assert not [n for n, _ in rds.calls if "delete" in n]


def test_report_says_a_stopped_database_starts_again_after_7_days(pr):
    pr = _ops(pr)
    said = []
    pr.report("runtime", {"rds": FakeRds(instance=_audit_instance("stopped"))}, log=said.append)
    assert any("after 7 days" in s and "still billed" in s for s in said)


def test_the_script_never_deletes_a_copy():
    source = (ROOT / "scripts" / "pause_resume.py").read_text(encoding="utf-8")
    assert not re.search(r"\.delete_|DeleteBackup|DeleteDB", source)


# --------------------------------------------------------------------------- the pipelines' order


def _steps(path: pathlib.Path, job: str) -> list[dict]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"][job]["steps"]


def _index(steps, needle):
    return next(i for i, s in enumerate(steps) if needle in (s.get("name", "") + s.get("run", "")))


def test_the_infra_pause_copies_everything_before_the_destroy_and_nothing_runs_after_a_failure():
    steps = _steps(FLOWS / "_infra-deploy.yml", "run")
    copy, destroy = _index(steps, "pause_resume.py snapshot"), _index(steps, "aurora_express.py destroy")
    assert copy < destroy
    assert steps[copy]["if"] == "env.ACTION == 'pause'"
    assert steps[destroy]["if"] == "env.ACTION == 'destroy' || env.ACTION == 'pause'"
    # No step may run past a failed copy: GitHub skips later steps unless their `if` says otherwise.
    assert not [s for s in steps if re.search(r"always\(\)|failure\(\)|continue-on-error", json.dumps(s))]
    assert _index(steps, "pause_resume.py report") > destroy


def test_the_infra_resume_restores_and_imports_before_the_plan_and_restores_aurora_after_the_apply():
    steps = _steps(FLOWS / "_infra-deploy.yml", "run")
    tables, plan = _index(steps, "restore-tables"), _index(steps, "plan, and Helios on it")
    apply = _index(steps, "aurora_express.py create")
    assert tables < plan < apply
    assert "terraform -chdir=\"terraform/$STACK\" import" in steps[tables]["run"]
    assert "env.ACTION == 'resume'" in steps[plan]["if"] and "env.ACTION == 'resume'" in steps[apply]["if"]
    assert '--from-snapshot "$FROM_SNAPSHOT"' in steps[apply]["run"]
    assert steps[apply]["env"]["FROM_SNAPSHOT"] == "${{ inputs.action == 'resume' && 'latest' || 'none' }}"
    known = steps[_index(steps, "A known action")]["run"]
    assert "plan|apply|apply-plan|destroy|pause|resume)" in known and "pause/undo-lab|resume/undo-lab)" in known


@pytest.mark.parametrize("env", ["dev", "prod"])
def test_a_deploy_can_pause_and_resume_and_resume_brings_the_apps_back_in_the_same_run(env):
    flow = yaml.safe_load((FLOWS / f"deploy-{env}.yml").read_text(encoding="utf-8"))
    on = flow.get("on") or flow.get(True)
    assert {"pause", "resume"} <= set(on["workflow_dispatch"]["inputs"]["infra_action"]["options"])
    job = flow["jobs"]["apps-after-resume"]
    assert job["if"] == "inputs.part == 'infra' && inputs.infra_action == 'resume'"
    assert job["needs"] == ["infra", "apps-check"] and job["with"]["target"] == "all"
    assert "inputs.infra_action == 'resume'" in flow["jobs"]["apps-check"]["if"]


def test_the_runtime_pause_copies_the_audit_before_the_switch_and_stops_it_after_the_apply():
    steps = _steps(FLOWS / "runtime.yml", "deploy")
    copy, apply = _index(steps, "pause_resume.py snapshot --stack runtime"), _index(steps, "apply the plan just made")
    run = steps[copy]["run"]
    assert run.index("pause_resume.py snapshot") < run.index("tf/paused\" --value true")
    assert copy < _index(steps, "terraform -chdir=terraform/runtime plan") < apply < _index(steps, "pause_resume.py stop-db")
    start = _index(steps, "pause_resume.py start-db")
    assert steps[start]["run"].index("start-db") < steps[start]["run"].index("--value false") and start < apply
    assert not [s for s in steps if re.search(r"always\(\)|failure\(\)|continue-on-error", json.dumps(s))]
    flow = yaml.safe_load((FLOWS / "runtime.yml").read_text(encoding="utf-8"))
    on = flow.get("on") or flow.get(True)
    assert {"pause", "resume"} <= set(on["workflow_dispatch"]["inputs"]["action"]["options"])
    # The runtime job names its environment RUNTIME_ENV; the script refuses without WARDEN_ENV.
    calls = re.findall(r"^\s*(.*)python scripts/pause_resume.py", "\n".join(s.get("run", "") for s in steps), re.MULTILINE)
    assert calls and all(c == 'WARDEN_ENV="$RUNTIME_ENV" ' for c in calls), calls


def test_the_runtime_installs_its_tools_before_it_holds_credentials():
    steps = _steps(FLOWS / "runtime.yml", "deploy")
    creds = next(i for i, s in enumerate(steps) if "configure-aws-credentials" in s.get("uses", ""))
    uv = next(i for i, s in enumerate(steps) if "setup-uv" in s.get("uses", ""))
    sync = _index(steps, "uv sync --locked --no-build --only-group infra-deploy")
    assert uv < sync < creds and steps[uv]["with"]["enable-cache"] is False


# --------------------------------------------------------------------------- permissions


def _evaluator():
    return _load("test_destroy_permissions", ROOT / "tests" / "test_destroy_permissions.py")


RUNTIME_CALLS = [
    ("rds:CreateDBSnapshot", ["db:warden-ops-audit", "snapshot:warden-ops-audit-pause-20261020t062500z"]),
    ("rds:AddTagsToResource", ["snapshot:warden-ops-audit-pause-20261020t062500z"]),
    ("rds:CreateDBClusterSnapshot", ["cluster:warden-ops-audit", "cluster-snapshot:warden-ops-audit-pause-20261020t062500z"]),
    ("rds:StopDBInstance", ["db:warden-ops-audit"]), ("rds:StartDBInstance", ["db:warden-ops-audit"]),
    ("rds:StopDBCluster", ["cluster:warden-ops-audit"]), ("rds:StartDBCluster", ["cluster:warden-ops-audit"]),
    ("rds:DescribeDBSnapshots", ["*"]), ("rds:DescribeDBClusterSnapshots", ["*"]),
]


@pytest.mark.parametrize("action, kinds", RUNTIME_CALLS)
def test_the_runtime_deploy_role_may_pause_and_resume_its_audit(action, kinds):
    ev = _evaluator()
    region = ev.r.names("ops").region
    arns = ["*" if k == "*" else f"arn:aws:rds:{region}:{ev.ACCOUNT}:{k}" for k in kinds]
    ctx = {"aws:RequestedRegion": region, "aws:RequestTag/Environment": "ops"}
    assert ev.refusal("ops", action, arns, ctx) is None


def test_the_runtime_pause_switch_is_the_only_parameter_the_role_may_write():
    ev = _evaluator()
    region = ev.r.names("ops").region
    ctx = {"aws:RequestedRegion": region}
    param = f"arn:aws:ssm:{region}:{ev.ACCOUNT}:parameter/warden/ops/tf/"
    assert ev.refusal("ops", "ssm:PutParameter", [param + "paused"], ctx) is None
    for other in ("model", "page_topic_arn", "paused2"):
        assert ev.refusal("ops", "ssm:PutParameter", [param + other], ctx), other


@pytest.mark.parametrize("env", ["dev", "prod", "ops"])
def test_no_role_may_delete_a_pause_copy(env):
    ev = _evaluator()
    region = ev.r.names(env).region
    ctx = {"aws:RequestedRegion": region, "aws:ResourceTag/Environment": env}
    for action, arn in (("rds:DeleteDBClusterSnapshot", f"arn:aws:rds:{region}:{ev.ACCOUNT}:cluster-snapshot:warden-{env}-aurora-pause-1"),
                        ("rds:DeleteDBSnapshot", f"arn:aws:rds:{region}:{ev.ACCOUNT}:snapshot:warden-{env}-audit-pause-1")):
        assert ev.refusal(env, action, [arn], ctx), (env, action)
    if env != "ops":
        backup = f"arn:aws:dynamodb:{region}:{ev.ACCOUNT}:table/warden-{env}-carts/backup/0001"
        assert "NeverDeleteABackup" in ev.refusal(env, "dynamodb:DeleteBackup", [backup], ctx)
