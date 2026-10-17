"""scripts/preflight_db_ops.py with the database faked (characterisation before the cognitive-complexity split of
main): the baseline gate first, each op's landed check and revert, the ingress cut and restore, every line it
prints and its exit code."""

from __future__ import annotations

import importlib.util
import pathlib
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("preflight_db_ops", ROOT / "scripts" / "preflight_db_ops.py")
pdb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pdb)


class FakeDb:
    """Counts per query; ops change them the way the real ones would. `reachable` is the security group."""

    def __init__(self, *, land=True, cut=True, back=True, raise_on=None, dirty_after=()):
        self.counts = {"SELECT 1": 1, pdb.IDLE: 0, pdb.WAITING: 0, pdb.SLEEPING: 0, pdb.TOTAL: 5}
        self.land, self.cut, self.back, self.raise_on = land, cut, back, raise_on
        self.dirty_after, self.reachable, self.calls, self.last = set(dirty_after), True, [], None

    def op(self, name):
        def run(clients, target, **kwargs):
            self.calls.append(name)
            self.last = name
            if name == self.raise_on:
                raise RuntimeError(f"{name} refused")
            effect = {"db_open_idle_transactions": pdb.IDLE, "db_run_long_query": pdb.SLEEPING,
                      "db_take_blocking_lock": pdb.WAITING}
            if name in effect and self.land:
                self.counts[effect[name]] += 1
            if name == "db_saturate_connections" and self.land:
                self.counts[pdb.TOTAL] += 3
            if name == "db_release_everything":
                self.counts.update({pdb.IDLE: 0, pdb.WAITING: 0, pdb.SLEEPING: 0, pdb.TOTAL: 5})
            if name == "db_revoke_ingress" and self.cut:
                self.reachable = False
            if name == "db_restore_ingress":
                self.reachable = self.back
        return run

    def scalar(self, clients, sql):
        if not self.reachable:
            raise ConnectionError("timeout")
        return self.counts[sql]

    def baseline(self, clients, target):
        if self.last in self.dirty_after:
            return [f"left over from {self.last}"]
        return []


@pytest.fixture
def db(monkeypatch):
    def make(**kw):
        fake = FakeDb(**kw)
        names = ["db_open_idle_transactions", "db_saturate_connections", "db_run_long_query",
                 "db_take_blocking_lock", "db_release_everything", "db_revoke_ingress", "db_restore_ingress"]
        monkeypatch.setattr(pdb.ops_db, "OPS", {n: fake.op(n) for n in names})
        monkeypatch.setattr(pdb, "_scalar", fake.scalar)
        monkeypatch.setattr(pdb, "check_baseline_db", fake.baseline)
        monkeypatch.setattr(pdb, "_db_live_harness",
                            lambda timeout_s: types.SimpleNamespace(clients="C", target="T"))
        monkeypatch.setattr(pdb.time, "sleep", lambda s: None)
        return fake
    return make


def test_every_op_lands_and_reverts(db, capsys):
    fake = db()
    assert pdb.main() == 0
    assert capsys.readouterr().out == (
        "OK   idle-in-transaction session: fault landed; after revert baseline clean\n"
        "OK   connection saturation: fault landed; after revert baseline clean\n"
        "OK   long active query: fault landed; after revert baseline clean\n"
        "OK   blocking lock with a waiter: fault landed; after revert baseline clean\n"
        "OK   security-group revoke: connection cut; restore reconnected; baseline clean\n"
        "\nALL OPS VERIFIED AGAINST THE REAL DATABASE\n")
    assert fake.calls[-2:] == ["db_revoke_ingress", "db_restore_ingress"]


def test_a_dirty_database_stops_before_any_op(db, capsys):
    fake = db(dirty_after={None})
    assert pdb.main() == 1
    assert capsys.readouterr().out == "NOT AT BASELINE before starting: ['left over from None']\n"
    assert fake.calls == []


def test_a_fault_that_does_not_land_or_raises_or_leaves_dirt_fails(db, capsys, monkeypatch):
    db(land=False, raise_on="db_run_long_query", dirty_after={"db_release_everything"})
    monkeypatch.setattr(pdb, "_settle_to_baseline", lambda clients, target: pdb.check_baseline_db(clients, target))
    assert pdb.main() == 1
    assert capsys.readouterr().out == (
        "FAIL idle-in-transaction session: fault DID NOT LAND; after revert ['left over from db_release_everything']\n"
        "FAIL connection saturation: fault DID NOT LAND; after revert ['left over from db_release_everything']\n"
        "   inject raised RuntimeError: db_run_long_query refused\n"
        "FAIL long active query: fault DID NOT LAND; after revert ['left over from db_release_everything']\n"
        "FAIL blocking lock with a waiter: fault DID NOT LAND; after revert ['left over from db_release_everything']\n"
        "OK   security-group revoke: connection cut; restore reconnected; baseline clean\n"
        "\n4 FAILED - do not run the wave\n")


def test_an_ingress_that_is_not_cut_or_not_restored_fails(db, capsys):
    db(cut=False)
    assert pdb.main() == 1
    assert capsys.readouterr().out.endswith(
        "FAIL security-group revoke: connection NOT cut; restore reconnected; baseline clean\n"
        "\n1 FAILED - do not run the wave\n")
    fake = db(back=False)
    assert pdb.main() == 1
    assert capsys.readouterr().out.endswith(
        "FAIL security-group revoke: connection cut; restore DID NOT reconnect; ['still unreachable after restore']\n"
        "\n1 FAILED - do not run the wave\n")
    assert fake.calls[-1] == "db_restore_ingress"


def test_the_ingress_is_restored_even_when_the_revoke_raises(db):
    fake = db(raise_on="db_revoke_ingress")
    with pytest.raises(RuntimeError, match="db_revoke_ingress refused"):
        pdb.main()
    assert fake.calls[-2:] == ["db_revoke_ingress", "db_restore_ingress"]
