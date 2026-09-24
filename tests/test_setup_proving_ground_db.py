"""The one-off that marks a database as the Wave 3 proving ground.

⛔ Every test here is about REFUSING. The script's whole job is to be hard to aim at the wrong
database, because everything downstream trusts the mark it leaves behind.
"""

from __future__ import annotations

import pytest
from scripts.setup_proving_ground_db import SENTINEL, main

DSN = "postgresql://warden@db.internal:5432/warden"


class FakeCursor:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self._conn.statements.append(sql)

    def fetchone(self):
        sql = self._conn.statements[-1]
        if "current_database()" in sql:
            return (self._conn.live_database,)
        if "to_regclass" in sql:
            return (SENTINEL if self._conn.exists else None,)
        return (0,)


class FakeConn:
    def __init__(self, *, live_database="warden", exists=False):
        self.live_database, self.exists = live_database, exists
        self.statements: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return FakeCursor(self)


@pytest.fixture
def connect(monkeypatch):
    """Patches psycopg.connect and hands back the connection the script used."""
    import types

    holder: dict[str, FakeConn] = {}

    def install(conn: FakeConn) -> FakeConn:
        holder["conn"] = conn
        monkeypatch.setitem(
            __import__("sys").modules, "psycopg",
            types.SimpleNamespace(connect=lambda *a, **k: conn),
        )
        return conn

    return install


def test_a_dsn_naming_another_database_is_refused_before_connecting(monkeypatch, capsys):
    monkeypatch.setenv("WARDEN_BENCH_DB_DSN", "postgresql://app@prod.internal:5432/payments")

    assert main(["--apply"]) == 1
    assert "refusing" in capsys.readouterr().err


def test_a_server_that_answers_with_a_different_database_is_refused(monkeypatch, connect, capsys):
    """⛔ The check the DSN text cannot make: a pooler can route a connection somewhere else
    entirely, so the server's own answer is checked too."""
    monkeypatch.setenv("WARDEN_BENCH_DB_DSN", DSN)
    conn = connect(FakeConn(live_database="payments"))

    assert main(["--apply"]) == 1
    assert "refusing" in capsys.readouterr().err
    assert not any("CREATE TABLE" in s for s in conn.statements)


def test_a_dry_run_creates_nothing(monkeypatch, connect):
    monkeypatch.setenv("WARDEN_BENCH_DB_DSN", DSN)
    conn = connect(FakeConn())

    assert main([]) == 0
    assert not any("CREATE TABLE" in s for s in conn.statements)


def test_apply_creates_the_sentinel(monkeypatch, connect):
    """The positive control: it has to actually work, or the guard can never be satisfied."""
    monkeypatch.setenv("WARDEN_BENCH_DB_DSN", DSN)
    conn = connect(FakeConn())

    assert main(["--apply"]) == 0
    assert any(f"CREATE TABLE {SENTINEL}" in s for s in conn.statements)


def test_running_it_twice_is_harmless(monkeypatch, connect):
    monkeypatch.setenv("WARDEN_BENCH_DB_DSN", DSN)
    conn = connect(FakeConn(exists=True))

    assert main(["--apply"]) == 0
    assert not any("CREATE TABLE" in s for s in conn.statements)


def test_a_missing_dsn_is_an_error_not_a_guess(monkeypatch, capsys):
    monkeypatch.delenv("WARDEN_BENCH_DB_DSN", raising=False)

    assert main(["--apply"]) == 1
    assert "WARDEN_BENCH_DB_DSN" in capsys.readouterr().err
