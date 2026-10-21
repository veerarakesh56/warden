"""The one-off that marks a database as the Wave 3 proving ground.

⛔ Every test here is about REFUSING. The script's whole job is to be hard to aim at the wrong
database, because everything downstream trusts the mark it leaves behind.
"""

from __future__ import annotations

import pytest
from scripts.setup_proving_ground_db import SENTINEL, main

from fakes import HUNTER2

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


# ---- characterisation of --reader and the printed lines (before the cognitive-complexity split of main)

READER_PASSWORD = HUNTER2 + "-reader"  # tests/fakes.py: built from parts, a fake, never a credential


class ReaderConn(FakeConn):
    def __init__(self, *, reader_exists=False, **kw):
        super().__init__(**kw)
        self.reader_exists = reader_exists

    def cursor(self):
        conn = self

        class Cursor(FakeCursor):
            def fetchone(self):
                if "pg_roles" in conn.statements[-1]:
                    return (1,) if conn.reader_exists else None
                return super().fetchone()
        return Cursor(self)


@pytest.fixture
def reader(monkeypatch, connect):
    import sys
    import types

    def install(conn):
        connect(conn)
        fake_sql = types.SimpleNamespace(
            SQL=lambda text: types.SimpleNamespace(format=lambda *a: text.format(*(str(x) for x in a))),
            Literal=lambda value: "<literal>", Identifier=lambda name: f'"{name}"')
        sys.modules["psycopg"].sql = fake_sql
        monkeypatch.setenv("WARDEN_BENCH_DB_DSN", DSN)
        return conn
    return install


def test_the_reader_needs_its_password_from_the_environment(monkeypatch, reader, capsys):
    monkeypatch.delenv("WARDEN_BENCH_DB_READER_PASSWORD", raising=False)
    conn = reader(ReaderConn())
    assert main(["--reader", "--apply"]) == 1
    assert capsys.readouterr().err == "\n⛔ set WARDEN_BENCH_DB_READER_PASSWORD for the warden_reader login\n"
    assert conn.statements == ["SELECT current_database()"]


def test_a_dry_run_says_what_it_would_create_for_the_reader_and_the_sentinel(monkeypatch, reader, capsys):
    monkeypatch.setenv("WARDEN_BENCH_DB_READER_PASSWORD", READER_PASSWORD)
    conn = reader(ReaderConn())
    assert main(["--reader"]) == 0
    assert capsys.readouterr().out == (
        "DRY RUN\n  host      db.internal\n  database  warden\n  table     warden_proving_ground\n"
        "\ndry run - warden_reader would be created with pg_monitor. Re-run with --apply.\n"
        "\ndry run - nothing was created. Re-run with --apply.\n")
    assert not any(s.startswith(("CREATE", "GRANT")) for s in conn.statements)


def test_apply_creates_the_reader_then_the_sentinel(monkeypatch, reader, capsys):
    monkeypatch.setenv("WARDEN_BENCH_DB_READER_PASSWORD", READER_PASSWORD)
    conn = reader(ReaderConn())
    assert main(["--reader", "--apply"]) == 0
    assert [s.split(" (")[0] for s in conn.statements] == [
        "SELECT current_database()", "SELECT 1 FROM pg_roles WHERE rolname = 'warden_reader'",
        "CREATE ROLE warden_reader LOGIN PASSWORD <literal>", "GRANT pg_monitor TO warden_reader",
        'GRANT CONNECT ON DATABASE "warden" TO warden_reader', f"SELECT to_regclass('{SENTINEL}')",
        f"CREATE TABLE {SENTINEL}", f"INSERT INTO {SENTINEL}"]
    assert capsys.readouterr().out == (
        "APPLYING\n  host      db.internal\n  database  warden\n  table     warden_proving_ground\n"
        "\nwarden_reader created (pg_monitor, CONNECT only).\n"
        "\ncreated. warden on db.internal is now injectable by the Wave 3 harness.\n")


def test_an_existing_reader_is_left_alone(monkeypatch, reader, capsys):
    monkeypatch.setenv("WARDEN_BENCH_DB_READER_PASSWORD", READER_PASSWORD)
    conn = reader(ReaderConn(reader_exists=True, exists=True))
    assert main(["--reader", "--apply"]) == 0
    assert capsys.readouterr().out.endswith(
        "\nwarden_reader already exists.\n"
        f"\n{SENTINEL} already exists - nothing to do. This database is the proving ground.\n")
    assert not any(s.startswith(("CREATE", "GRANT")) for s in conn.statements)
