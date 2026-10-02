"""Audit A-B-M1, register O8: every database connection WARDEN opens bounds its statements and lock waits - a read of
an already-degraded database must not hang behind a lock or add a long query to its load. The reader and the
remediation platform both connect through these adapters."""
from __future__ import annotations

import sys
import types

import pytest

from warden import database


class _Cursor:
    def __init__(self, sql):
        self.sql = sql

    def execute(self, statement, params=()):
        self.sql.append(statement)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Conn:
    def __init__(self):
        self.sql: list[str] = []

    def cursor(self):
        return _Cursor(self.sql)


def _fake(monkeypatch, module, attr="connect"):
    seen = {}

    def connect(*args, **kwargs):
        seen["args"], seen["kwargs"] = args, kwargs
        seen["conn"] = _Conn()
        return seen["conn"]

    monkeypatch.setitem(sys.modules, module, types.SimpleNamespace(**{attr: connect}))
    return seen


def test_postgres_bounds_every_statement_and_lock_wait(monkeypatch):
    seen = _fake(monkeypatch, "psycopg")
    database._Postgres.connect("postgresql://db.example/orders")
    sql = seen["conn"].sql
    assert f"SET statement_timeout = {int(database.STATEMENT_TIMEOUT * 1000)}" in sql
    assert f"SET lock_timeout = {int(database.LOCK_TIMEOUT * 1000)}" in sql
    assert "SET application_name = 'warden'" in sql
    assert "options" not in seen["kwargs"]  # options the DSN carries are kept


def test_sql_server_bounds_every_statement_and_lock_wait(monkeypatch):
    seen = _fake(monkeypatch, "pymssql")
    database._MSSQL.connect("mssql://db.example/orders")
    assert seen["kwargs"]["timeout"] == int(database.STATEMENT_TIMEOUT)
    assert f"SET LOCK_TIMEOUT {int(database.LOCK_TIMEOUT * 1000)}" in seen["conn"].sql


def test_mysql_bounds_every_read_and_write(monkeypatch):
    seen = _fake(monkeypatch, "pymysql")
    database._MySQL.connect("mysql://db.example/orders")
    assert seen["kwargs"]["read_timeout"] == seen["kwargs"]["write_timeout"] == int(database.STATEMENT_TIMEOUT)


def test_mongo_bounds_every_socket_read(monkeypatch):
    seen = _fake(monkeypatch, "pymongo", attr="MongoClient")
    database._Mongo.connect("mongodb://db.example/orders")
    assert seen["kwargs"]["socketTimeoutMS"] == int(database.STATEMENT_TIMEOUT * 1000)


@pytest.mark.parametrize("bound", ["STATEMENT_TIMEOUT", "LOCK_TIMEOUT"])
def test_the_bounds_are_short(bound):
    assert 0 < getattr(database, bound) <= 30
