"""Against REAL databases. Skipped unless opted in; FAILS (never skips) if opted in and the database
you named is unreachable.

    WARDEN_DB_INTEGRATION=1 WARDEN_TEST_PG_DSN=postgresql://... pytest tests/integration -q

Each engine is configured by its own DSN variable, and an engine with no DSN set is simply not part of
this run:
    WARDEN_TEST_PG_DSN     postgresql://warden:warden@localhost:55432/warden
    WARDEN_TEST_MYSQL_DSN  mysql://root:warden@localhost:53306/warden
    WARDEN_TEST_REDIS_DSN  redis://localhost:56379/0
    WARDEN_TEST_MONGO_DSN  mongodb://localhost:57017/warden
    WARDEN_TEST_MSSQL_DSN  mssql://sa:<password>@localhost:11433/master

⛔ The distinction that matters: a DSN that is SET but unreachable is a FAILURE, not a skip. "You told
me this database exists" and "it answered" are different claims, and a green run must only ever mean
the second one. This is the same discipline as test_live_cluster.py.

What this proves that the unit tests cannot: that the statements are valid against the real server's
grammar and catalog views, and that after `terminate` the stuck connection is ACTUALLY GONE — not that
a stub recorded a string.

Every test is self-contained: it opens its own victim connection and cleans up after itself.
"""

from __future__ import annotations

import contextlib
import os
import time

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("WARDEN_DB_INTEGRATION") != "1",
    reason="set WARDEN_DB_INTEGRATION=1 (plus at least one WARDEN_TEST_*_DSN) to run these",
)

from warden.database import _MSSQL, _Mongo, _MySQL, _Postgres, _Redis
from warden.database_remediation import (
    _MongoKiller,
    _MSSQLKiller,
    _MySQLKiller,
    _PostgresKiller,
    _RedisKiller,
)
from warden.tools import PARTIAL_PREFIX

PG_DSN = os.environ.get("WARDEN_TEST_PG_DSN")
MYSQL_DSN = os.environ.get("WARDEN_TEST_MYSQL_DSN")
REDIS_DSN = os.environ.get("WARDEN_TEST_REDIS_DSN")
MONGO_DSN = os.environ.get("WARDEN_TEST_MONGO_DSN")
MSSQL_DSN = os.environ.get("WARDEN_TEST_MSSQL_DSN")

needs_pg = pytest.mark.skipif(not PG_DSN, reason="WARDEN_TEST_PG_DSN not set")
needs_mysql = pytest.mark.skipif(not MYSQL_DSN, reason="WARDEN_TEST_MYSQL_DSN not set")
needs_redis = pytest.mark.skipif(not REDIS_DSN, reason="WARDEN_TEST_REDIS_DSN not set")
needs_mongo = pytest.mark.skipif(not MONGO_DSN, reason="WARDEN_TEST_MONGO_DSN not set")
needs_mssql = pytest.mark.skipif(not MSSQL_DSN, reason="WARDEN_TEST_MSSQL_DSN not set")


def _connect_or_fail(adapter, dsn, label):
    """A configured-but-unreachable database is a FAILURE. Skipping here would turn a broken
    integration run into a green one."""
    try:
        return adapter.connect(dsn)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{label} DSN is set but the server did not answer: {exc}")


# ------------------------------------------------------------------ PostgreSQL

@needs_pg
def test_postgres_metrics_come_back_from_a_real_server():
    conn = _connect_or_fail(_Postgres, PG_DSN, "postgres")
    m = _Postgres.metrics(conn)
    # These keys only exist if the real catalog queries parsed and returned.
    for key in ("active_connections", "idle_in_transaction", "max_connections", "locks_waiting"):
        assert key in m, f"{key} missing from a real Postgres read: {m}"
    assert m["active_connections"] >= 1.0, "our own connection should be counted"
    assert m["max_connections"] >= 1.0
    conn.close()


@needs_pg
def test_postgres_terminate_actually_removes_the_stuck_connection():
    """The whole claim, against a real server: a connection left idle-in-transaction is selected and
    then genuinely disappears from pg_stat_activity."""
    import psycopg

    admin = _connect_or_fail(_Postgres, PG_DSN, "postgres")
    victim = psycopg.connect(PG_DSN, autocommit=False)
    try:
        # Leave the victim idle INSIDE a transaction - the exact state that holds pool slots + locks.
        with victim.cursor() as cur:
            cur.execute("SELECT 1")
        victim_pid = victim.info.backend_pid
        time.sleep(1.0)

        with admin.cursor() as cur:
            cur.execute(
                "SELECT state, EXTRACT(EPOCH FROM (now() - state_change)) "
                "FROM pg_stat_activity WHERE pid = %s",
                (victim_pid,),
            )
            state, age = cur.fetchone()
        assert state == "idle in transaction", f"victim is {state!r}, not idle in transaction"

        if age is not None and float(age) < 0:
            # The server stamped this connection in the FUTURE - a host clock step, which Docker
            # Desktop's VM does under load (measured: 2 rounds in 10, age reported as -115s). The
            # documented behaviour is to decline to terminate what cannot be aged, and to SAY SO.
            # Assert exactly that rather than failing: it is the correct outcome, not a flake.
            assert victim_pid not in _PostgresKiller.candidates(admin, 0, 20), (
                "a connection whose age is unknowable must never be terminated"
            )
            partials = [
                line for line in _Postgres.problem_ops(admin, 0) if line.startswith(PARTIAL_PREFIX)
            ]
            assert partials, "clock skew must be reported as a partial, not passed over in silence"
            pytest.skip(f"host clock skew (age {float(age):.0f}s); asserted the fail-safe path instead")

        # idle_secs=0 so the freshly-made victim qualifies; the ceiling still applies.
        candidates = _PostgresKiller.candidates(admin, 0, 20)
        assert victim_pid in candidates, f"the stuck pid {victim_pid} was not selected: {candidates}"
        with admin.cursor() as cur:
            cur.execute("SELECT pg_backend_pid()")
            own_pid = cur.fetchone()[0]
        assert own_pid not in candidates, "it selected its OWN connection for termination"

        assert _PostgresKiller.terminate(admin, [victim_pid]) == 1

        with admin.cursor() as cur:
            cur.execute("SELECT count(*) FROM pg_stat_activity WHERE pid = %s", (victim_pid,))
            still_there = cur.fetchone()[0]
        assert still_there == 0, "the connection was reported terminated but is still on the server"
    finally:
        # The victim was just terminated, so closing it may itself raise - that IS the success case.
        with contextlib.suppress(Exception):
            victim.close()
        admin.close()


# ------------------------------------------------------------------ MySQL

@needs_mysql
def test_mysql_metrics_come_back_from_a_real_server():
    conn = _connect_or_fail(_MySQL, MYSQL_DSN, "mysql")
    m = _MySQL.metrics(conn)
    for key in ("active_connections", "max_connections", "idle_in_transaction"):
        assert key in m, f"{key} missing from a real MySQL read: {m}"
    assert m["active_connections"] >= 1.0
    conn.close()


@needs_mysql
def test_mysql_terminate_actually_kills_the_sleeping_transaction():
    from urllib.parse import urlparse

    import pymysql

    admin = _connect_or_fail(_MySQL, MYSQL_DSN, "mysql")
    u = urlparse(MYSQL_DSN)
    victim = pymysql.connect(
        host=u.hostname, port=u.port or 3306, user=u.username, password=u.password or "",
        database=u.path.lstrip("/") or None, autocommit=False,
    )
    try:
        with victim.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS warden_probe (id INT PRIMARY KEY)")
        victim.commit()
        with victim.cursor() as cur:
            cur.execute("START TRANSACTION")
            cur.execute("INSERT INTO warden_probe (id) VALUES (1) ON DUPLICATE KEY UPDATE id = id")
            cur.execute("SELECT CONNECTION_ID()")
            victim_id = cur.fetchone()[0]
        time.sleep(1.0)  # now Sleeping with an open transaction

        candidates = _MySQLKiller.candidates(admin, 0, 20)
        assert victim_id in candidates, f"the sleeping trx {victim_id} was not selected: {candidates}"
        with admin.cursor() as cur:
            cur.execute("SELECT CONNECTION_ID()")
            own_id = cur.fetchone()[0]
        assert own_id not in candidates, "it selected its OWN session to KILL"

        assert _MySQLKiller.terminate(admin, [victim_id]) == 1
        time.sleep(0.5)
        with admin.cursor() as cur:
            cur.execute("SELECT count(*) FROM information_schema.processlist WHERE id = %s", (victim_id,))
            still_there = cur.fetchone()[0]
        assert still_there == 0, "the session was reported killed but is still in the processlist"
    finally:
        with contextlib.suppress(Exception):
            victim.close()
        with admin.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS warden_probe")
        admin.close()


# ------------------------------------------------------------------ Redis

@needs_redis
def test_redis_metrics_come_back_from_a_real_server():
    conn = _connect_or_fail(_Redis, REDIS_DSN, "redis")
    m = _Redis.metrics(conn)
    for key in ("connected_clients", "maxclients", "used_memory", "idle_in_transaction"):
        assert key in m, f"{key} missing from a real Redis read: {m}"
    assert m["connected_clients"] >= 1.0


@needs_redis
def test_redis_terminate_actually_disconnects_the_idle_client():
    import redis as redis_lib

    admin = _connect_or_fail(_Redis, REDIS_DSN, "redis")
    victim = redis_lib.from_url(REDIS_DSN, decode_responses=True)
    victim.ping()  # force the connection to exist
    victim_id = victim.client_id()
    try:
        # idle_secs=0 so a freshly-opened client qualifies.
        candidates = _RedisKiller.candidates(admin, 0, 20)
        assert victim_id in candidates, f"idle client {victim_id} was not selected: {candidates}"
        assert admin.client_id() not in candidates, "it selected its OWN client to kill"

        assert _RedisKiller.terminate(admin, [victim_id]) == 1
        remaining = {int(c["id"]) for c in admin.client_list()}
        assert victim_id not in remaining, "the client was reported killed but is still connected"
    finally:
        with contextlib.suppress(Exception):
            victim.close()


# ------------------------------------------------------------------ MongoDB

@needs_mongo
def test_mongo_metrics_come_back_from_a_real_server():
    conn = _connect_or_fail(_Mongo, MONGO_DSN, "mongo")
    m = _Mongo.metrics(conn)
    for key in ("current_connections", "available_connections", "long_running_ops"):
        assert key in m, f"{key} missing from a real Mongo read: {m}"
    assert m["current_connections"] >= 1.0
    conn.close()


def _slow_mongo_query(dsn, seconds, outcome):
    """A genuinely long-running query on a USER namespace.

    `$where` with a busy loop needs only server-side JavaScript (on by default), not the `sleep` test
    command — so this works against a stock container, in CI, with no special server flags.
    """
    import pymongo

    client = pymongo.MongoClient(dsn)
    try:
        ms = int(seconds) * 1000
        js = f"function(){{var t=new Date(); while((new Date())-t < {ms}){{}} return true;}}"
        list(client.warden.warden_probe.find({"$where": js}))
        outcome["result"] = "completed normally"
    except Exception as exc:  # noqa: BLE001 - being killed IS the expected outcome
        outcome["result"] = f"{type(exc).__name__}"


@needs_mongo
def test_mongo_terminate_kills_a_real_long_running_query_and_spares_the_heartbeats():
    """The bug this test exists for, found against a real server: `currentOp` reports MongoDB's own
    awaitable `hello` heartbeats, which sit active for seconds by design. A naive
    `secs_running >= threshold` filter selected them — so the terminator would have killed the
    drivers' monitoring connections (its own included) while never touching the stuck query.
    """
    import threading


    admin = _connect_or_fail(_Mongo, MONGO_DSN, "mongo")
    admin.warden.warden_probe.drop()
    admin.warden.warden_probe.insert_many([{"x": i} for i in range(50)])
    outcome: dict[str, str] = {}
    threading.Thread(target=_slow_mongo_query, args=(MONGO_DSN, 20, outcome), daemon=True).start()

    try:
        # Poll rather than sleep a fixed amount: CI machines vary.
        target = None
        for _ in range(40):
            for op in admin.admin.command("currentOp", {"active": True}).get("inprog", []):
                if "warden_probe" in str(op.get("ns") or "") and float(op.get("secs_running") or 0) >= 1:
                    target = int(op["opid"])
            if target is not None:
                break
            time.sleep(0.5)
        assert target is not None, "the long-running user query never appeared in currentOp"

        inprog = admin.admin.command("currentOp", {"active": True}).get("inprog", [])
        heartbeats = [
            int(op["opid"]) for op in inprog
            if next(iter(op.get("command") or {}), "") in ("hello", "isMaster", "ismaster")
        ]
        selected = _MongoKiller.candidates(admin, 1, 20)

        assert target in selected, f"the real stuck query {target} was not selected: {selected}"
        for hb in heartbeats:
            assert hb not in selected, (
                f"heartbeat op {hb} was selected for termination - killing a driver's monitoring "
                "connection is an outage, not a remediation"
            )
        own = [int(op["opid"]) for op in inprog if "currentOp" in (op.get("command") or {})]
        for opid in own:
            assert opid not in selected, "it selected its OWN operation to kill"

        assert _MongoKiller.terminate(admin, [target]) == 1
        time.sleep(1.5)
        still = [
            op for op in admin.admin.command("currentOp", {"active": True}).get("inprog", [])
            if int(op.get("opid", -1)) == target
        ]
        assert not still, "the op was reported killed but is still running on the server"
    finally:
        with contextlib.suppress(Exception):
            admin.warden.warden_probe.drop()
        admin.close()


@needs_mongo
def test_mongo_metrics_do_not_count_the_servers_own_heartbeats_as_long_running_ops():
    """An idle MongoDB must read as idle. Before the fix, its own `hello` heartbeats were counted,
    so a healthy server reported long-running operations every single time."""
    conn = _connect_or_fail(_Mongo, MONGO_DSN, "mongo")
    try:
        m = _Mongo.metrics(conn)
        assert m["long_running_ops"] == 0.0, f"a quiet server reported long-running ops: {m}"
        assert m["idle_in_transaction"] == 0.0, f"a quiet server reported stuck ops: {m}"
    finally:
        conn.close()


# ------------------------------------------------------------------ SQL Server

@needs_mssql
def test_mssql_metrics_come_back_from_a_real_server():
    conn = _connect_or_fail(_MSSQL, MSSQL_DSN, "mssql")
    try:
        m = _MSSQL.metrics(conn)
        for key in ("active_connections", "idle_in_transaction", "long_running_queries"):
            assert key in m, f"{key} missing from a real SQL Server read: {m}"
        assert m["active_connections"] >= 1.0, "our own session should be counted"
    finally:
        conn.close()


@needs_mssql
def test_mssql_does_not_count_its_own_background_tasks_as_long_running_queries():
    """A quiet SQL Server must read as quiet.

    `sys.dm_exec_requests` also lists the instance's own background tasks (LAZY WRITER, CHECKPOINT,
    XE TIMER...), which have been running since startup. Before the join to `dm_exec_sessions`, a
    freshly started, completely idle server reported 28 long-running queries.
    """
    conn = _connect_or_fail(_MSSQL, MSSQL_DSN, "mssql")
    try:
        assert _MSSQL.metrics(conn)["long_running_queries"] == 0.0, (
            "an idle server reported long-running queries - background tasks are being counted"
        )
    finally:
        conn.close()


@needs_mssql
def test_mssql_terminate_actually_kills_the_sleeping_transaction():
    from urllib.parse import urlparse

    import pymssql

    admin = _connect_or_fail(_MSSQL, MSSQL_DSN, "mssql")
    u = urlparse(MSSQL_DSN)
    victim = pymssql.connect(
        server=u.hostname, port=str(u.port or 1433), user=u.username, password=u.password or "",
        database=u.path.lstrip("/") or "master", autocommit=False,
    )
    try:
        vc = victim.cursor()
        vc.execute("SELECT @@SPID")
        victim_spid = int(vc.fetchone()[0])
        # An open transaction that is then left idle - the state that holds locks and blocks others.
        vc.execute("BEGIN TRANSACTION")
        vc.execute("SELECT 1")
        time.sleep(2.0)

        candidates = _MSSQLKiller.candidates(admin, 0, 20)
        assert victim_spid in candidates, f"the sleeping trx {victim_spid} was not selected: {candidates}"
        ac = admin.cursor()
        ac.execute("SELECT @@SPID")
        own_spid = int(ac.fetchone()[0])
        assert own_spid not in candidates, "it selected its OWN session to KILL"

        assert _MSSQLKiller.terminate(admin, [victim_spid]) == 1
        time.sleep(1.0)
        ac = admin.cursor()
        ac.execute("SELECT count(*) FROM sys.dm_exec_sessions WHERE session_id = %d", (victim_spid,))
        assert int(ac.fetchone()[0]) == 0, "the session was reported killed but is still connected"
    finally:
        with contextlib.suppress(Exception):
            victim.close()
        admin.close()
