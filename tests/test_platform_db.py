"""The database platform behind the RemediationWorkflow (decision D16) - fake connections, no server.

The real servers' grammar and the session ACTUALLY closing are proven in CI's db job
(tests/integration/test_live_database.py). Here: the scoping the removed backend lacked (its own
database, the application's logins only - audit A-B-H1), the ceiling twice, and the refusals."""

from __future__ import annotations

import pytest

from test_remediation_workflow import _approve_with, _run, owner, world  # noqa: F401 - fixtures
from warden.platforms import RoutedPlatform
from warden.platforms.db import DatabasePlatform, DatabasePlatformError

APP = ["orders_app"]


class _Cursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.sql.append((sql, params))
        if self.conn.fail:
            raise RuntimeError("boom: server unreachable")
        if sql.startswith(("SELECT current_database()", "SELECT DATABASE()", "SELECT DB_NAME()")):
            self.rows = [(self.conn.db,)]
        elif sql in ("SELECT session_user", "SELECT SUBSTRING_INDEX(CURRENT_USER(), '@', 1)", "SELECT SUSER_SNAME()"):
            self.rows = [(self.conn.me,)]
        elif "pg_terminate_backend(b.pid)" in sql:
            # A blocker close: this pid, this backend start, still blocking - all in the one statement.
            pid, started = params[0], params[1]
            hit = "pg_blocking_pids" in sql and self.conn.blocking.get(pid) == started
            if hit:
                self.conn.killed.append(pid)
            self.rows = [(True,)] if hit else []
        elif "count(w.pid)" in sql:
            self.rows = [(pid, started, n) for pid, (started, n) in self.conn.blockers.items()]
        elif "pg_terminate_backend" in sql:
            # The close carries the selection (R7-O1): only a session still idle in a transaction is closed.
            checked = "pid = %s" in sql and "state = 'idle in transaction'" in sql and "usename = ANY" in sql
            still = params[0] in self.conn.still or not checked
            if still:
                self.conn.killed.append(params[0])
            self.rows = [(True,)] if still else []
        elif sql.startswith("KILL"):
            self.conn.killed.append(int(sql.split()[1]))
        elif "p.id = %s" in sql:
            self.rows = [(params[0],)] if params[0] in self.conn.still else []
        elif "WHERE session_id = " in sql:
            spid = int(sql.split("WHERE session_id = ")[1].split()[0])
            self.rows = [(spid,)] if spid in self.conn.still else []
        else:
            self.rows = [(i,) for i in self.conn.stuck]

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _Conn:
    def __init__(self, db="orders", stuck=(101, 102), fail=False, me="warden_terminator"):
        self.db, self.stuck, self.fail, self.me = db, list(stuck), fail, me
        self.still = set(stuck)  # the sessions still idle when they are closed
        self.sql: list = []
        self.killed: list = []
        self.blockers: dict = {}  # pid -> (backend start, sessions it blocks), as read
        self.blocking: dict = {}  # pid -> backend start, for the sessions still blocking at the close

    def cursor(self):
        return _Cursor(self)


def _platform(engine="postgres", conn=None, users=APP, **kw):
    return DatabasePlatform(engine=engine, conn=conn or _Conn(), app_users=users, **{"environment": "dev", **kw})


PARAMS = {"database": "orders", "min_idle_seconds": 300, "max_sessions": 5}


def test_live_names_the_connected_database_only_when_app_logins_are_named():
    assert _platform().live("db_terminate_idle_in_tx", {})["database"] == {"orders"}
    assert _platform(users=[]).live("db_terminate_idle_in_tx", {}) == {}, "no allowlist: nothing may be closed"
    assert _platform(conn=_Conn(fail=True)).live("db_terminate_idle_in_tx", {}) == {}
    assert _platform("mysql").live("db_terminate_blocker", {}) == {}, "blockers: PostgreSQL only"


def test_postgres_closes_only_idle_app_sessions_in_its_own_database_and_never_its_own():
    conn = _Conn()
    out = _platform(conn=conn).apply("db_terminate_idle_in_tx", PARAMS)
    assert conn.killed == [101, 102] and "closed 2 session(s)" in out
    select = next(sql for sql, _ in conn.sql if "pg_stat_activity" in sql)
    for clause in ("state = 'idle in transaction'", "datname = current_database()", "usename = ANY(%s)",
                   "pid <> pg_backend_pid()", "LIMIT %s"):
        assert clause in select, clause
    params = next(p for sql, p in conn.sql if "pg_stat_activity" in sql)
    assert params == (APP, 300, 5)


def test_mysql_and_mssql_are_scoped_the_same_way():
    my = _Conn()
    _platform("mysql", my).apply("db_terminate_idle_in_tx", PARAMS)
    sql, params = next((s, p) for s, p in my.sql if "innodb_trx" in s)
    assert "p.db = DATABASE()" in sql and "p.user IN %s" in sql and "CONNECTION_ID()" in sql
    # Idle time, not the transaction's age (sixth review).
    assert "p.time >= %s" in sql and "trx_started" not in sql
    assert params == (tuple(APP), 300, 5) and my.killed == [101, 102]
    ms = _Conn()
    _platform("mssql", ms, users=["orders_app", "orders_ro"]).apply("db_terminate_idle_in_tx", PARAMS)
    sql, params = next((s, p) for s, p in ms.sql if "dm_exec_sessions" in s)
    assert "database_id = DB_ID()" in sql and "login_name IN (%s, %s)" in sql and "@@SPID" in sql
    assert params == ("orders_app", "orders_ro")


def test_the_ceiling_holds_in_python_even_if_the_server_returns_more():
    conn = _Conn(stuck=range(200, 260))
    _platform(conn=conn).apply("db_terminate_idle_in_tx", {**PARAMS, "max_sessions": 3})
    assert conn.killed == [200, 201, 202]


@pytest.mark.parametrize(("change", "match"), [
    ({"database": "billing"}, "not the one this platform is connected to"),
    ({"min_idle_seconds": 10}, "outside the bounds"),
    ({"max_sessions": 0}, "outside the bounds"),
    ({"max_sessions": 50}, "outside the bounds"),
    ({"max_sessions": True}, "outside the bounds"),
])
def test_a_plan_outside_the_bounds_or_for_another_database_is_refused_before_any_close(change, match):
    conn = _Conn()
    with pytest.raises(DatabasePlatformError, match=match):
        _platform(conn=conn).apply("db_terminate_idle_in_tx", {**PARAMS, **change})
    assert conn.killed == []


def test_no_app_logins_named_closes_nothing():
    conn = _Conn()
    with pytest.raises(DatabasePlatformError, match="no application logins"):
        _platform(conn=conn, users=[" ", ""]).apply("db_terminate_idle_in_tx", PARAMS)
    assert conn.killed == []


@pytest.mark.parametrize("engine", ["redis", "mongo", "sqlite"])
def test_engines_without_an_idle_in_transaction_state_are_refused(engine):
    with pytest.raises(DatabasePlatformError, match="no terminate support"):
        DatabasePlatform(engine=engine, conn=_Conn(), app_users=APP)


def test_other_entries_and_faults_are_errors():
    with pytest.raises(DatabasePlatformError, match="not something the database platform does"):
        _platform().apply("aurora_failover", {"cluster": "orders", "target_instance": "b"})
    with pytest.raises(DatabasePlatformError):
        _platform(conn=_Conn(fail=True)).apply("db_terminate_idle_in_tx", PARAMS)


def test_ids_are_ints_before_they_reach_kill():
    conn = _Conn(stuck=["7; DROP TABLE orders"])
    with pytest.raises(DatabasePlatformError, match="invalid literal for int"):
        _platform("mysql", conn).apply("db_terminate_idle_in_tx", PARAMS)
    assert not any(sql.startswith("KILL") for sql, _ in conn.sql)


def test_nothing_to_roll_back_and_health_is_a_positive_read():
    p = _platform(conn=_Conn(stuck=()))
    assert "nothing to roll back" in p.rollback("db_terminate_idle_in_tx", PARAMS, {})
    assert p.knows("orders") and p.healthy("orders") and not p.healthy("billing")
    assert not _platform(conn=_Conn(stuck=(9,))).healthy("orders")
    assert not _platform(conn=_Conn(stuck=()), users=[]).healthy("orders")


def test_an_approved_close_runs_through_the_workflow_end_to_end(world, owner, monkeypatch):  # noqa: F811
    conn = _Conn(stuck=(101,))
    platform = _platform(conn=conn)
    world["platform"] = RoutedPlatform(db=platform)
    # After the close the database is healthy: no session is stuck any more.
    original = platform.apply

    def apply_then_clear(entry, params):
        out = original(entry, params)
        conn.stuck = []
        return out

    monkeypatch.setattr(platform, "apply", apply_then_clear)
    out = _run(world, _approve_with(owner), entry="db_terminate_idle_in_tx", service="orders", params=PARAMS)
    assert out.status == "recovered", (out.status, out.reasons)
    assert conn.killed == [101]


@pytest.mark.parametrize("engine", ["postgres", "mysql", "mssql"])
def test_its_own_login_is_never_an_application_login(engine):
    """Sixth review (2026-10-01): WARDEN_DB_APP_USERS could name the terminate role's own login, so it closed other
    WARDEN sessions. Refused before anything is listed or closed."""
    conn = _Conn(me="orders_app")
    with pytest.raises(DatabasePlatformError, match="own login"):
        _platform(engine, conn, users=["orders_app"]).apply("db_terminate_idle_in_tx", PARAMS)
    assert conn.killed == [] and not any("innodb_trx" in s or "pg_stat_activity" in s or "dm_exec_sessions" in s
                                         for s, _ in conn.sql)


def test_a_broken_connection_is_reopened_and_use_is_one_at_a_time(monkeypatch):
    """Sixth review (2026-10-01): one connection forever - after a drop `healthy` was False until a restart - and
    shared by the worker's threads without a lock."""
    import threading
    import time

    from warden.platforms import db as dbmod

    opened, live = [], {"now": 0, "most": 0}

    class Overlaps(_Conn):
        def cursor(self):
            live["now"] += 1
            live["most"] = max(live["most"], live["now"])
            time.sleep(0.01)
            live["now"] -= 1
            if self.fail:
                raise RuntimeError("server closed the connection")
            return super().cursor()

        def close(self):
            pass

    class Adapter:
        @staticmethod
        def connect(dsn):
            conn = Overlaps(stuck=(), fail=not opened)  # the first connection is broken
            opened.append(conn)
            return conn

    monkeypatch.setattr(dbmod, "adapter_for", lambda engine: Adapter)
    p = DatabasePlatform(dsn="postgresql://warden_terminator@db.example/orders", app_users=APP)
    assert p.healthy("orders") is False and len(opened) == 1  # broken: dropped
    assert p.healthy("orders") is True and len(opened) == 2  # reopened
    threads = [threading.Thread(target=p.healthy, args=("orders",)) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert live["most"] == 1, "two threads used the connection at once"


def test_the_plan_names_the_database_server_but_no_credential():
    pw = "s3cr3t" + "-pw"
    p = DatabasePlatform(dsn=f"postgresql://warden_terminator:{pw}@prod-db.example:5432/orders", conn=_Conn(),
                         app_users=APP)
    state = p.live("db_terminate_idle_in_tx", PARAMS)["state"]
    assert state["server"] == "prod-db.example:5432" and pw not in str(state) and "warden_terminator" not in str(state)


@pytest.mark.parametrize("dsn, where", [
    ("postgresql://u:{pw}@db-a:5432,db-b:5433/orders?target_session_attrs=read-write", "db-a:5432,db-b:5433"),
    ("postgresql://u:{pw}@db.prod:5432/orders?host=db.staging", "db.prod:5432 host=db.staging"),
    ("postgresql://u:{pw}@db.prod/orders?hostaddr=10.0.0.9", "db.prod hostaddr=10.0.0.9"),
    ("postgresql:///orders?host=/var/run/postgresql", "host=/var/run/postgresql"),
    ("postgresql://u:{pw}@[2001:db8::5]:5432/orders", "[2001:db8::5]:5432"),
    ("host=db.prod port=6432 dbname=orders user=u password={pw}", "host=db.prod port=6432"),
])
def test_the_plan_names_where_libpq_really_connects(dsn, where):
    """Seventh review (2026-10-01): a multi-host DSN made the server lookup raise on every attempt, so no plan was
    ever written; `?host=` and `hostaddr=` - where libpq connects - were not shown, nor a socket. Never a password."""
    pw = "s3cr3t" + "-pw"
    p = DatabasePlatform(dsn=dsn.format(pw=pw), engine="postgres", conn=_Conn(), app_users=APP)
    state = p.live("db_terminate_idle_in_tx", PARAMS)["state"]
    assert state["server"] == where and pw not in str(state)


@pytest.mark.parametrize("engine", ["postgres", "mysql", "mssql"])
@pytest.mark.parametrize("named", ["ORDERS_APP", "Orders_App"])
def test_its_own_login_in_another_letter_case_is_refused_too(engine, named):
    """Seventh review (2026-10-01): MySQL's processlist.user and SQL Server's login_name match without case, so an
    allowlist naming the platform's own login in capitals had it close its own sessions."""
    conn = _Conn(me="orders_app")
    with pytest.raises(DatabasePlatformError, match="own login"):
        _platform(engine, conn, users=[named]).apply("db_terminate_idle_in_tx", PARAMS)
    assert conn.killed == []


@pytest.mark.parametrize("engine, dsn, env, where", [
    ("postgres", "postgresql:///orders?service=prod", {}, "service=prod"),
    ("postgres", "postgresql:///orders", {"PGHOST": "db.prod"}, "PGHOST=db.prod"),
    ("mysql", "mysql://u:{pw}@/orders", {}, "localhost:3306 (TCP)"),
    ("mysql", "mysql://u:{pw}@db-staging/orders?host=db-prod", {}, "db-staging"),
    ("postgres", "password=S3cr.host=hunter2 dbname=orders", {}, "the local socket"),
    ("postgres", "password='x port=6543' host=db.prod dbname=orders", {}, "host=db.prod"),
    # Ninth review: urlsplit ends the authority at `?` or `#` - the user and the password's start were the "server".
    ("postgres", "postgresql://orders_app:{pw}" + "?x@db.prod:5432/orders", {}, "db.prod:5432"),
    ("postgres", "postgresql://orders_app:{pw}" + "#x@db.prod/orders", {}, "db.prod"),
    ("postgres", "postgresql://orders_app:{pw}" + "?host=evil@db.prod/orders?port=6543", {}, "db.prod port=6543"),
    ("postgres", "postgresql://orders_app:{pw}" + "/x@db.prod/orders", {}, "db.prod"),
    ("mysql", "mysql://orders_app:{pw}" + "?x@db-staging/orders", {}, "db-staging"),
    ("postgres", "postgresql://db.prod/orders?application_name=a@b&password={pw}", {},
     "a host the DSN does not state plainly (not shown)"),
    # Register R9-O4: libpq takes PGHOSTADDR and PGPORT from the environment for what the DSN leaves out.
    ("postgres", "postgresql://db.prod/orders", {"PGHOSTADDR": "10.9.9.9"}, "db.prod PGHOSTADDR=10.9.9.9 (environment)"),
    ("postgres", "postgresql://db.prod/orders", {"PGPORT": "6543"}, "db.prod PGPORT=6543 (environment)"),
    ("postgres", "postgresql://db.prod:5432/orders", {"PGPORT": "6543"}, "db.prod:5432"),
    ("postgres", "host=db.prod dbname=orders", {"PGHOSTADDR": "10.9.9.9"}, "host=db.prod PGHOSTADDR=10.9.9.9 (environment)"),
    ("postgres", "host=db.prod hostaddr=10.1.1.1 dbname=orders", {"PGHOSTADDR": "10.9.9.9"}, "host=db.prod hostaddr=10.1.1.1"),
    ("mysql", "mysql://u:{pw}@db-staging/orders", {"PGHOSTADDR": "10.9.9.9"}, "db-staging"),
])
def test_the_plan_names_the_server_the_driver_really_reaches(monkeypatch, engine, dsn, env, where):
    """Eighth review (2026-10-01): a service file and PGHOST showed "the local socket"; MySQL with no host is TCP to
    localhost; pymysql ignores `?host=`; and text inside a password value was read as a host or a port."""
    for k in ("PGHOST", "PGHOSTADDR", "PGPORT", "PGSERVICE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    pw = "s3cr3t" + "-pw"
    p = DatabasePlatform(dsn=dsn.format(pw=pw), engine=engine, conn=_Conn(), app_users=APP)
    state = p.live("db_terminate_idle_in_tx", PARAMS)["state"]
    assert state["server"] == where and pw not in str(state) and "hunter2" not in str(state), state["server"]
    assert "orders_app" not in state["server"], state["server"]


@pytest.mark.parametrize("engine", ["postgres", "mysql", "mssql"])
def test_its_own_login_reported_in_capitals_is_refused_too(engine):
    """Eighth review: the fold was tested only with a lowercase own login - folding the allowlist alone passed."""
    conn = _Conn(me="ORDERS_APP")
    with pytest.raises(DatabasePlatformError, match="own login"):
        _platform(engine, conn, users=["orders_app"]).apply("db_terminate_idle_in_tx", PARAMS)
    assert conn.killed == []


@pytest.mark.parametrize("engine", ["postgres", "mysql", "mssql"])
def test_a_close_with_nothing_to_close_says_so_and_closes_nothing(engine):
    """Audit A-B-M2: "applied" was reported even when nothing changed. With no session idle long enough, the platform
    closes nothing and its report - what the audit and the approver see - says so."""
    conn = _Conn(stuck=())
    report = _platform(engine, conn).apply("db_terminate_idle_in_tx", PARAMS)
    assert conn.killed == [] and "nothing closed" in report and "closed 0" not in report, report


@pytest.mark.parametrize("engine", ["postgres", "mysql", "mssql"])
def test_a_session_that_resumed_after_it_was_listed_is_not_closed(engine):
    """Register R7-O1: a session was listed idle and closed by a separate statement, with no re-check - one that
    resumed or committed in between was closed anyway."""
    conn = _Conn(stuck=(101, 102))
    conn.still = {102}  # 101 committed between the list and the close
    out = _platform(engine, conn).apply("db_terminate_idle_in_tx", PARAMS)
    assert conn.killed == [102] and out.startswith("closed 1 session"), (conn.killed, out)


STARTED = "2026-10-04 09:00:00.123+00"


def _blocking(conn=None):
    conn = conn or _Conn(stuck=())
    conn.blockers = {4242: (STARTED, 3), 4343: (STARTED, 1)}
    conn.blocking = {4242: STARTED, 4343: STARTED}
    return conn


def test_a_blocker_close_may_name_only_a_session_seen_blocking():
    conn = _blocking()
    live = _platform(conn=conn).live("db_terminate_blocker", {"pid": "4242"})
    assert live["pid"] == {"4242", "4343"} and live["database"] == {"orders"}
    assert live["state"]["blocker"] == {"pid": "4242", "backend_start": STARTED}  # the named one, nothing that moves
    conn.blockers[4545] = (STARTED, 9)  # another blocker, more waiters: the plan's snapshot is unchanged (no drift)
    conn.blockers[4242] = (STARTED, 7)
    assert _platform(conn=conn).live("db_terminate_blocker", {"pid": "4242"})["state"] == live["state"]
    sql, params = next((s, p) for s, p in conn.sql if "count(w.pid)" in s)
    for clause in ("pg_blocking_pids(w.pid)", "b.datname = current_database()", "w.datname = current_database()",
                   "b.usename = ANY(%s)", "b.pid <> pg_backend_pid()", "w.query_start < now() - make_interval"):
        assert clause in sql, clause
    assert params[0] == APP and params[1] >= 30  # the app's logins only; a momentary lock is not a blocker
    assert _platform(users=[], conn=_blocking()).live("db_terminate_blocker", {}) == {}


def test_a_blocker_is_closed_only_if_it_is_still_the_same_session_and_still_blocking():
    conn = _blocking()
    platform = _platform(conn=conn)
    snapshot = platform.live("db_terminate_blocker", {"pid": "4242"})["state"]
    out = platform.apply("db_terminate_blocker", {"database": "orders", "pid": "4242"}, snapshot)
    assert conn.killed == [4242] and "was blocking others" in out
    sql = next(s for s, _ in conn.sql if "pg_terminate_backend(b.pid)" in s)
    assert "b.backend_start::text = %s" in sql and "pg_blocking_pids(w.pid)" in sql and "b.usename = ANY(%s)" in sql
    snapshot = platform.live("db_terminate_blocker", {"pid": "4343"})["state"]
    conn.blocking[4343] = "2026-10-04 09:30:00+00"  # the pid now belongs to a later session
    out = platform.apply("db_terminate_blocker", {"database": "orders", "pid": "4343"}, snapshot)
    assert conn.killed == [4242] and "nothing closed" in out


@pytest.mark.parametrize("params, snapshot, needle", [
    ({"database": "orders", "pid": "9999"}, None, "not a session the approved plan showed"),
    ({"database": "orders", "pid": "4242; SELECT 1"}, None, "not a session the approved plan showed"),
    ({"database": "other", "pid": "4242"}, None, "not the one this platform is connected to"),
])
def test_a_blocker_close_refuses_what_the_plan_did_not_show(params, snapshot, needle):
    conn = _blocking()
    platform = _platform(conn=conn)
    snapshot = snapshot or platform.live("db_terminate_blocker", {"pid": "4242"})["state"]
    with pytest.raises(DatabasePlatformError, match=needle):
        platform.apply("db_terminate_blocker", params, snapshot)
    assert conn.killed == []
    with pytest.raises(DatabasePlatformError, match="PostgreSQL only"):
        _platform("mysql", _blocking()).apply("db_terminate_blocker", {"database": "orders", "pid": "4242"},
                                              {"blocker": {"pid": "4242", "backend_start": STARTED}})


def test_a_database_with_a_blocker_is_not_healthy():
    assert _platform(conn=_Conn(stuck=())).healthy("orders")
    assert not _platform(conn=_blocking()).healthy("orders")
