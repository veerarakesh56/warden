"""The read-only database evidence backend: engine selection, per-engine metric parsing, partial
failures — and the tripwire that proves the module cannot write.

The stubs mimic each driver's response SHAPE (what psycopg/pymysql/redis/pymongo/pymssql actually
return), because that shape is the thing a unit test can get wrong and a live database cannot.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from warden.database import (
    _MSSQL,
    DatabaseBackend,
    _Mongo,
    _MySQL,
    _Postgres,
    _Redis,
    adapter_for,
    dsn_of,
    engine_of,
)
from warden.models import Alert, Severity
from warden.tools import PARTIAL_PREFIX, ToolError, resolve_backend


def _alert(**labels):
    return Alert(
        alert_id="inc-005", name="DBConnectionsStuck", severity=Severity.high, service="payments",
        environment="staging", summary="pool exhausted", started_at="2026-08-26T00:00:00Z",
        labels=labels,
    )


# ------------------------------------------------------------------ engine + DSN resolution

@pytest.mark.parametrize("dsn,engine", [
    ("postgresql://u:p@h:5432/db", "postgres"),
    ("postgres://u:p@h/db", "postgres"),
    ("mysql://u:p@h:3306/db", "mysql"),
    ("mariadb://u:p@h/db", "mysql"),
    ("redis://h:6379/0", "redis"),
    ("rediss://h:6379/0", "redis"),
    ("mongodb://h:27017/db", "mongo"),
    ("mongodb+srv://h/db", "mongo"),
    ("mssql://u:p@h:1433/db", "mssql"),
    ("sqlserver://u:p@h/db", "mssql"),
])
def test_engine_is_read_from_the_dsn_scheme(dsn, engine):
    assert engine_of(dsn) == engine


def test_an_unsupported_scheme_is_refused_with_the_known_list():
    with pytest.raises(ToolError, match="unsupported database DSN scheme"):
        engine_of("oracle://u:p@h/db")


def test_dsn_comes_from_the_alert_label_first_then_the_environment(monkeypatch):
    monkeypatch.setenv("WARDEN_DB_DSN", "postgresql://env/db")
    assert dsn_of(_alert(dsn="postgresql://label/db")) == "postgresql://label/db"
    assert dsn_of(_alert()) == "postgresql://env/db"


def test_no_dsn_anywhere_is_a_tool_error_not_a_silent_empty_read(monkeypatch):
    monkeypatch.delenv("WARDEN_DB_DSN", raising=False)
    with pytest.raises(ToolError, match="no database DSN"):
        dsn_of(_alert())


@pytest.mark.parametrize("name,engine", [
    ("postgres", "postgres"), ("postgresql", "postgres"), ("mysql", "mysql"), ("mariadb", "mysql"),
    ("redis", "redis"), ("mongo", "mongo"), ("mongodb", "mongo"), ("mssql", "mssql"),
    ("sqlserver", "mssql"), ("db", None), ("database", None),
])
def test_resolve_backend_maps_every_database_name(name, engine):
    backend = resolve_backend(name)
    assert isinstance(backend, DatabaseBackend)
    assert backend._engine == engine


def test_an_unknown_backend_lists_what_is_available():
    with pytest.raises(ToolError) as exc:
        resolve_backend("cassandra")
    message = str(exc.value)
    assert "postgres" in message and "mssql" in message and "k8s" in message


def test_databases_have_no_deploys_so_p5_cannot_be_satisfied_by_one():
    """P5 refuses a rollback without a deploy in evidence. A database never supplies one."""
    assert DatabaseBackend(engine="postgres", conn=object()).deploys(_alert()) == []


# ------------------------------------------------------------------ per-engine metric parsing

class _SqlStub:
    """Answers queries by substring, like a tiny fake server. Records what it was asked."""

    def __init__(self, answers: dict[str, list]):
        self.answers = answers
        self.asked: list[str] = []

    # psycopg / pymysql style: cursor() is a context manager
    def cursor(self):
        return _StubCursor(self)

    def _answer(self, sql: str):
        self.asked.append(" ".join(sql.split()))
        for needle, rows in self.answers.items():
            if needle.lower() in sql.lower():
                return rows
        raise AssertionError(f"stub has no answer for: {sql}")


class _StubCursor:
    def __init__(self, owner):
        self.owner = owner
        self.rows: list = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        self.rows = self.owner._answer(sql)

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


def test_postgres_metrics_are_parsed_and_named_for_what_they_count():
    conn = _SqlStub({
        "count(*) from pg_stat_activity where state = 'idle in transaction'": [(25,)],
        "count(*) from pg_stat_activity where state = 'active'": [(2,)],
        "count(*) from pg_stat_activity": [(100,)],
        "show max_connections": [("100",)],
        "pg_locks": [(4,)],
        "pg_last_xact_replay_timestamp": [(None,)],
    })
    m = _Postgres.metrics(conn)
    assert m["active_connections"] == 100.0
    assert m["idle_in_transaction"] == 25.0
    assert m["long_running_queries"] == 2.0
    assert m["max_connections"] == 100.0
    assert m["locks_waiting"] == 4.0
    assert m["connections_used_pct"] == 1.0
    # NULL replay timestamp = a primary. Omitted, never reported as 0.0 (which reads as "no lag").
    assert "replica_lag_seconds" not in m


def test_postgres_reports_replica_lag_when_it_is_a_replica():
    conn = _SqlStub({
        "count(*) from pg_stat_activity where state = 'idle in transaction'": [(0,)],
        "count(*) from pg_stat_activity where state = 'active'": [(0,)],
        "count(*) from pg_stat_activity": [(5,)],
        "show max_connections": [("100",)],
        "pg_locks": [(0,)],
        "pg_last_xact_replay_timestamp": [(12.5,)],
    })
    assert _Postgres.metrics(conn)["replica_lag_seconds"] == 12.5


def test_postgres_problem_ops_excludes_own_backend_and_redacts_query_text():
    conn = _SqlStub({"pg_stat_activity": [(101, "idle in transaction", 900, "SELECT * FROM users WHERE email='a@b.io'")]})
    lines = _Postgres.problem_ops(conn, 300)
    assert lines and "pid=101" in lines[0]
    assert "a@b.io" not in lines[0], "query text can carry PII and must be redacted"
    assert "pid <> pg_backend_pid()" in conn.asked[0]


def test_mysql_metrics_read_status_and_variables():
    conn = _SqlStub({
        "threads_connected": [("Threads_connected", "42")],
        "max_connections": [("max_connections", "151")],
        "innodb_trx": [(3,)],
        "command = 'query'": [(1,)],
    })
    m = _MySQL.metrics(conn)
    assert m["active_connections"] == 42.0
    assert m["max_connections"] == 151.0
    assert m["idle_in_transaction"] == 3.0
    assert m["long_running_queries"] == 1.0


def test_mssql_metrics_are_parsed():
    conn = _SqlStub({
        "open_transaction_count > 0": [(6,)],
        "total_elapsed_time": [(2,)],
        "is_user_process = 1": [(30,)],
    })
    m = _MSSQL.metrics(conn)
    assert m["active_connections"] == 30.0
    assert m["idle_in_transaction"] == 6.0
    assert m["long_running_queries"] == 2.0


class _RedisStub:
    def __init__(self, clients, info=None):
        self._clients = clients
        self._info = info or {}

    def info(self):
        return self._info

    def config_get(self, key):
        return {"maxclients": "10000"}

    def client_list(self):
        return self._clients

    def client_id(self):
        return 1


def test_redis_metrics_count_idle_clients_under_the_common_key():
    conn = _RedisStub(
        clients=[{"id": "1", "idle": "0", "addr": "10.0.0.1:5000"},
                 {"id": "2", "idle": "900", "addr": "10.0.0.2:5001"},
                 {"id": "3", "idle": "400", "addr": "10.0.0.3:5002"}],
        info={"connected_clients": 3, "blocked_clients": 1, "used_memory": 1000,
              "maxmemory": 4000, "evicted_keys": 7, "rejected_connections": 2},
    )
    m = _Redis.metrics(conn)
    assert m["connected_clients"] == 3.0
    assert m["blocked_clients"] == 1.0
    assert m["evicted_keys"] == 7.0
    assert m["memory_used_pct"] == 0.25
    # two clients are idle past the 300s default -> exposed as idle_in_transaction so the reasoner
    # treats a stuck Redis client like a stuck SQL connection.
    assert m["idle_in_transaction"] == 2.0


def test_redis_problem_ops_never_lists_its_own_client():
    conn = _RedisStub(clients=[{"id": "1", "idle": "900", "addr": "x"},
                               {"id": "2", "idle": "900", "addr": "y"}])
    lines = _Redis.problem_ops(conn, 300)
    assert len(lines) == 1 and "id=2" in lines[0], "client id 1 is this connection"


class _MongoStub:
    def __init__(self, ops, conns=None):
        self.admin = self
        self._ops = ops
        self._conns = conns or {"current": 10, "available": 90}

    def command(self, name, *args, **kw):
        if name == "serverStatus":
            return {"connections": self._conns}
        return {"inprog": self._ops}


def test_mongo_metrics_count_long_running_ops():
    conn = _MongoStub(ops=[
        {"secs_running": 900, "opid": 1, "ns": "warden.orders", "command": {"find": "orders"}},
        {"secs_running": 70, "opid": 2, "ns": "warden.orders", "command": {"find": "orders"}},
        {"secs_running": 1, "opid": 3, "ns": "warden.orders", "command": {"find": "orders"}},
    ])
    m = _Mongo.metrics(conn)
    assert m["current_connections"] == 10.0
    assert m["available_connections"] == 90.0
    assert m["long_running_ops"] == 2.0        # >= 60s
    assert m["idle_in_transaction"] == 1.0     # >= 300s
    assert m["connections_used_pct"] == 0.1


# ------------------------------------------------------------------ the contract + failures

def test_logs_prefix_each_stuck_connection_with_the_engine():
    conn = _SqlStub({"pg_stat_activity": [(101, "idle in transaction", 900, "SELECT 1")]})
    lines = DatabaseBackend(engine="postgres", conn=conn).logs(_alert())
    assert lines and lines[0].startswith("postgres stuck connection:")


def test_a_failed_problem_op_read_is_a_PARTIAL_not_evidence():
    """gather() routes a TOOL-PARTIAL line into tool_errors, where policy P8 sees it — it must never
    be counted as a log line that looks like evidence."""
    class Boom:
        def cursor(self):
            raise RuntimeError("permission denied for pg_stat_activity")

    lines = DatabaseBackend(engine="postgres", conn=Boom()).logs(_alert())
    assert len(lines) == 1 and lines[0].startswith(PARTIAL_PREFIX)
    assert "permission denied" in lines[0]


def test_a_failed_metrics_read_is_a_hard_ToolError():
    class Boom:
        def cursor(self):
            raise RuntimeError("connection refused")

    with pytest.raises(ToolError, match="database metrics read failed"):
        DatabaseBackend(engine="postgres", conn=Boom()).metrics(_alert())


def test_injecting_a_connection_without_an_engine_is_refused():
    with pytest.raises(ToolError, match="also needs engine"):
        DatabaseBackend(conn=object())


def test_every_engine_has_an_adapter():
    for engine in ("postgres", "mysql", "redis", "mongo", "mssql"):
        assert adapter_for(engine).engine == engine
    with pytest.raises(ToolError, match="no database adapter"):
        adapter_for("oracle")


# ------------------------------------------------------------------ the read-only tripwire

WRITE_VERBS = (
    "pg_terminate", "killop", "client_kill", "client kill", "flushall", "flushdb",
    "insert into", "update ", "delete from", "drop ", "truncate", "alter ", "grant ", "kill ",
)


# The calls that actually send something to a database server. A write verb only matters if it can
# reach one of these.
_EXECUTING_CALLS = frozenset({"execute", "executemany", "command", "run_command", "eval"})


def _statements_this_module_can_execute(path: pathlib.Path) -> list[str]:
    """Every string this module passes to a database-executing call.

    Deliberately NOT "every string literal": that version flagged two innocent things and would keep
    doing so. The module docstring NAMES the forbidden verbs in order to state the rule, and
    `_MONGO_INTERNAL_COMMANDS` lists `killOp` precisely so it is never SELECTED. Both are *mentions*,
    not *instances* — the same mention-counted-as-instance trap this repo keeps meeting.

    What actually matters is narrower and checkable: does a write verb appear in something handed to
    `.execute()` / `.command()`? f-strings are included via their literal parts, which is how
    `f"KILL {int(spid)}"` stays visible to this check.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name not in _EXECUTING_CALLS:
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                out.append(arg.value)
            elif isinstance(arg, ast.JoinedStr):  # an f-string: keep its literal parts
                out.extend(
                    part.value for part in arg.values
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                )
    return out


def test_the_read_backend_contains_no_executable_write_verb():
    """Read-only BY CONSTRUCTION. The write path lives in database_remediation.py, behind its own
    credential — exactly as the k8s read backend is separate from the k8s write backend."""
    path = pathlib.Path(__file__).resolve().parents[1] / "src" / "warden" / "database.py"
    offenders = [
        (verb, s) for s in _statements_this_module_can_execute(path)
        for verb in WRITE_VERBS if verb in s.lower()
    ]
    assert not offenders, f"write verb in the READ-ONLY backend: {offenders}"


def test_the_tripwire_can_actually_fire():
    """A guard nobody has watched fail is not a guard. The remediation module DOES write, so the same
    check must flag it — otherwise the test above passes for the wrong reason."""
    path = pathlib.Path(__file__).resolve().parents[1] / "src" / "warden" / "database_remediation.py"
    found = [
        verb for s in _statements_this_module_can_execute(path)
        for verb in WRITE_VERBS if verb in s.lower()
    ]
    assert found, "the tripwire found no write verb in the WRITE module - it cannot be trusted"


# ------------------------------------------------------------------ the clock-skew finding
# Found against a REAL PostgreSQL container: 2 rounds in 10 missed a genuinely stuck connection,
# and the server itself reported its age as MINUS 115 seconds - a state_change stamped in the future
# by a host clock step. Such a connection can never satisfy `state_change < now() - interval`, so it
# is invisible to both the evidence read and the terminator, forever and silently.

def test_connections_whose_age_cannot_be_judged_are_reported_as_a_partial():
    """Declining to terminate an unageable connection is right; doing it silently is not.

    The TOOL-PARTIAL prefix routes this into tool_errors, which fires policy P8 and sends the
    incident to a human — the correct answer to "there is something here I cannot measure".
    """
    conn = _SqlStub({
        "state_change > now()": [(2,)],
        "pg_stat_activity": [(101, "idle in transaction", 900, "SELECT 1")],
    })
    lines = _Postgres.problem_ops(conn, 300)
    partials = [line for line in lines if line.startswith(PARTIAL_PREFIX)]
    assert len(partials) == 1, f"clock-skewed connections must be surfaced: {lines}"
    assert "future" in partials[0] and "clock skew" in partials[0]


def test_no_clock_skew_means_no_noise():
    conn = _SqlStub({
        "state_change > now()": [(0,)],
        "pg_stat_activity": [(101, "idle in transaction", 900, "SELECT 1")],
    })
    lines = _Postgres.problem_ops(conn, 300)
    assert not any(line.startswith(PARTIAL_PREFIX) for line in lines)


def test_a_partial_from_the_adapter_reaches_gather_with_its_prefix_intact():
    """If logs() prefixed it as evidence, "I could not measure this" would be counted as a log line
    the verifier treats as knowledge."""
    conn = _SqlStub({
        "state_change > now()": [(3,)],
        "pg_stat_activity": [],
    })
    lines = DatabaseBackend(engine="postgres", conn=conn).logs(_alert())
    assert len(lines) == 1
    assert lines[0].startswith(PARTIAL_PREFIX), f"prefix was mangled: {lines[0]!r}"
    assert "stuck connection" not in lines[0]
