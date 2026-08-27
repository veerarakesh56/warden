"""Read-only database evidence backend — the DB twin of `k8s_backend.py`.

Drops into `gather(alert, backend=DatabaseBackend())` with no change above it: the same three-method
contract (`logs` / `metrics` / `deploys`) `FixtureBackend` satisfies. Reads health from PostgreSQL,
MySQL/MariaDB, Redis, MongoDB or SQL Server — chosen from the DSN scheme — and reports it as evidence.

Read-only BY CONSTRUCTION: every statement here is a SELECT / SHOW / INFO / serverStatus / currentOp.
There is no INSERT/UPDATE/DELETE/DROP/KILL/pg_terminate/FLUSH/killOp anywhere in this file — a test
greps for exactly that. The terminate (write) path lives in a SEPARATE module, `database_remediation.py`,
behind its own least-privilege credential, exactly as the k8s write path is separate from the read one.

Mapping an alert to a connection:
    dsn = alert.labels["dsn"]  or  $WARDEN_DB_DSN
The engine is the DSN scheme (postgresql://, mysql://, redis://, mongodb://, mssql://). The driver for
that engine is an optional extra (`pip install -e ".[postgres]"` …), imported lazily.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from .models import Alert
from .redaction import redact
from .tools import PARTIAL_PREFIX, ToolError

CONNECT_TIMEOUT = float(os.environ.get("WARDEN_DB_CONNECT_TIMEOUT", "4.0"))
# A connection counts as "stuck" (terminate-eligible, and evidence in its own right) once it has been
# idle-in-transaction / idle / a long-running op for this many seconds.
IDLE_SECS = int(os.environ.get("WARDEN_DB_TERMINATE_IDLE_SECS", "300"))
PROBLEM_OP_LIMIT = int(os.environ.get("WARDEN_DB_PROBLEM_LIMIT", "10"))

# DSN scheme -> engine key. The engine key selects the adapter here and the terminate adapter there.
_SCHEME_ENGINE = {
    "postgres": "postgres", "postgresql": "postgres",
    "mysql": "mysql", "mariadb": "mysql",
    "redis": "redis", "rediss": "redis",
    "mongodb": "mongo", "mongodb+srv": "mongo",
    "mssql": "mssql", "sqlserver": "mssql",
}


def engine_of(dsn: str) -> str:
    scheme = urlparse(dsn).scheme.lower()
    if scheme not in _SCHEME_ENGINE:
        raise ToolError(f"unsupported database DSN scheme '{scheme}'. Known: {sorted(set(_SCHEME_ENGINE))}")
    return _SCHEME_ENGINE[scheme]


def dsn_of(alert: Alert) -> str:
    dsn = alert.labels.get("dsn") or os.environ.get("WARDEN_DB_DSN")
    if not dsn:
        raise ToolError("no database DSN (set alert.labels['dsn'] or $WARDEN_DB_DSN)")
    return dsn


# --------------------------------------------------------------------------- read adapters
# Each adapter is read-only. It connects, reads metrics, and lists the problem connections as text.
# `connect` is shared with the terminate module so both open the connection the same way.


class _Postgres:
    engine = "postgres"

    @staticmethod
    def connect(dsn: str):
        import psycopg

        return psycopg.connect(dsn, connect_timeout=int(CONNECT_TIMEOUT), autocommit=True)

    @staticmethod
    def _rows(conn, sql: str, params=()):
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    @classmethod
    def metrics(cls, conn) -> dict[str, float]:
        r = cls._rows
        total = r(conn, "SELECT count(*) FROM pg_stat_activity")[0][0]
        idle_tx = r(conn, "SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction'")[0][0]
        long_q = r(conn, "SELECT count(*) FROM pg_stat_activity WHERE state = 'active' "
                         "AND now() - query_start > interval '60 seconds'")[0][0]
        max_conn = int(r(conn, "SHOW max_connections")[0][0])
        waiting = r(conn, "SELECT count(*) FROM pg_locks WHERE NOT granted")[0][0]
        out = {
            "active_connections": float(total),
            "idle_in_transaction": float(idle_tx),
            "long_running_queries": float(long_q),
            "max_connections": float(max_conn),
            "locks_waiting": float(waiting),
            "connections_used_pct": float(total) / float(max_conn) if max_conn else 0.0,
        }
        lag = r(conn, "SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))")[0][0]
        if lag is not None:  # NULL on a primary — omit rather than report 0 (which reads as "no lag")
            out["replica_lag_seconds"] = float(lag)
        return out

    @classmethod
    def problem_ops(cls, conn, idle_secs: int) -> list[str]:
        rows = cls._rows(
            conn,
            "SELECT pid, state, EXTRACT(EPOCH FROM (now() - state_change))::int, left(query, 80) "
            "FROM pg_stat_activity "
            "WHERE state = 'idle in transaction' AND state_change < now() - make_interval(secs => %s) "
            "AND pid <> pg_backend_pid() ORDER BY state_change LIMIT %s",
            (idle_secs, PROBLEM_OP_LIMIT),
        )
        lines = [
            f"pid={pid} {state} for {age}s: {redact(str(q or '')).text}"
            for pid, state, age, q in rows
        ]
        return lines + cls._unageable(conn)

    @classmethod
    def _unageable(cls, conn) -> list[str]:
        """Connections whose `state_change` is in the FUTURE — found against a real server.

        A clock step (an NTP correction, a VM pause/resume, a container host resyncing) can stamp a
        connection with a timestamp ahead of `now()`. Such a connection can never satisfy
        `state_change < now() - interval`, so it is silently invisible to both the evidence read and
        the terminator — a genuinely stuck connection that no amount of waiting will surface.

        Declining to terminate something whose age is unknowable is the right call: it might be one
        second old. Doing so SILENTLY is not. Reported with the TOOL-PARTIAL prefix, this becomes a
        `tool_error`, which fires policy P8 (partial context) and sends the incident to a human —
        the correct outcome for "there is something here I cannot measure".
        """
        rows = cls._rows(
            conn,
            "SELECT count(*) FROM pg_stat_activity "
            "WHERE state = 'idle in transaction' AND state_change > now()",
        )
        skewed = int(rows[0][0]) if rows else 0
        if not skewed:
            return []
        return [
            (
                f"{PARTIAL_PREFIX}{skewed} idle-in-transaction connection(s) carry a state_change in "
                "the future (server clock skew); their age cannot be judged, so they were neither "
                "counted nor eligible for termination"
            )
        ]


class _MySQL:
    engine = "mysql"

    @staticmethod
    def connect(dsn: str):
        import pymysql

        u = urlparse(dsn)
        return pymysql.connect(
            host=u.hostname or "localhost", port=u.port or 3306,
            user=(u.username or "root"), password=(u.password or ""),
            database=(u.path.lstrip("/") or None), connect_timeout=int(CONNECT_TIMEOUT), autocommit=True,
        )

    @staticmethod
    def _rows(conn, sql, params=()):
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    @classmethod
    def metrics(cls, conn) -> dict[str, float]:
        r = cls._rows
        threads = int(r(conn, "SHOW STATUS LIKE 'Threads_connected'")[0][1])
        max_conn = int(r(conn, "SHOW VARIABLES LIKE 'max_connections'")[0][1])
        # idle-in-transaction ≈ a session inside an open trx that is not currently executing.
        idle_tx = r(conn, "SELECT count(*) FROM information_schema.innodb_trx t "
                          "JOIN information_schema.processlist p ON t.trx_mysql_thread_id = p.id "
                          "WHERE p.command = 'Sleep' AND t.trx_started < (NOW() - INTERVAL 60 SECOND)")[0][0]
        long_q = r(conn, "SELECT count(*) FROM information_schema.processlist "
                         "WHERE command = 'Query' AND time > 60")[0][0]
        return {
            "active_connections": float(threads),
            "max_connections": float(max_conn),
            "idle_in_transaction": float(idle_tx or 0),
            "long_running_queries": float(long_q or 0),
            "connections_used_pct": float(threads) / float(max_conn) if max_conn else 0.0,
        }

    @classmethod
    def problem_ops(cls, conn, idle_secs: int) -> list[str]:
        rows = cls._rows(
            conn,
            "SELECT p.id, p.time, LEFT(COALESCE(p.info,''), 80) "
            "FROM information_schema.innodb_trx t "
            "JOIN information_schema.processlist p ON t.trx_mysql_thread_id = p.id "
            "WHERE p.command = 'Sleep' AND t.trx_started < (NOW() - INTERVAL %s SECOND) "
            "AND p.id <> CONNECTION_ID() ORDER BY t.trx_started LIMIT %s",
            (idle_secs, PROBLEM_OP_LIMIT),
        )
        return [f"id={i} idle-in-trx {t}s: {redact(str(q or '')).text}" for i, t, q in rows]


class _Redis:
    engine = "redis"

    @staticmethod
    def connect(dsn: str):
        import redis

        return redis.from_url(dsn, socket_connect_timeout=CONNECT_TIMEOUT, socket_timeout=CONNECT_TIMEOUT,
                              decode_responses=True)

    @classmethod
    def metrics(cls, conn) -> dict[str, float]:
        info = conn.info()
        clients = float(info.get("connected_clients", 0))
        maxclients = float(conn.config_get("maxclients").get("maxclients", 0) or 0)
        idle = sum(1 for c in conn.client_list() if int(c.get("idle", 0)) >= IDLE_SECS)
        out = {
            "connected_clients": clients,
            "blocked_clients": float(info.get("blocked_clients", 0)),
            "maxclients": maxclients,
            "used_memory": float(info.get("used_memory", 0)),
            "evicted_keys": float(info.get("evicted_keys", 0)),
            "rejected_connections": float(info.get("rejected_connections", 0)),
            # a Redis client idle past the threshold is the "stuck connection" the terminator kills;
            # exposed under the common key so the reasoner treats it like idle-in-transaction.
            "idle_in_transaction": float(idle),
        }
        maxmem = float(info.get("maxmemory", 0))
        if maxmem:
            out["memory_used_pct"] = out["used_memory"] / maxmem
        return out

    @classmethod
    def problem_ops(cls, conn, idle_secs: int) -> list[str]:
        me = conn.client_id()
        out = []
        for c in conn.client_list():
            if int(c.get("idle", 0)) >= idle_secs and int(c.get("id", 0)) != me:
                out.append(f"id={c.get('id')} idle {c.get('idle')}s addr={redact(str(c.get('addr',''))).text}")
                if len(out) >= PROBLEM_OP_LIMIT:
                    break
        return out


# MongoDB's `currentOp` reports the SERVER'S OWN background work alongside user queries, and some of
# it legitimately runs for a long time. The awaitable `hello` heartbeat every driver (including ours)
# keeps open is the worst trap: it sits "active" for seconds by design, so a naive
# `secs_running >= threshold` filter selects it — which would inflate the evidence with normal
# background activity AND, on the terminate path, kill the driver's own monitoring connections while
# never touching the stuck query somebody actually called about. Observed against a real server.
#
# So the rule is an ALLOW-list, not a deny-list: killing is destructive, and under-selecting is the
# safe direction to be wrong in.
_MONGO_INTERNAL_COMMANDS = frozenset({
    "hello", "ismaster", "isMaster", "ping", "replSetHeartbeat", "replSetUpdatePosition",
    "currentOp", "killOp", "serverStatus", "buildInfo", "getLog", "connPoolStats", "top",
    "waitForFailPoint", "getParameter", "setParameter", "listDatabases", "endSessions",
})
# Namespaces owned by the server, not by an application. A stuck application query never lives here.
_MONGO_SYSTEM_NS = ("admin.", "local.", "config.", "$cmd.aggregate")


def _mongo_is_user_op(op: dict) -> bool:
    """Is this a real application operation a human would want terminated?"""
    if op.get("opid") is None:
        return False
    secs = op.get("secs_running")
    if secs is None:  # an op with no measured duration cannot be judged old
        return False
    command = op.get("command") or {}
    first = next(iter(command), "")
    if first in _MONGO_INTERNAL_COMMANDS:
        return False
    # A server-owned namespace (or none at all) is never an application's stuck query.
    ns = str(op.get("ns") or "")
    return bool(ns) and not ns.startswith(_MONGO_SYSTEM_NS)


class _Mongo:
    engine = "mongo"

    @staticmethod
    def connect(dsn: str):
        import pymongo

        return pymongo.MongoClient(dsn, serverSelectionTimeoutMS=int(CONNECT_TIMEOUT * 1000))

    @classmethod
    def metrics(cls, conn) -> dict[str, float]:
        status = conn.admin.command("serverStatus")
        conns = status.get("connections", {})
        current = float(conns.get("current", 0))
        available = float(conns.get("available", 0))
        ops = conn.admin.command("currentOp", {"active": True})
        # USER ops only. Counting the server's own heartbeats here reported a healthy cluster as
        # having several long-running operations, every single time.
        user_ops = [op for op in ops.get("inprog", []) if _mongo_is_user_op(op)]
        long_ops = sum(1 for op in user_ops if float(op.get("secs_running", 0)) >= 60)
        idle = sum(1 for op in user_ops if float(op.get("secs_running", 0)) >= IDLE_SECS)
        return {
            "current_connections": current,
            "available_connections": available,
            "long_running_ops": float(long_ops),
            "idle_in_transaction": float(idle),
            "connections_used_pct": current / (current + available) if (current + available) else 0.0,
        }

    @classmethod
    def problem_ops(cls, conn, idle_secs: int) -> list[str]:
        ops = conn.admin.command("currentOp", {"active": True})
        out = []
        for op in ops.get("inprog", []):
            if not _mongo_is_user_op(op):
                continue
            if float(op.get("secs_running", 0)) >= idle_secs:
                ns = redact(str(op.get("ns", ""))).text
                out.append(f"opid={op.get('opid')} running {int(op.get('secs_running',0))}s ns={ns}")
                if len(out) >= PROBLEM_OP_LIMIT:
                    break
        return out


class _MSSQL:
    engine = "mssql"

    @staticmethod
    def connect(dsn: str):
        import pymssql

        u = urlparse(dsn)
        return pymssql.connect(
            server=u.hostname or "localhost", port=str(u.port or 1433),
            user=(u.username or "sa"), password=(u.password or ""),
            database=(u.path.lstrip("/") or "master"), login_timeout=int(CONNECT_TIMEOUT), autocommit=True,
        )

    @staticmethod
    def _rows(conn, sql, params=()):
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()

    @classmethod
    def metrics(cls, conn) -> dict[str, float]:
        r = cls._rows
        total = r(conn, "SELECT count(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1")[0][0]
        idle_tx = r(conn, "SELECT count(*) FROM sys.dm_exec_sessions s "
                          "WHERE s.is_user_process = 1 AND s.open_transaction_count > 0 AND s.status = 'sleeping' "
                          "AND s.last_request_end_time < DATEADD(second, -60, GETDATE())")[0][0]
        # USER requests only. `sys.dm_exec_requests` also lists SQL Server's own background tasks -
        # LAZY WRITER, CHECKPOINT, XE TIMER and friends - which run for the lifetime of the instance
        # and so always have an enormous total_elapsed_time. Counting those reported **28
        # long-running queries on a freshly started, completely idle server**, which would have gone
        # into the evidence as though the database were in trouble. Observed against a real server;
        # the same shape as MongoDB's `hello` heartbeats.
        long_q = r(conn, "SELECT count(*) FROM sys.dm_exec_requests req "
                         "JOIN sys.dm_exec_sessions s ON req.session_id = s.session_id "
                         "WHERE s.is_user_process = 1 AND req.total_elapsed_time > 60000")[0][0]
        return {
            "active_connections": float(total),
            "idle_in_transaction": float(idle_tx),
            "long_running_queries": float(long_q),
        }

    @classmethod
    def problem_ops(cls, conn, idle_secs: int) -> list[str]:
        # TOP (n) and DATEADD's offset cannot be parameterised by pymssql; both are int()-coerced.
        rows = cls._rows(
            conn,
            f"SELECT TOP ({int(PROBLEM_OP_LIMIT)}) session_id, "
            "DATEDIFF(second, last_request_end_time, GETDATE()) "
            "FROM sys.dm_exec_sessions WHERE is_user_process = 1 AND open_transaction_count > 0 "
            "AND status = 'sleeping' "
            f"AND last_request_end_time < DATEADD(second, -{int(idle_secs)}, GETDATE()) "
            "AND session_id <> @@SPID ORDER BY last_request_end_time",
        )
        return [f"spid={sid} idle-in-trx {age}s" for sid, age in rows]


_ADAPTERS = {a.engine: a for a in (_Postgres, _MySQL, _Redis, _Mongo, _MSSQL)}


def adapter_for(engine: str):
    if engine not in _ADAPTERS:
        raise ToolError(f"no database adapter for engine '{engine}'")
    return _ADAPTERS[engine]


# --------------------------------------------------------------------------- the read backend


class DatabaseBackend:
    """Reads connection/transaction health for the database an alert points at. Read-only."""

    name = "database"

    def __init__(self, *, dsn: str | None = None, engine: str | None = None, conn=None) -> None:
        # Injectable (engine, conn) so unit tests need no real database.
        self._injected = conn
        if conn is not None:
            if engine is None:
                raise ToolError("DatabaseBackend(conn=…) also needs engine=…")
            self._engine = engine
            self._dsn = dsn
        else:
            self._dsn = dsn  # may be None; resolved per-alert from labels/env
            self._engine = engine

    def _resolve(self, alert: Alert):
        # An injected connection needs no DSN — it is already open, and demanding credentials for a
        # connection somebody else supplied (a pool, a test) would be a pointless failure.
        if self._injected is not None:
            return adapter_for(self._engine), self._injected
        dsn = self._dsn or dsn_of(alert)
        engine = self._engine or engine_of(dsn)
        adapter = adapter_for(engine)
        conn = self._injected if self._injected is not None else adapter.connect(dsn)
        return adapter, conn

    def metrics(self, alert: Alert) -> dict[str, float]:
        adapter, conn = self._resolve(alert)
        try:
            return adapter.metrics(conn)
        except Exception as exc:
            raise ToolError(f"database metrics read failed: {_one_line(exc)}") from exc

    def logs(self, alert: Alert) -> list[str]:
        adapter, conn = self._resolve(alert)
        try:
            ops = adapter.problem_ops(conn, IDLE_SECS)
        except Exception as exc:  # noqa: BLE001 - partial: metrics may still be usable
            return [f"{PARTIAL_PREFIX}problem_ops: {_one_line(exc)}"]
        # An adapter may report a PARTIAL of its own (e.g. connections whose age cannot be judged
        # because of clock skew). Those must reach `gather()` with the prefix INTACT — prefixing them
        # as evidence would turn "I could not measure this" into a log line the verifier counts.
        return [
            line if line.startswith(PARTIAL_PREFIX) else f"{adapter.engine} stuck connection: {line}"
            for line in ops
        ]

    def deploys(self, alert: Alert) -> list[dict[str, str]]:
        # Databases don't "deploy" in the rollout sense P5 checks for.
        return []


def _one_line(value) -> str:
    text = str(value).strip()
    first = text.splitlines()[0] if text else ""
    return first[:200]
