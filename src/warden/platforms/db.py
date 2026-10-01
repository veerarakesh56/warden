"""Databases behind the RemediationWorkflow: `db_terminate_idle_in_tx` (decision D16).

The workflow decides whether to act; this closes the sessions an approved plan describes - idle inside
a transaction for at least `min_idle_seconds`, at most `max_sessions` of them - and nothing else. What
the removed in-process backend (database_remediation.py) did server-wide, this does only:
- in the database the platform is connected to (audit A-B-H1: the old selection crossed databases),
- for the application's own logins (WARDEN_DB_APP_USERS; none named means none closed),
- never its own session, the count ceiling enforced in SQL AND again in Python, ids coerced to int.
PostgreSQL, MySQL and SQL Server: the engines with an "idle in a transaction" state. Redis (D16) and
MongoDB (its "terminate" killed running operations, not idle sessions) are not supported; a proposal
for them is advice for a person. Closing a session destroys no data: its transaction rolls back and
the application reconnects - so there is nothing to roll back.

Credentials: a least-privilege role per engine (PostgreSQL pg_signal_backend + pg_read_all_stats; MySQL
CONNECTION_ADMIN + PROCESS; SQL Server ALTER ANY CONNECTION + VIEW SERVER STATE), never the master user.
"""

from __future__ import annotations

import os
from typing import Any

from ..database import IDLE_SECS, adapter_for, engine_of

MAX_TERMINATE = int(os.environ.get("WARDEN_DB_TERMINATE_MAX", "20"))
_ENTRY = "db_terminate_idle_in_tx"


class DatabasePlatformError(RuntimeError):
    pass


def _as_ids(rows: Any) -> list[int]:
    """Ids the server returned, coerced to int: MySQL's and SQL Server's KILL take no placeholders, so the
    int is what keeps an id from becoming SQL."""
    return [int(r[0] if isinstance(r, tuple | list) else r) for r in rows]


class _Postgres:
    @staticmethod
    def database(conn: Any) -> str:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database()")
            return cur.fetchone()[0]

    @staticmethod
    def candidates(conn: Any, idle_secs: int, limit: int, users: list[str]) -> list[int]:
        with conn.cursor() as cur:
            cur.execute("SELECT pid FROM pg_stat_activity "
                        "WHERE state = 'idle in transaction' AND datname = current_database() "
                        "AND usename = ANY(%s) AND state_change < now() - make_interval(secs => %s) "
                        "AND pid <> pg_backend_pid() ORDER BY state_change LIMIT %s",
                        (users, idle_secs, limit))
            return _as_ids(cur.fetchall())

    @staticmethod
    def terminate(conn: Any, ids: list[int]) -> int:
        killed = 0
        with conn.cursor() as cur:
            for pid in ids:
                cur.execute("SELECT pg_terminate_backend(%s)", (int(pid),))
                row = cur.fetchone()
                killed += bool(row and row[0])
        return killed


class _MySQL:
    @staticmethod
    def database(conn: Any) -> str:
        with conn.cursor() as cur:
            cur.execute("SELECT DATABASE()")
            return cur.fetchone()[0] or ""

    @staticmethod
    def candidates(conn: Any, idle_secs: int, limit: int, users: list[str]) -> list[int]:
        with conn.cursor() as cur:
            cur.execute("SELECT p.id FROM information_schema.innodb_trx t "
                        "JOIN information_schema.processlist p ON t.trx_mysql_thread_id = p.id "
                        "WHERE p.command = 'Sleep' AND p.db = DATABASE() AND p.user IN %s "
                        "AND t.trx_started < (NOW() - INTERVAL %s SECOND) AND p.id <> CONNECTION_ID() "
                        "ORDER BY t.trx_started LIMIT %s", (tuple(users), idle_secs, limit))
            return _as_ids(cur.fetchall())

    @staticmethod
    def terminate(conn: Any, ids: list[int]) -> int:
        with conn.cursor() as cur:
            for tid in ids:
                cur.execute(f"KILL {int(tid)}")  # nosec B608 - an int; KILL takes no placeholders
        return len(ids)


class _MSSQL:
    @staticmethod
    def database(conn: Any) -> str:
        cur = conn.cursor()
        cur.execute("SELECT DB_NAME()")
        return cur.fetchone()[0]

    @staticmethod
    def candidates(conn: Any, idle_secs: int, limit: int, users: list[str]) -> list[int]:
        cur = conn.cursor()
        marks = ", ".join(["%s"] * len(users))
        # TOP (n) and DATEADD's offset cannot be parameterised by pymssql: both are ints.
        cur.execute(f"SELECT TOP ({int(limit)}) session_id FROM sys.dm_exec_sessions "  # nosec B608
                    "WHERE is_user_process = 1 AND open_transaction_count > 0 AND status = 'sleeping' "
                    f"AND database_id = DB_ID() AND login_name IN ({marks}) "
                    f"AND last_request_end_time < DATEADD(second, -{int(idle_secs)}, GETDATE()) "
                    "AND session_id <> @@SPID ORDER BY last_request_end_time", tuple(users))
        return _as_ids(cur.fetchall())

    @staticmethod
    def terminate(conn: Any, ids: list[int]) -> int:
        cur = conn.cursor()
        for spid in ids:
            cur.execute(f"KILL {int(spid)}")  # nosec B608 - an int; KILL takes no placeholders
        return len(ids)


ENGINES = {"postgres": _Postgres, "mysql": _MySQL, "mssql": _MSSQL}


class DatabasePlatform:
    def __init__(self, *, dsn: str | None = None, engine: str | None = None, conn: Any = None,
                 app_users: list[str] | None = None, max_terminate: int = MAX_TERMINATE) -> None:
        self._dsn = dsn or os.environ.get("WARDEN_DB_ADMIN_DSN")
        self._engine = engine or (engine_of(self._dsn) if self._dsn else None)
        if self._engine not in ENGINES:
            raise DatabasePlatformError(f"no terminate support for engine {self._engine!r} "
                                        f"(supported: {', '.join(sorted(ENGINES))})")
        if conn is None and not self._dsn:
            raise DatabasePlatformError("no database: set WARDEN_DB_ADMIN_DSN (the least-privilege terminate role)")
        self._conn = conn
        env_users = os.environ.get("WARDEN_DB_APP_USERS", "")
        self._users = [u for u in (app_users if app_users is not None else env_users.split(",")) if u.strip()]
        self._users = [u.strip() for u in self._users]
        self._max = max_terminate
        self._sql = ENGINES[self._engine]

    def _connection(self) -> Any:
        if self._conn is None:
            self._conn = adapter_for(self._engine).connect(self._dsn)
        return self._conn

    def _database(self) -> str | None:
        try:
            return self._sql.database(self._connection())
        except Exception:  # noqa: BLE001 - unreadable: nothing is allowed
            return None

    def live(self, entry: str, params: dict[str, Any]) -> dict[str, Any]:
        """The connected database, and only when the application's logins are named: with no allowlist
        nothing may be closed, so nothing is read and the catalogue refuses."""
        if entry != _ENTRY or not self._users:
            return {}
        name = self._database()
        if not name:
            return {}
        return {"database": {name}, "state": {"engine": self._engine, "database": name,
                                              "app_users": sorted(self._users)}}

    def knows(self, service: str) -> bool:
        return self._database() == service

    def healthy(self, service: str) -> bool:
        """The database answers and none of the application's sessions is still idle in a transaction past
        the threshold - a positive read, never the absence of an error."""
        if not self._users or self._database() != service:
            return False
        try:
            return self._sql.candidates(self._connection(), IDLE_SECS, 1, self._users) == []
        except Exception:  # noqa: BLE001 - unknown is not healthy
            return False

    def apply(self, entry: str, params: dict[str, Any]) -> str:
        if entry != _ENTRY:
            raise DatabasePlatformError(f"{entry} is not something the database platform does "
                                        f"(it does {_ENTRY} only)")
        if not self._users:
            raise DatabasePlatformError("no application logins are named (WARDEN_DB_APP_USERS); nothing is closed")
        name = self._database()
        if name is None or params.get("database") != name:
            raise DatabasePlatformError(f"database {params.get('database')!r} is not the one this platform is "
                                        f"connected to ({name})")
        idle, limit = params.get("min_idle_seconds"), params.get("max_sessions")
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (idle, limit)) \
                or idle < IDLE_SECS or not 1 <= limit <= self._max:
            raise DatabasePlatformError(f"min_idle_seconds={idle!r} / max_sessions={limit!r} are outside the "
                                        f"bounds (idle at least {IDLE_SECS}s, 1..{self._max} sessions)")
        conn = self._connection()
        try:
            # The ceiling again in Python: a broken LIMIT must not widen what is closed.
            ids = self._sql.candidates(conn, idle, limit, self._users)[:limit]
        except Exception as exc:
            raise DatabasePlatformError(f"could not list idle sessions in {name}: {_one_line(exc)}") from exc
        if not ids:
            return f"no session of {', '.join(sorted(self._users))} in {name} was idle in a transaction for " \
                   f"{idle}s or more; nothing closed"
        try:
            closed = self._sql.terminate(conn, ids)
        except Exception as exc:
            raise DatabasePlatformError(f"closing sessions in {name} failed: {_one_line(exc)}") from exc
        return f"closed {closed} session(s) idle in a transaction for {idle}s or more in {name} " \
               f"({self._engine}; ids {', '.join(map(str, ids))})"

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any]) -> str:
        if entry != _ENTRY:
            raise DatabasePlatformError(f"{entry} is not something the database platform does")
        return "nothing to roll back: a closed session's transaction rolled back, and the application reconnects"


def _one_line(value: Any) -> str:
    text = str(value).strip()
    return (text.splitlines()[0] if text else "")[:200]
