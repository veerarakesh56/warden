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

import contextlib
import os
import re
import threading
from typing import Any

from ..database import IDLE_SECS, adapter_for, engine_of

MAX_TERMINATE = int(os.environ.get("WARDEN_DB_TERMINATE_MAX", "20"))
_ENTRY = "db_terminate_idle_in_tx"


# What decides the server a libpq DSN reaches, in the order the plan shows them.
_WHERE = ("host", "hostaddr", "port", "service")


def _conninfo(dsn: str) -> dict[str, str]:
    """libpq's key=value DSN, read pair by pair as libpq does - quoted values with \\ escapes, whitespace between
    pairs - so a value is never searched for keys: `password=S3cr.host=hunter2` holds no host (eighth review)."""
    out: dict[str, str] = {}
    i, n = 0, len(dsn)
    while i < n:
        while i < n and dsn[i].isspace():
            i += 1
        j = i
        while j < n and (dsn[j].isalnum() or dsn[j] == "_"):
            j += 1
        key = dsn[i:j]
        while j < n and dsn[j].isspace():
            j += 1
        if not key or j >= n or dsn[j] != "=":
            break  # not a conninfo string libpq would accept: show nothing rather than guess
        j += 1
        while j < n and dsn[j].isspace():
            j += 1
        value = []
        if j < n and dsn[j] == "'":
            j += 1
            while j < n and dsn[j] != "'":
                if dsn[j] == "\\" and j + 1 < n:
                    j += 1
                value.append(dsn[j])
                j += 1
            j += 1
        else:
            while j < n and not dsn[j].isspace():
                if dsn[j] == "\\" and j + 1 < n:
                    j += 1
                value.append(dsn[j])
                j += 1
        out[key] = "".join(value)
        i = j
    return out


class DatabasePlatformError(RuntimeError):
    pass


class DatabasePlatformRefused(DatabasePlatformError):
    """Refused before any session was closed: "nothing was changed" (sixth review)."""

    nothing_changed = True


def _as_ids(rows: Any) -> list[int]:
    """Ids the server returned, coerced to int: MySQL's and SQL Server's KILL take no placeholders, so the
    int is what keeps an id from becoming SQL."""
    return [int(r[0] if isinstance(r, tuple | list) else r) for r in rows]


class _Postgres:
    ME = "SELECT session_user"  # the login pg_stat_activity lists; current_user changes with SET ROLE (eighth review)

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
    ME = "SELECT SUBSTRING_INDEX(CURRENT_USER(), '@', 1)"

    @staticmethod
    def database(conn: Any) -> str:
        with conn.cursor() as cur:
            cur.execute("SELECT DATABASE()")
            return cur.fetchone()[0] or ""

    @staticmethod
    def candidates(conn: Any, idle_secs: int, limit: int, users: list[str]) -> list[int]:
        with conn.cursor() as cur:
            # Idle time is processlist.time while the session sleeps: the transaction's start said nothing
            # about it, so a busy batch paused for a second between statements was closed (sixth review).
            cur.execute("SELECT p.id FROM information_schema.innodb_trx t "
                        "JOIN information_schema.processlist p ON t.trx_mysql_thread_id = p.id "
                        "WHERE p.command = 'Sleep' AND p.db = DATABASE() AND p.user IN %s "
                        "AND p.time >= %s AND p.id <> CONNECTION_ID() "
                        "ORDER BY p.time DESC LIMIT %s", (tuple(users), idle_secs, limit))
            return _as_ids(cur.fetchall())

    @staticmethod
    def terminate(conn: Any, ids: list[int]) -> int:
        with conn.cursor() as cur:
            for tid in ids:
                cur.execute(f"KILL {int(tid)}")  # nosec B608 - an int; KILL takes no placeholders
        return len(ids)


class _MSSQL:
    ME = "SELECT SUSER_SNAME()"

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
        # One connection, one user at a time: the worker runs activities on several threads, and pymysql and
        # pymssql connections are not thread-safe. One the platform opened itself is dropped after a failure
        # and reopened on the next call - a NAT timeout or a failover left it broken until a restart (sixth
        # review, 2026-10-01). A connection handed in is the caller's and is never dropped.
        self._lock = threading.RLock()
        self._owned = conn is None
        env_users = os.environ.get("WARDEN_DB_APP_USERS", "")
        self._users = [u for u in (app_users if app_users is not None else env_users.split(",")) if u.strip()]
        self._users = [u.strip() for u in self._users]
        self._max = max_terminate
        self._sql = ENGINES[self._engine]

    def _connection(self) -> Any:
        if self._conn is None:
            self._conn = adapter_for(self._engine).connect(self._dsn)
        return self._conn

    def _drop(self) -> None:
        if self._owned and self._conn is not None:
            conn, self._conn = self._conn, None
            with contextlib.suppress(Exception):
                conn.close()

    def _database(self) -> str | None:
        with self._lock:
            try:
                return self._sql.database(self._connection())
            except Exception:  # noqa: BLE001 - unreadable: nothing is allowed
                self._drop()
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
                                              "app_users": sorted(self._users), "server": self._server()}}

    def _server(self) -> str:
        """Where the connection goes, in the plan the approver signs (sixth review) - never the user or password.
        Every host libpq may use, and the `host`/`hostaddr`/`port` parameters that override them; it never raises:
        a multi-host DSN made `.port` raise, and the plan was never written (seventh review, 2026-10-01)."""
        from urllib.parse import parse_qs

        if not self._dsn:
            return ""
        if "://" not in self._dsn:  # libpq's `key=value` form, read pair by pair: a value is never searched
            params = _conninfo(self._dsn)
            return " ".join(f"{k}={params[k]}" for k in _WHERE if k in params) or self._unstated()
        # After the LAST `@`, cut at the first `/`, `?` or `#`: urlsplit ends the authority at `?` or `#`, so a password
        # holding one showed the user and the password's start (ninth review); libpq reads to the `@`. The query is
        # read from there too - never from inside the password. What is left must look like hosts, or it is not shown.
        rest = self._dsn.split("://", 1)[1].rpartition("@")[2]
        hosts = re.split(r"[/?#]", rest, maxsplit=1)[0]
        if not re.fullmatch(r"[\w.\-:\[\],%]*", hosts):
            return "a host the DSN does not state plainly (not shown)"
        try:
            query = parse_qs(rest.partition("?")[2].partition("#")[0])
        except ValueError:
            return "a DSN that could not be read"
        if self._engine != "postgres":  # only libpq reads `?host=`; pymysql and pymssql ignore it (eighth review)
            return hosts or ("localhost:3306 (TCP)" if self._engine == "mysql" else "localhost (TCP)")
        over = [f"{k}={query[k][-1]}" for k in _WHERE if k in query]
        return " ".join(([hosts] if hosts else []) + over) or self._unstated()

    def _unstated(self) -> str:
        """No host in the DSN: libpq takes PGHOST or PGSERVICE from the environment, else the local socket."""
        env = [f"{k}={os.environ[k]}" for k in ("PGHOST", "PGHOSTADDR", "PGPORT", "PGSERVICE") if os.environ.get(k)]
        return " ".join(env) if env and self._engine == "postgres" else "the local socket"

    def knows(self, service: str) -> bool:
        return self._database() == service

    def healthy(self, service: str) -> bool:
        """The database answers and none of the application's sessions is still idle in a transaction past
        the threshold - a positive read, never the absence of an error."""
        with self._lock:
            if not self._users or self._database() != service:
                return False
            try:
                return self._sql.candidates(self._connection(), IDLE_SECS, 1, self._users) == []
            except Exception:  # noqa: BLE001 - unknown is not healthy
                self._drop()
                return False

    def apply(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any] | None = None) -> str:
        # `snapshot` (what the approver saw) adds nothing here: the sessions are chosen afresh by the bounds.
        with self._lock:
            try:
                return self._apply(entry, params)
            except DatabasePlatformError as exc:
                if exc.__cause__ is not None:  # the server failed, not the plan: reconnect next time
                    self._drop()
                raise

    def _apply(self, entry: str, params: dict[str, Any]) -> str:
        if entry != _ENTRY:
            raise DatabasePlatformRefused(f"{entry} is not something the database platform does "
                                        f"(it does {_ENTRY} only)")
        if not self._users:
            raise DatabasePlatformRefused("no application logins are named (WARDEN_DB_APP_USERS); nothing is closed")
        name = self._database()
        if name is None or params.get("database") != name:
            raise DatabasePlatformRefused(f"database {params.get('database')!r} is not the one this platform is "
                                        f"connected to ({name})")
        idle, limit = params.get("min_idle_seconds"), params.get("max_sessions")
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (idle, limit)) \
                or idle < IDLE_SECS or not 1 <= limit <= self._max:
            raise DatabasePlatformRefused(f"min_idle_seconds={idle!r} / max_sessions={limit!r} are outside the "
                                        f"bounds (idle at least {IDLE_SECS}s, 1..{self._max} sessions)")
        conn = self._connection()
        try:
            cur = conn.cursor()
            cur.execute(self._sql.ME)
            own = cur.fetchone()[0]
        except Exception as exc:
            raise DatabasePlatformRefused(f"could not read this platform's own login: {_one_line(exc)}") from exc
        if own.casefold() in {u.casefold() for u in self._users}:
            # The terminate role closing sessions of its own login - other WARDEN workers - is not an application
            # fix (sixth review, 2026-10-01). In any letter case: MySQL and SQL Server match logins without it
            # (seventh review); on PostgreSQL this can only refuse more.
            raise DatabasePlatformRefused(f"WARDEN_DB_APP_USERS names this platform's own login {own!r}; "
                                        "nothing is closed")
        try:
            # The ceiling again in Python: a broken LIMIT must not widen what is closed.
            ids = self._sql.candidates(conn, idle, limit, self._users)[:limit]
        except Exception as exc:
            raise DatabasePlatformRefused(f"could not list idle sessions in {name}: {_one_line(exc)}") from exc
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
