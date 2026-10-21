"""Databases behind the RemediationWorkflow: `db_terminate_idle_in_tx` and `db_terminate_blocker` (decision D16).

`db_terminate_blocker` (PostgreSQL only) closes ONE session the approver saw blocking others: an application
login's session in this database that others have waited behind for at least BLOCK_SECS (pg_blocking_pids). The
close carries the whole selection again, in the same statement - still blocking, still the same backend (its start
time, so a pid the server reused is not closed) - and the plan shows what it blocked.

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

In the cloud runtime (`db_from_environment`, Aurora PostgreSQL with IAM authentication) no password exists: reads sign
in as the read-only login (pg_monitor) with a token the environment's platform-reader role signs, and each close as the
terminate login (`warden_<env>_terminate`: pg_signal_backend + pg_read_all_stats) with a token signed by an actor
session minted for that one approved plan - the only identity whose policy may connect as that login.
"""

from __future__ import annotations

import contextlib
import os
import re
import threading
from collections.abc import Callable
from typing import Any

from .. import settings
from ..database import IDLE_SECS, adapter_for, engine_of

MAX_TERMINATE = int(os.environ.get("WARDEN_DB_TERMINATE_MAX", "20"))
# How long others must have waited behind a session before it counts as blocking - a lock held for a moment is how
# a database works, not an incident.
BLOCK_SECS = int(os.environ.get("WARDEN_DB_BLOCK_SECS", "30"))
_ENTRY = "db_terminate_idle_in_tx"
_BLOCKER = "db_terminate_blocker"
_ENTRIES = (_ENTRY, _BLOCKER)


# What decides the server a libpq DSN reaches, in the order the plan shows them.
_WHERE = ("host", "hostaddr", "port", "service")


def _conninfo(dsn: str) -> dict[str, str]:
    """libpq's key=value DSN, read pair by pair as libpq does - quoted values with \\ escapes, whitespace between
    pairs - so a value is never searched for keys: `password=S3cr.host=evil` holds no host."""
    out: dict[str, str] = {}
    i, n = 0, len(dsn)
    while i < n:
        key, j = _conninfo_key(dsn, _past_space(dsn, i))
        j = _past_space(dsn, j)
        if not key or j >= n or dsn[j] != "=":
            break  # not a conninfo string libpq would accept: show nothing rather than guess
        out[key], i = _conninfo_value(dsn, _past_space(dsn, j + 1))
    return out


def _past_space(dsn: str, i: int) -> int:
    """The index of the first character at or after `i` that is not whitespace."""
    while i < len(dsn) and dsn[i].isspace():
        i += 1
    return i


def _conninfo_key(dsn: str, i: int) -> tuple[str, int]:
    """(the keyword starting at `i` - letters, digits and _ - and the index just past it)."""
    j = i
    while j < len(dsn) and (dsn[j].isalnum() or dsn[j] == "_"):
        j += 1
    return dsn[i:j], j


def _conninfo_value(dsn: str, j: int) -> tuple[str, int]:
    """(the value starting at `j`, the index just past it): quoted up to its closing ', or bare up to whitespace; a
    backslash takes the character after it as it is."""
    n = len(dsn)
    quoted = j < n and dsn[j] == "'"
    if quoted:
        j += 1
    value = []
    while j < n and not _ends_value(dsn[j], quoted):
        if dsn[j] == "\\" and j + 1 < n:
            j += 1
        value.append(dsn[j])
        j += 1
    if quoted:
        j += 1  # past the closing quote
    return "".join(value), j


def _ends_value(c: str, quoted: bool) -> bool:
    """A quoted value ends at its closing quote; a bare one at whitespace."""
    if quoted:
        return c == "'"
    return c.isspace()


class DatabasePlatformError(RuntimeError):
    pass


class DatabasePlatformRefused(DatabasePlatformError):
    """Refused before any session was closed: "nothing was changed"."""

    nothing_changed = True


def _as_ids(rows: Any) -> list[int]:
    """Ids the server returned, coerced to int: MySQL's and SQL Server's KILL take no placeholders, so the
    int is what keeps an id from becoming SQL."""
    return [int(r[0] if isinstance(r, tuple | list) else r) for r in rows]


class _Postgres:
    ME = "SELECT session_user"  # the login pg_stat_activity lists; current_user changes with SET ROLE

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
    def terminate(conn: Any, ids: list[int], idle_secs: int, users: list[str]) -> int:
        # The selection again, in the SAME statement as the close (register R7-O1): a session listed idle that has
        # since resumed, committed, or been replaced by another under its pid is not closed.
        killed = 0
        with conn.cursor() as cur:
            for pid in ids:
                cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE pid = %s AND state = 'idle in transaction' AND datname = current_database() "
                            "AND usename = ANY(%s) AND state_change < now() - make_interval(secs => %s) "
                            "AND pid <> pg_backend_pid()", (int(pid), users, idle_secs))
                row = cur.fetchone()
                killed += bool(row and row[0])
        return killed

    # A session of an application login that a session of this database has waited behind for `wait` seconds.
    BLOCKING = ("b.datname = current_database() AND b.usename = ANY(%s) AND b.pid <> pg_backend_pid() AND "
                "w.datname = current_database() AND b.pid = ANY(pg_blocking_pids(w.pid)) AND "
                "w.query_start < now() - make_interval(secs => %s)")

    @staticmethod
    def blockers(conn: Any, users: list[str], wait: int, limit: int) -> list[tuple[int, str, int]]:
        """(pid, backend start, sessions it blocks), the most blocking first."""
        with conn.cursor() as cur:
            cur.execute("SELECT b.pid, b.backend_start::text, count(w.pid) FROM pg_stat_activity w "  # nosec B608 - constant SQL; every value is a parameter
                        "JOIN pg_stat_activity b ON true WHERE " + _Postgres.BLOCKING +
                        " GROUP BY b.pid, b.backend_start ORDER BY count(w.pid) DESC, b.pid LIMIT %s",
                        (users, wait, limit))
            return [(int(r[0]), str(r[1]), int(r[2])) for r in cur.fetchall()]

    @staticmethod
    def terminate_blocker(conn: Any, pid: int, started: str, users: list[str], wait: int) -> bool:
        # The selection again in the same statement (register R7-O1): still blocking, still the same backend.
        with conn.cursor() as cur:
            cur.execute("SELECT pg_terminate_backend(b.pid) FROM pg_stat_activity b WHERE b.pid = %s AND "  # nosec B608 - constant SQL; every value is a parameter
                        "b.backend_start::text = %s AND EXISTS (SELECT 1 FROM pg_stat_activity w WHERE " +
                        _Postgres.BLOCKING + ")", (int(pid), started, users, wait))
            row = cur.fetchone()
            return bool(row and row[0])


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
            # about it, so a busy batch paused for a second between statements was closed.
            cur.execute("SELECT p.id FROM information_schema.innodb_trx t "
                        "JOIN information_schema.processlist p ON t.trx_mysql_thread_id = p.id "
                        "WHERE p.command = 'Sleep' AND p.db = DATABASE() AND p.user IN %s "
                        "AND p.time >= %s AND p.id <> CONNECTION_ID() "
                        "ORDER BY p.time DESC LIMIT %s", (tuple(users), idle_secs, limit))
            return _as_ids(cur.fetchall())

    @staticmethod
    def terminate(conn: Any, ids: list[int], idle_secs: int, users: list[str]) -> int:
        # KILL takes no condition: each session is checked again right before its KILL (register R7-O1). The
        # window left is one statement long, not the whole list.
        killed = 0
        with conn.cursor() as cur:
            for tid in ids:
                cur.execute("SELECT p.id FROM information_schema.innodb_trx t "
                            "JOIN information_schema.processlist p ON t.trx_mysql_thread_id = p.id "
                            "WHERE p.id = %s AND p.command = 'Sleep' AND p.db = DATABASE() AND p.user IN %s "
                            "AND p.time >= %s AND p.id <> CONNECTION_ID()", (int(tid), tuple(users), idle_secs))
                if cur.fetchall():
                    cur.execute(f"KILL {int(tid)}")  # nosec B608 - an int; KILL takes no placeholders
                    killed += 1
        return killed


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
    def terminate(conn: Any, ids: list[int], idle_secs: int, users: list[str]) -> int:
        # As for MySQL: checked again right before each KILL (register R7-O1).
        cur = conn.cursor()
        marks = ", ".join(["%s"] * len(users))
        killed = 0
        for spid in ids:
            cur.execute(f"SELECT session_id FROM sys.dm_exec_sessions WHERE session_id = {int(spid)} "  # nosec B608
                        "AND is_user_process = 1 AND open_transaction_count > 0 AND status = 'sleeping' "
                        f"AND database_id = DB_ID() AND login_name IN ({marks}) "
                        f"AND last_request_end_time < DATEADD(second, -{int(idle_secs)}, GETDATE()) "
                        "AND session_id <> @@SPID", tuple(users))
            if cur.fetchall():
                cur.execute(f"KILL {int(spid)}")  # nosec B608 - an int; KILL takes no placeholders
                killed += 1
        return killed


ENGINES = {"postgres": _Postgres, "mysql": _MySQL, "mssql": _MSSQL}


class DatabasePlatform:
    def __init__(self, *, dsn: str | None = None, engine: str | None = None, conn: Any = None,
                 app_users: list[str] | None = None, max_terminate: int = MAX_TERMINATE,
                 environment: str | None = None, sign: Callable[[str], str] | None = None,
                 writer: Callable[[dict[str, Any]], Any] | None = None, writes_to: str | None = None) -> None:
        self._dsn = dsn or settings.getenv("WARDEN_DB_TERMINATE_DSN") or None
        # A database carries no tag WARDEN can read: whoever configures the connection states its environment
        # (P18, register S6). Unset, it is in no environment WARDEN may change.
        self._environment = environment or os.environ.get("WARDEN_DB_ENVIRONMENT") or None
        self._engine = engine or (engine_of(self._dsn) if self._dsn else None)
        if self._engine not in ENGINES:
            raise DatabasePlatformError(f"no terminate support for engine {self._engine!r} "
                                        f"(supported: {', '.join(sorted(ENGINES))})")
        if conn is None and not self._dsn:
            raise DatabasePlatformError("no database: set WARDEN_DB_TERMINATE_DSN (the least-privilege terminate role)")
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
        # `sign`: the read DSN -> the DSN to connect with (an IAM token in it). `writer`: an approved plan's who -> a
        # connection of its own for that plan's close (an actor session's token), closed after it. Without a writer
        # the one connection reads and closes, as with a DSN that carries its own credentials.
        self._sign, self._writer = sign, writer
        # `writes_to`: the DSN the writer's connections reach. The plan was read through another (the read zone's), so a
        # close goes ahead only when both name the same Aurora cluster.
        self._writes_to = writes_to

    def _connection(self) -> Any:
        if self._conn is None:
            self._conn = adapter_for(self._engine).connect(self._sign(self._dsn) if self._sign else self._dsn)
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
        if entry not in _ENTRIES or not self._users or (entry == _BLOCKER and self._engine != "postgres"):
            return {}
        name = self._database()
        if not name:
            return {}
        state = {"engine": self._engine, "database": name, "app_users": sorted(self._users), "server": self._server()}
        live = {"database": {name}, "environment": self._environment, "state": state}
        if entry == _BLOCKER:
            # The sessions blocking others now: the only pids an approved plan may name. The named one's start time
            # goes into the plan - so the close can tell it from a later session the server gave the same pid - and
            # nothing else that moves while the approver reads (another waiter queueing is not drift).
            with self._lock:
                try:
                    found = self._sql.blockers(self._connection(), self._users, BLOCK_SECS, self._max)
                except Exception:  # noqa: BLE001 - unreadable: nothing is allowed
                    self._drop()
                    return {}
            live["pid"] = {str(pid) for pid, _, _ in found}
            named = next(((pid, started) for pid, started, _ in found if str(pid) == params.get("pid")), None)
            if named:
                state["blocker"] = {"pid": str(named[0]), "backend_start": named[1]}
        return live

    def _server(self) -> str:
        """Where the connection goes, in the plan the approver signs - never the user or password.
        Every host libpq may use, and the `host`/`hostaddr`/`port` parameters that override them; it never raises:
        a multi-host DSN made `.port` raise, and the plan was never written."""
        from urllib.parse import parse_qs

        if not self._dsn:
            return ""
        if "://" not in self._dsn:  # libpq's `key=value` form, read pair by pair: a value is never searched
            params = _conninfo(self._dsn)
            where = [f"{k}={params[k]}" for k in _WHERE if k in params]
            return " ".join(where + self._env_over(set(params))) if where else self._unstated()
        # After the LAST `@`, cut at the first `/`, `?` or `#`: urlsplit ends the authority at `?` or `#`, so a password
        # holding one showed the user and the password's start; libpq reads to the `@`. The query is
        # read from there too - never from inside the password. What is left must look like hosts, or it is not shown.
        rest = self._dsn.split("://", 1)[1].rpartition("@")[2]
        hosts = re.split(r"[/?#]", rest, maxsplit=1)[0]
        if not re.fullmatch(r"[\w.\-:\[\],%]*", hosts):
            return "a host the DSN does not state plainly (not shown)"
        try:
            query = parse_qs(rest.partition("?")[2].partition("#")[0])
        except ValueError:
            return "a DSN that could not be read"
        if self._engine != "postgres":  # only libpq reads `?host=`; pymysql and pymssql ignore it
            return hosts or ("localhost:3306 (TCP)" if self._engine == "mysql" else "localhost (TCP)")
        over = [f"{k}={query[k][-1]}" for k in _WHERE if k in query]
        if not hosts and not over:
            return self._unstated()
        stated = set(query) | ({"port"} if re.search(r":\d+(?:,|$)", hosts) else set())
        return " ".join(([hosts] if hosts else []) + over + self._env_over(stated))

    def _env_over(self, stated: set[str]) -> list[str]:
        """libpq takes PGHOSTADDR and PGPORT from the environment for any parameter the DSN leaves out - and
        PGHOSTADDR then decides the address, whatever host the DSN names (register R9-O4). The plan shows them."""
        if self._engine != "postgres":
            return []
        return [f"{k}={os.environ[k]} (environment)" for k, key in (("PGHOSTADDR", "hostaddr"), ("PGPORT", "port"))
                if os.environ.get(k) and key not in stated]

    def _unstated(self) -> str:
        """No host in the DSN: libpq takes PGHOST or PGSERVICE from the environment, else the local socket."""
        env = [f"{k}={os.environ[k]}" for k in ("PGHOST", "PGHOSTADDR", "PGPORT", "PGSERVICE") if os.environ.get(k)]
        return " ".join(env) if env and self._engine == "postgres" else "the local socket"

    def knows(self, service: str) -> bool:
        return self._database() == service

    def healthy(self, service: str) -> bool:
        """The database answers and none of the application's sessions is still idle in a transaction past
        the threshold, nor (PostgreSQL) blocking others past BLOCK_SECS - a positive read, never the absence of an
        error."""
        with self._lock:
            if not self._users or self._database() != service:
                return False
            try:
                conn = self._connection()
                return self._sql.candidates(conn, IDLE_SECS, 1, self._users) == [] and \
                    (self._engine != "postgres" or self._sql.blockers(conn, self._users, BLOCK_SECS, 1) == [])
            except Exception:  # noqa: BLE001 - unknown is not healthy
                self._drop()
                return False

    def apply(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any] | None = None,
              who: dict[str, Any] | None = None) -> str:
        # `snapshot` (what the approver saw) adds nothing to the idle close - the sessions are chosen afresh by the
        # bounds - and names the one session a blocker close may touch.
        with self._lock:
            self._opened = None
            try:
                if entry == _BLOCKER:
                    return self._close_blocker(params, snapshot or {}, who)
                return self._apply(entry, params, who, snapshot or {})
            except DatabasePlatformError as exc:
                if exc.__cause__ is not None:  # the server failed, not the plan: reconnect next time
                    self._drop()
                raise
            finally:
                if self._opened is not None:  # the plan's own connection ends with the plan's close
                    with contextlib.suppress(Exception):
                        self._opened.close()
                    self._opened = None

    def _for_write(self, who: dict[str, Any] | None, snapshot: dict[str, Any]) -> Any:
        """The plan's own connection, in an actor session minted for it - never the reader's - to the cluster the
        approved plan was read from."""
        if not who or not who.get("approvers"):
            raise DatabasePlatformRefused("a close needs the approved plan's actor session; nothing is closed")
        if self._writes_to is not None:
            read, writes = aurora_cluster(str(snapshot.get("server", ""))), aurora_cluster(self._writes_to)
            if read is None or read != writes:
                raise DatabasePlatformRefused("the terminate login does not reach the Aurora cluster the approved plan "
                                            "was read from; nothing is closed")
        try:
            self._opened = self._writer(who)
        except Exception as exc:
            raise DatabasePlatformRefused(f"could not sign in as the terminate login: {_one_line(exc)}; nothing is "
                                        "closed") from exc
        return self._opened

    def _checked(self, params: dict[str, Any], who: dict[str, Any] | None = None,
                 snapshot: dict[str, Any] | None = None) -> tuple[str, Any]:
        """(database, connection) once the plan names this platform's database and the application logins exclude
        the platform's own; refused otherwise, before anything is closed."""
        if not self._users:
            raise DatabasePlatformRefused("no application logins are named (WARDEN_DB_APP_USERS); nothing is closed")
        conn = None
        if self._writer is None:
            name = self._database()
        else:
            conn = self._for_write(who, snapshot or {})
            try:
                name = self._sql.database(conn)
            except Exception:  # noqa: BLE001  # unreadable: refused below
                name = None
        if name is None or params.get("database") != name:
            raise DatabasePlatformRefused(f"database {params.get('database')!r} is not the one this platform is "
                                        f"connected to ({name})")
        conn = conn or self._connection()
        try:
            cur = conn.cursor()
            cur.execute(self._sql.ME)
            own = cur.fetchone()[0]
        except Exception as exc:
            raise DatabasePlatformRefused(f"could not read this platform's own login: {_one_line(exc)}") from exc
        if own.casefold() in {u.casefold() for u in self._users}:
            # The terminate role closing sessions of its own login - other WARDEN workers - is not an application
            # fix. In any letter case: MySQL and SQL Server match logins without it
            #; on PostgreSQL this can only refuse more.
            raise DatabasePlatformRefused(f"WARDEN_DB_APP_USERS names this platform's own login {own!r}; "
                                        "nothing is closed")
        return name, conn

    def _close_blocker(self, params: dict[str, Any], snapshot: dict[str, Any], who: dict[str, Any] | None) -> str:
        if self._engine != "postgres":
            raise DatabasePlatformRefused(f"{_BLOCKER} is supported on PostgreSQL only, not {self._engine}")
        pid, seen = params.get("pid"), snapshot.get("blocker")
        if not (isinstance(pid, str) and pid.isdigit() and isinstance(seen, dict) and seen.get("pid") == pid
                and seen.get("backend_start")):
            raise DatabasePlatformRefused(f"pid {pid!r} is not a session the approved plan showed blocking others")
        name, conn = self._checked(params, who, snapshot)
        try:
            closed = self._sql.terminate_blocker(conn, int(pid), seen["backend_start"], self._users, BLOCK_SECS)
        except Exception as exc:
            raise DatabasePlatformError(f"closing session {pid} in {name} failed: {_one_line(exc)}") from exc
        if not closed:
            return f"session {pid} in {name} no longer blocks anyone (or is another session now); nothing closed"
        return f"closed session {pid} in {name}, which was blocking others (started {seen['backend_start']})"

    def _apply(self, entry: str, params: dict[str, Any], who: dict[str, Any] | None,
               snapshot: dict[str, Any] | None = None) -> str:
        if entry != _ENTRY:
            raise DatabasePlatformRefused(f"{entry} is not something the database platform does "
                                        f"(it does {', '.join(_ENTRIES)} only)")
        idle, limit = params.get("min_idle_seconds"), params.get("max_sessions")
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (idle, limit)) \
                or idle < IDLE_SECS or not 1 <= limit <= self._max:
            raise DatabasePlatformRefused(f"min_idle_seconds={idle!r} / max_sessions={limit!r} are outside the "
                                        f"bounds (idle at least {IDLE_SECS}s, 1..{self._max} sessions)")
        name, conn = self._checked(params, who, snapshot)
        try:
            # The ceiling again in Python: a broken LIMIT must not widen what is closed.
            ids = self._sql.candidates(conn, idle, limit, self._users)[:limit]
        except Exception as exc:
            raise DatabasePlatformRefused(f"could not list idle sessions in {name}: {_one_line(exc)}") from exc
        if not ids:
            return f"no session of {', '.join(sorted(self._users))} in {name} was idle in a transaction for " \
                   f"{idle}s or more; nothing closed"
        try:
            closed = self._sql.terminate(conn, ids, idle, self._users)
        except Exception as exc:
            raise DatabasePlatformError(f"closing sessions in {name} failed: {_one_line(exc)}") from exc
        return f"closed {closed} session(s) idle in a transaction for {idle}s or more in {name} " \
               f"({self._engine}; ids {', '.join(map(str, ids))})"

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any]) -> str:
        """Every platform's rollback takes (entry, params, snapshot); closing sessions changed nothing to restore, so
        this one reads neither params nor snapshot here."""
        if entry not in _ENTRIES:
            raise DatabasePlatformError(f"{entry} is not something the database platform does")
        return "nothing to roll back: a closed session's transaction rolled back, and the application reconnects"


def db_from_environment() -> Any:
    """The database platform of the cloud runtime: the one watched database of WARDEN_DB_ENVIRONMENT (Aurora
    PostgreSQL, IAM authentication), its application logins WARDEN_DB_APP_USERS. A zone reads with the read-only login
    of WARDEN_STACK_DB_PRIMARY_RO_DSN (the read zone holds it) and closes with the terminate login of
    WARDEN_DB_TERMINATE_DSN (the act zone holds it): neither DSN carries a password. Any other environment, or none of
    either DSN, reads and writes nothing (platforms.Unconfigured): the plan is refused and goes to a person.
    ponytail: one watched database per runtime; a map like WARDEN_EKS_CLUSTERS when a second environment has one."""
    import boto3

    from .. import identity
    from ..aws_stack import iam_dsn
    from ..environments import region
    from . import NotConfigured, PerEnvironment, reader_clients, role_arn, session_clients

    where = region()
    sts = boto3.client("sts", region_name=where)

    def build(env: str) -> DatabasePlatform:
        read_dsn, write_dsn = _logins(env)
        reader, actor_arn = reader_clients(sts, where, role_arn(env, "platform-reader")), role_arn(env, "actor")

        def sign(dsn: str) -> str:
            if not read_dsn:
                raise NotConfigured("this worker holds no read login (WARDEN_STACK_DB_PRIMARY_RO_DSN)")
            return iam_dsn(reader("rds"), dsn, verify=True)  # reads verified as closes are

        def writer(who: dict[str, Any]) -> Any:
            if not write_dsn:
                raise NotConfigured("this worker holds no terminate login (WARDEN_DB_TERMINATE_DSN)")
            creds = identity.actor_session(sts, role_arn=actor_arn, incident=who["incident"],
                                           plan_hash=who["plan_hash"], approvers=who["approvers"],
                                           actions=["rds-db:connect"],
                                           resources=[dbuser_arn(reader("rds"), write_dsn, actor_arn)])
            return adapter_for("postgres").connect(iam_dsn(session_clients(creds, where)("rds"), write_dsn, verify=True))

        return DatabasePlatform(dsn=read_dsn or write_dsn, engine="postgres", environment=env, sign=sign, writes_to=write_dsn,
                                writer=writer)

    return PerEnvironment(build, "database")


def _logins(env: str) -> tuple[str | None, str | None]:
    """The read and terminate DSNs this worker holds for `env`'s database, each one WARDEN can sign with an IAM token
    and verify; NotConfigured (the plan goes to a person) when there is no database for `env`, no login, or a DSN
    iam_dsn would pass through as it is."""
    from . import NotConfigured

    if env != os.environ.get("WARDEN_DB_ENVIRONMENT", "").strip():
        raise NotConfigured(f"no database is configured for {env} (WARDEN_DB_ENVIRONMENT)")
    read_dsn = settings.getenv("WARDEN_STACK_DB_PRIMARY_RO_DSN")
    write_dsn = settings.getenv("WARDEN_DB_TERMINATE_DSN")
    if not read_dsn and not write_dsn:
        raise NotConfigured(f"this worker holds no login to {env}'s database")
    for name, dsn in (("WARDEN_STACK_DB_PRIMARY_RO_DSN", read_dsn), ("WARDEN_DB_TERMINATE_DSN", write_dsn)):
        if why := _not_iam_only(dsn):
            # A standing password would sign in whoever holds the DSN - for the terminate login with no plan and
            # no approver - and iam_dsn leaves such a DSN as it is: unsigned, and not verified against RDS's
            # certificate authorities (review, PR 48: the read DSN too).
            raise NotConfigured(f"{name} {why}; WARDEN signs in with an IAM token only, verified (verify-full)")
    return read_dsn, write_dsn


def _not_iam_only(dsn: str | None) -> str:
    """Why `dsn` cannot be signed with an IAM token and verified by iam_dsn, or "" when it can (or is not set)."""
    if not dsn:
        return ""
    from psycopg.conninfo import conninfo_to_dict

    parts = conninfo_to_dict(dsn)
    if parts.get("password"):
        return "carries a password"
    if not parts.get("host") or not parts.get("user"):
        return "names no host or no user"
    return ""


# An Aurora cluster endpoint: `<cluster>.cluster-<id>.<region>.rds.amazonaws.com`.
_WRITER_ENDPOINT = re.compile(r"(?<![\w.-])([a-z][a-z0-9-]{0,62}+)\.cluster-([a-z0-9]++)\.([a-z0-9.-]++)")


def aurora_cluster(text: str) -> tuple[str, str, str] | None:
    """(cluster, endpoint id, the rest of the host) of the one Aurora cluster WRITER endpoint `text` names - a DSN, or a plan's
    `server` - or None: none, more than one, or a reader (`cluster-ro-`) or instance endpoint, none of which proves
    which cluster's writer a session is on. Endpoints, not raw hosts, are compared."""
    found = {m.groups() for m in _WRITER_ENDPOINT.finditer(text.lower())}
    return next(iter(found)) if len(found) == 1 else None


_CLUSTER_ENDPOINT = re.compile(r"([a-z][a-z0-9-]{0,62})\.cluster-[a-z0-9]+\.")


def dbuser_arn(rds: Any, dsn: str, role_arn: str) -> str:
    """The exact `rds-db:connect` resource of the DSN's login: its cluster's resource id, read in the reader role
    (which reads only its own environment's clusters), and the login. The account is the role's own."""
    from psycopg.conninfo import conninfo_to_dict

    parts = conninfo_to_dict(dsn)
    host, user = str(parts.get("host") or ""), str(parts.get("user") or "")
    found = _CLUSTER_ENDPOINT.match(host)
    if not found or not re.fullmatch(r"[A-Za-z_]\w{0,62}", user, re.ASCII):
        raise DatabasePlatformRefused("WARDEN_DB_TERMINATE_DSN names no Aurora cluster endpoint and login")
    [cluster] = rds.describe_db_clusters(DBClusterIdentifier=found.group(1))["DBClusters"]
    account = role_arn.split(":")[4]
    return f"arn:aws:rds-db:{rds.meta.region_name}:{account}:dbuser:{cluster['DbClusterResourceId']}/{user}"


def _one_line(value: Any) -> str:
    text = str(value).strip()
    return (text.splitlines()[0] if text else "")[:200]
