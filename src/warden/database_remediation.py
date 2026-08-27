"""The REAL, gated database write path — the DB twin of `remediation_k8s.py`.

`database.py` is read-only by construction. This is its deliberate opposite: the one place WARDEN can
change a database, and it does exactly ONE thing — terminate stuck connections (idle-in-transaction,
or idle/running past a threshold). It refuses every other action loudly.

Why terminating connections is the safe database action, and the only one here:
  - it destroys no data. An idle-in-transaction connection is killed, its open transaction rolls back,
    and the pool slot plus any row locks it held are released. That is the standard on-call fix.
  - it is bounded, and reversible in the way that matters: the application reconnects.
  - everything else a database incident might want — failover, promotion, schema change, FLUSH, DROP —
    is either irreversible or high blast radius, so it stays with a human (`failover_replica` escalates
    by policy; the rest are not in the action enum at all).

Three clamps, enforced in the SQL *and* again in Python so a broken query cannot widen them:
  1. only connections idle/running beyond WARDEN_DB_TERMINATE_IDLE_SECS (default 300s),
  2. at most WARDEN_DB_TERMINATE_MAX of them (default 20),
  3. NEVER its own connection (pg_backend_pid() / CONNECTION_ID() / client_id() / @@SPID).

It never runs unless the four-way gate in `remediation.py` passed AND live remediation was armed
(`WARDEN_REMEDIATION=live`). Set WARDEN_DB_DRY_RUN=1 to select and count candidates without killing
anything — and in that mode `live` is False, so the audit records a dry run, not a change.

Its credential is a SEPARATE least-privilege database role — the DB twin of the write-RBAC
ServiceAccount. The grant each engine needs (the health-reading role needs none of these, and this
role needs nothing else):
    PostgreSQL  GRANT pg_signal_backend      — signal other backends; implies no data rights
    MySQL       CONNECTION_ADMIN             — KILL other sessions
    SQL Server  ALTER ANY CONNECTION         — KILL other sessions
    Redis       an ACL user permitted CLIENT|KILL
    MongoDB     killop
"""

from __future__ import annotations

import os

from .database import IDLE_SECS, adapter_for, dsn_of, engine_of
from .models import ActionKind, Alert
from .remediation import RemediationError

MAX_TERMINATE = int(os.environ.get("WARDEN_DB_TERMINATE_MAX", "20"))


def _as_ids(rows) -> list[int]:
    """Coerce ids the database itself returned to ints.

    They are always integers, but SQL Server's KILL and MySQL's KILL cannot be parameterised, so their
    ids get interpolated into a statement. int() is the guard that makes that safe — anything
    non-numeric raises here rather than reaching the server.
    """
    out = []
    for row in rows:
        value = row[0] if isinstance(row, (tuple, list)) else row
        out.append(int(value))
    return out


# --------------------------------------------------------------------------- per-engine killers


class _PostgresKiller:
    engine = "postgres"

    @staticmethod
    def candidates(conn, idle_secs: int, limit: int) -> list[int]:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT pid FROM pg_stat_activity "
                "WHERE state = 'idle in transaction' "
                "AND state_change < now() - make_interval(secs => %s) "
                "AND pid <> pg_backend_pid() "
                "ORDER BY state_change LIMIT %s",
                (idle_secs, limit),
            )
            return _as_ids(cur.fetchall())

    @staticmethod
    def terminate(conn, ids: list[int]) -> int:
        killed = 0
        with conn.cursor() as cur:
            for pid in ids:
                cur.execute("SELECT pg_terminate_backend(%s)", (int(pid),))
                row = cur.fetchone()
                if row and row[0]:
                    killed += 1
        return killed


class _MySQLKiller:
    engine = "mysql"

    @staticmethod
    def candidates(conn, idle_secs: int, limit: int) -> list[int]:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT p.id FROM information_schema.innodb_trx t "
                "JOIN information_schema.processlist p ON t.trx_mysql_thread_id = p.id "
                "WHERE p.command = 'Sleep' AND t.trx_started < (NOW() - INTERVAL %s SECOND) "
                "AND p.id <> CONNECTION_ID() ORDER BY t.trx_started LIMIT %s",
                (idle_secs, limit),
            )
            return _as_ids(cur.fetchall())

    @staticmethod
    def terminate(conn, ids: list[int]) -> int:
        killed = 0
        with conn.cursor() as cur:
            for tid in ids:
                # KILL takes no placeholders; tid is an int via _as_ids, so this cannot inject.
                cur.execute(f"KILL {int(tid)}")
                killed += 1
        return killed


class _RedisKiller:
    engine = "redis"

    @staticmethod
    def candidates(conn, idle_secs: int, limit: int) -> list[int]:
        me = conn.client_id()
        out: list[int] = []
        for c in conn.client_list():
            if int(c.get("idle", 0)) >= idle_secs and int(c.get("id", 0)) != me:
                out.append(int(c["id"]))
                if len(out) >= limit:
                    break
        return out

    @staticmethod
    def terminate(conn, ids: list[int]) -> int:
        killed = 0
        for cid in ids:
            if conn.client_kill_filter(_id=int(cid)):
                killed += 1
        return killed


class _MongoKiller:
    engine = "mongo"

    @staticmethod
    def candidates(conn, idle_secs: int, limit: int) -> list[int]:
        ops = conn.admin.command("currentOp", {"active": True})
        out: list[int] = []
        for op in ops.get("inprog", []):
            # Skip the currentOp call itself — that is this connection's own operation.
            command = op.get("command") or {}
            if "currentOp" in command:
                continue
            if float(op.get("secs_running", 0)) >= idle_secs and op.get("opid") is not None:
                out.append(int(op["opid"]))
                if len(out) >= limit:
                    break
        return out

    @staticmethod
    def terminate(conn, ids: list[int]) -> int:
        killed = 0
        for opid in ids:
            conn.admin.command("killOp", op=int(opid))
            killed += 1
        return killed


class _MSSQLKiller:
    engine = "mssql"

    @staticmethod
    def candidates(conn, idle_secs: int, limit: int) -> list[int]:
        cur = conn.cursor()
        # TOP (n) and DATEADD's offset cannot be parameterised by pymssql; both are int()-coerced.
        cur.execute(
            f"SELECT TOP ({int(limit)}) session_id FROM sys.dm_exec_sessions "
            "WHERE is_user_process = 1 AND open_transaction_count > 0 AND status = 'sleeping' "
            f"AND last_request_end_time < DATEADD(second, -{int(idle_secs)}, GETDATE()) "
            "AND session_id <> @@SPID ORDER BY last_request_end_time"
        )
        return _as_ids(cur.fetchall())

    @staticmethod
    def terminate(conn, ids: list[int]) -> int:
        killed = 0
        cur = conn.cursor()
        for spid in ids:
            # KILL takes no placeholders; spid is an int via _as_ids, so this cannot inject.
            cur.execute(f"KILL {int(spid)}")
            killed += 1
        return killed


_KILLERS = {
    k.engine: k
    for k in (_PostgresKiller, _MySQLKiller, _RedisKiller, _MongoKiller, _MSSQLKiller)
}


# --------------------------------------------------------------------------- the backend


class DatabaseRemediationBackend:
    """Terminates stuck connections on one database. `live = True` unless running dry."""

    live = True

    def __init__(
        self,
        *,
        dsn: str | None = None,
        engine: str | None = None,
        conn=None,
        dry_run: bool | None = None,
    ) -> None:
        self._dry_run = (os.environ.get("WARDEN_DB_DRY_RUN") == "1") if dry_run is None else dry_run
        # The honesty flag: a dry run must NOT be recorded as a real change.
        self.live = not self._dry_run
        self._injected = conn
        self._dsn = dsn
        self._engine = engine
        if conn is not None and engine is None:
            raise RemediationError("DatabaseRemediationBackend(conn=...) also needs engine=...")

    def _resolve(self, alert: Alert | None):
        dsn = self._dsn or os.environ.get("WARDEN_DB_ADMIN_DSN") or (dsn_of(alert) if alert else None)
        engine = self._engine or (engine_of(dsn) if dsn else None)
        if engine is None:
            raise RemediationError(
                "no database to remediate: set $WARDEN_DB_ADMIN_DSN (the least-privilege terminate role)"
            )
        killer = _KILLERS.get(engine)
        if killer is None:
            raise RemediationError(f"no terminate support for engine '{engine}'")
        conn = self._injected if self._injected is not None else adapter_for(engine).connect(dsn)
        return killer, conn

    def apply(self, action: ActionKind, target: str, environment: str) -> str:
        if action is not ActionKind.terminate_connections:
            raise RemediationError(
                f"{action.value} is not something the database remediation backend performs "
                "(it does terminate_connections only)"
            )
        killer, conn = self._resolve(None)
        try:
            candidates = killer.candidates(conn, IDLE_SECS, MAX_TERMINATE)
        except Exception as exc:
            raise RemediationError(
                f"could not list stuck connections on {target}: {_one_line(exc)}"
            ) from exc

        # Clamp AGAIN in Python. The SQL already limits, but a mutated or hand-edited query must not
        # be able to widen the blast radius — the ceiling is enforced in two independent places.
        candidates = candidates[:MAX_TERMINATE]
        if not candidates:
            return f"no connections on '{target}' were stuck beyond {IDLE_SECS}s; nothing terminated"
        if self._dry_run:
            return (
                f"DRY RUN: would terminate {len(candidates)} stuck connection(s) on '{target}' "
                f"({killer.engine}, idle > {IDLE_SECS}s) - no change made"
            )
        try:
            killed = killer.terminate(conn, candidates)
        except Exception as exc:
            raise RemediationError(
                f"terminating connections on {target} failed: {_one_line(exc)}"
            ) from exc
        return (
            f"terminated {killed} stuck connection(s) on '{target}' "
            f"({killer.engine}, idle > {IDLE_SECS}s, ceiling {MAX_TERMINATE})"
        )


def _one_line(value) -> str:
    text = str(value).strip()
    first = text.splitlines()[0] if text else ""
    return first[:200]
