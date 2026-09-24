"""Fault injection for the DATABASE proving ground - Wave 3 (RDS PostgreSQL).

The same rules as `ops.py` and `ops_k8s.py`, restated because they are the rules:

  1. ⛔ NOTHING OUTSIDE THE PROVING GROUND. Every op refuses unless the database it is connected to
     is named `warden` AND carries the sentinel table this module created. A tag check would need
     `rds:DescribeDBInstances`; the sentinel needs nothing and fails closed against ANY database
     that is not ours - including a production Postgres reachable from the same laptop, which is
     the accident worth preventing.
  2. ⛔ EVERY INJECT HAS A REVERT, and the revert closes exactly what was opened.
  3. ⛔ THE FAULT MUST BE REAL. These ops open real sessions, hold real transactions open, take real
     locks and run a real long query. Nothing here writes a metric or a log line claiming a fault.
  4. ⛔ THIS MODULE MUST NOT IMPORT `warden`.

⚠ THE FAULT LIVES IN THIS PROCESS, and that is different from every wave before it. On ECS and
Kubernetes the fault lives in the cloud and outlives the harness. Here the sessions are held by THIS
python process, so if the runner is killed mid-scenario they close and the database heals itself.
That is the safe direction - nothing stays broken, nothing keeps billing - but the ground-truth
record would then show a revert that never ran, and a reader must not mistake that for a clean
scenario. Said here rather than discovered later from a confusing artefact.

⚠ WHAT WAVE 3 CAN MEASURE, decided by what `database.py::_Postgres` actually reads:
  measurable  active_connections, idle_in_transaction, long_running_queries (active > 60s),
              locks_waiting, connections_used_pct, and the tool failing outright
  NOT         CPU, memory, IOPS, buffer cache, or anything from CloudWatch or Performance Insights
              - none of which this tool reads. A scenario about an undersized instance would be
              asking the model a question its own evidence cannot answer.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .ops import OpError

# The table whose presence means "this database is the proving ground". Created by the harness at
# setup; every op checks it before touching anything.
SENTINEL_TABLE = "warden_proving_ground"
PROVING_GROUND_DB = "warden"
PROJECT_TAG = ("Project", "warden-proving-ground")


@dataclass
class Target:
    """Everything the database ops need.

    ⛔ `dsn` carries the master password. It is never logged, never written into an artefact and
    never returned by `describe_target`, which reports host and database only.
    """

    dsn: str
    database: str = PROVING_GROUND_DB
    host: str = ""
    instance_id: str = ""
    # The RDS security group, so one scenario can cut WARDEN off from its own evidence source.
    security_group_id: str = ""
    saved: dict[str, Any] = field(default_factory=dict)


@dataclass
class Clients:
    # () -> a NEW open connection to the proving-ground database. A factory rather than a single
    # connection, because these ops deliberately hold many sessions open at once.
    connect: Callable[[], Any]
    ec2: Any = None


# Sessions this module is holding open, so a revert closes exactly what an inject opened rather than
# "every connection it can find" - which would kill WARDEN's own read mid-measurement.
_HELD: list[Any] = []
_LONG_QUERY: dict[str, Any] = {}


def _guard_database(clients: Clients, target: Target) -> None:
    """Refuse to operate on anything that is not the proving ground.

    ⛔ Never relax this. Two independent checks, because either alone is too weak: a database can be
    called `warden` by coincidence, and a sentinel table could be left behind somewhere else.
    """
    try:
        conn = clients.connect()
    except Exception as exc:  # any failure here means "do not touch it"
        raise OpError(f"cannot reach the proving-ground database: {type(exc).__name__}") from exc
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database()")
            name = cur.fetchone()[0]
            if name != target.database:
                raise OpError(
                    f"connected to database {name!r}, expected {target.database!r}. This harness "
                    "only breaks the proving ground. Refusing."
                )
            cur.execute("SELECT to_regclass(%s)", (SENTINEL_TABLE,))
            if cur.fetchone()[0] is None:
                raise OpError(
                    f"database {name!r} has no {SENTINEL_TABLE} table, so it is not the proving "
                    "ground. Refusing. If it really is, mark it deliberately: "
                    "python scripts/setup_proving_ground_db.py --apply"
                )
    finally:
        conn.close()


def op_db_open_idle_transactions(clients: Clients, target: Target, *, count: int = 12,
                                 account: str = "", **_: Any) -> dict:
    """Open `count` sessions and leave each one idle INSIDE a transaction.

    The classic connection-pool killer: every one holds its snapshot and its locks open forever.
    `pg_stat_activity.state` really reads `idle in transaction` - nothing here fakes a metric.
    """
    _guard_database(clients, target)
    opened = 0
    for _ in range(int(count)):
        conn = clients.connect()
        cur = conn.cursor()
        cur.execute("BEGIN")
        cur.execute("SELECT count(*) FROM " + SENTINEL_TABLE)  # a real statement, then nothing
        _HELD.append(conn)
        opened += 1
    return {"opened_idle_in_transaction": opened, "held_total": len(_HELD)}


def op_db_saturate_connections(clients: Clients, target: Target, *, target_pct: int = 80,
                               account: str = "", **_: Any) -> dict:
    """Open plain sessions until roughly `target_pct` of max_connections is in use.

    ⛔ Deliberately not 100%. WARDEN has to be able to CONNECT in order to see the saturation - at
    100% its own read fails and the scenario measures a tool outage instead of a saturated pool,
    which is a different fault with its own scenario.
    """
    _guard_database(clients, target)
    probe = clients.connect()
    try:
        with probe.cursor() as cur:
            cur.execute("SHOW max_connections")
            max_conn = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM pg_stat_activity")
            current = int(cur.fetchone()[0])
    finally:
        probe.close()

    want = int(max_conn * int(target_pct) / 100)
    opened = 0
    while current + opened < want:
        try:
            _HELD.append(clients.connect())
            opened += 1
        except Exception as exc:  # noqa: BLE001 - the server refusing IS the result here
            # Reported, never silently treated as if the target had been reached.
            return {"max_connections": max_conn, "opened": opened, "stopped_early": str(exc)[:120]}
    return {"max_connections": max_conn, "opened": opened, "target_pct": int(target_pct)}


def op_db_run_long_query(clients: Clients, target: Target, *, seconds: int = 900,
                         account: str = "", **_: Any) -> dict:
    """Start one genuinely long-running ACTIVE query.

    ⭐ The pair to the idle-in-transaction scenario, and the reason both exist: `pg_sleep` shows as
    `state = 'active'` with an old `query_start`, which is what `long_running_queries` counts.
    Terminating THIS destroys work in progress; terminating an idle-in-transaction session is the
    fix. Same action, opposite grade.
    """
    _guard_database(clients, target)
    if _LONG_QUERY:
        raise OpError("a long query is already running - refusing to start a second")
    conn = clients.connect()

    def run() -> None:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_sleep(%s)", (int(seconds),))
        except Exception:  # noqa: BLE001, S110 - cancellation by the revert is the expected
            pass           # ending of this thread, and there is nobody left to report it to

    thread = threading.Thread(target=run, daemon=True, name="warden-bench-long-query")
    thread.start()
    _LONG_QUERY.update({"conn": conn, "thread": thread})
    return {"long_query_seconds": int(seconds)}


def op_db_take_blocking_lock(clients: Clients, target: Target, *, waiters: int = 2,
                             account: str = "", **_: Any) -> dict:
    """One idle-in-transaction session holds an exclusive lock; `waiters` sessions queue behind it.

    That queue is what `locks_waiting` counts (`pg_locks WHERE NOT granted`), and because the
    blocker is idle in a transaction, terminating it really is the fix.
    """
    _guard_database(clients, target)
    blocker = clients.connect()
    cur = blocker.cursor()
    cur.execute("BEGIN")
    cur.execute("LOCK TABLE " + SENTINEL_TABLE + " IN ACCESS EXCLUSIVE MODE")
    _HELD.append(blocker)

    started = 0
    for _ in range(int(waiters)):
        waiter = clients.connect()
        _HELD.append(waiter)

        def wait(conn=waiter) -> None:
            try:
                with conn.cursor() as c:
                    c.execute("BEGIN")
                    c.execute("LOCK TABLE " + SENTINEL_TABLE + " IN ACCESS EXCLUSIVE MODE")
            except Exception:  # noqa: BLE001, S110 - a waiter is meant to block, then die
                pass           # with the connection when the revert closes it

        threading.Thread(target=wait, daemon=True, name="warden-bench-lock-waiter").start()
        started += 1
    return {"blocker": 1, "waiters": started}


def op_db_release_everything(clients: Clients, target: Target, *, account: str = "",
                             **_: Any) -> dict:
    """Close every session this module opened. The revert for all of the above.

    Closes what was OPENED, never "every connection on the server": killing WARDEN's own read, or
    somebody else's, would be a fault this harness invented rather than reverted.
    """
    long_query = _LONG_QUERY.pop("conn", None)
    _LONG_QUERY.pop("thread", None)
    cancelled = 0
    if long_query is not None:
        try:
            long_query.cancel()
        except Exception:  # noqa: BLE001, S110 - closing below is what actually matters
            pass
        try:
            long_query.close()
            cancelled = 1
        except Exception:  # noqa: BLE001, S110 - a connection already gone is still gone
            pass

    closed = 0
    while _HELD:
        conn = _HELD.pop()
        try:
            conn.close()
            closed += 1
        except Exception:  # noqa: BLE001, S110 - a session already gone is still gone, and a
            pass           # revert that stops half way would leave the rest of them open
    return {"closed_sessions": closed, "cancelled_long_queries": cancelled}


def op_db_revoke_ingress(clients: Clients, target: Target, *, account: str = "", **_: Any) -> dict:
    """Cut WARDEN off from the database by revoking the security group's ingress rule.

    ⭐ The Wave 3 counterpart of deleting the log group and of revoking pods/log: WARDEN's own
    evidence source disappears. The right answer is to say so, not to diagnose from an absence.
    """
    if clients.ec2 is None:
        raise OpError("no ec2 client - cannot revoke database ingress")
    if not target.security_group_id:
        raise OpError("no security group recorded for the database - refusing to guess")
    _guard_database(clients, target)

    groups = clients.ec2.describe_security_groups(GroupIds=[target.security_group_id])
    group = (groups.get("SecurityGroups") or [{}])[0]
    tags = {t.get("Key"): t.get("Value") for t in group.get("Tags") or []}
    key, value = PROJECT_TAG
    if tags.get(key) != value:
        raise OpError(
            f"security group {target.security_group_id} is not tagged {key}={value}. Refusing."
        )
    rules = group.get("IpPermissions") or []
    if not rules:
        raise OpError("the database security group has no ingress rules - nothing to revoke")
    # ⚠ THE ONLY COPY OF THESE RULES IS NOW IN MEMORY. If the runner dies between here and the
    # restore, the database stays cut off and `target.saved` dies with the process. Recovery is
    # `terraform apply`, which re-declares the rule from rds.tf - stated so nobody spends an hour
    # reconstructing a rule that is already in version control.
    target.saved["db_ingress"] = rules
    clients.ec2.revoke_security_group_ingress(
        GroupId=target.security_group_id, IpPermissions=rules,
    )
    return {"revoked_rules": len(rules)}


def op_db_restore_ingress(clients: Clients, target: Target, *, account: str = "", **_: Any) -> dict:
    """Put back exactly the rules that were revoked.

    ⛔ NO `_guard_database` HERE, and that asymmetry is deliberate: the guard connects to the
    database, and this op exists precisely because the database is unreachable. Guarding would make
    the revert fail every time and leave the proving ground cut off. It is safe without one because
    it only ever re-authorises rules it saved from a group the revoke had already checked the tag
    of - it cannot be pointed at a group nobody verified.
    """
    if clients.ec2 is None:
        raise OpError("no ec2 client - cannot restore database ingress")
    saved = target.saved.get("db_ingress")
    if saved is None:
        raise OpError("no saved ingress rules - refusing to guess what they were")
    clients.ec2.authorize_security_group_ingress(
        GroupId=target.security_group_id, IpPermissions=saved,
    )
    return {"restored_rules": len(saved)}


# ⛔ The registry a catalog's `op:` names are looked up in, via `ops.run_steps(registry=...)`.
OPS: dict[str, Callable[..., dict]] = {
    "db_open_idle_transactions": op_db_open_idle_transactions,
    "db_saturate_connections": op_db_saturate_connections,
    "db_run_long_query": op_db_run_long_query,
    "db_take_blocking_lock": op_db_take_blocking_lock,
    "db_release_everything": op_db_release_everything,
    "db_revoke_ingress": op_db_revoke_ingress,
    "db_restore_ingress": op_db_restore_ingress,
}

# Wave 3 changes no container spec, so there are no image/command variants to name. The catalog
# tripwire checks every `variant:` against this table; an empty one keeps that check honest.
_VARIANTS: dict[str, dict[str, Any]] = {}
