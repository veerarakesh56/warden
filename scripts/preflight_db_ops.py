"""Before a live database wave: run every fault op for real, smallest size, and prove it reverts.

    export WARDEN_BENCH_DB_DSN=... WARDEN_BENCH_DB_SG=...     # as for the wave itself
    python scripts/preflight_db_ops.py

For each op: inject at minimum size, CHECK THE FAULT IS REALLY THERE (a session idle in a
transaction, a lock waiter, an active query, a refused connection), revert, and require the same
baseline gate the wave uses (`check_baseline_db`) to come back clean. Exits non-zero on any failure.

⛔ WHY. The Kubernetes wave's first live run stopped twice on harness bugs that every unit test had
passed, because the fakes accepted what the real server did not (scripts/preflight_k8s_ops.py).
This is the database counterpart: it asks the real Postgres, and the real security group, instead.
"""

from __future__ import annotations

import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from scenarios import ops_db
from scenarios.runner import _db_live_harness, check_baseline_db


def _scalar(clients, sql: str):
    conn = clients.connect()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchone()[0]
    finally:
        conn.close()


def _reachable(clients) -> bool:
    try:
        _scalar(clients, "SELECT 1")
        return True
    except Exception:  # noqa: BLE001 - unreachable is the answer being asked for
        return False


IDLE = "SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction'"
WAITING = "SELECT count(*) FROM pg_locks WHERE NOT granted"
SLEEPING = "SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND query ILIKE '%pg_sleep%'"
TOTAL = "SELECT count(*) FROM pg_stat_activity"

CHECKS = [
    ("idle-in-transaction session", ("db_open_idle_transactions", {"count": 1}),
     lambda c, before: _scalar(c, IDLE) >= 1),
    ("connection saturation", ("db_saturate_connections", {"target_pct": 15}),
     lambda c, before: _scalar(c, TOTAL) > before),
    ("long active query", ("db_run_long_query", {"seconds": 120}),
     lambda c, before: _scalar(c, SLEEPING) >= 1),
    ("blocking lock with a waiter", ("db_take_blocking_lock", {"waiters": 1}),
     lambda c, before: _scalar(c, WAITING) >= 1),
]


def _settle_to_baseline(clients, target, seconds: int = 30) -> list[str]:
    deadline = time.monotonic() + seconds
    while True:
        problems = check_baseline_db(clients, target)
        if not problems or time.monotonic() > deadline:
            return problems
        time.sleep(2)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    harness = _db_live_harness(timeout_s=60)
    clients, target = harness.clients, harness.target
    failed = 0

    problems = check_baseline_db(clients, target)
    if problems:
        print(f"NOT AT BASELINE before starting: {problems}")
        return 1

    for label, (op, args), landed in CHECKS:
        before = _scalar(clients, TOTAL)
        try:
            ops_db.OPS[op](clients, target, **args)
            time.sleep(3)
            ok = bool(landed(clients, before))
        except Exception as exc:  # noqa: BLE001
            ok = False
            print(f"   inject raised {type(exc).__name__}: {exc}")
        ops_db.OPS["db_release_everything"](clients, target)
        left = _settle_to_baseline(clients, target)
        verdict = "OK  " if ok and not left else "FAIL"
        failed += verdict == "FAIL"
        print(f"{verdict} {label}: fault {'landed' if ok else 'DID NOT LAND'}; "
              f"after revert {'baseline clean' if not left else left}")

    # The evidence outage: revoke must really cut the connection, restore must really bring it back.
    try:
        ops_db.OPS["db_revoke_ingress"](clients, target)
        time.sleep(5)
        cut = not _reachable(clients)
    finally:
        ops_db.OPS["db_restore_ingress"](clients, target)
    back = False
    for _ in range(15):
        if _reachable(clients):
            back = True
            break
        time.sleep(2)
    left = _settle_to_baseline(clients, target) if back else ["still unreachable after restore"]
    verdict = "OK  " if cut and back and not left else "FAIL"
    failed += verdict == "FAIL"
    print(f"{verdict} security-group revoke: connection {'cut' if cut else 'NOT cut'}; "
          f"restore {'reconnected' if back else 'DID NOT reconnect'}; {left or 'baseline clean'}")

    print("\nALL OPS VERIFIED AGAINST THE REAL DATABASE" if not failed else f"\n{failed} FAILED - do not run the wave")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
