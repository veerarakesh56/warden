"""The audit on a REAL PostgreSQL (G6: Aurora in the runtime). Skipped unless opted in; fails if opted in and the
database is unreachable - like tests/integration/test_live_database.py, and run in the same CI job.

    WARDEN_DB_INTEGRATION=1 WARDEN_TEST_PG_DSN=postgresql://... pytest tests/integration/test_live_audit_pg.py -q

Many writers, one chain: workers and Lambdas append at once, each append holding the chain's advisory lock.
"""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("WARDEN_DB_INTEGRATION") != "1" or not os.environ.get("WARDEN_TEST_PG_DSN"),
    reason="set WARDEN_DB_INTEGRATION=1 and WARDEN_TEST_PG_DSN to run these",
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import audit

DSN = os.environ.get("WARDEN_TEST_PG_DSN", "")


@pytest.fixture
def fresh():
    import psycopg

    with psycopg.connect(DSN, autocommit=True) as db:
        db.execute("DROP TABLE IF EXISTS entries, checkpoints CASCADE")
    audit.migrate(DSN)
    return DSN


def test_many_writers_build_one_unbroken_chain(fresh):
    key = Ed25519PrivateKey.generate()
    logs = [audit.AuditLog(fresh, key=key, checkpoint_every=25) for _ in range(3)]

    def write(log, n):
        for i in range(40):
            log.append(f"inc-{n}", "test.row", {"i": i})

    threads = [threading.Thread(target=write, args=(log, n)) for n, log in enumerate(logs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    logs[0].checkpoint()
    result = audit.verify(fresh, key.public_key())
    assert result.ok, result.problems
    assert result.rows == 120 and result.unsigned_tail == 0
    assert [e["seq"] for e in logs[1].entries()] == list(range(1, 121))
    assert len(logs[2].entries("inc-1", kinds=("test.row",))) == 40
    assert logs[0].entries(since=datetime.now(UTC) - timedelta(minutes=5)) and not logs[0].entries(
        since=datetime.now(UTC) + timedelta(minutes=5))
    for log in logs:
        log.close()


def test_the_rows_cannot_be_changed_deleted_or_truncated(fresh):
    import psycopg

    key = Ed25519PrivateKey.generate()
    log = audit.AuditLog(fresh, key=key)
    log.append("inc-1", "test.row", {"x": 1})
    assert log.checkpoint() == 1  # a row in each table: a row-level trigger fires only on a row (CI, 2026-10-03)
    with psycopg.connect(fresh, autocommit=True) as db:
        for statement in ("UPDATE entries SET body = '{}'", "DELETE FROM entries", "TRUNCATE entries",
                          "DELETE FROM checkpoints"):
            with pytest.raises(psycopg.Error, match="append-only"):
                db.execute(statement)
    result = audit.verify(fresh, key.public_key())
    assert result.ok and result.rows == 1 and result.signed_through == 1
    log.close()


def test_the_runtime_role_may_only_read_and_append(fresh):
    import psycopg

    with psycopg.connect(fresh, autocommit=True) as db:
        db.execute("DROP ROLE IF EXISTS warden_audit_writer_test")
        db.execute("CREATE ROLE warden_audit_writer_test NOLOGIN")
    audit.migrate(fresh, writer_role="warden_audit_writer_test")
    with psycopg.connect(fresh, autocommit=True) as db:
        for table in ("entries", "checkpoints"):
            granted = {p: db.execute("SELECT has_table_privilege('warden_audit_writer_test', %s, %s)",
                                     (table, p)).fetchone()[0]
                       for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")}
            assert granted == {"SELECT": True, "INSERT": True, "UPDATE": False, "DELETE": False, "TRUNCATE": False}
        db.execute("REVOKE ALL ON entries, checkpoints FROM warden_audit_writer_test")
        db.execute("DROP ROLE warden_audit_writer_test")
