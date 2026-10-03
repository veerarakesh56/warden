"""G6: the audit on PostgreSQL, checked without a database (the real one runs in CI: tests/integration/
test_live_audit_pg.py). Every append takes the chain's advisory lock inside its transaction; the schema and the
runtime role's grants come only from `migrate`; a role name is never pasted into SQL unchecked."""

from __future__ import annotations

import contextlib

import pytest

from warden import audit

DSN = "postgresql://" + "u@h/db"


class _Conn:
    def __init__(self):
        self.sql, self.rows = [], []
        self.in_tx = False

    def execute(self, sql, params=()):
        self.sql.append((sql, tuple(params), self.in_tx))
        conn = self

        class _Cur:
            rowcount = 1

            def fetchone(self):
                return (len(conn.rows), f"h{len(conn.rows)}") if sql.startswith("SELECT seq, hash") and conn.rows else None

            def fetchall(self):
                return []
        if sql.startswith("INSERT INTO entries"):
            self.rows.append(params)
        return _Cur()

    @contextlib.contextmanager
    def transaction(self):
        self.in_tx = True
        yield
        self.in_tx = False

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def conn(monkeypatch):
    c = _Conn()
    monkeypatch.setattr(audit, "_pg_connect", lambda dsn: c)
    return c


def test_each_append_holds_the_chains_lock_in_its_transaction(conn):
    log = audit.AuditLog(DSN)
    log.append("inc-1", "x", {"a": 1})
    log.append("inc-1", "x", {"a": 2})
    locks = [s for s in conn.sql if s[0].startswith("SELECT pg_advisory_xact_lock")]
    inserts = [s for s in conn.sql if s[0].startswith("INSERT INTO entries")]
    assert len(locks) == 2 and all(in_tx for _, _, in_tx in locks + inserts)
    assert all("%s" in sql and "?" not in sql for sql, _, _ in inserts)
    assert [p[0] for _, p, _ in inserts] == [1, 2]  # seq follows the head read under the lock
    assert not any(s[0].startswith("CREATE") for s in conn.sql)  # the runtime never creates or changes the schema


def test_migrate_makes_the_tables_append_only_and_grants_only_read_and_append(conn):
    audit.migrate(DSN, writer_role="warden_audit_writer")
    text = [s[0] for s in conn.sql]
    for table in ("entries", "checkpoints"):
        assert any(f"TRIGGER {table}_append_only BEFORE UPDATE OR DELETE" in t for t in text)
        assert any(f"TRIGGER {table}_no_truncate BEFORE TRUNCATE" in t for t in text)
        assert f"GRANT SELECT, INSERT ON {table} TO warden_audit_writer" in text
        assert text.index(f"REVOKE ALL ON {table} FROM warden_audit_writer") < text.index(
            f"GRANT SELECT, INSERT ON {table} TO warden_audit_writer")
    for bad in ("x; DROP TABLE entries", "Writer", "a b"):
        with pytest.raises(ValueError):
            audit.migrate(DSN, writer_role=bad)


def test_a_postgres_log_is_read_only_through_its_methods(conn):
    log = audit.AuditLog(DSN)
    with pytest.raises(AttributeError):
        _ = log.db
    assert audit._is_postgres(DSN) and not audit._is_postgres("audit.db")


def test_the_runtime_uses_the_shared_audit_when_its_dsn_is_set(monkeypatch, tmp_path):
    from warden import runtime

    monkeypatch.setenv("WARDEN_AUDIT_DB", str(tmp_path / "a.db"))
    monkeypatch.delenv("WARDEN_AUDIT_DSN", raising=False)
    assert runtime.audit_target() == tmp_path / "a.db"
    monkeypatch.setenv("WARDEN_AUDIT_DSN", DSN)
    assert runtime.audit_target() == DSN
    monkeypatch.setenv("WARDEN_AUDIT_DSN", "mysql://u@h/db")
    with pytest.raises(RuntimeError, match="postgresql"):
        runtime.audit_target()


def test_migrate_runs_only_with_the_migration_roles_dsn(conn, monkeypatch, capsys):
    from warden.cli import main

    monkeypatch.delenv("WARDEN_AUDIT_MIGRATION_DSN", raising=False)
    assert main(["audit", "migrate", "--writer-role", "warden_audit_writer"]) == 1
    assert conn.sql == []
    monkeypatch.setenv("WARDEN_AUDIT_MIGRATION_DSN", DSN)
    assert main(["audit", "migrate", "--writer-role", "warden_audit_writer"]) == 0
    assert any("GRANT SELECT, INSERT ON entries TO warden_audit_writer" == s[0] for s in conn.sql)
