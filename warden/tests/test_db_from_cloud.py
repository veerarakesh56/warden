"""The cloud runtime reads the watched database with a 15-minute IAM token signed in the incident's reader role - no
password anywhere (2026-10-15: the cloud read no database at all; WARDEN_STACK_DB_*_DSN were empty)."""

from __future__ import annotations

from psycopg.conninfo import conninfo_to_dict

from warden import aws_stack


class _Rds:
    def __init__(self):
        self.asked = []

    def generate_db_auth_token(self, DBHostname, Port, DBUsername):
        self.asked.append((DBHostname, Port, DBUsername))
        return "signed-token-for-" + DBUsername


def test_a_dsn_without_a_password_gets_the_roles_token():
    rds = _Rds()
    got = conninfo_to_dict(aws_stack.iam_dsn(rds, "postgresql://warden_dev_ro@db.example.test:5432/shop"))
    assert rds.asked == [("db.example.test", 5432, "warden_dev_ro")]
    assert got["password"] == "signed-token-for-warden_dev_ro"
    assert got["sslmode"] == "require"
    assert got["dbname"] == "shop"
    assert got["user"] == "warden_dev_ro"


def test_a_dsn_with_a_password_or_without_a_user_is_left_as_it_is():
    rds = _Rds()
    for dsn in ("postgresql://u:pw@h/db", "postgresql://h/db"):
        assert aws_stack.iam_dsn(rds, dsn) == dsn
    assert rds.asked == []


def test_the_stack_reader_signs_only_when_told_to(monkeypatch):
    seen = []

    class _Db:
        def metrics(self, alert):
            return {}

        def logs(self, alert):
            return []

    b = aws_stack.StackBackend.__new__(aws_stack.StackBackend)
    b._rds, b._db_factory = _Rds(), lambda dsn: seen.append(dsn) or _Db()
    monkeypatch.setenv("WARDEN_STACK_DB_PRIMARY_RO_DSN", "postgresql://warden_dev_ro@h/shop")
    monkeypatch.delenv("WARDEN_STACK_DB_IAM_AUTH", raising=False)
    b._read_db(aws_stack._Out(), "WARDEN_STACK_DB_PRIMARY_RO_DSN", "", None)
    monkeypatch.setenv("WARDEN_STACK_DB_IAM_AUTH", "1")
    b._read_db(aws_stack._Out(), "WARDEN_STACK_DB_PRIMARY_RO_DSN", "", None)
    assert "password" not in conninfo_to_dict(seen[0])
    assert conninfo_to_dict(seen[1])["password"].startswith("signed-")
