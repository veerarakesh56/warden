"""G6: the cloud audit has no password. The runtime connects as `warden_audit_writer` with a 15-minute IAM token
(WARDEN_AUDIT_IAM_AUTH=1 and a DSN without a password); the migrate Lambda, the one reader of the cluster's master
secret, creates the schema and that login (rds_iam, SELECT and INSERT only)."""

from __future__ import annotations

import json

import pytest

from warden import audit, lambdas

DSN = "postgresql://warden_audit_writer@db.example:5432/warden_audit?sslmode=require"


@pytest.fixture
def fakes(monkeypatch):
    seen = {"connect": [], "sql": [], "token": []}

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, *a):
            seen["sql"].append(sql)

    def connect(dsn, **kw):
        seen["connect"].append((dsn, kw))
        return Conn()

    monkeypatch.setattr("psycopg.connect", connect)

    class Rds:
        def generate_db_auth_token(self, **kw):
            seen["token"].append(kw)
            return "signed-token"

    class Secrets:
        def get_secret_value(self, SecretId):
            assert SecretId == "arn:master"
            return {"SecretString": json.dumps({"username": "warden_admin", "password": "pw"})}

    monkeypatch.setattr("boto3.client", lambda name, **kw: {"rds": Rds(), "secretsmanager": Secrets()}[name])
    monkeypatch.setattr("warden.environments.region", lambda: "test-region-1")
    return seen


def test_the_runtime_signs_in_with_an_iam_token_and_no_password(fakes, monkeypatch):
    monkeypatch.setenv("WARDEN_AUDIT_IAM_AUTH", "1")
    audit._pg_connect(DSN)
    ((dsn, kw),) = fakes["connect"]
    assert dsn == DSN and kw["password"] == "signed-token" and kw["sslmode"] == "require"
    assert fakes["token"] == [{"DBHostname": "db.example", "Port": 5432, "DBUsername": "warden_audit_writer"}]
    monkeypatch.delenv("WARDEN_AUDIT_IAM_AUTH")
    audit._pg_connect(DSN)  # without the switch, no token
    assert "password" not in fakes["connect"][-1][1] and len(fakes["token"]) == 1


def test_migrate_creates_the_writer_as_an_iam_login_with_select_and_insert_only(fakes):
    audit.migrate("postgresql://admin:pw@db.example/warden_audit", "warden_audit_writer", iam_login=True)
    sql = " ; ".join(fakes["sql"])
    assert "CREATE ROLE warden_audit_writer LOGIN" in sql and "PASSWORD" not in sql.upper()
    assert "GRANT rds_iam TO warden_audit_writer" in sql
    for t in ("entries", "checkpoints"):
        assert f"REVOKE ALL ON {t} FROM warden_audit_writer" in sql and f"GRANT SELECT, INSERT ON {t} TO warden_audit_writer" in sql
    with pytest.raises(ValueError, match="plain database role"):
        audit.migrate("postgresql://admin:pw@db.example/warden_audit", "x; DROP TABLE entries", iam_login=True)


def test_the_migrate_lambda_reads_the_master_secret_and_makes_the_writer(fakes, monkeypatch):
    monkeypatch.setenv("WARDEN_AUDIT_MASTER_SECRET", "arn:master")
    monkeypatch.setenv("WARDEN_AUDIT_HOST", "db.example")
    monkeypatch.setenv("WARDEN_AUDIT_DB", "warden_audit")
    monkeypatch.delenv("WARDEN_AUDIT_IAM_AUTH", raising=False)
    assert lambdas.migrate({}) == {"migrated": True, "writer": "warden_audit_writer"}
    ((dsn, _),) = fakes["connect"]
    assert "user=warden_admin" in dsn and "sslmode=require" in dsn and "host=db.example" in dsn
    assert any("GRANT rds_iam TO warden_audit_writer" in q for q in fakes["sql"])
