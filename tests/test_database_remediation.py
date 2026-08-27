"""The gated database write path: the exact statement each engine issues, the three clamps, dry-run,
refusal of everything else, the router, and the gate around it all.

These assert the STATEMENT, not just "it did something" — the difference between terminating a stuck
connection and terminating the wrong thing is the text of one query.
"""

from __future__ import annotations

import pytest

from warden.database_remediation import (
    MAX_TERMINATE,
    DatabaseRemediationBackend,
    _as_ids,
    _MongoKiller,
    _MSSQLKiller,
    _MySQLKiller,
    _PostgresKiller,
    _RedisKiller,
)
from warden.models import (
    ActionKind,
    Alert,
    RemediationProposal,
    Severity,
    Verdict,
    VerdictStatus,
)
from warden.remediation import (
    RemediationError,
    RemediationOutcome,
    RemediationRequest,
    decide_remediation,
)
from warden.remediation_k8s import LiveRemediationRouter

# ------------------------------------------------------------------ SQL-shaped stubs

class _Cur:
    def __init__(self, owner):
        self.owner = owner

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        self.owner.sql.append((" ".join(sql.split()), params))

    def fetchall(self):
        return self.owner.rows

    def fetchone(self):
        return (True,)


class SqlStub:
    """Returns the ids it was constructed with, and records every statement executed."""

    def __init__(self, ids=(), fail=False):
        self.rows = [(i,) for i in ids]
        self.sql: list[tuple[str, tuple]] = []
        self.fail = fail

    def cursor(self):
        if self.fail:
            raise RuntimeError("connection refused")
        return _Cur(self)


def _alert(env="staging"):
    return Alert(alert_id="inc-005", name="DBConnectionsStuck", severity=Severity.high,
                 service="payments", environment=env, summary="pool exhausted",
                 started_at="2026-08-26T00:00:00Z")


def _prop(action=ActionKind.terminate_connections):
    return RemediationProposal(action=action, target="payments-db", reasoning="r",
                               expected_effect="pool frees", blast_radius="single_service",
                               reversible=True)


def _approved():
    return Verdict(status=VerdictStatus.approved_for_human)


def _backend(ids=(), **kw):
    kw.setdefault("dry_run", False)
    return DatabaseRemediationBackend(engine="postgres", conn=SqlStub(ids), **kw)


# ------------------------------------------------------------------ honesty flag

def test_it_declares_itself_live_when_it_will_really_kill():
    assert _backend([1]).live is True


def test_a_dry_run_is_not_reported_as_live():
    """The `live` flag IS the audit trail: a dry run recorded as a change would be a lie."""
    assert DatabaseRemediationBackend(engine="postgres", conn=SqlStub([1]), dry_run=True).live is False


def test_dry_run_can_be_armed_by_environment(monkeypatch):
    monkeypatch.setenv("WARDEN_DB_DRY_RUN", "1")
    assert DatabaseRemediationBackend(engine="postgres", conn=SqlStub([1])).live is False
    monkeypatch.setenv("WARDEN_DB_DRY_RUN", "0")
    assert DatabaseRemediationBackend(engine="postgres", conn=SqlStub([1])).live is True


# ------------------------------------------------------------------ postgres

def test_postgres_selects_only_idle_in_transaction_past_the_threshold_and_never_itself():
    stub = SqlStub([101, 102])
    ids = _PostgresKiller.candidates(stub, 300, 20)
    sql, params = stub.sql[0]
    assert ids == [101, 102]
    assert "state = 'idle in transaction'" in sql
    assert "pid <> pg_backend_pid()" in sql, "it must never terminate its own connection"
    assert "make_interval(secs => %s)" in sql and "LIMIT %s" in sql
    assert params == (300, 20), "threshold and ceiling are bound parameters, not interpolated"


def test_postgres_terminates_each_pid_with_a_bound_parameter():
    stub = SqlStub([101, 102])
    assert _PostgresKiller.terminate(stub, [101, 102]) == 2
    assert stub.sql[0] == ("SELECT pg_terminate_backend(%s)", (101,))
    assert len(stub.sql) == 2


# ------------------------------------------------------------------ mysql

def test_mysql_selects_sleeping_transactions_and_never_its_own_connection():
    stub = SqlStub([7])
    _MySQLKiller.candidates(stub, 300, 20)
    sql, params = stub.sql[0]
    assert "innodb_trx" in sql and "p.command = 'Sleep'" in sql
    assert "p.id <> CONNECTION_ID()" in sql, "it must never KILL its own session"
    assert params == (300, 20)


def test_mysql_kill_interpolates_only_an_integer():
    stub = SqlStub([7])
    assert _MySQLKiller.terminate(stub, [7]) == 1
    assert stub.sql[0][0] == "KILL 7"


# ------------------------------------------------------------------ mssql

def test_mssql_excludes_its_own_spid_and_caps_with_top():
    stub = SqlStub([55])
    _MSSQLKiller.candidates(stub, 300, 20)
    sql = stub.sql[0][0]
    assert "session_id <> @@SPID" in sql, "it must never KILL its own session"
    assert "TOP (20)" in sql and "DATEADD(second, -300, GETDATE())" in sql
    assert "open_transaction_count > 0" in sql and "status = 'sleeping'" in sql


def test_mssql_kill_interpolates_only_an_integer():
    stub = SqlStub([55])
    assert _MSSQLKiller.terminate(stub, [55]) == 1
    assert stub.sql[0][0] == "KILL 55"


# ------------------------------------------------------------------ redis

class RedisStub:
    def __init__(self, clients, me=1):
        self._clients = clients
        self._me = me
        self.killed: list[int] = []

    def client_id(self):
        return self._me

    def client_list(self):
        return self._clients

    def client_kill_filter(self, _id=None):
        self.killed.append(int(_id))
        return 1


def test_redis_selects_idle_clients_but_never_its_own():
    conn = RedisStub([{"id": "1", "idle": "900"}, {"id": "2", "idle": "900"},
                      {"id": "3", "idle": "5"}], me=1)
    assert _RedisKiller.candidates(conn, 300, 20) == [2], "id 1 is us, id 3 is not idle enough"


def test_redis_terminate_kills_by_id():
    conn = RedisStub([])
    assert _RedisKiller.terminate(conn, [2, 3]) == 2
    assert conn.killed == [2, 3]


# ------------------------------------------------------------------ mongo

class MongoStub:
    def __init__(self, ops):
        self.admin = self
        self._ops = ops
        self.killed: list[int] = []

    def command(self, name, *args, **kw):
        if name == "killOp":
            self.killed.append(int(kw["op"]))
            return {"ok": 1}
        return {"inprog": self._ops}


def test_mongo_skips_its_own_currentOp_call_and_short_ops():
    conn = MongoStub([
        {"secs_running": 900, "opid": 10, "command": {"currentOp": 1}},  # this very call
        {"secs_running": 900, "opid": 11},
        {"secs_running": 30, "opid": 12},
    ])
    assert _MongoKiller.candidates(conn, 300, 20) == [11]


def test_mongo_terminate_calls_killop():
    conn = MongoStub([])
    assert _MongoKiller.terminate(conn, [11]) == 1
    assert conn.killed == [11]


# ------------------------------------------------------------------ the clamps

def test_the_ceiling_is_enforced_a_second_time_in_python():
    """The SQL already LIMITs. This proves a widened/mutated query still cannot exceed the ceiling."""
    backend = _backend(range(1, MAX_TERMINATE + 15))
    message = backend.apply(ActionKind.terminate_connections, "payments-db", "staging")
    assert f"terminated {MAX_TERMINATE} " in message


def test_a_dry_run_selects_candidates_but_issues_no_terminate():
    stub = SqlStub([201, 202, 203])
    backend = DatabaseRemediationBackend(engine="postgres", conn=stub, dry_run=True)
    message = backend.apply(ActionKind.terminate_connections, "payments-db", "staging")
    assert "would terminate 3" in message and "no change made" in message
    assert not any("pg_terminate_backend" in sql for sql, _ in stub.sql), "dry run must kill nothing"


def test_nothing_stuck_is_reported_plainly_rather_than_as_a_fix():
    message = _backend([]).apply(ActionKind.terminate_connections, "payments-db", "staging")
    assert "nothing terminated" in message


def test_ids_must_be_integers_which_is_what_makes_the_interpolated_kill_safe():
    assert _as_ids([(7,), (8,)]) == [7, 8]
    with pytest.raises(ValueError):
        _as_ids([("7; DROP TABLE users",)])


# ------------------------------------------------------------------ refusal

@pytest.mark.parametrize("action", [
    ActionKind.restart_pods, ActionKind.scale_up, ActionKind.scale_down,
    ActionKind.rollback_deploy, ActionKind.failover_replica, ActionKind.clear_cache,
])
def test_it_refuses_every_action_except_terminate_connections(action):
    with pytest.raises(RemediationError, match="terminate_connections only"):
        _backend([1]).apply(action, "payments-db", "prod")


def test_injecting_a_connection_without_an_engine_is_refused():
    with pytest.raises(RemediationError, match="also needs engine"):
        DatabaseRemediationBackend(conn=object())


def test_with_no_dsn_and_no_engine_it_says_which_credential_is_missing(monkeypatch):
    monkeypatch.delenv("WARDEN_DB_ADMIN_DSN", raising=False)
    with pytest.raises(RemediationError, match="WARDEN_DB_ADMIN_DSN"):
        DatabaseRemediationBackend().apply(ActionKind.terminate_connections, "db", "staging")


# ------------------------------------------------------------------ the router

class K8sStub:
    live = True

    def __init__(self):
        self.calls = []

    def apply(self, action, target, environment):
        self.calls.append(action)
        return f"k8s did {action.value}"


def test_the_router_sends_kubernetes_actions_to_kubernetes():
    k8s = K8sStub()
    router = LiveRemediationRouter(k8s=k8s, database=_backend([1]))
    assert router.apply(ActionKind.scale_up, "svc", "staging") == "k8s did scale_up"
    assert k8s.calls == [ActionKind.scale_up]


def test_the_router_sends_terminate_connections_to_the_database():
    k8s = K8sStub()
    router = LiveRemediationRouter(k8s=k8s, database=_backend([9]))
    out = router.apply(ActionKind.terminate_connections, "payments-db", "staging")
    assert "terminated 1 stuck connection(s)" in out
    assert k8s.calls == [], "a database action must never reach the cluster backend"


def test_the_router_refuses_an_action_no_backend_performs():
    router = LiveRemediationRouter(k8s=K8sStub(), database=_backend([1]))
    with pytest.raises(RemediationError, match="no live remediation backend"):
        router.apply(ActionKind.clear_cache, "x", "staging")


def test_the_router_reports_the_delegates_honesty_not_its_own():
    """A dry-running database delegate must make the whole run read as a dry run."""
    dry = DatabaseRemediationBackend(engine="postgres", conn=SqlStub([7]), dry_run=True)
    router = LiveRemediationRouter(k8s=K8sStub(), database=dry)
    router.apply(ActionKind.terminate_connections, "db", "staging")
    assert router.live is False


# ------------------------------------------------------------------ through the gate

def test_staging_authorised_and_approved_actually_terminates():
    backend = _backend([11, 12])
    result = decide_remediation(_alert(), _prop(), _approved(),
                                RemediationRequest(principal="role:oncall", approved=True),
                                backend=backend)
    assert result.outcome is RemediationOutcome.applied
    assert result.changed_infrastructure is True
    assert "terminated 2 stuck connection(s)" in result.applied_change


def test_prod_never_reaches_the_database_backend():
    stub = SqlStub([1, 2])
    result = decide_remediation(_alert("prod"), _prop(), _approved(),
                                RemediationRequest(principal="role:oncall", approved=True),
                                backend=DatabaseRemediationBackend(engine="postgres", conn=stub,
                                                                   dry_run=False))
    assert result.outcome is RemediationOutcome.not_auto_remediable
    assert stub.sql == [], "production must not even be queried for candidates"


def test_an_unapproved_request_terminates_nothing():
    stub = SqlStub([1, 2])
    result = decide_remediation(_alert(), _prop(), _approved(),
                                RemediationRequest(principal="role:oncall", approved=False),
                                backend=DatabaseRemediationBackend(engine="postgres", conn=stub,
                                                                   dry_run=False))
    assert result.outcome is RemediationOutcome.awaiting_approval
    assert stub.sql == []


def test_a_database_fault_becomes_a_failed_result_not_a_crash():
    backend = DatabaseRemediationBackend(engine="postgres", conn=SqlStub(fail=True), dry_run=False)
    result = decide_remediation(_alert(), _prop(), _approved(),
                                RemediationRequest(principal="role:oncall", approved=True),
                                backend=backend)
    assert result.outcome is RemediationOutcome.failed
    assert result.changed_infrastructure is False
    assert "connection refused" in result.detail
