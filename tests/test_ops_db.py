"""The database fault injectors, against a stubbed Postgres.

⛔ The one that matters most is the guard pair: `test_a_database_that_is_not_the_proving_ground_is_refused`
and its POSITIVE control. These ops open dozens of sessions, take exclusive locks and revoke a
security group. A Postgres reachable from this laptop could be anyone's, and the k8s guard already
taught this project that a guard which refuses *everything* looks identical to one that works until
something has to be allowed through.
"""

from __future__ import annotations

import pytest
from scenarios.ops import OpError, run_steps
from scenarios.ops_db import _HELD, _LONG_QUERY, OPS, SENTINEL_TABLE, Clients, Target


class FakeCursor:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self._conn.statements.append(sql.strip().split("\n")[0])
        self._conn.last = (sql, params)
        return self

    def fetchone(self):
        sql = self._conn.last[0]
        if "current_database()" in sql:
            return (self._conn.database,)
        if "to_regclass" in sql:
            return (SENTINEL_TABLE if self._conn.sentinel else None,)
        if "max_connections" in sql:
            return (str(self._conn.max_connections),)
        if "pg_stat_activity" in sql:
            return (self._conn.existing_sessions,)
        return (0,)


class FakeConn:
    def __init__(self, factory):
        self._factory = factory
        self.database = factory.database
        self.sentinel = factory.sentinel
        self.max_connections = factory.max_connections
        self.existing_sessions = factory.existing_sessions
        self.statements: list[str] = []
        self.last = ("", None)
        self.closed = False
        self.cancelled = False

    def cursor(self):
        return FakeCursor(self)

    def close(self):
        self.closed = True

    def cancel(self):
        self.cancelled = True


class FakeFactory:
    """Hands out connections and remembers every one, so a test can assert what was closed."""

    def __init__(self, *, database="warden", sentinel=True, max_connections=100,
                 existing_sessions=5, refuse_after=None):
        self.database, self.sentinel = database, sentinel
        self.max_connections, self.existing_sessions = max_connections, existing_sessions
        self.refuse_after = refuse_after
        self.handed: list[FakeConn] = []

    def __call__(self):
        if self.refuse_after is not None and len(self.handed) >= self.refuse_after:
            raise RuntimeError("FATAL: sorry, too many clients already")
        conn = FakeConn(self)
        self.handed.append(conn)
        return conn


class FakeEc2:
    def __init__(self, *, tagged=True, rules=None):
        self.rules = rules if rules is not None else [
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
             "IpRanges": [{"CidrIp": "203.0.113.4/32", "Description": "the operator"}]},
        ]
        self.tagged = tagged
        self.revoked: list[list[dict]] = []
        self.authorized: list[list[dict]] = []

    def describe_security_groups(self, **_kw):
        tags = [{"Key": "Project", "Value": "warden-proving-ground"}] if self.tagged else []
        return {"SecurityGroups": [{"IpPermissions": self.rules, "Tags": tags}]}

    def revoke_security_group_ingress(self, **kw):
        self.revoked.append(kw["IpPermissions"])

    def authorize_security_group_ingress(self, **kw):
        self.authorized.append(kw["IpPermissions"])


@pytest.fixture(autouse=True)
def _no_sessions_leak_between_tests():
    _HELD.clear()
    _LONG_QUERY.clear()
    yield
    _HELD.clear()
    _LONG_QUERY.clear()


def _target(**kw):
    base = dict(dsn="postgresql://warden@db.example:5432/warden", database="warden",
                host="db.example", instance_id="warden-pg", security_group_id="sg-123")
    base.update(kw)
    return Target(**base)


def _clients(factory=None, ec2=None):
    return Clients(connect=factory or FakeFactory(), ec2=ec2)


# --------------------------------------------------------------------------- the guard


@pytest.mark.parametrize("factory,expected", [
    (FakeFactory(database="production"), "only breaks the proving ground"),
    (FakeFactory(sentinel=False), "not the proving ground"),
])
def test_a_database_that_is_not_the_proving_ground_is_refused(factory, expected):
    with pytest.raises(OpError, match=expected):
        OPS["db_open_idle_transactions"](_clients(factory), _target(), count=3)
    assert not _HELD, "it opened sessions anyway"


def test_the_guard_allows_the_proving_ground_itself():
    """⛔ THE POSITIVE CONTROL. A guard that refuses everything is indistinguishable from one that
    works - exactly how the Kubernetes namespace guard shipped broken and its tests still passed."""
    factory = FakeFactory()
    OPS["db_open_idle_transactions"](_clients(factory), _target(), count=2)
    assert len(_HELD) == 2, "the proving ground must be allowed through"


def test_an_unreachable_database_is_refused_not_assumed_safe():
    class Dead(FakeFactory):
        def __call__(self):
            raise RuntimeError("connection refused")

    with pytest.raises(OpError, match="cannot reach the proving-ground database"):
        OPS["db_take_blocking_lock"](_clients(Dead()), _target())


# --------------------------------------------------------------------------- the faults


def test_idle_transactions_are_really_left_open_inside_a_transaction():
    factory = FakeFactory()
    result = OPS["db_open_idle_transactions"](_clients(factory), _target(), count=4)
    assert result["opened_idle_in_transaction"] == 4
    held = factory.handed[1:]  # the first connection is the guard's, and it is closed again
    assert all("BEGIN" in c.statements for c in held), "a session idle OUTSIDE a transaction is not the fault"


def test_saturation_stops_below_the_ceiling_so_warden_can_still_connect():
    """⛔ At 100% WARDEN's own read fails and the scenario measures a tool outage instead of a
    saturated pool - a different fault, with its own scenario."""
    factory = FakeFactory(max_connections=100, existing_sessions=10)
    result = OPS["db_saturate_connections"](_clients(factory), _target(), target_pct=80)
    assert result["opened"] == 70 and result["max_connections"] == 100


def test_a_server_refusing_mid_saturation_is_reported_not_hidden():
    factory = FakeFactory(max_connections=100, existing_sessions=10, refuse_after=20)
    result = OPS["db_saturate_connections"](_clients(factory), _target(), target_pct=80)
    assert "stopped_early" in result and "too many clients" in result["stopped_early"]


def test_only_one_long_query_may_run_at_a_time():
    clients, target = _clients(), _target()
    OPS["db_run_long_query"](clients, target, seconds=1)
    with pytest.raises(OpError, match="already running"):
        OPS["db_run_long_query"](clients, target, seconds=1)


def test_the_blocking_lock_has_a_blocker_and_waiters():
    result = OPS["db_take_blocking_lock"](_clients(), _target(), waiters=3)
    assert result == {"blocker": 1, "waiters": 3}


# --------------------------------------------------------------------------- revert


def test_the_revert_closes_exactly_what_was_opened():
    factory = FakeFactory()
    clients, target = _clients(factory), _target()
    OPS["db_open_idle_transactions"](clients, target, count=5)
    result = OPS["db_release_everything"](clients, target)

    assert result["closed_sessions"] == 5
    assert not _HELD, "the module must not still be holding sessions"


def test_the_revert_cancels_the_long_query_rather_than_waiting_for_it():
    clients, target = _clients(), _target()
    OPS["db_run_long_query"](clients, target, seconds=900)
    conn = _LONG_QUERY["conn"]
    result = OPS["db_release_everything"](clients, target)
    assert conn.cancelled and conn.closed and result["cancelled_long_queries"] == 1


# --------------------------------------------------------------------------- the evidence outage


def test_only_the_proving_grounds_own_security_group_may_be_revoked():
    ec2 = FakeEc2(tagged=False)
    with pytest.raises(OpError, match="not tagged"):
        OPS["db_revoke_ingress"](_clients(ec2=ec2), _target())
    assert ec2.revoked == [], "it revoked anyway"


def test_ingress_is_restored_verbatim_not_reconstructed():
    """Reconstructing 'the usual rule' would leave the environment subtly different from how it
    started, and every later scenario would run against something nobody described."""
    ec2 = FakeEc2()
    clients, target = _clients(ec2=ec2), _target()
    original = [dict(r) for r in ec2.rules]

    OPS["db_revoke_ingress"](clients, target)
    OPS["db_restore_ingress"](clients, target)

    assert ec2.authorized[0] == original
    assert ec2.authorized[0][0]["IpRanges"][0]["Description"] == "the operator"


def test_restoring_ingress_that_was_never_revoked_is_an_error():
    with pytest.raises(OpError, match="refusing to guess"):
        OPS["db_restore_ingress"](_clients(ec2=FakeEc2()), _target())


# --------------------------------------------------------------------------- dispatch


def test_the_catalog_dispatches_through_the_shared_run_steps():
    factory = FakeFactory()
    performed = run_steps(
        _clients(factory), _target(),
        [{"op": "db_open_idle_transactions", "count": 2}], account="", registry=OPS,
    )
    assert performed[0]["op"] == "db_open_idle_transactions"
    assert performed[0]["result"]["opened_idle_in_transaction"] == 2


def test_an_unknown_op_names_the_database_registry():
    with pytest.raises(OpError, match="db_open_idle_transactions"):
        run_steps(_clients(), _target(), [{"op": "ecs_deploy_variant"}], account="", registry=OPS)
