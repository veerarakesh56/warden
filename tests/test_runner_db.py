"""The Wave 3 harness wiring: the environment WARDEN is given, and the gate before each scenario.

⛔ Half of this file is about ONE fact: the DSN carries the proving-ground database's master
password. It has to reach the tool under test and must reach nothing else - not the manifest, not
the ground truth, not an argv, not a log line. Wave 1 and Wave 2 handed out a temporary role ARN,
which is not a secret; this wave is the first that hands out a credential in plain text, so the
places it could leak get a test each rather than a comment.
"""

from __future__ import annotations

import pathlib
import subprocess

import pytest
from scenarios import ops_db
from scenarios.runner import (
    _db_dry_harness,
    _subprocess_warden_db,
    check_baseline_db,
    db_warden_env,
    describe_target,
    quiet_seconds_for,
)

from warden.redaction import redact

PASSWORD = "hunter2-not-a-real-password"
DSN = f"postgresql://warden:{PASSWORD}@db.internal:5432/warden"


def _target() -> ops_db.Target:
    return ops_db.Target(
        dsn=DSN, database="warden", host="db.internal",
        instance_id="warden-pg-db", security_group_id="sg-0abc",
    )


@pytest.fixture(autouse=True)
def _no_sessions_leak_between_tests():
    ops_db._HELD.clear()
    ops_db._LONG_QUERY.clear()
    yield
    ops_db._HELD.clear()
    ops_db._LONG_QUERY.clear()


# --------------------------------------------------------------------------- the credential


def test_the_password_never_reaches_the_manifest():
    """`describe_target` is written into the published manifest verbatim."""
    described = describe_target(_target())

    assert PASSWORD not in str(described)
    assert "dsn" not in described
    # ...and it still says enough to identify which database was measured.
    assert described["host"] == "db.internal"
    assert described["database"] == "warden"
    assert described["target_kind"] == "db"


def test_the_dsn_is_never_put_on_the_command_line():
    """An argv is readable by every other process on the box, and lands in crash dumps."""
    captured: dict[str, list[str]] = {}

    def fake_run(cmd, **_kw):
        captured["cmd"] = cmd
        raise AssertionError("stop here - the command line is all this test needs")

    invoke = _subprocess_warden_db(_target(), timeout_s=5)
    with pytest.raises(AssertionError):
        real, subprocess.run = subprocess.run, fake_run
        try:
            invoke({"WARDEN_DB_DSN": DSN}, pathlib.Path("report.json"))
        finally:
            subprocess.run = real

    assert PASSWORD not in " ".join(captured["cmd"])
    assert DSN not in " ".join(captured["cmd"])


def test_redaction_masks_a_connection_string_password():
    """⛔ The last line of defence. WARDEN reads the DSN from its environment, and anything it
    echoes back - an error, a tool failure, a log line quoted into the prompt - goes through
    `redact` first. If this regressed, the password would reach the model and the transcript."""
    result = redact(f"could not connect using {DSN}")

    assert PASSWORD not in result.text
    # The shape has to survive, or the model cannot tell what kind of thing failed.
    assert "postgresql://warden:" in result.text
    assert "@db.internal:5432/warden" in result.text


# --------------------------------------------------------------------------- the environment


def test_warden_gets_the_database_and_no_aws_credentials():
    env = db_warden_env({"WARDEN_DB_DSN": DSN}, _target(), {"arn": "postgres:warden@db.internal/warden"})

    assert env["WARDEN_BACKEND"] == "postgres"
    assert env["WARDEN_DB_DSN"] == DSN
    leaked = [k for k in env if k.startswith("AWS_")]
    assert leaked == [], f"the tool under test was handed AWS credentials: {leaked}"


# --------------------------------------------------------------------------- the baseline gate


def _clean_clients():
    return _db_dry_harness().clients


def test_a_clean_database_passes_the_gate():
    """⛔ THE POSITIVE CONTROL. A gate that never passes would stop the wave on scenario one, and
    a gate that never fails is the k8s namespace-guard bug again."""
    assert check_baseline_db(_clean_clients(), _target()) == []


def test_a_session_the_previous_revert_left_open_stops_the_next_scenario():
    """This is the contamination the gate exists for: the next scenario would read a leaked
    session as its own fault, and db-01 would report a pile-up nobody injected."""
    ops_db._HELD.append(object())

    problems = check_baseline_db(_clean_clients(), _target())

    assert any("still holding" in p for p in problems)


def test_an_uncancelled_long_query_is_named_as_such_not_counted_as_a_session():
    """They are released by different code paths - a query is cancelled, a session is closed - so
    saying "0 session(s)" while a query still runs points at the wrong half of the revert."""
    ops_db._LONG_QUERY["conn"] = object()

    problems = check_baseline_db(_clean_clients(), _target())

    assert any("uncancelled long query" in p for p in problems)
    assert not any("0 held session" in p for p in problems)


def test_a_database_that_cannot_be_reached_is_not_treated_as_clean():
    def dead():
        raise RuntimeError("connection refused")

    problems = check_baseline_db(ops_db.Clients(connect=dead, ec2=None), _target())

    assert problems and "cannot reach the database" in problems[0]


def test_a_missing_sentinel_table_is_a_problem_not_a_pass():
    """If the sentinel is gone, this is not the proving ground - or someone has been editing it."""
    harness = _db_dry_harness()

    class NoSentinel(type(harness.clients.connect())):
        def cursor(self):
            cur = super().cursor()
            fetchone = cur.fetchone

            def patched():
                return (None,) if "to_regclass" in self.last else fetchone()

            cur.fetchone = patched
            return cur

    problems = check_baseline_db(ops_db.Clients(connect=NoSentinel, ec2=None), _target())

    assert any("sentinel" in p for p in problems)


# --------------------------------------------------------------------------- the quiet period


def test_the_database_wave_does_not_wait_out_cloudwatchs_window():
    """A database is read by querying it: `pg_stat_activity` is the state right now, and there is
    no window into the past to wait out. Inheriting ECS's 18 minutes would add over an hour and a
    half to the wave and buy nothing."""
    assert quiet_seconds_for("db") < quiet_seconds_for("ecs")
    assert quiet_seconds_for("db") == 4 * 60
