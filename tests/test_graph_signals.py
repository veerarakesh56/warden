"""The Signals layer and the mock reasoning branches.

The eval suite runs the four FIXTURE incidents through the whole graph, but the cluster-shaped
branches - the ones a live Kubernetes backend triggers - had no direct test. `bad_deploy` in
particular was added so a live incident (a recent image change plus a crash loop, no OOM) can reach
the rollback verdict; nothing exercised it. This tests the derivation and every branch, cluster
shape included, at the level where the bug would live.
"""

from __future__ import annotations

from aegis.graph import Signals, _mock_proposal, _mock_root_cause
from aegis.models import ActionKind, Alert, ContextBundle, Severity


def _signals(**metrics) -> Signals:
    """Build Signals straight from a metrics dict, the way gather() would hand it over."""
    state = {
        "context": ContextBundle(
            metrics=metrics,
            recent_deploys=[{"x": "y"}] if metrics.pop("_has_deploy", False) else [],
            logs=["a", "b", "c"],
        ),
        "alert": Alert(alert_id="s", name="n", severity=Severity.high, service="checkout",
                       environment="prod", summary="", started_at="1970-01-01T00:00:00Z"),
    }
    return Signals.of(state)


# --------------------------------------------------------------------------- derivation


def test_cluster_metric_keys_map_to_signals():
    s = _signals(oom_killed_containers=2.0, restart_count=9.0, crashloop_containers=1.0, _has_deploy=True)
    assert s.oom_killed == 2 and s.restarts == 9 and s.crashloop == 1 and s.has_deploy is True


def test_missing_cluster_keys_default_to_zero():
    """A fixture incident carries none of these; they must not blow up or misfire."""
    s = _signals(error_rate=0.04, _has_deploy=True)
    assert s.oom_killed == 0 and s.crashloop == 0 and s.restarts == 0


def test_non_finite_count_metrics_degrade_to_zero_not_crash():
    """A JSON backend can parse `NaN`/`Infinity` into real floats, and metrics bypass pydantic
    (set via setattr in gather). `int(nan)` used to raise and abort the whole run with a traceback.
    A malformed count means 'nothing observed' = 0, and the derived signals must not raise."""
    for bad in ({"oom_killed_containers": float("nan")},
                {"restart_count": float("inf")},
                {"crashloop_containers": float("-inf")}):
        s = _signals(**bad)
        assert s.oom_killed == 0 and s.restarts == 0 and s.crashloop == 0
        # the derived properties must not raise on the coerced values
        assert s.memory_pressure is False
        assert s.bad_deploy is False


# --------------------------------------------------------------------------- memory_pressure


def test_memory_pressure_from_oom_kills_alone():
    assert _signals(oom_killed_containers=1.0).memory_pressure is True


def test_memory_pressure_from_utilisation_alone():
    assert _signals(memory_utilisation=0.9).memory_pressure is True


def test_no_memory_pressure_when_neither():
    assert _signals(restart_count=3.0).memory_pressure is False


# --------------------------------------------------------------------------- bad_deploy


def test_bad_deploy_needs_a_deploy():
    """No recent deploy - a crash loop is not a bad deploy no matter how bad."""
    assert _signals(crashloop_containers=5.0).bad_deploy is False


def test_bad_deploy_from_the_fixture_shape():
    """Error-rate metric + a deploy = the classic bad release."""
    assert _signals(error_rate=0.04, _has_deploy=True).bad_deploy is True


def test_bad_deploy_from_the_cluster_shape():
    """The branch added for live Kubernetes: a recent deploy, containers crash-looping, NO OOM.

    A live cluster never reports error_rate, so without this a real bad deploy could only ever
    escalate.
    """
    assert _signals(crashloop_containers=2.0, _has_deploy=True).bad_deploy is True


def test_an_oom_after_a_deploy_is_NOT_a_bad_deploy():
    """OOM has its own remedy (scale_up). A deploy that OOMs must not be routed to rollback -
    memory pressure wins, and bad_deploy must yield."""
    s = _signals(crashloop_containers=2.0, oom_killed_containers=1.0, _has_deploy=True)
    assert s.bad_deploy is False
    assert s.memory_pressure is True


def test_oom_wins_over_the_error_rate_clause_too_not_just_the_cluster_clause():
    """Regression: the fixture clause (error_rate) had no OOM guard, so a deploy that was OOM-killing
    AND showing a raised error rate (they co-occur — OOM causes 5xx) was mis-routed to rollback. OOM
    must win here as well, so this routes to scale_up, never rollback_deploy."""
    s = _signals(error_rate=0.05, oom_killed_containers=3.0, _has_deploy=True)
    assert s.bad_deploy is False
    assert s.memory_pressure is True
    assert _mock_proposal(s).action is ActionKind.scale_up


# --------------------------------------------------------------------------- routing


def test_cluster_bad_deploy_routes_to_rollback():
    s = _signals(crashloop_containers=2.0, restart_count=6.0, _has_deploy=True)
    assert _mock_root_cause(s).hypothesis.lower().startswith("a recent deploy")
    assert _mock_proposal(s).action is ActionKind.rollback_deploy


def test_cluster_oom_routes_to_scale_up():
    s = _signals(oom_killed_containers=1.0, restart_count=4.0)
    rc = _mock_root_cause(s)
    assert "oom" in rc.hypothesis.lower()
    # The evidence line quotes the real counts, not a utilisation figure it never had.
    assert "OOMKilled" in rc.evidence[0]
    assert _mock_proposal(s).action is ActionKind.scale_up


def test_thin_cluster_evidence_declines():
    """A deploy present but nothing broke - not enough to act on."""
    s = _signals(_has_deploy=True)
    assert _mock_proposal(s).action is ActionKind.escalate_to_human
