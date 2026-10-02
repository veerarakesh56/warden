"""Register R9-O3: P15 reads a bad thing in any inflection and only in the measure's own clause; a bare `cluster` label
that WARDEN's own metrics show is a database may be a data action's target."""

from __future__ import annotations

import pytest

from warden.cli import DEMO_ALERTS
from warden.grounding import _supports
from warden.models import ActionKind as A
from warden.models import Alert, Citation, ContextBundle, RemediationProposal, RootCause
from warden.verifier import verify


@pytest.mark.parametrize("quote, key", [
    ("leaked connections: 0 free", "connection"), ("throttling connections: 0 remaining", "connection"),
    ("timed out connections: 0 left", "connection"), ("erroring connections: 0 available", "connection"),
    ("failing probes: 0 left", "probe"), ("evicted memory pods: 0 free", "memory"),
])
def test_none_of_a_bad_thing_in_any_inflection_is_no_shortage(quote, key):
    assert not _supports(quote, key), quote


@pytest.mark.parametrize("quote", ["errors: 12, connections: 0 free", "timeouts (3); connections: 0 available",
                                   "connections: 0 free"])
def test_a_shortage_beside_an_unrelated_bad_thing_is_still_a_shortage(quote):
    assert _supports(quote, "connection"), quote


def _policies(labels, metrics):
    alert = Alert(**{**DEMO_ALERTS["inc-002"], "labels": labels})
    ctx = ContextBundle(logs=["CONFIG deploy revision 7", "x ERROR a", "x ERROR b"],
                        metrics={"error_rate": 0.1, **metrics}, recent_deploys=[{"kind": "ecs", "service": "orders"}])
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote="deploy revision 7")])
    prop = RemediationProposal(action=A.terminate_connections, target="orders-db", reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)
    return verify(alert, ctx, rc, prop).policy_ids


def test_a_bare_cluster_label_wardens_metrics_show_is_a_database_may_be_closed_on():
    assert "P14-TARGET-NOT-IN-EVIDENCE" not in _policies({"cluster": "orders-db"},
                                                         {"rds_connections__orders-db": 950})


@pytest.mark.parametrize("metrics", [{}, {"ecs_cpu__orders-db": 90}, {"connections__orders-db": 950}])
def test_without_a_database_metric_a_bare_cluster_label_stays_a_scope(metrics):
    """Label text alone never makes a name a database: on an ECS alert `cluster` is the ECS cluster (wave 1)."""
    assert "P14-TARGET-NOT-IN-EVIDENCE" in _policies({"cluster": "orders-db"}, metrics)
