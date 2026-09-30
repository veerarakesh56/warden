"""Verifier cases from the second independent review (2026-09-30, area C): P11 lag names and units,
P14 on real model targets and invisible characters, P15 on WARDEN's own fact spellings, P5 on a target
that names both the service and its deployed function."""

from __future__ import annotations

import pytest

from test_verifier_review import CITE, P5, P15, _ids, _prop
from warden.grounding import target_problem
from warden.models import ActionKind

P11 = "P11-ACTION-CONTRADICTS-EVIDENCE"


@pytest.mark.parametrize("metric, value", [("redis_replication_lag_s", 120.0),
                                           ("replica_lag_seconds__payments_msvc", 47.0)])
def test_every_lag_metric_name_counts_in_seconds_from_its_own_name(metric, value):
    """`redis_replication_lag_s` (aws_stack) was unknown; `_ms` was looked for in the whole key, so a
    resource suffix like `__payments_msvc` read 47 s as 47 ms."""
    assert P11 in _ids(ActionKind.scale_down, "orders cpu idle 3%", metrics={metric: value})
    assert P11 not in _ids(ActionKind.failover_replica, "orders replica unreachable", metrics={metric: value})


@pytest.mark.parametrize("target", ["deployment=checkout (namespace=warden-pg)", "deployment=checkout"])
def test_p14_accepts_a_resource_kind_named_with_equals(target):
    """Real proposals from recorded runs (k8s-02, k8s-04, k8s-05) were rejected by the `=` rule."""
    assert target_problem(_prop(ActionKind.rollback_deploy, target), {"checkout", "warden-pg"}) is None


@pytest.mark.parametrize("target", ["app=checkout", "x=checkout", "checkout --set image=evil", "checkout =all"])
def test_p14_still_refuses_a_selector_or_an_assignment(target):
    assert target_problem(_prop(ActionKind.rollback_deploy, target), {"checkout", "evil", "app", "x"})


@pytest.mark.parametrize("hidden", ["\u00ad", "\u180e", "\u2060", "\u200d"])
def test_p14_sees_a_flag_behind_an_invisible_character(hidden):
    target = f"checkout {hidden}-n kube-system"
    assert target_problem(_prop(ActionKind.restart_pods, target), {"checkout", "kube-system", "n"})


@pytest.mark.parametrize("action, quote", [
    (ActionKind.restart_pods, "code=OOMKilled; object=Pod/orders-1"),
    (ActionKind.restart_pods, "code=OutOfMemoryError"),
    (ActionKind.scale_up, "code=OutOfMemoryError"),
    (ActionKind.restart_pods, "exitCode=137"),
    (ActionKind.scale_up, "CPUUtilization=99.2"),
    (ActionKind.terminate_connections, 'phrase="deadlock detected"'),
])
def test_p15_accepts_wardens_own_fact_spellings(action, quote):
    assert P15 not in _ids(action, quote), (action, quote)


def test_p5_accepts_a_target_naming_the_service_and_its_deployed_function():
    """The deployed function is the service behind a CONFIGURED environment prefix (third review,
    2026-09-30: any name component also let payments-orders count as orders)."""
    deploys = [{"kind": "lambda", "service": "warden-dev-checkout", "at": "2026-09-28T09:59:00Z"}]
    from test_verifier_review import ALERT

    alert = ALERT.model_copy(update={"service": "checkout"})
    from warden.models import Citation, ContextBundle, RootCause
    from warden.verifier import verify

    ctx = ContextBundle(logs=[f"CONFIG {CITE}", "checkout ERROR a", "checkout ERROR b"],
                        metrics={"error_rate": 0.1}, recent_deploys=deploys)
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote=CITE)])
    target = "checkout (lambda warden-dev-checkout, version 7 -> 6)"
    assert P5 not in verify(alert, ctx, rc, _prop(ActionKind.rollback_deploy, target)).policy_ids
    for borrowed in ("checkout (after payments deploy)", "checkout, payments"):
        other = [{"kind": "lambda", "service": "payments", "at": "2026-09-28T09:59:00Z"}]
        ctx2 = ctx.model_copy(update={"recent_deploys": other})
        assert P5 in verify(alert, ctx2, rc, _prop(ActionKind.rollback_deploy, borrowed)).policy_ids
