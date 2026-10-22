"""B17, owner decision 2026-10-20 (option B): WARDEN plans no Kubernetes rollback. An undo writes the Deployment's pod
template, which the remediator's admission policy refuses on purpose (k8s/remediation-rbac.yaml), and WARDEN's own
workloads are Git-managed. A rollback proposal on a labelled Deployment is advice for a person - "roll back in Git or
Argo CD" - never a plan put to an approver."""

from __future__ import annotations

from test_fix_path_g10b import _alert, _prop
from warden import catalog, resolver
from warden.models import ActionKind, Citation, ContextBundle, RootCause
from warden.verifier import verify

LABELS = {"namespace": "shop", "deployment": "checkout"}


def test_no_catalogue_entry_carries_out_a_kubernetes_rollback():
    assert catalog.for_action(ActionKind.rollback_deploy, "k8s") is None
    assert catalog.for_action(ActionKind.rollback_deploy, "ecs").name == "ecs_rollback_service"  # others unchanged


def test_the_fix_path_says_to_roll_back_in_git():
    why = resolver.no_fix_path(_alert(**LABELS), _prop(ActionKind.rollback_deploy, "checkout"))
    assert why.startswith("no catalogue entry carries out rollback_deploy on checkout")
    assert "roll back in Git, or in Argo CD" in why


def test_the_planner_opens_no_plan_and_says_why():
    request, why = resolver.request_for(_alert(**LABELS), _prop(ActionKind.rollback_deploy, "checkout"),
                                        lambda entry, params: {})
    assert request is None
    assert "roll back in Git" in why


def test_the_gate_escalates_it_with_the_advice():
    context = ContextBundle(logs=[f"LOG k8s/shop/checkout 2026-10-10T00:00:0{i}Z ERROR 500 after deploy v42"
                                  for i in range(5)],
                            metrics={"error_rate": 0.4, "p99_latency_ms": 900.0})
    rc = RootCause(hypothesis="the v42 deploy broke checkout", confidence=0.9, evidence=["500 after deploy"],
                   citations=[Citation(id="L1", quote="ERROR 500 after deploy v42")])
    verdict = verify(_alert(**LABELS), context, rc, _prop(ActionKind.rollback_deploy, "checkout"))
    assert verdict.status.value != "approved_for_human"
    assert "P30-NO-FIX-PATH" in verdict.policy_ids
    assert any("roll back in Git" in r for r in verdict.reasons)


def test_the_entry_asked_for_directly_is_refused_with_the_advice():
    params = {"namespace": "shop", "deployment": "checkout", "to_revision": "7"}
    [why] = catalog.validate("k8s_rollout_undo", params, {})  # no platform reads it: the Kubernetes one never does
    assert why.startswith("k8s_rollout_undo is advice only: roll back in Git")
