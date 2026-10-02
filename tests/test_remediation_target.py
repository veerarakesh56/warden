"""A remediation is bound to the resource it changes, the environment that resource is really in, and the code and
catalogue it was planned under (G2: registers S6, C3, O5; audit A-B-M4)."""

from __future__ import annotations

import pytest
from temporalio.exceptions import ApplicationError

from test_apply_reverifies import _acts, _approve
from test_remediation_workflow import REQ
from warden import activities, bounds, catalog
from warden.activities import FixRequest


@pytest.mark.parametrize("own", ["prod", None, ""])
def test_a_target_whose_own_environment_is_another_is_refused(own):
    """S6: an alert labelled dev, for a resource whose own label says prod - or says nothing - plans nothing."""
    acts, platform, _ = _acts()
    live = platform.live
    platform.live = lambda entry, params: {**live(entry, params), "environment": own}
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert any(p.startswith("P18 ENV-MISMATCH") for p in plan.problems), plan.problems


def test_a_name_carrying_another_environments_prefix_is_refused():
    acts, platform, _ = _acts()
    live = platform.live
    platform.live = lambda entry, params: {**live(entry, params), "deployment": {"warden-prod-orders"}}
    req = {**REQ, "service": "warden-prod-orders", "params": {**REQ["params"], "deployment": "warden-prod-orders"}}
    plan = acts.resolve_plan(FixRequest(**req), "rem-1")
    assert any("named for 'prod'" in p for p in plan.problems), plan.problems


def test_an_environment_wardens_list_does_not_have_is_refused_at_the_request():
    with pytest.raises(ValueError, match="unknown environment"):
        FixRequest(**{**REQ, "environment": "prodd"})


def test_the_environment_moving_after_approval_stops_the_apply():
    acts, platform, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert _approve(acts, owner, plan, "rem-1").enough
    live = platform.live
    platform.live = lambda entry, params: {**live(entry, params), "environment": "prod"}
    assert any(p.startswith("P18") for p in acts.precheck(plan))
    with pytest.raises(ApplicationError):
        acts.apply(plan, REQ["service"])
    assert platform.applied == []


def test_the_bounds_key_on_the_resource_and_environment_not_the_service_name():
    """C3 / A-B-M4: `orders` in namespace shop and `orders` in namespace other are two targets - three changes to one
    do not stop the other, and `service` text cannot move a plan under another target's limits."""
    acts, _, _ = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert plan.target == "dev/k8s:shop/orders"
    other = "dev/k8s:other/orders"
    for _ in range(acts.limits.per_service_per_hour):
        bounds.record_applied(acts.audit, "inc-0", service=other, action_class="k8s_restart")
    assert acts.gate(plan, "orders") == []
    for _ in range(acts.limits.per_service_per_hour):
        bounds.record_applied(acts.audit, "inc-0", service=plan.target, action_class="k8s_restart")
    assert acts.gate(plan, "anything") != []


def test_a_plan_carried_to_another_target_is_refused_at_apply():
    acts, platform, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert _approve(acts, owner, plan, "rem-1").enough
    acts.precheck(plan)
    with pytest.raises(ApplicationError, match="no such plan"):
        acts.apply(plan.model_copy(update={"target": "dev/k8s:quiet/elsewhere"}), REQ["service"])
    assert platform.applied == []


def test_the_target_key_names_every_parameter_that_identifies_the_resource():
    assert catalog.target_key("k8s_scale", {"namespace": "a", "deployment": "x", "replicas": 3}) == "k8s:a/x"
    assert catalog.target_key("k8s_scale", {"namespace": "b", "deployment": "x", "replicas": 3}) == "k8s:b/x"
    assert catalog.target_key("ecs_rollback_service", {"cluster": "c1", "service": "s", "to_task_definition": "t"}) \
        == "ecs:c1/s"
    assert catalog.target_key("lambda_enable_esm", {"mapping": "m-1"}) == "lambda:m-1"


def test_a_plan_made_under_other_code_or_another_catalogue_is_not_applied(monkeypatch):
    """O5: a worker deployed, or the catalogue changed, while a plan waited for approval: the plan is re-made."""
    for swap in ("code_version", "fingerprint"):
        acts, platform, owner = _acts()
        plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
        assert _approve(acts, owner, plan, "rem-1").enough
        with monkeypatch.context() as m:
            if swap == "code_version":
                m.setattr(activities, "code_version", lambda: "0" * 64)
            else:
                m.setattr(catalog, "fingerprint", lambda: "1" * 64)
            assert any("code or catalogue changed" in p for p in acts.precheck(plan))
            with pytest.raises(ApplicationError, match="code or catalogue|precheck"):
                acts.apply(plan, REQ["service"])
        assert platform.applied == []


def test_the_plan_hash_covers_the_environment_the_catalogue_the_code_and_the_record():
    acts, _, _ = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert set(plan.basis) == {"environment", "catalog", "code", "evidence"}
    for key in plan.basis:
        other = {**plan.basis, key: "x"}
        assert activities.plan_hash(plan.entry, plan.params, plan.snapshot, other) != plan.plan_hash, key
    acts.audit.append(REQ["incident_id"], "incident.verify", {"status": "approved_for_human"})
    again = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert again.basis["evidence"] != plan.basis["evidence"] and again.plan_hash != plan.plan_hash
