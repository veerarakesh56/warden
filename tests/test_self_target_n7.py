"""Register N7 / audit A-N-7: WARDEN does not act on its own components (P22-SELF-TARGET)."""

from __future__ import annotations

import pytest

from test_apply_reverifies import _acts
from test_remediation_workflow import REQ
from test_verifier import _alert, _ctx, _prop, _rc
from warden.activities import FixRequest
from warden.environments import default_environment_policies
from warden.models import ActionKind, VerdictStatus
from warden.verifier import verify

RUNTIME = default_environment_policies().runtime_environment


def test_an_alert_about_wardens_own_runtime_goes_to_a_person_whatever_is_proposed():
    assert RUNTIME
    for action in (ActionKind.no_action, ActionKind.restart_pods):
        v = verify(_alert(environment=RUNTIME), _ctx(), _rc(confidence=0.95), _prop(action=action))
        assert "P22-SELF-TARGET" in v.policy_ids and v.status is not VerdictStatus.auto_safe, (action, v)
        assert v.status is not VerdictStatus.approved_for_human
    other = verify(_alert(environment="dev"), _ctx(), _rc(confidence=0.95), _prop(action=ActionKind.no_action))
    assert "P22-SELF-TARGET" not in other.policy_ids


@pytest.mark.parametrize(("env", "live_env", "deployment"), [
    (RUNTIME, RUNTIME, "orders"),                 # a request filed in the runtime environment
    ("dev", RUNTIME, "orders"),                   # a target whose own label says runtime
    ("dev", "dev", f"warden-{RUNTIME}-worker"),   # a target named for the runtime
])
def test_a_remediation_of_wardens_own_components_is_refused(env, live_env, deployment):
    acts, platform, _ = _acts()
    live = platform.live
    platform.live = lambda entry, params: {**live(entry, params), "environment": live_env,
                                           "deployment": {deployment}}
    req = {**REQ, "environment": env, "service": deployment, "params": {**REQ["params"], "deployment": deployment}}
    plan = acts.resolve_plan(FixRequest(**req), "rem-1")
    assert any(p.startswith("P22 SELF-TARGET") for p in plan.problems), plan.problems
