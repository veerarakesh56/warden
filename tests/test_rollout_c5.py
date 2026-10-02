"""Register C5: WARDEN does not act on a target mid-rollout (P21), but a stalled rollout may still be rolled back."""

from __future__ import annotations

import types

import pytest
from temporalio.exceptions import ApplicationError

from test_apply_reverifies import _acts, _approve
from test_platform_k8s import _Apps, _platform
from test_remediation_workflow import REQ
from warden import catalog
from warden.activities import FixRequest


def _live_with(**status):
    apps = _Apps()
    dep = apps._dep

    def patched(name):
        d = dep(name)
        for k, v in status.items():
            setattr(d.status, k, v)
        return d

    apps._dep = patched
    return _platform(apps).live("k8s_scale", {"deployment": "orders"})


def test_the_platform_reads_a_rollout_as_complete_progressing_or_stalled():
    assert _live_with()["rollout"] == "complete"
    assert _live_with(updated_replicas=1)["rollout"] == "progressing"  # old pods still serving
    assert _live_with(observed_generation=6)["rollout"] == "progressing"  # the controller has not seen the spec
    assert _live_with(available_replicas=0)["rollout"] == "progressing"  # new pods not ready yet
    stalled = types.SimpleNamespace(type="Progressing", reason="ProgressDeadlineExceeded")
    assert _live_with(available_replicas=0, conditions=[stalled])["rollout"] == "stalled"


@pytest.mark.parametrize(("rollout", "refused"), [("progressing", True), ("stalled", False), ("complete", False)])
def test_a_change_mid_rollout_is_refused(rollout, refused):
    live = {"namespace": {"shop"}, "deployment": {"orders"}, "current_replicas": 2, "rollout": rollout}
    problems = catalog.validate("k8s_restart", {"namespace": "shop", "deployment": "orders"}, live)
    assert any(p.startswith("P21-ROLLOUT-IN-PROGRESS") for p in problems) is refused, problems


def test_a_rollout_that_starts_after_the_approval_stops_the_apply():
    acts, platform, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert not plan.problems and _approve(acts, owner, plan, "rem-1").enough
    live = platform.live
    platform.live = lambda entry, params: {**live(entry, params), "rollout": "progressing"}
    assert any(p.startswith("P21") for p in acts.precheck(plan))
    with pytest.raises(ApplicationError):
        acts.apply(plan, REQ["service"])
    assert platform.applied == []
