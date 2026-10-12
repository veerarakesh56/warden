"""How long a plan waits for its approval is the environment's own setting, in hours up to a week (register G10-34).

Owner, 2026-10-12: "people won't see it immediately; sometimes after discussions they will decide - a few days or a
week as the limit is fine". That day a 30-minute plan behind a 15-minute link ran out on a person twice. A plan made
hours ago is still safe to approve: the target is read again before anything is applied."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from test_approval_ladder_h10 import sink  # noqa: F401
from test_approval_page import PLAN, T0, _Clock, _show
from test_approval_page import setup as page_setup  # noqa: F401
from test_plan_fix_g9d import _alert, _proposal
from test_remediation_workflow import REQ, _no_approval, _run, owner, world  # noqa: F401
from warden import approval_page, audit, environments, resolver
from warden.activities import MAX_APPROVAL_TTL_MINUTES, FixRequest, Plan, _deadline
from warden.models import ActionKind


def test_the_wait_is_an_environments_own_setting_within_a_week():
    policies = environments.default_environment_policies()
    assert policies.for_env("dev").approval_wait_hours == environments.APPROVAL_WAIT_HOURS == 72
    assert policies.for_env("an-unknown-one").approval_wait_hours == 72
    assert environments.MAX_APPROVAL_WAIT_HOURS == 168 and MAX_APPROVAL_TTL_MINUTES == 168 * 60
    assert FixRequest(**{**REQ, "approval_ttl_minutes": 168 * 60}).approval_ttl_minutes == 10080
    with pytest.raises(ValidationError):
        FixRequest(**{**REQ, "approval_ttl_minutes": 168 * 60 + 1})
    for bad in (0, 169, "24", True, 1.5):
        with pytest.raises(environments.EnvironmentPolicyError, match="approval_wait_hours"):
            environments._wait_hours("dev", {"approval_wait_hours": bad})
    assert environments._wait_hours("dev", {"approval_wait_hours": 72}) == 72


def test_a_plan_made_from_an_incident_waits_as_long_as_its_environment_says():
    req, why = resolver.request_for(_alert(dynamodb_table="warden-dev-carts"),
                                    _proposal(ActionKind.scale_up, "warden-dev-carts"),
                                    lambda e, p: {"table": {"warden-dev-carts"}, "current_capacity": 50})
    assert why == "" and req["approval_ttl_minutes"] == 72 * 60
    assert FixRequest(**{k: v for k, v in req.items() if k != "workflow_id"}).approval_ttl_minutes == 72 * 60


def test_the_message_says_until_when_and_the_link_lasts_as_long_as_the_plan(world, sink):  # noqa: F811
    out = _run(world, _no_approval, approval_ttl_minutes=600)
    assert out.status == "expired"
    assert "It waits until " in sink.texts[0] and "unapproved by then, it expires and nothing is changed" in sink.texts[0]
    plan = Plan(workflow_id="w", incident_id="i", entry="e", params={}, created_at=T0, approval_ttl_minutes=600)
    assert _deadline(plan) == T0 + timedelta(hours=10)
    assert _deadline(plan.model_copy(update={"approval_ttl_minutes": 0})) == T0 + timedelta(minutes=30)  # an old plan


def test_a_link_hours_old_is_still_found_by_the_lambdas_store_and_ends_with_its_own_time(page_setup, tmp_path):  # noqa: F811
    import dataclasses

    page, device, _, _ = page_setup
    clock, log = _Clock(), audit.AuditLog(tmp_path / "a.db")
    store = approval_page.AuditLinkStore(log, clock=clock)
    page = dataclasses.replace(page, store=store, clock=clock)
    store.add_link("t" * 43, approval_page.Link(PLAN.workflow_id, "owner", T0 + timedelta(hours=30)))
    clock.now = T0 + timedelta(hours=29)
    shown = _show(page, device, "t" * 43)
    assert shown.status == 200 and '"link_seconds": 3600' in shown.body  # an hour left, said to the page
    clock.now = T0 + timedelta(hours=30, seconds=1)
    assert page.handle("GET", "/a/" + "t" * 43).status == 404
    assert approval_page.LINK_LIFE_MAX >= timedelta(hours=environments.MAX_APPROVAL_WAIT_HOURS)
    assert approval_page.LINK_TTL == timedelta(minutes=15)  # an enrolment's or a reset's link stays short
    assert '(h ? h + " h " + m + " min"' in approval_page._PAGE
