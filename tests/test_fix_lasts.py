"""Research 2026-10-16, "who will change this field back, and when?": a runtime fix lasts only as long as whatever else
owns the field leaves it - a rollback the next deploy undoes, a value the next infrastructure apply sets back. Every
catalogue entry says how long its fix lasts and what must follow, and the approver reads it before deciding."""

from __future__ import annotations

from datetime import UTC, datetime

from warden import catalog
from warden.activities import Plan, RemediationActivities


def test_every_entry_says_how_long_its_fix_lasts():
    assert set(catalog.LASTS) == set(catalog.CATALOG), sorted(set(catalog.CATALOG) ^ set(catalog.LASTS))
    kinds = {k for k, _ in catalog.LASTS.values()}
    assert kinds <= {"restores", "until_deploy", "until_apply", "until_scaled", "temporary", "one_off"}
    # A rollback holds only until the next deploy unless Git is fixed; a raised limit until the next apply.
    assert catalog.LASTS["lambda_move_alias"][0] == catalog.LASTS["k8s_rollout_undo"][0] == "until_deploy"
    assert catalog.LASTS["lambda_set_reserved_concurrency"][0] == "until_apply"
    assert catalog.LASTS["arc_zonal_shift"][0] == "temporary"


def test_the_approval_request_says_how_long_the_fix_lasts(world, sink):
    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    plan = Plan(workflow_id="rem-dev-0123456789abcdef", incident_id="inc-8", entry="lambda_move_alias", tier="T2",
                params={"function": "warden-dev-checkout", "alias": "live", "to_version": "3"}, plan_hash="p" * 64,
                created_at=datetime.now(UTC), target="dev/lambda:warden-dev-checkout/live", environment="dev")
    acts.announce(plan, "waiting")
    assert ("How long it lasts: it lasts until the next deploy of this code or configuration. Revert or fix the change "
            "in Git first, or the next deploy brings it back.") in sink.texts[-1]
