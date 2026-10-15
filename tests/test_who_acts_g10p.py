"""Every report says who has something to do now, and what (register G10-36).

Owner, 2026-10-12: "the info for respective teams to move forward - I see only Platform / DevOps here". The team
follow-ups were printed only when a fixed pattern fired, and a report held by P31 read "a person decides" a minute
before WARDEN itself sent a plan to approve."""

from __future__ import annotations

from test_reporting import _alert, _prop
from warden.models import ActionKind, ContextBundle, Verdict, VerdictStatus
from warden.reporting import build_report


def _report(action=ActionKind.scale_up, status=VerdictStatus.approved_for_human, policies=(), labels=None, **ctx):
    alert = _alert().model_copy(update={"labels": labels or {"eventbridge_rule": "warden-dev-tick", "alarm": "a"}})
    return build_report(alert, proposal=_prop(action), context=ContextBundle(**ctx),
                        verdict=Verdict(status=status, policy_ids=list(policies)))


def test_every_verdict_tells_the_on_call_what_is_theirs_to_do():
    said = {
        "approved": _report().markdown,
        "offered": _report(status=VerdictStatus.escalated, policies=["P31-UNADDRESSED-CHANGE"]).markdown,
        "escalated": _report(status=VerdictStatus.escalated, policies=["P8-MISSING-EVIDENCE"]).markdown,
        "rejected": _report(status=VerdictStatus.rejected, policies=["P2-IRREVERSIBLE-IN-PROD"]).markdown,
        "handed": _report(action=ActionKind.escalate_to_human, status=VerdictStatus.auto_safe).markdown,
        "quiet": _report(action=ActionKind.no_action, status=VerdictStatus.auto_safe).markdown,
    }
    assert all("## Who acts now" in text for text in said.values())
    assert "**On-call**: approve or deny the fix plan with the button in this message" in said["approved"]
    assert "offers the undo of that change as a plan to approve or deny" in said["offered"]
    assert "**On-call**: decide what to do: WARDEN runs nothing here" in said["escalated"]
    assert "**On-call**: decide what to do: WARDEN runs nothing here" in said["rejected"]
    assert "**On-call**: look at this incident" in said["handed"] and "nothing to run" not in said["handed"]
    assert "**On-call**: nothing to run; check that the alarm clears." in said["quiet"]


def test_a_fix_held_only_for_an_unaddressed_change_says_wardens_own_offer_is_coming():
    offered = _report(status=VerdictStatus.escalated, policies=["P31-UNADDRESSED-CHANGE"]).markdown
    assert "**Next step: Held - a recent change was left unaddressed. WARDEN offers the undo of that change" in offered
    both = _report(status=VerdictStatus.escalated, policies=["P31-UNADDRESSED-CHANGE", "P6-BLAST-RADIUS"]).markdown
    assert "**Next step: Escalated - a person decides." in both  # held by more than that: no offer is made


def test_the_team_that_owns_the_resource_is_named_by_its_kind_and_developers_when_code_or_a_deploy_is_in_the_evidence():
    rule = _report().markdown
    # What would stop it happening again, for the kind of fix proposed (owner, 2026-10-15: "what are the counter
    # measures") - a scale-up's here.
    assert ("**Platform / DevOps**: owns warden-dev-tick: confirm the cause, then stop it happening again - size the "
            "service from its measured peak, with an alarm before it runs out of headroom.") in rule
    assert "**Who changed it**" not in rule  # no change in the evidence: nobody is named
    change = ("CHANGE 2026-10-15T11:57:16Z ecs.amazonaws.com UpdateService on warden-dev-tick by "
              "role/warden-dev-deploy request=desiredCount")
    changed = _report(logs=[change]).markdown
    assert ("**Who changed it**: the newest change before the alert was `UpdateService` on `warden-dev-tick` at "
            "2026-10-15T11:57:16Z by `role/warden-dev-deploy`") in changed
    assert "**Developers**" not in rule and "**DBA / data**" not in rule
    table = _report(labels={"dynamodb_table": "warden-dev-orders", "alarm": "a"}).markdown
    assert "**DBA / data**: owns warden-dev-orders" in table
    deployed = _report(labels={"lambda": "warden-dev-checkout"},
                       recent_deploys=[{"service": "warden-dev-checkout", "version": "7"}]).markdown
    assert "**Developers**: the evidence holds a code finding or a recent deploy: review that change." in deployed
    # A label that only qualifies a resource is not a resource to own.
    assert "owns" not in _report(labels={"alarm": "only-the-alarm", "namespace": "shop"}).markdown
    data = _report(labels={"dynamodb_table": "warden-dev-orders"}).data
    assert [team for team, _ in data["who_acts"]] == ["On-call", "DBA / data"]
