"""The remediation report: redacted output + a promotion plan derived from the env policy."""

from __future__ import annotations

from warden.models import (
    ActionKind,
    Alert,
    RemediationProposal,
    RootCause,
    Severity,
    Verdict,
    VerdictStatus,
)
from warden.reporting import CLOSING, build_report


def _alert(environment="staging", summary="OOM"):
    return Alert(
        alert_id="inc-002", name="PodOOMKilled", severity=Severity.high, service="checkout",
        environment=environment, summary=summary, started_at="2026-08-23T00:00:00Z",
    )


def _prop(action=ActionKind.scale_up):
    return RemediationProposal(
        action=action, target="checkout", reasoning="r", expected_effect="relief",
        blast_radius="single_service", reversible=True,
    )


def test_report_masks_identifiers_everywhere_it_renders_them():
    a = _alert(summary="OOM for user priya.nair@corp.io from 10.2.3.4 tenant_id=acme-42")
    rep = build_report(
        a,
        root_cause=RootCause(hypothesis="leak affecting bob@corp.io", confidence=0.8),
        proposal=_prop(),
        verdict=Verdict(status=VerdictStatus.approved_for_human),
    )
    for secret in ("priya.nair@corp.io", "10.2.3.4", "acme-42", "bob@corp.io"):
        assert secret not in rep.markdown, f"{secret} leaked into report markdown"
    # and into the structured data
    blob = str(rep.data)
    for secret in ("priya.nair@corp.io", "10.2.3.4", "bob@corp.io"):
        assert secret not in blob, f"{secret} leaked into report data"


def test_promotion_lists_higher_environments_that_permit_the_action():
    rep = build_report(_alert(environment="dev"), proposal=_prop(ActionKind.scale_up))
    # scale_up is allowed in prod -> the promotion target from dev; dev itself (the same tier) is not one.
    assert [t.environment for t in rep.promotion] == ["prod"]


def test_promotion_excludes_environments_that_deny_the_action():
    # scale_down is denied in prod.
    rep = build_report(_alert(environment="dev"), proposal=_prop(ActionKind.scale_down))
    assert rep.promotion == ()


def test_prod_has_no_promotion_targets():
    rep = build_report(_alert(environment="prod"), proposal=_prop(ActionKind.scale_up))
    assert rep.promotion == () and rep.data["promotion"] == []


def test_report_always_carries_the_safety_line():
    """A13 (2026-10-16): it said "Nothing was executed against production by this tool" - untrue since WARDEN applies
    approved plans itself."""
    rep = build_report(_alert(), proposal=_prop())
    assert rep.markdown.endswith(CLOSING)
    assert "It changes nothing except by applying a catalogue fix plan an approver approved" in rep.markdown
    assert "Nothing was executed against production" not in rep.markdown


def test_the_masked_identifiers_hint_says_it_is_a_local_option():
    """A9 (2026-10-16): the hint told every reader to set WARDEN_REPORT_SHOW_IDENTIFIERS, which the cloud runtime
    ignores (activities.notify passes show_identifiers=False)."""
    from warden.models import ContextBundle

    ctx = ContextBundle(logs=["2026-09-24T12:30:00Z checkout ERROR failed for user=a.person@corp.io"])
    md = build_report(_alert(), proposal=_prop(), context=ctx, show_identifiers=False).markdown
    assert "_Identifiers are masked; secrets stay masked either way. A local `warden run` can show" in md
    assert "in your own channel" not in md


def test_promotion_names_the_account_to_use_in_each_target_env_in_the_data_only():
    """A10 (2026-10-16): the markdown pointed a person at a manual replay with each environment's deploy role; WARDEN
    watches only where it is installed. The targets stay in the data."""
    rep = build_report(_alert(environment="staging"), proposal=_prop(ActionKind.scale_up))
    # every promotion target carries the credentials pointer for that environment
    for t in rep.data["promotion"]:
        assert t["credentials_ref"], f"{t['environment']} missing credentials_ref"
    assert "warden-prod-deploy" not in rep.markdown and "## Promotion" not in rep.markdown


def test_a_hand_off_says_a_person_should_look_and_promotes_nothing():
    """The runtime's first report on live AWS (2026-10-11) escalated to a person, yet read "No change proposed -
    recorded, nothing to run" and listed three environments in which "a human applies this fix"."""
    safe = Verdict(status=VerdictStatus.auto_safe)
    handed = build_report(_alert(), proposal=_prop(ActionKind.escalate_to_human), verdict=safe).markdown
    assert "**Next step: Handed to a person" in handed and "Someone should look" in handed
    assert "nothing to run" not in handed and "Promotion" not in handed and "applies this fix" not in handed
    quiet = build_report(_alert(), proposal=_prop(ActionKind.no_action), verdict=safe).markdown
    assert "**Next step: No change proposed - recorded, nothing to run.**" in quiet and "Promotion" not in quiet
    # A hand-off the gate did not let stand keeps the gate's own next step.
    held = build_report(_alert(), proposal=_prop(ActionKind.escalate_to_human),
                        verdict=Verdict(status=VerdictStatus.escalated)).markdown
    assert "**Next step: Escalated - a person decides." in held and "Promotion" not in held


def test_a_fix_held_for_approval_offers_no_manual_replay():
    fix = build_report(_alert(), proposal=_prop(ActionKind.scale_up),
                       verdict=Verdict(status=VerdictStatus.approved_for_human)).markdown
    assert "## Promotion" not in fix and "deploy role" not in fix
    assert "**Next step: Held for approval - WARDEN applies its fix plan only if an approver approves it.**" in fix


def test_the_timeline_and_the_key_lines_show_the_change_nearest_the_alert_and_an_undo_is_not_promoted():
    """Live, 2026-10-12 (the owner: "not sure they are correct"): beside a diagnosis citing a change made nine minutes
    before the alarm, the timeline held only "alert fired", the key lines showed changes five hours old, and a
    dev-only rule's undo listed pre-prod and prod as places to apply it."""
    from warden.models import ContextBundle
    from warden.reporting import _key_log_lines, _timeline

    alert = _alert().model_copy(update={"started_at": "2026-10-12T19:02:59+00:00"})
    logs = ["CHANGE 2026-10-12T18:54:01Z events.amazonaws.com DisableRule on warden-dev-lab-tick by role/warden-dev-harness request=name",
            "CHANGE 2026-10-12T18:10:44Z events.amazonaws.com EnableRule on warden-dev-lab-tick by role/warden-dev-actor request=name",
            "CHANGE 2026-10-12T17:09:41Z events.amazonaws.com DisableRule on warden-dev-lab-tick by role/warden-dev-harness request=name",
            "CHANGE 2026-10-12T13:50:45Z events.amazonaws.com EnableRule on warden-dev-lab-tick by role/warden-dev-harness request=name",
            "CHANGE 2026-10-12T13:23:07Z events.amazonaws.com DisableRule on warden-dev-lab-tick by role/warden-dev-harness request=name",
            "RULE warden-dev-lab-tick State=DISABLED schedule=rate(1 minute)"]
    said = [what for _, what in _timeline(alert, ContextBundle(logs=logs))]
    assert said == ["change recorded: `EnableRule on warden-dev-lab-tick by role/warden-dev-actor`",
                    "change recorded: `DisableRule on warden-dev-lab-tick by role/warden-dev-harness`",
                    "alert `PodOOMKilled` fired"]  # the hour before the alert, in order; nothing older
    keys = _key_log_lines(logs)
    assert keys[0].startswith("CHANGE 2026-10-12T18:54:01Z") and not any("T13:" in k for k in keys) and len(keys) == 4
    undo = build_report(alert, proposal=_prop(ActionKind.revert_change))
    assert undo.promotion == () and "## Promotion" not in undo.markdown
    assert build_report(alert, proposal=_prop(ActionKind.scale_up)).promotion  # a change to replay still is


def test_a_follow_ups_heading_is_printed_only_with_a_follow_up_under_it():
    """Live, 2026-10-12: once the one follow-up a report had was left out - it asked for the alarm that had fired -
    the heading stood there with nothing under it."""
    from warden.models import ContextBundle

    logs = ["RULE warden-dev-lab-tick State=DISABLED schedule=rate(1 minute)"]

    def report(**labels):
        alert = _alert().model_copy(update={"labels": {"eventbridge_rule": "warden-dev-lab-tick", **labels}})
        return build_report(alert, proposal=_prop(ActionKind.revert_change), context=ContextBundle(logs=logs)).markdown

    fired_by_that_alarm = report(alarm="warden-dev-lab-tick-silent")
    assert "Scheduled rule disabled" in fired_by_that_alarm and "## Follow-ups by team" not in fired_by_that_alarm
    with_one = report()  # no such alarm yet: the follow-up is worth making, under its heading
    assert "## Follow-ups by team" in with_one and "Alarm on the target's Invocations dropping to zero" in with_one


def test_based_on_is_the_models_reasoning_not_the_ids_the_citations_already_show():
    """Live, 2026-10-12: a report's "Based on" was "C2, C18, M9, C1" - four ids, each shown with its quote two lines
    above, and no word of reasoning."""
    from warden.models import Citation, RootCause

    def said(evidence):
        cause = RootCause(hypothesis="h", confidence=0.9, evidence=evidence,
                          citations=[Citation(id="C2", quote="DisableRule"), Citation(id="M9", quote="rule_enabled=0")])
        return build_report(_alert(), root_cause=cause, proposal=_prop()).markdown

    assert "**Based on:**" not in said(["C2", " M9 "]) and "**Cited evidence**" in said(["C2", "M9"])
    mixed = said(["C2", "C2 shows the most recent change is DisableRule", "L7"])
    assert "**Based on:**\n- C2 shows the most recent change is DisableRule\n- L7" in mixed  # an uncited id stays
