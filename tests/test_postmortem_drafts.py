"""Item 16b: a postmortem draft on the records page, built only from the incident's signed record.

Each test builds a record from audit rows as WARDEN writes them, and reads the draft as a person would: marked a
draft, the one root cause WARDEN named (or "not established"), what was done and what verified it, times in UTC with
the display zone, no false alarm for a planned shutdown, next steps per team, and nobody shown by the list's id."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import approvals, audit, postmortem, records

INC = "inc-pm"


@pytest.fixture
def log(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DISPLAY_ZONE", "Asia/Kolkata")
    return audit.AuditLog(tmp_path / "a.db")


@pytest.fixture
def policy():
    pem = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return approvals.ApproverPolicy(approvers={
        "owner": approvals.Approver(name="Asha Rao", team="SRE", public_key=pem, tiers=["T1"]),
        "noname": approvals.Approver(public_key=pem, tiers=["T1"])})


def _incident(log, labels=None, hypothesis="the new build leaks connections", verdict="approved_for_human",
              action="restart_service"):
    log.append(INC, "intake.decision", {"action": "start", "workflow_id": f"inc-{INC}"})
    log.append(INC, "incident.ingest", {"env": "dev"})
    log.append(INC, "incident.alert", {"alert": {"environment": "dev", "service": "warden-dev-checkout",
                                                 "name": "HighErrorRate", "severity": "high", "summary": "",
                                                 "labels": {"alarm": "warden-dev-checkout-5xx", **(labels or {})}}})
    log.append(INC, "incident.diagnose", {"hypothesis": hypothesis, "action": action, "target": "warden-dev-checkout",
                                          "confidence": 0.8})
    log.append(INC, "incident.verify", {"status": verdict, "policies": []})


def _fixed(log, status="recovered", approver="owner", entry="restart_service", checks=(True, True, True)):
    log.append(INC, "remediation.plan", {"workflow_id": "rem-1", "run_id": "r1", "entry": entry,
                                         "target": "warden-dev-checkout", "tier": "T1", "plan_hash": "h"})
    log.append(INC, "approval.accepted", {"approver": approver, "method": "passkey", "note": "go"})
    log.append(INC, "remediation.applied", {"workflow_id": "rem-1"})
    for healthy in checks:
        log.append(INC, "remediation.check", {"workflow_id": "rem-1", "run_id": "r1", "healthy": healthy})
    log.append(INC, "workflow.end", {"workflow_id": "rem-1", "run_id": "r1", "status": status})


def _draft(log, policy):
    return postmortem.draft(records.record(log, INC, policy))


def _section(d, heading):
    return dict(d.sections)[heading]


def test_the_draft_says_it_is_a_draft_first_and_follows_the_record(log, policy):
    _incident(log)
    _fixed(log)
    text = postmortem.markdown(_draft(log, policy))
    assert text.splitlines()[2] == f"_{postmortem.DRAFT}_"


def test_the_sections_are_the_ones_a_postmortem_has(log, policy):
    _incident(log)
    assert [h for h, _ in _draft(log, policy).sections] == [
        "What happened", "Timeline", "Root cause", "What was done", "What verified it", "Next steps, per team"]


def test_every_time_is_in_utc_with_the_display_zone_beside_it(log, policy):
    _incident(log)
    _fixed(log)
    timeline = _section(_draft(log, policy), "Timeline")
    assert all("Z (" in line and "IST)" in line for line in timeline)


def test_the_timeline_keeps_the_steps_a_person_looks_for_in_order(log, policy):
    _incident(log)
    _fixed(log)
    said = [line.split(" - ", 1)[1] for line in _section(_draft(log, policy), "Timeline")]
    assert said == ["The alarm came in", "WARDEN named a likely cause", "WARDEN's rules checked the diagnosis",
                    "A fix plan was made", "The fix was approved by Asha Rao (SRE)", "WARDEN applied the fix",
                    "The fix run ended: the fix worked and held through its re-checks"]


def test_the_root_cause_is_the_one_warden_named_and_says_it_is_not_confirmed(log, policy):
    _incident(log)
    cause = _section(_draft(log, policy), "Root cause")
    assert cause[0] == "WARDEN's diagnosis, not yet confirmed by a person: the new build leaks connections"


@pytest.mark.parametrize(("hypothesis", "verdict"), [("", "escalated"), ("the cache", "rejected")])
def test_a_cause_warden_did_not_establish_is_said_to_be_not_established(log, policy, hypothesis, verdict):
    _incident(log, hypothesis=hypothesis, verdict=verdict)
    assert _section(_draft(log, policy), "Root cause")[0].startswith("Not established")


def test_a_rejected_diagnosis_is_never_shown_as_the_reason(log, policy):
    """CodeRabbit, PR 79: "Not established: the cache." printed the rejected diagnosis where the cause would be."""
    _incident(log, hypothesis="the cache", verdict="rejected")
    assert _section(_draft(log, policy), "Root cause") == [
        "Not established: WARDEN's rules rejected its diagnosis. A person finds the cause."]


def test_a_fix_only_about_to_be_applied_is_not_said_to_be_applied(log, policy):
    """CodeRabbit, PR 79: remediation.intent is written before the platform applies, and stays when it refuses."""
    _incident(log)
    log.append(INC, "remediation.intent", {"workflow_id": "rem-1"})
    said = [line.split(" - ", 1)[1] for line in _section(_draft(log, policy), "Timeline")]
    assert "WARDEN applied the fix" not in said


def test_a_fix_run_still_open_asks_on_call_to_wait_not_to_fix_by_hand(log, policy):
    """CodeRabbit, PR 79: an open run told on-call to fix it by hand, which would make the run drift."""
    _incident(log)
    log.append(INC, "remediation.plan", {"workflow_id": "rem-1", "run_id": "r1", "entry": "restart_service",
                                         "target": "warden-dev-checkout", "tier": "T1"})
    assert _section(_draft(log, policy), "Next steps, per team")[0] == (
        "On-call: the fix run has not ended - wait for its result before changing anything by hand.")


def test_a_nameless_approver_is_never_shown_by_its_id_in_what_was_done(log, policy):
    """CodeRabbit, PR 79: the decision line used the list's id for an approver with no name."""
    _incident(log)
    _fixed(log, approver="noname")
    assert _section(_draft(log, policy), "What was done")[1].startswith("Approved by an approver at ")


def test_a_degraded_diagnosis_says_why_there_is_no_cause(log, policy):
    _incident(log, hypothesis="")
    log.append(INC, "incident.diagnose", {"degraded": "the daily model cap is reached", "action": "escalate_to_human"})
    assert _section(_draft(log, policy), "Root cause")[0] == (
        "Not established: the daily model cap is reached. A person finds the cause.")


def test_what_was_done_names_the_fix_who_approved_it_and_how_it_ended(log, policy):
    _incident(log)
    _fixed(log, status="rolled_back", checks=(False, False, False))
    done = _section(_draft(log, policy), "What was done")
    assert done == ["Fix plan: restart_service on warden-dev-checkout (risk T1).",
                    f"Approved by Asha Rao (SRE) at {done[1].split(' at ', 1)[1].split(' - ')[0]} - their note: go",
                    "Outcome: the fix did not work and was undone."]


def test_a_fix_that_held_says_what_verified_it(log, policy):
    _incident(log)
    _fixed(log)
    assert _section(_draft(log, policy), "What verified it") == [
        "3 health check(s) after the fix, 3 healthy.",
        "WARDEN's own check: healthy readings in a row, then re-checks 15 and 60 minutes later, all healthy."]


def test_a_fix_that_did_not_recover_is_said_to_be_unverified(log, policy):
    _incident(log)
    _fixed(log, status="not_recovered", checks=(False, True, False))
    assert _section(_draft(log, policy), "What verified it")[-1] == (
        "The checks did not show recovery: the fix is not verified.")


def test_nothing_changed_needs_nothing_verified(log, policy):
    _incident(log, verdict="escalated")
    assert _section(_draft(log, policy), "What verified it") == ["Nothing was changed, so nothing needed verifying."]


def test_a_planned_shutdown_is_no_alarm_and_gives_nobody_work(log, policy):
    _incident(log, hypothesis="", verdict="")
    log.append(INC, "incident.after_hold", {"firing": False})
    d = _draft(log, policy)
    assert _section(d, "Next steps, per team") == [
        "Nobody: this was a planned shutdown. Check that the declaration's times were right."]


def test_a_planned_shutdown_has_no_root_cause(log, policy):
    _incident(log, hypothesis="", verdict="")
    log.append(INC, "incident.after_hold", {"firing": False})
    assert _section(_draft(log, policy), "Root cause")[0].startswith("None: the alarm went off during a declared")


def test_a_fix_that_held_asks_on_call_to_watch_and_the_owners_to_prevent_it(log, policy):
    _incident(log)
    _fixed(log)
    teams = _section(_draft(log, policy), "Next steps, per team")
    assert teams[:2] == ["On-call: confirm the alarm stays quiet for the next day.",
                         ("The service's team (Platform / DevOps): confirm the root cause above and stop it happening "
                          "again on warden-dev-checkout.")]


def test_a_problem_warden_did_not_fix_goes_back_to_on_call(log, policy):
    _incident(log)
    _fixed(log, status="denied", checks=())
    assert _section(_draft(log, policy), "Next steps, per team")[0].startswith(
        "On-call: the problem was not fixed by WARDEN")


def test_a_database_resource_is_for_the_data_team(log, policy):
    _incident(log, labels={"rds_instance": "warden-dev-orders"})
    assert any(t.startswith("DBA / data:") for t in _section(_draft(log, policy), "Next steps, per team"))


def test_a_deploy_cause_is_for_the_developers(log, policy):
    _incident(log, action="rollback_deploy")
    assert any(t.startswith("Developers:") for t in _section(_draft(log, policy), "Next steps, per team"))


@pytest.mark.parametrize(("via", "product"), [("guardduty", "GuardDuty"), ("securityhub", "Security Hub")])
def test_a_security_finding_goes_first_to_the_security_team(log, policy, via, product):
    _incident(log, labels={"via": via}, verdict="escalated")
    first = _section(_draft(log, policy), "Next steps, per team")[0]
    assert first.startswith(f"Security team: review the finding in {product}")


def test_an_approver_the_list_gives_no_name_is_never_shown_by_its_id(log, policy):
    _incident(log)
    _fixed(log, approver="noname")
    text = postmortem.markdown(_draft(log, policy))
    assert "noname" not in text.split("## Timeline")[1].split("## Root cause")[0]


def test_the_records_page_shows_the_draft_folded_marked_and_escaped(log, policy):
    _incident(log, hypothesis="<script>alert(1)</script>")
    page = records.incident_page(records.record(log, INC, policy))
    assert '<summary>Postmortem draft <span class="badge warn">Draft</span></summary>' in page


def test_the_drafts_words_are_text_never_markup(log, policy):
    _incident(log, hypothesis="<script>alert(1)</script>")
    page = records.incident_page(records.record(log, INC, policy))
    assert "<script>alert(1)" not in page
