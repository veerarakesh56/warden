"""B37: the investigation card and the notes learned from related records, on an incident's record page.

Both are read from WARDEN's own signed rows only: the card from the incident's rows, the notes from how its related
records (a person's links, WARDEN's found links) ended. Every text is redacted and escaped; nothing comes from the
vault."""

from __future__ import annotations

import pytest

from fakes import AWS_ACCESS_KEY_ID
from warden import audit, cards, records


def _incident(log, incident, env="dev", service="checkout"):
    log.append(incident, "incident.ingest", {"env": env})
    log.append(incident, "incident.alert", {"alert": {"environment": env, "service": service, "name": "HighErrorRate",
                                                      "severity": "high", "summary": "", "labels": {}}})


def _investigated(log, incident, *, failed=0, action="rollback_deploy", target="checkout", status="approved_for_human",
                  policies=()):
    log.append(incident, "incident.gather", {"node": "gather", "backend": "aws", "logs": 12, "metrics": 4,
                                             "deploys": 1, "tool_errors": failed, "references": 0})
    log.append(incident, "incident.investigate", {"node": "investigate", "read": ["rds:orders-db"]})
    log.append(incident, "incident.diagnose", {"node": "diagnose", "hypothesis": "h", "confidence": 0.8,
                                               "action": action, "target": target, "cited": ["D1", "M2"],
                                               "need_evidence": [{"kind": "rds_instance", "name": "orders-db"}]})
    log.append(incident, "incident.verify", {"node": "verify", "status": status, "policies": list(policies)})


def _fix(log, incident, status, entry="k8s_rollout_undo"):
    log.append(incident, "remediation.plan", {"workflow_id": f"rem-{incident}", "entry": entry, "target": "checkout",
                                              "tier": "T1"})
    log.append(incident, "workflow.end", {"workflow_id": f"rem-{incident}", "status": status})


@pytest.fixture
def log(tmp_path):
    return audit.AuditLog(tmp_path / "a.db")


def _card(log, incident):
    return dict(cards.card_rows(records.record(log, incident)))


def test_the_card_says_what_was_read_cited_asked_proposed_and_decided(log):
    _incident(log, "inc-a")
    _investigated(log, "inc-a", policies=("P6-BLAST-RADIUS",))
    card = _card(log, "inc-a")
    assert card["Read"] == "12 log lines, 4 metrics, 1 recent deploy; no read failed"
    assert card["Read more"] == "1 more read of what the alarm names"
    assert card["Cited"] == "2 evidence items: D1, M2"
    assert card["Asked for"] == "1 more resource to read"
    assert card["Proposed"] == "rollback deploy on checkout"
    assert card["Rules"] == "passed its checks - waits for a person (P6-BLAST-RADIUS)"
    assert card["Ended"] == "Diagnosed"


def test_a_failed_read_is_unknown_never_healthy(log):
    _incident(log, "inc-a")
    _investigated(log, "inc-a", failed=2)
    assert _card(log, "inc-a")["Read"].endswith("; 2 reads FAILED - unknown, not healthy")


def test_a_step_missing_from_the_record_is_said_missing_not_guessed(log):
    _incident(log, "inc-a")
    card = _card(log, "inc-a")
    assert card["Read"] == "No evidence read is on the record"
    assert card["Diagnosis"] == "None on the record"
    assert "Proposed" not in card
    assert "Rules" not in card


@pytest.mark.parametrize(("action", "said"), [("no_action", "nothing to change"),
                                              ("escalate_to_human", "hand it to a person")])
def test_an_inert_proposal_is_said_in_words(log, action, said):
    _incident(log, "inc-a")
    _investigated(log, "inc-a", action=action, target="oncall", status="auto_safe")
    card = _card(log, "inc-a")
    assert card["Proposed"] == said
    assert card["Rules"] == "auto safe - no policy fired"


def test_nothing_cited_is_said_plainly(log):
    _incident(log, "inc-a")
    log.append("inc-a", "incident.diagnose", {"node": "diagnose", "action": "restart_pods", "target": "checkout",
                                              "cited": []})
    assert _card(log, "inc-a")["Cited"] == "0 evidence items - nothing the rules could check"


def test_a_citation_is_redacted_before_it_is_shown(log):
    """Review, PR 180: a citation id is the model's text; a secret in one is masked like any other free text."""
    _incident(log, "inc-a")
    log.append("inc-a", "incident.diagnose", {"node": "diagnose", "action": "restart_pods", "target": "checkout",
                                              "cited": ["D1", f"key {AWS_ACCESS_KEY_ID}"]})
    cited = _card(log, "inc-a")["Cited"]
    assert AWS_ACCESS_KEY_ID not in cited
    assert cited.startswith("2 evidence items: D1, ")


def test_a_reopened_incident_shows_only_its_latest_run(log):
    """Review, PR 180: after a reopening, the new diagnosis is never shown beside the earlier run's rule decision."""
    _incident(log, "inc-a")
    _investigated(log, "inc-a", policies=("P6-BLAST-RADIUS",))
    log.append("inc-a", "incident.reopened", {"workflow_id": "rem-inc-a"})
    log.append("inc-a", "incident.gather", {"node": "gather", "backend": "aws", "logs": 3, "metrics": 1, "deploys": 0,
                                            "tool_errors": 0, "references": 0})
    log.append("inc-a", "incident.diagnose", {"node": "diagnose", "action": "scale_up", "target": "checkout",
                                              "cited": ["M1"]})
    card = _card(log, "inc-a")
    assert card["Read"] == "3 log lines, 1 metric, 0 recent deploys; no read failed"
    assert card["Proposed"] == "scale up on checkout"
    assert "Rules" not in card  # the earlier run's decision is not this run's
    assert "Read more" not in card


def test_a_reopening_with_nothing_read_yet_says_so(log):
    _incident(log, "inc-a")
    _investigated(log, "inc-a")
    log.append("inc-a", "incident.reopened", {"workflow_id": "rem-inc-a"})
    card = _card(log, "inc-a")
    assert card["Read"] == "No evidence read is on the record"
    assert card["Diagnosis"] == "None on the record"


def test_a_diagnosis_without_an_action_is_said_to_propose_nothing(log):
    _incident(log, "inc-a")
    log.append("inc-a", "incident.diagnose", {"node": "diagnose", "target": "checkout", "cited": ["D1"]})
    assert _card(log, "inc-a")["Proposed"] == "No proposal"


def test_the_card_redacts_and_escapes_what_it_shows(log):
    _incident(log, "inc-a")
    _investigated(log, "inc-a", target=f"<script>x</script> {AWS_ACCESS_KEY_ID}", policies=("<b>P1</b>",))
    r = records.record(log, "inc-a")
    card = cards.section(r)  # the record's other parts are written redacted; the card redacts again what it shows
    assert AWS_ACCESS_KEY_ID not in card
    assert "<APIKEY_1>" in records.html.unescape(card)
    assert "<script>x</script>" not in card
    assert "&lt;script&gt;" in card
    assert "<b>P1</b>" not in card
    assert card in records.incident_page(r)


def test_notes_say_how_related_records_ended_and_add_them_up(log):
    _incident(log, "inc-old1")
    _fix(log, "inc-old1", "recovered")
    _incident(log, "inc-old2")
    _fix(log, "inc-old2", "rolled_back", entry="restart_service")
    _incident(log, "inc-old3")
    log.append("inc-old3", "incident.after_hold", {"firing": False})
    _incident(log, "inc-now")
    r = records.record(log, "inc-now")
    by = {n["with"]: n for n in r.learned}
    assert set(by) == {"inc-old1", "inc-old2", "inc-old3"}  # found: the same resource, one environment
    assert by["inc-old1"]["status"] == "Fixed and held"
    assert by["inc-old1"]["fix"] == "k8s_rollout_undo"
    assert by["inc-old2"]["kind"] == "bad"
    assert cards.lesson(r.learned) == ("Of 3 related records: 1 fixed (by k8s_rollout_undo); 1 where the fix went wrong "
                                       "or set off other alarms; 1 cleared during a planned shutdown.")
    page = records.incident_page(r)
    assert "<h2>Learned from related records</h2>" in page
    assert "WARDEN acts on none of it" in page
    assert 'href="/r/inc-old1"' in page


def test_notes_stay_in_one_environment_and_are_bounded(log, monkeypatch):
    monkeypatch.setattr(cards, "MOST_NOTES", 2)
    _incident(log, "inc-prod", env="prod")
    _fix(log, "inc-prod", "recovered")
    for i in range(cards.MOST_NOTES + 3):
        _incident(log, f"inc-{i}")
    _incident(log, "inc-now")
    notes = records.record(log, "inc-now").learned
    assert "inc-prod" not in {n["with"] for n in notes}
    assert len(notes) <= cards.MOST_NOTES


def test_a_related_record_of_another_environment_is_never_a_note(log):
    _incident(log, "inc-prod", env="prod")
    _fix(log, "inc-prod", "recovered")
    _incident(log, "inc-now")
    r = records.record(log, "inc-now")
    r.found = [*r.found, {"with": "inc-prod", "side": "same-resource", "words": "is on the same resource as"}]
    assert "inc-prod" not in {n["with"] for n in cards.learned(log, r)}


def test_no_related_record_shows_no_notes(log):
    _incident(log, "inc-a", service="alone")
    r = records.record(log, "inc-a")
    assert r.learned == []
    assert cards.lesson([]) == ""
    assert "Learned from related records" not in records.incident_page(r)


def test_the_list_reads_no_notes(log):
    _incident(log, "inc-a")
    _incident(log, "inc-b")
    assert records.record(log, "inc-b", light=True).learned == []


def test_a_note_is_escaped(log):
    note = {"with": "inc-x", "how": "<i>same</i>", "first": None, "status": "<b>Fixed</b>", "kind": "ok",
            "fix": "<u>f</u>", "action": ""}
    r = records.Record(id="inc-y", first=None, last=None, learned=[note])
    html = cards.section(r)
    assert "<i>" not in html
    assert "<b>Fixed" not in html
    assert "<u>" not in html
    assert "&lt;b&gt;Fixed" in html


def test_an_odd_row_leaves_the_card_saying_so_and_the_page_up(log):
    _incident(log, "inc-a")
    log.append("inc-a", "incident.diagnose", {"node": "diagnose", "action": "restart_pods", "cited": 5})
    page = records.incident_page(records.record(log, "inc-a"))
    assert "The investigation card could not be drawn from this record" in page
    assert "Every step on the record" in page
