"""Item 16c: the confidence block - Low (red), Medium (amber), High (green) - from signals on the signed record only.

Never the model's own confidence: the tests change it, and the P4 rule that reads it, and the level does not move."""

from __future__ import annotations

import types
from datetime import UTC, datetime

import pytest

from warden import audit, records
from warden import trust as confidence

INC = "inc-cf"


@pytest.fixture
def log(tmp_path):
    return audit.AuditLog(tmp_path / "a.db")


def _incident(log, *, tool_errors=0, read=5, status="approved_for_human", policies=(), model_confidence=0.9,
              agree=None, end=None):
    log.append(INC, "incident.ingest", {"env": "dev"})
    log.append(INC, "incident.gather", {"node": "gather", "logs": read, "metrics": 0, "deploys": 0,
                                        "tool_errors": tool_errors})
    log.append(INC, "incident.diagnose", {"hypothesis": "a leak", "action": "restart_service",
                                          "confidence": model_confidence})
    log.append(INC, "incident.verify", {"status": status, "policies": list(policies)})
    if agree is not None:
        log.append(INC, "incident.second_opinion", {"agree": agree})
    if end:
        log.append(INC, "workflow.end", {"workflow_id": "rem-1", "status": end})
    return records.record(log, INC)


def _proven(**kw):
    """A proven fix as links.proven_fix returns it (PR 56)."""
    return {"incident": "inc-old", "entry": "restart_service", "target": "checkout", "environment": "dev",
            "workflow_id": "rem-old", "verified_at": datetime(2026, 10, 1, tzinfo=UTC), "path": [{}], **kw}


def _signal(b, name):
    return next(s for s in b.signals if s.name == name)


def test_checked_evidence_rules_and_a_second_opinion_that_agreed_are_high_and_green(log):
    b = confidence.block(_incident(log, agree=True))
    assert (b.level, b.colour) == ("High", "ok")


def test_high_names_the_signals_that_decided_it(log):
    b = confidence.block(_incident(log, agree=True))
    assert b.decided_by == ["evidence", "grounded", "rules", "second opinion"]


def test_a_fix_that_held_backs_the_answer(log):
    assert confidence.block(_incident(log, end="recovered")).level == "High"


def test_nothing_failed_but_nothing_backs_the_answer_is_medium_and_amber(log):
    b = confidence.block(_incident(log))
    assert (b.level, b.colour, b.decided_by) == ("Medium", "warn", ["second opinion", "fix verified", "proven fix"])


@pytest.mark.parametrize(("kw", "failed"), [
    ({"tool_errors": 2}, "evidence"), ({"read": 0}, "evidence"),
    ({"status": "escalated", "policies": ["P13-UNGROUNDED"]}, "grounded"),
    ({"status": "rejected", "policies": ["P2-IRREVERSIBLE-IN-PROD"]}, "rules"),
    ({"status": "escalated", "policies": ["P8-PARTIAL-CONTEXT"]}, "rules"),
    ({"agree": False}, "second opinion"), ({"end": "rolled_back"}, "fix verified"), ({"end": "relapsed"}, "fix verified"),
    ({"end": "mitigated"}, "fix verified")])
def test_any_failed_signal_is_low_and_red_and_is_named(log, kw, failed):
    b = confidence.block(_incident(log, agree=kw.pop("agree", True), **kw))
    assert (b.level, b.colour, failed in b.decided_by) == ("Low", "bad", True)


@pytest.mark.parametrize("model_confidence", [0.01, 0.5, 0.99])
def test_the_models_own_confidence_never_moves_the_level(log, model_confidence):
    assert confidence.block(_incident(log, agree=True, model_confidence=model_confidence)).level == "High"


def test_the_rule_that_reads_the_models_confidence_is_not_counted_either(log):
    r = _incident(log, agree=True, status="escalated", policies=["P4-LOW-CONFIDENCE"])
    assert _signal(confidence.block(r), "rules").passed is True


def test_no_diagnosis_leaves_grounding_unchecked_never_passed(log):
    r = _incident(log, status="escalated", policies=["P0-MODEL-UNAVAILABLE"])
    assert _signal(confidence.block(r), "grounded").passed is None


def test_no_diagnosis_is_medium_at_most(log):
    r = _incident(log, status="escalated", policies=["P0-MODEL-UNAVAILABLE"], end=None)
    assert confidence.block(r).level == "Medium"


def test_a_proven_fix_on_a_linked_record_backs_the_answer(log):
    r = _incident(log)
    r.proven = _proven()  # what links.py puts on a record
    assert confidence.block(r).level == "High"


def test_a_record_without_linked_records_does_not_count_a_proven_fix(log):
    r = types.SimpleNamespace(rows=_incident(log).rows)  # no `proven` attribute at all
    assert _signal(confidence.block(r), "proven fix").passed is None


def test_an_empty_record_is_medium_and_says_what_was_not_checked(log):
    b = confidence.block(types.SimpleNamespace(rows=[]))
    assert (b.level, b.decided_by[:3]) == ("Medium", ["evidence", "grounded", "rules"])


def test_the_page_shows_the_level_in_its_colour_and_every_signal(log):
    page = records.incident_page(_incident(log, tool_errors=1, agree=True))
    assert '<span class="badge bad">Confidence: Low</span> Decided by: evidence.' in page


def test_the_page_lists_each_signal_with_what_it_found(log):
    page = records.incident_page(_incident(log, agree=True))
    assert page.count("<li><strong>") >= len(confidence.BASE + confidence.BACKING)


def test_the_page_says_the_models_own_confidence_is_not_used(log):
    page = records.incident_page(_incident(log, agree=True))
    assert "never the model's own confidence" in page


def test_backing_without_the_base_checks_is_medium_never_high(log):
    log.append(INC, "incident.verify", {"status": "approved_for_human", "policies": []})
    log.append(INC, "incident.second_opinion", {"agree": True})  # no evidence read on the record
    assert confidence.block(records.record(log, INC)).level == "Medium"


def test_what_a_signal_quotes_from_the_record_is_text_never_markup(log):
    r = _incident(log)
    r.proven = _proven(entry="<img src=x onerror=alert(1)>")
    assert "<img src=x" not in records.incident_page(r)
