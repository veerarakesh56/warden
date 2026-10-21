"""Characterisation of KnowledgeBase.match and expected._entry, written BEFORE their cognitive-complexity refactor
(Sonar python:S3776) and passing on the code as it was: the same matches, scores, signals and their order; the same
declarations read and refused."""

from __future__ import annotations

from datetime import date, datetime
from zoneinfo import ZoneInfo

import pytest

from warden import expected
from warden.knowledge import KnowledgeBase
from warden.models import Alert, ContextBundle, Severity

TODAY = date(2026, 10, 20)


def _sig(sid, detect, reviewed="2026-10-01"):
    return KnowledgeBase._parse_signature(dict(
        id=sid, category="c", maturity="basic", title="t", root_cause="rc", detect=detect, reviewed=reviewed,
        suggested_actions=[{"kind": "restart_pods", "rationale": "r"}], remediation_risk="low"))


def _alert(name="PodOOMKilled", sev=Severity.high, summary=""):
    return Alert(alert_id="k-1", name=name, severity=sev, service="checkout", environment="dev", summary=summary,
                 started_at="2026-10-20T00:00:00+00:00")


KB = KnowledgeBase([
    _sig("A-ALL", {"event_reason": ["OOMKilled"], "log_contains": ["exit 137"], "name_matches": "OOM",
                   "metric_gte": {"restarts": 3, "absent": 1}, "metric_lte": {"free_mb": 10, "gone": 5},
                   "deploy_recent": True}),
    _sig("B-LOG", {"log_contains": ["Timeout", "exit 137"]}),
    _sig("C-SEV", {"severity_in": ["critical"], "log_contains": ["exit 137"]}),
    _sig("D-STALE", {"log_contains": ["exit 137"]}, reviewed="2025-01-01"),
    _sig("E-NONE", {"deploy_recent": False, "metric_gte": {"restarts": 99}}),
    _sig("F-NAME", {"name_matches": "^Pod"}),
    _sig("G-LTE", {"metric_lte": {"free_mb": 10}}),
    _sig("H-NEG", {"log_contains": ["replica lag"]}),
])

CONTEXT = ContextBundle(logs=["container exit 137", "Reason: OOMKilled"],
                        metrics={"restarts": 3.0, "free_mb": 10.0},
                        recent_deploys=[{"revision": "7", "at": "2026-10-20T00:00:00+00:00"}])


def _rows(matches):
    return [(m.signature.id, m.score, m.signals) for m in matches]


def test_match_scores_signals_in_their_fixed_order_and_ranks_by_score_then_id():
    got = KB.match(_alert(summary="no replica lag here"), CONTEXT, limit=10, today=TODAY)
    assert _rows(got) == [
        ("A-ALL", 5, ("log/event:oomkilled", "name", "restarts>=3", "free_mb<=10", "deploy_recent")),
        ("B-LOG", 1, ("log/event:exit 137",)),
        ("F-NAME", 1, ("name",)),
        ("G-LTE", 1, ("free_mb<=10",)),
    ]


def test_match_keeps_the_limit_and_reads_the_summary():
    assert [m.signature.id for m in KB.match(_alert(), CONTEXT, today=TODAY)] == ["A-ALL", "B-LOG", "F-NAME"]
    got = KB.match(_alert(name="x", summary="the replica lag grew"), ContextBundle(), limit=10, today=TODAY)
    assert _rows(got) == [("H-NEG", 1, ("log/event:replica lag",))]


def test_match_a_severity_guard_and_review_age():
    got = KB.match(_alert(sev=Severity.critical), CONTEXT, limit=10, today=TODAY)
    assert ("C-SEV", 1, ("log/event:exit 137",)) in _rows(got)
    assert "D-STALE" not in [m.signature.id for m in got]
    old = KB.match(_alert(), CONTEXT, limit=10, today=date(2025, 6, 1))
    assert "D-STALE" in [m.signature.id for m in old]


def test_match_metric_bounds_are_inclusive_and_a_missing_metric_never_fires():
    ctx = ContextBundle(metrics={"restarts": 2.99, "free_mb": 10.01})
    assert _rows(KB.match(_alert(name="x"), ctx, limit=10, today=TODAY)) == []
    ctx = ContextBundle(metrics={"free_mb": 0.0})
    assert _rows(KB.match(_alert(name="x"), ctx, limit=10, today=TODAY)) == [
        ("A-ALL", 1, ("free_mb<=10",)), ("G-LTE", 1, ("free_mb<=10",))]


def test_match_a_deploy_counts_only_when_required_and_present():
    ctx = ContextBundle(recent_deploys=[{"revision": "7"}])
    assert _rows(KB.match(_alert(name="x"), ctx, limit=10, today=TODAY)) == [("A-ALL", 1, ("deploy_recent",))]


def test_match_the_first_term_that_fires_is_named():
    kb = KnowledgeBase([_sig("T", {"event_reason": ["absent", "BackOff"], "log_contains": ["crash"]})])
    got = kb.match(_alert(name="x"), ContextBundle(logs=["CrashLoop BackOff"]), today=TODAY)
    assert _rows(got) == [("T", 1, ("log/event:backoff",))]


# --------------------------------------------------------------------------- expected._entry

UTC_ = ZoneInfo("UTC")


def test_entry_reads_every_field():
    got = expected._entry({"name": "nightly", "environments": ["dev"], "services": ["a", 2], "zone": "Asia/Kolkata",
                           "hours": "22:00-06:30", "days": ["Mon", "saturday"], "dates": ["2026-12-25"],
                           "from": "2026-10-01T00:00:00", "until": "2026-11-01T08:00:00"})
    zone = ZoneInfo("Asia/Kolkata")
    assert list(got) == ["name", "scope", "zone", "hours", "days", "dates", "from", "until"]
    assert got == {"name": "nightly", "scope": {"environments": {"dev"}, "services": {"a", "2"}}, "zone": zone,
                   "hours": (1320, 390), "days": {0, 5}, "dates": {date(2026, 12, 25)},
                   "from": datetime(2026, 10, 1, tzinfo=zone), "until": datetime(2026, 11, 1, 8, 0, tzinfo=zone)}


def test_entry_defaults():
    assert expected._entry({"resources": ["r1"]}) == {"name": "unnamed", "scope": {"resources": {"r1"}},
                                                     "zone": UTC_}
    assert expected._entry({"services": ["s"], "until": "2026-11-01T00:00:00"})["until"] == datetime(
        2026, 11, 1, tzinfo=UTC_)


@pytest.mark.parametrize("raw", [
    {"environments": ["prod"]},
    {"environments": ["dev", "no-such-env"]},
    {"environments": ["prod"], "from": "2026-10-01T00:00:00"},
])
def test_entry_an_endless_declaration_may_not_cover_production(raw):
    with pytest.raises(ValueError, match="^an endless declaration may not cover a production environment$"):
        expected._entry(raw)


@pytest.mark.parametrize("raw", [
    {"environments": ["dev"]},
    {"environments": ["prod"], "hours": "01:00-02:00"},
    {"environments": ["prod"], "days": ["sun"]},
    {"environments": ["prod"], "dates": ["2026-12-25"]},
    {"environments": ["prod"], "until": "2026-11-01T00:00:00"},
    {"services": ["s"]},
])
def test_entry_a_bounded_or_nonprod_declaration_is_read(raw):
    assert expected._entry(raw)["scope"]


@pytest.mark.parametrize(("raw", "error", "message"), [
    ([], ValueError, "unknown keys"),
    ({"services": ["s"], "colour": "red"}, ValueError, "unknown keys"),
    ({}, ValueError, "names no environment, service or resource"),
    ({"services": []}, ValueError, "names no environment, service or resource"),
    ({"services": "s"}, ValueError, "names no environment, service or resource"),
    ({"services": ["s"], "hours": "05:00-05:00"}, ValueError, "hours"),
    ({"services": ["s"], "hours": "25:00-05:00"}, ValueError, "25:00"),
    ({"services": ["s"], "hours": "05:00"}, ValueError, None),
    ({"services": ["s"], "days": ["funday"]}, ValueError, None),
    ({"services": ["s"], "dates": ["soon"]}, ValueError, None),
    ({"services": ["s"], "zone": "Mars/Base"}, Exception, None),
])
def test_entry_refusals(raw, error, message):
    with pytest.raises(error) as err:
        expected._entry(raw)
    if message is not None:
        assert str(err.value) == message
