"""Report lines the S19 refactor of reporting._render_markdown and _timeline moved into helpers, which no other test
pinned: the impact a report states when WARDEN could read nothing, what a deploy replaced, the latest error, and each
section helper's own branch."""

from __future__ import annotations

from warden.models import Alert, ContextBundle, Severity
from warden.reporting import build_report


def _alert():
    return Alert(alert_id="inc-s19", name="PodOOMKilled", severity=Severity.high, service="checkout",
                 environment="staging", summary="OOM", started_at="2026-08-23T00:10:00Z")


def test_a_report_with_nothing_read_says_its_impact_is_unknown():
    rep = build_report(_alert(), context=ContextBundle(tool_errors=["cloudwatch: AccessDenied"]),
                       show_identifiers=False)
    assert "- **Impact**: unknown - WARDEN could not read the system (see below)." in rep.markdown


def test_a_deploy_on_the_timeline_says_what_it_replaced_and_who_made_it():
    deploy = {"at": "2026-08-23T00:01:00Z", "service": "checkout", "image": "shop:v2", "previous_image": "shop:v1",
              "by": "ci-pipeline"}
    rep = build_report(_alert(), context=ContextBundle(recent_deploys=[deploy]), show_identifiers=False)
    line = next(ln for ln in rep.markdown.splitlines() if "deploy of" in ln)
    assert "(was `shop:v1`)" in line
    assert line.endswith(" by ci-pipeline")


def test_the_timeline_marks_the_first_and_the_latest_error_line():
    logs = ["2026-08-23T00:05:00Z ERROR checkout: payment failed", "2026-08-23T00:07:00Z ERROR checkout: payment failed",
            "2026-08-23T00:09:00Z ERROR checkout: payment failed"]
    rep = build_report(_alert(), context=ContextBundle(logs=logs), show_identifiers=False)
    assert "first error in the evidence" in rep.markdown
    assert "latest error (3 error lines in total)" in rep.markdown


# Each section helper of reporting._render_markdown, on the smallest input that shows its own branch.

def test_a_follow_up_two_patterns_share_is_listed_once_under_the_first():
    from warden.reporting import _team_follow_ups

    assert _team_follow_ups([("Pool full", "raise the pool"), ("Slow query", "raise the pool")], many=True) == [
        "- raise the pool  _(Pool full)_"]


def test_the_verdict_lists_what_is_observed_but_not_enforced():
    from warden.reporting import _verdict_lines

    lines = _verdict_lines({"status": "escalated", "policy_ids": ["P1"], "reasons": ["why"], "observed": ["P9 seen"]})
    assert "- **Observed only, not enforced** (policies being measured before they decide anything):" in lines
    assert "  - `P9 seen`" in lines


def test_a_diagnosis_that_is_not_grounded_says_so():
    from warden.reporting import _diagnosis_lines

    d = {"root_cause": {"confidence": 0.5, "hypothesis": "a leak", "grounded": False, "citations": [], "evidence": []}}
    assert any(ln.startswith("**⚠ Not grounded**") for ln in _diagnosis_lines(d))


def test_a_code_finding_cannot_close_its_own_code_block():
    from warden.reporting import _code_finding_lines

    d = {"code": [{"function": "fn", "file": "app.py", "line": 3, "in": "handler", "exception": "KeyError",
                   "source": ["x = 1", "``` # planted"]}]}
    lines = _code_finding_lines(d)
    assert lines.count("```") == 1
    assert "``` # planted" not in lines


def test_the_remediation_says_the_change_it_applied():
    from warden.reporting import _remediation_lines

    d = {"remediation": {"outcome": "verified", "detail": "health checks passed", "applied_change": "scaled to 3"}}
    assert "- scaled to 3" in _remediation_lines(d)


def test_matched_signatures_are_listed():
    from warden.reporting import _signature_lines

    d = {"matched_signatures": [{"id": "SIG-1", "title": "Pool", "category": "db", "score": 2, "root_cause": "rc"}]}
    assert _signature_lines(d)[0] == "## Known incident signatures that fit"


def test_a_proposal_has_its_own_section():
    from warden.reporting import _proposal_lines

    p = {"action": "scale_up", "target": "checkout", "expected_effect": "relief", "blast_radius_effective": "x",
         "blast_radius": "y", "reversible_by_table": True, "reversible": True}
    assert _proposal_lines(p)[0] == "## Proposed action"


def test_who_acts_has_its_own_section():
    from warden.reporting import _who_acts_lines

    assert _who_acts_lines({"who_acts": [["On-call", "look"]]}) == ["## Who acts now", "- **On-call**: look.", ""]


def test_the_checks_show_the_crashed_containers_own_output():
    from warden.reporting import _checked_lines

    lines = _checked_lines({"checked": {"status": [], "previous": ["boom"], "rollout": []}})
    assert "**The crashed containers' own last output** (`logs --previous`)" in lines


def test_more_than_five_affected_values_say_how_many_more():
    from warden.reporting import _affected_lines

    d = {"evidence": {"affected": {"tenant": [(f"t{i}", 1) for i in range(7)]}}, "identifiers_shown": True}
    assert _affected_lines(d)[1].endswith(" and 2 more")


def test_an_action_the_gate_says_cannot_work_is_flagged_before_the_follow_ups():
    from warden.reporting import _contradiction_lines

    v = {"reasons": ["it cannot"], "policy_ids": ["P11-ACTION-CONTRADICTS-EVIDENCE"]}
    assert _contradiction_lines(v, {"action": "restart"})[0] == "## ⚠ Before you act"


def test_the_metrics_have_their_own_section():
    from warden.reporting import _evidence_lines

    d = {"evidence": {"metrics": {"cpu": 0.5}, "timeline": [], "affected": {}, "key_log_lines": []}}
    assert _evidence_lines(d)[0] == "## Metrics at the time"


def test_detected_patterns_have_their_own_section():
    from warden.reporting import _pattern_lines

    d = {"patterns": [{"title": "Pool full", "seen": "x", "likely_cause": "y"}]}
    assert _pattern_lines(d)[0] == "## Patterns detected in the evidence  (fixed checks, not the model)"
