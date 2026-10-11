"""What WARDEN decided, on one line of its own log (live window, 2026-10-11): the only sign of an incident in the
worker's log was the model's HTTP request, so whether a verdict passed or a fix plan opened could be seen only in the
chat or the database. One line for the verdict's plan, in WARDEN's own words, never more than one line."""

from __future__ import annotations

import logging

from warden import activities
from warden.activities import Diagnosed, IncidentActivities, Verified
from warden.audit import AuditLog
from warden.models import (
    ActionKind,
    Alert,
    CostRecord,
    RemediationProposal,
    RootCause,
    Severity,
    Verdict,
    VerdictStatus,
)

TABLE = "warden-dev-lab-orders"
ALERT = Alert(alert_id="inc-1", name="n", service=TABLE, environment="dev", severity=Severity.high, summary="",
              started_at="2026-10-10T00:00:00+00:00", labels={"dynamodb_table": TABLE, "alarm": "warden-dev-lab-x"})


def _diag(action=ActionKind.revert_change):
    proposal = RemediationProposal(action=action, target=TABLE, reasoning="r", expected_effect="e",
                                   blast_radius="single_service", reversible=True)
    return Diagnosed(root_cause=RootCause(hypothesis="h", confidence=0.9), proposal=proposal, cost=CostRecord())


class _Refuses:
    def live(self, entry, params):
        return {"table": {TABLE}, "alarm": {"warden-dev-lab-x"}, "event": set(), "throughput": set(),
                "refused": "AWS Config has not\nrecorded the change yet"}


class _Plans:
    def live(self, entry, params):
        return {"table": {TABLE}, "alarm": {"warden-dev-lab-x"}, "event": {"e-1"}, "throughput": {"5/10"},
                "environment": "dev", "rollout": "complete"}


def _lines(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "warden.incident"]


def test_the_log_says_whether_a_fix_plan_opened_and_why_not(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="warden.incident")
    passed = Verified(verdict=Verdict(status=VerdictStatus.approved_for_human))
    acts = IncidentActivities(audit=AuditLog(tmp_path / "a.db", key=None), platform=_Plans())
    assert acts.plan_fix(ALERT, _diag(), passed)["entry"] == "dynamodb_restore_capacity"
    assert _lines(caplog)[-1] == "inc-1 fix plan opened: dynamodb_restore_capacity"
    acts = IncidentActivities(audit=AuditLog(tmp_path / "b.db", key=None), platform=_Refuses())
    assert acts.plan_fix(ALERT, _diag(), passed) == {}
    # The platform's own reason, on one line.
    assert _lines(caplog)[-1] == ("inc-1 fix plan not opened: no change WARDEN may undo: AWS Config has not recorded "
                                  "the change yet")
    held = Verified(verdict=Verdict(status=VerdictStatus.escalated, policy_ids=["P9-THIN-EVIDENCE"]))
    acts.plan_fix(ALERT, _diag(), held)
    assert _lines(caplog)[-1] == "inc-1 fix plan not opened: the verdict is escalated"


def test_a_note_is_one_short_line_whatever_it_is_given(caplog):
    caplog.set_level(logging.INFO, logger="warden.incident")
    activities._note("a\n  b\tc " + "x" * 1000)
    line = _lines(caplog)[-1]
    assert line.startswith("a b c x") and "\n" not in line and len(line) == 300


def test_the_log_says_the_verdict_with_its_policies(tmp_path, caplog):
    from warden.activities import EvidencePack
    from warden.models import ContextBundle

    caplog.set_level(logging.INFO, logger="warden.incident")
    acts = IncidentActivities(audit=AuditLog(tmp_path / "a.db", key=None), platform=None)
    pack = EvidencePack(alert=ALERT, context=ContextBundle(), prompt="", masked=0)
    out = acts.verify(pack, _diag(ActionKind.restart_pods))
    line = _lines(caplog)[-1]
    assert line.startswith("inc-1 alarm=warden-dev-lab-x action=restart_pods verdict=" + out.verdict.status.value)
    assert "policies=" + ",".join(out.verdict.policy_ids) in line and "P9-THIN-EVIDENCE" in line
