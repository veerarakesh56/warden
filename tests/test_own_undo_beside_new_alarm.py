"""Live, 2026-10-16 (fs-01): WARDEN undid its own working fix at 08:04:45Z, which broke checkout again, and the
diagnosis of the alarm that followed listed WARDEN's fix at 07:59 but never its undo - the change that caused it. An
undo of WARDEN's is now a change beside a later alarm's evidence, as its fix is; and an undo cited as the cause is not
counted as its fix failing (the fix held until it was undone)."""

from __future__ import annotations

from datetime import UTC, datetime

from test_own_fix_beside_new_alarm import _alert, _fix
from test_security_review_g10_16 import _diagnosed
from warden import approvals, audit, bounds
from warden.activities import IncidentActivities, Plan, RemediationActivities
from warden.llm import LLMClient

WID = "rem-dev-180000b1cc263177"


def _undo(log, incident, *, undone=True, run="r1"):
    log.append(incident, "remediation.rollback", {"workflow_id": WID, "run_id": run, "plan_hash": "h1",
                                                  "detail": "moved it back", "undone": undone})


def test_warden_undo_is_a_change_beside_the_new_alarm_with_its_own_item(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    _fix(log, "inc-earlier", _alert().environment)
    _undo(log, "inc-earlier")
    alert = _alert()
    inc = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True))
    pack = inc.prepare(alert)
    lines = [ln for ln in pack.prompt.splitlines() if "by WARDEN (its own fix" in ln]
    assert len(lines) == 2, lines
    assert any("warden undo of lambda_enable_esm on warden-dev-order-processor" in ln and "undone 0 min before" in ln
               for ln in lines)
    step = log.entries(alert.alert_id, kinds=("incident.own_fixes",))[-1]["body"]
    fix, undo = sorted(step["fixes"], key=lambda f: bool(f.get("undo")))
    assert fix["item"]
    assert undo["item"]
    assert fix["item"] != undo["item"]
    assert undo["undo"] == "1"
    # Citing the undo as the cause does not count the fix as failed; citing the fix does.
    inc.verify(pack, _diagnosed([undo["item"]]))
    assert not log.entries("inc-earlier", kinds=(bounds.RESULT,))
    inc.verify(pack, _diagnosed([fix["item"]]))
    assert [r["body"].get("connected_by") for r in log.entries("inc-earlier", kinds=(bounds.RESULT,))] == [alert.alert_id]


def test_an_undo_that_changed_nothing_is_not_a_change(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    _fix(log, "inc-earlier", _alert().environment)
    _undo(log, "inc-earlier", undone=False)
    _undo(log, "inc-earlier", run="r-other")  # an undo row of a run that applied nothing here names no fix
    pack = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True)).prepare(_alert())
    assert len([ln for ln in pack.prompt.splitlines() if "by WARDEN (its own fix" in ln]) == 1


def test_the_rollback_records_whether_it_changed_the_target_back(tmp_path):
    for said, undone in (("moved alias live back to version 4", True),
                         ("nothing to roll back: a restart replaced tasks with the same task definition", False)):
        class Platform:
            text = said

            def rollback(self, entry, params, snapshot, who=None, environment=None):
                return self.text

        log = audit.AuditLog(tmp_path / f"{undone}.db", key=None)
        plan = Plan(workflow_id=WID, incident_id="inc-1", entry="lambda_move_alias", tier="T2", params={}, plan_hash="h1",
                    created_at=datetime.now(UTC), target="dev/lambda:f", environment="dev")
        log.append("inc-1", bounds.APPLIED, {"workflow_id": WID, "run_id": "", "plan_hash": "h1"})
        acts = RemediationActivities(audit=log, policy=approvals.ApproverPolicy(approvers={}), platform=Platform())
        acts._who = lambda plan, run: {"approvers": ["owner"]}
        assert acts.rollback(plan) == said
        assert log.entries("inc-1", kinds=("remediation.rollback",))[-1]["body"]["undone"] is undone
