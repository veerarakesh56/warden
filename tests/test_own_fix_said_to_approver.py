"""A new alarm after one of WARDEN's own fixes may be that fix's doing, or not - the approver of the
new incident's plan is told of the earlier fix, and whether this diagnosis cited it as the cause (read from the
diagnosis's citations, never its prose)."""

from __future__ import annotations

from datetime import UTC, datetime

from test_approval_ladder_h10 import sink  # noqa: F401
from test_own_fix_beside_new_alarm import _alert, _fix
from test_remediation_workflow import owner, world  # noqa: F401
from warden import audit
from warden.activities import IncidentActivities, Plan, RemediationActivities
from warden.llm import LLMClient


def _incident(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    _fix(log, "inc-earlier", _alert().environment)
    alert = _alert()
    IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True)).prepare(alert)
    return log, alert


def test_the_link_records_the_evidence_ids_the_model_is_shown(tmp_path):
    log, alert = _incident(tmp_path)
    step = log.entries(alert.alert_id, kinds=("incident.own_fixes",))[-1]["body"]
    assert len(step["items"]) == 1
    assert step["items"][0].startswith("C")
    assert step["fixes"][0]["entry"] == "lambda_enable_esm"


def test_the_approver_hears_of_the_earlier_fix_and_whether_this_diagnosis_cites_it(tmp_path, world):  # noqa: F811
    log, alert = _incident(tmp_path)
    item = log.entries(alert.alert_id, kinds=("incident.own_fixes",))[-1]["body"]["items"][0]
    acts = RemediationActivities(audit=log, policy=world["policy"], platform=world["platform"])
    log.append(alert.alert_id, "incident.diagnose", {"hypothesis": "h", "cited": ["L999"]})
    said = acts._own_fix_said(alert.alert_id)
    assert "WARDEN's own fix was applied in this environment shortly before - `lambda_enable_esm` on " \
           "`warden-dev-order-processor` (incident `inc-earlier`)" in said
    assert "does not cite it: it found another cause" in said
    log.append(alert.alert_id, "incident.diagnose", {"hypothesis": "h", "cited": [item]})
    assert "This diagnosis cites that change as part of the cause." in acts._own_fix_said(alert.alert_id)
    assert acts._own_fix_said("inc-none") == ""


def test_no_earlier_fix_says_nothing(tmp_path, world):  # noqa: F811
    log = audit.AuditLog(tmp_path / "b.db", key=None)
    alert = _alert().model_copy(update={"started_at": datetime.now(UTC).isoformat()})
    IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True)).prepare(alert)
    acts = RemediationActivities(audit=log, policy=world["policy"], platform=world["platform"])
    assert acts._own_fix_said(alert.alert_id) == ""


def test_the_diagnosis_records_what_it_cited_and_the_request_says_it(tmp_path, world, sink):  # noqa: F811
    log, alert = _incident(tmp_path)
    inc = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True))
    pack = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True)).prepare(alert)
    inc.diagnose(pack)
    assert "cited" in log.entries(alert.alert_id, kinds=("incident.diagnose",))[-1]["body"]
    acts = RemediationActivities(audit=log, policy=world["policy"], platform=world["platform"])
    plan = Plan(workflow_id="rem-dev-0123456789abcdef", incident_id=alert.alert_id, entry="k8s_restart", tier="T1",
                params={"namespace": "shop", "deployment": "orders"}, plan_hash="p" * 64,
                created_at=datetime.now(UTC), target="dev/k8s:shop/orders", environment="dev")
    acts.announce(plan, "waiting")
    assert "Before you decide: WARDEN's own fix was applied in this environment shortly before" in sink.texts[-1]
