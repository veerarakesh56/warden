"""Owner, 2026-10-15: when something breaks again after a fix, WARDEN says so in the channel - the message itself,
not only the record page behind its "Full record" button."""

from __future__ import annotations

from warden import audit, chatops
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import Alert
from warden.resolver import named_resources


def test_the_channels_message_says_a_resource_fixed_before_is_failing_again(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(chatops, "notify", lambda report, sinks=None, threads=None: sent.append(report.markdown) or [])
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True))
    alert = Alert(**DEMO_ALERTS["inc-002"])
    service = min(named_resources(alert))
    log.append("inc-earlier", "remediation.plan", {"workflow_id": "rem-x", "run_id": "r1", "entry": "k8s_restart",
                                                   "target": f"{alert.environment}/{service}", "service": service,
                                                   "environment": alert.environment, "plan_hash": "h1"})
    log.append("inc-earlier", "workflow.end", {"workflow_id": "rem-x", "run_id": "r1", "status": "recovered",
                                               "approvers": ["owner"]})
    pack = acts.prepare(alert)
    diagnosed = acts.diagnose(pack)
    acts.notify(pack, diagnosed, acts.verify(pack, diagnosed), mode="none")
    title, blank, again = sent[-1].split("\n")[:3]
    assert title.startswith("# ") and blank == ""
    assert again.startswith("**Again:** WARDEN fixed this resource before - ") and "`k8s_restart`" in again
    # An incident on a resource never fixed before says nothing of the kind.
    fresh = audit.AuditLog(tmp_path / "b.db", key=None)
    acts2 = IncidentActivities(audit=fresh, llm_factory=lambda: LLMClient(mock=True))
    pack2 = acts2.prepare(alert)
    d2 = acts2.diagnose(pack2)
    acts2.notify(pack2, d2, acts2.verify(pack2, d2), mode="none")
    assert "**Again:**" not in sent[-1]
