"""The model sometimes makes mistakes, so it is checked twice. Before any fix reaches
a person, the model is asked once more on the same evidence; when the two answers name another action or another
target - or no second answer can be had - the fix is escalated and nothing is offered for approval."""

from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import audit, codec
from warden.activities import SECOND_OPINION, Diagnosed, EvidencePack, IncidentActivities, Verified
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import ActionKind, Alert, Verdict, VerdictStatus
from warden.workflows import IncidentWorkflow

APPROVED = Verdict(status=VerdictStatus.approved_for_human, policy_ids=[], reasons=["ok"])


def _run(tmp_path, second_action=None, second_target=None, second_fails=False):
    seen = {"diagnose": 0, "rows": []}

    class _Acts(IncidentActivities):
        @activity.defn(name="diagnose")
        def diagnose(self, pack: EvidencePack, escalate_only: str = "") -> Diagnosed:
            seen["diagnose"] += 1
            d = super().diagnose(pack, escalate_only)
            if seen["diagnose"] == 2:
                if second_fails:
                    raise RuntimeError("the model is down")
                p = d.proposal.model_copy(update={k: v for k, v in (("action", second_action),
                                                                     ("target", second_target)) if v is not None})
                d = d.model_copy(update={"proposal": p})
            return d

        @activity.defn(name="verify")
        def verify(self, pack: EvidencePack, diagnosed: Diagnosed) -> Verified:
            return super().verify(pack, diagnosed).model_copy(update={"verdict": APPROVED})

    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = _Acts(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.investigate, acts.diagnose, acts.verify,
                                           acts.second_opinion, acts.notify, acts.plan_fix],
                               activity_executor=ThreadPoolExecutor(2)):
            alert = Alert(**DEMO_ALERTS["inc-002"])
            handle = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-second", task_queue="q")
            report = await asyncio.wait_for(handle.result(), 120)
        seen["rows"] = [e["body"] for e in log.entries(alert.alert_id, kinds=("incident.second_opinion",))]
        seen["verdict"] = report.verdict
        return seen

    return asyncio.run(main())


def test_two_answers_that_agree_keep_the_fix_for_a_person(tmp_path):
    seen = _run(tmp_path)
    assert seen["diagnose"] == 2
    assert seen["rows"][0]["agree"] is True
    assert seen["verdict"].status == VerdictStatus.approved_for_human
    assert SECOND_OPINION not in seen["verdict"].policy_ids


def test_another_action_another_target_or_no_second_answer_escalates(tmp_path):
    for n, kw in enumerate(({"second_action": ActionKind.restart_pods}, {"second_target": "another-service"},
                            {"second_fails": True})):
        seen = _run(tmp_path / str(n), **kw) if (tmp_path / str(n)).mkdir() is None else None
        assert seen["verdict"].status == VerdictStatus.escalated, kw
        assert SECOND_OPINION in seen["verdict"].policy_ids
        assert seen["rows"][0]["agree"] is False
        assert any("a person decides, and no fix is offered" in r for r in seen["verdict"].reasons)
