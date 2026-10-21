"""One repair round (research 2026-10-15): an answer held only by checks a better-grounded answer can pass is asked
once more, with the checks' own words; safety policies are never fed back."""

from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import audit, codec
from warden.activities import Diagnosed, EvidencePack, IncidentActivities, Verified
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import Alert, Verdict, VerdictStatus
from warden.workflows import REPAIR_NOTE_CHARS, IncidentWorkflow, repair_note

QUEUE = "repair-test"


def _held(*ids, reason="L3 is quoted as 'timeout' but says 'time out'"):
    return Verdict(status=VerdictStatus.escalated, policy_ids=list(ids), reasons=[reason])


def test_only_an_answer_held_by_repairable_checks_alone_is_told_why():
    assert "P13-UNGROUNDED" in repair_note(_held("P13-UNGROUNDED"))
    assert "time out" in repair_note(_held("P13-UNGROUNDED"))
    for final in (_held("P16-INJECTION-SUSPECTED"), _held("P13-UNGROUNDED", "P2-IRREVERSIBLE-IN-PROD"),
                  Verdict(status=VerdictStatus.approved_for_human)):
        assert repair_note(final) == "", final.policy_ids
    long = repair_note(_held("P14-TARGET-NOT-IN-EVIDENCE", reason="~" * 5000))
    assert long.count("~") == REPAIR_NOTE_CHARS


def _run(tmp_path, first: Verdict):
    seen = {"diagnose": 0, "verify": 0, "prompts": []}

    class _Acts(IncidentActivities):
        @activity.defn(name="diagnose")
        def diagnose(self, pack: EvidencePack, escalate_only: str = "") -> Diagnosed:
            seen["diagnose"] += 1
            seen["prompts"].append(pack.prompt)
            return super().diagnose(pack, escalate_only)

        @activity.defn(name="verify")
        def verify(self, pack: EvidencePack, diagnosed: Diagnosed) -> Verified:
            seen["verify"] += 1
            real = super().verify(pack, diagnosed)
            return real.model_copy(update={"verdict": first}) if seen["verify"] == 1 else real

    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = _Acts(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue=QUEUE, workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.investigate, acts.diagnose, acts.verify, acts.second_opinion, acts.notify,
                                           acts.plan_fix],
                               activity_executor=ThreadPoolExecutor(2)):
            handle = await env.client.start_workflow(IncidentWorkflow.run, Alert(**DEMO_ALERTS["inc-002"]),
                                                     id="inc-repair", task_queue=QUEUE)
            await asyncio.wait_for(handle.result(), 120)

    asyncio.run(main())
    return seen


def test_a_misquoted_answer_is_asked_once_more_with_the_checks_words(tmp_path):
    seen = _run(tmp_path, _held("P13-UNGROUNDED"))
    # The repaired answer is approved, so it gets a second opinion too (2026-10-15): one more diagnosis.
    assert (seen["diagnose"], seen["verify"]) == (2 + 1, 2)
    assert "WARDEN'S CHECKS HELD YOUR PREVIOUS ANSWER (P13-UNGROUNDED)" in seen["prompts"][1]
    assert "HELD YOUR PREVIOUS ANSWER" not in seen["prompts"][0]


def test_a_safety_hold_is_never_fed_back(tmp_path):
    seen = _run(tmp_path, _held("P16-INJECTION-SUSPECTED"))
    assert (seen["diagnose"], seen["verify"]) == (1, 1)
