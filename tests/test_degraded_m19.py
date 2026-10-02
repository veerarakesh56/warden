"""Registers M19 / A-P-3 (a tested no-model path) and M18 / A-P-4 (a model cap across incidents)."""

from __future__ import annotations

import asyncio
import contextlib
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import activities, audit, codec
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS, _alert_from
from warden.graph import run
from warden.llm import LLMClient
from warden.models import ActionKind, Alert, VerdictStatus
from warden.providers import ProviderError
from warden.workflows import IncidentWorkflow


class _Down:
    name, model = "fake", "fake"

    def __init__(self):
        self.calls = 0

    def complete(self, *, system, user, schema=None):
        self.calls += 1
        raise ProviderError("the provider is down")


def test_with_no_model_the_incident_is_escalated_by_rules_alone():
    report = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(provider=_Down(), mock=False, call_timeout_s=5))
    assert report.verdict.status is VerdictStatus.escalated and report.verdict.requires_approval
    assert report.verdict.policy_ids[0] == "P0-MODEL-UNAVAILABLE"
    assert report.proposal.action is ActionKind.escalate_to_human and report.root_cause.confidence == 0.0
    assert any(step.get("degraded") for step in report.audit if step.get("node") == "diagnose")


def _incident(provider, seed=None):
    async def main():
        log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
        for alert_id, body in seed or []:
            log.append(alert_id, "incident.llm_spend", body)
        acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(provider=provider, mock=False,
                                                                            max_usd=0.50, call_timeout_s=5))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        alert = _alert_from(next(iter(DEMO_ALERTS)))
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            h = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-degraded", task_queue="q")
            with contextlib.suppress(Exception):
                await h.result()
            status = (await h.describe()).status.name
        return status, log.entries(alert.alert_id, kinds=("incident.verify",))

    return asyncio.run(main())


def test_a_run_without_the_model_is_escalated_audited_and_may_run_again():
    status, verified = _incident(_Down())
    assert status == "FAILED", status  # FAILED: the incident may be diagnosed again once the model is back
    assert [v["body"]["status"] for v in verified] == ["escalated"], verified
    assert "P0-MODEL-UNAVAILABLE" in verified[0]["body"]["policies"]


def test_the_daily_cap_stops_the_model_across_incidents():
    provider = _Down()
    spent = [(f"inc-other-{i}", {"usd": activities.DAILY_MAX_USD / 4, "calls": 1, "input_tokens": 10,
                                 "output_tokens": 10, "attempt": f"a{i}"}) for i in range(4)]
    status, verified = _incident(provider, seed=spent)
    assert provider.calls == 0, "the model was called past the day's cap"
    assert status == "FAILED" and [v["body"]["status"] for v in verified] == ["escalated"], verified
