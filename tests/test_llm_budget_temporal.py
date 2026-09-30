"""The per-incident model budget holds under Temporal (fourth review, 2026-09-30, audit A-C-7).

The diagnose activity built a fresh LLMClient on every attempt and was allowed 2 attempts, so a failing model
was paid for twice: max_usd=0.50 per client, $1.20 spent. The provider here always answers invalid JSON."""

from __future__ import annotations

import asyncio
import contextlib
import os
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import audit, codec
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS, _alert_from
from warden.llm import LLMClient
from warden.providers import Completion
from warden.workflows import IncidentWorkflow


class _NotJson:
    name, model = "fake", "fake"

    def __init__(self):
        self.calls = 0
        self.lock = threading.Lock()

    def complete(self, *, system, user, schema=None):
        with self.lock:
            self.calls += 1
        return Completion("not json at all", 100_000, 10)


def test_a_failing_model_is_paid_for_once_per_incident():
    provider, clients = _NotJson(), []

    def factory():
        client = LLMClient(provider=provider, max_calls=2, max_usd=0.50, mock=False, call_timeout_s=5)
        clients.append(client)
        return client

    async def main():
        log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
        acts = IncidentActivities(audit=log, llm_factory=factory)
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            h = await env.client.start_workflow(IncidentWorkflow.run, _alert_from(next(iter(DEMO_ALERTS))),
                                                id="budget-once", task_queue="q")
            with contextlib.suppress(Exception):  # the model never answers; what matters is what was spent
                await h.result()

    asyncio.run(main())
    assert len(clients) == 1, f"{len(clients)} budgets for one incident"
    # One budget: at most one call past the cap (a response's cost is known only after it arrives, A-C-17).
    assert provider.calls <= 2 and sum(c.cost.usd for c in clients) < 0.50 + 0.31
