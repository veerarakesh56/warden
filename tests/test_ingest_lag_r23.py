"""Requirement R23: logs arrive minutes late, so evidence is read only once the alert's last minutes have arrived."""

from __future__ import annotations

import asyncio
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import audit, codec, graph
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import LOG_INGEST_LAG, Alert, ingestion_wait
from warden.tools import FixtureBackend
from warden.workflows import IncidentWorkflow

NOW = datetime(2026, 10, 3, 2, 0, tzinfo=UTC)


def test_the_wait_lasts_until_the_alert_is_old_enough_and_never_longer():
    assert ingestion_wait(NOW.isoformat(), NOW) == LOG_INGEST_LAG
    assert ingestion_wait((NOW - timedelta(seconds=30)).isoformat(), NOW) == LOG_INGEST_LAG - timedelta(seconds=30)
    assert ingestion_wait((NOW - timedelta(minutes=10)).isoformat(), NOW) == timedelta(0)
    assert ingestion_wait((NOW + timedelta(hours=2)).isoformat(), NOW) == LOG_INGEST_LAG  # a clock ahead of ours
    assert ingestion_wait("", NOW) == timedelta(0)


def _fresh_alert():
    return Alert(**{**DEMO_ALERTS["inc-001"], "started_at": datetime.now(UTC).isoformat()})


def test_a_live_store_is_read_only_after_the_wait(monkeypatch):
    slept = []
    monkeypatch.setattr("time.sleep", lambda s: slept.append(s))

    class _Live(FixtureBackend):
        reads_live_store = True

    graph.node_gather({"alert": _fresh_alert(), "backend": _Live()})
    assert slept and 0 < slept[0] <= LOG_INGEST_LAG.total_seconds()
    slept.clear()
    graph.node_gather({"alert": _fresh_alert(), "backend": FixtureBackend()})  # a recording has its lines already
    assert slept == []


def _timer_before_first_read(alert: Alert) -> bool:
    async def main():
        log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
        acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            h = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-lag", task_queue="q")
            await h.result()
            kinds = [e.WhichOneof("attributes") async for e in h.fetch_history_events()]
        first_read = kinds.index("activity_task_scheduled_event_attributes")
        return "timer_started_event_attributes" in kinds[:first_read]

    return asyncio.run(main())


def test_the_incident_workflow_waits_durably_for_a_fresh_alert_only():
    assert _timer_before_first_read(_fresh_alert())
    assert not _timer_before_first_read(Alert(**DEMO_ALERTS["inc-001"]))  # weeks old: read at once


def test_every_backend_that_reads_a_live_store_says_so():
    from warden.aws_backend import AwsBackend
    from warden.aws_stack import StackBackend
    from warden.database import DatabaseBackend
    from warden.k8s_backend import KubernetesBackend

    assert all(b.reads_live_store is True for b in (AwsBackend, StackBackend, DatabaseBackend, KubernetesBackend))
    assert not getattr(FixtureBackend, "reads_live_store", False)
