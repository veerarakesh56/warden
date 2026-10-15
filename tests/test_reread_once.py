"""Research 2026-10-15, item 3 (owner: "5 to 20 minutes of delay"): a source that answered with nothing right after the
alert may only be early, so the incident reads once more when the alert is old enough for its slowest source - one
re-read at most, on a durable timer, with what it filled and the alert's age on the record."""

from __future__ import annotations

import asyncio
import os
import pathlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import audit, codec
from warden.activities import EvidencePack, IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import REREAD_AT, REREAD_MIN, REREAD_WITHIN, Alert, reread_wait
from warden.workflows import IncidentWorkflow

NOW = datetime(2026, 10, 15, 9, 0, tzinfo=UTC)


def test_the_re_read_waits_for_the_slowest_source_and_never_for_an_old_alert():
    assert reread_wait(NOW.isoformat(), NOW) == REREAD_AT
    assert reread_wait((NOW - timedelta(minutes=2)).isoformat(), NOW) == REREAD_AT - timedelta(minutes=2)
    assert reread_wait((NOW - timedelta(minutes=10)).isoformat(), NOW) == REREAD_MIN  # late, still once more
    assert reread_wait((NOW - REREAD_WITHIN).isoformat(), NOW) is None
    assert reread_wait((NOW + timedelta(hours=1)).isoformat(), NOW) == REREAD_AT  # a clock ahead of ours
    assert reread_wait("", NOW) is None


def _run(tmp_path: pathlib.Path, *, fresh: bool, empty_first: bool) -> tuple[int, list[dict]]:
    """The workflow over a first read that found the logs empty (or not); how often evidence was read, and the
    incident's re-read rows."""
    reads = []

    class _Acts(IncidentActivities):
        @activity.defn(name="prepare")
        def prepare(self, alert: Alert) -> EvidencePack:
            pack = super().prepare(alert)
            reads.append(1)
            if empty_first and len(reads) == 1:
                ctx = pack.context.model_copy(update={"logs": [], "empty_reads": ["logs"]})
                return pack.model_copy(update={"context": ctx})
            return pack

    started = datetime.now(UTC) if fresh else datetime(2026, 9, 1, tzinfo=UTC)
    alert = Alert(**{**DEMO_ALERTS["inc-001"], "started_at": started.isoformat()})

    tmp_path.mkdir(parents=True, exist_ok=True)

    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = _Acts(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.reread, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            h = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-reread", task_queue="q")
            await asyncio.wait_for(h.result(), 120)
        return [e["body"] for e in log.entries(alert.alert_id, kinds=("incident.reread",))]

    rows = asyncio.run(main())
    return len(reads), rows


def test_a_fresh_alert_with_an_empty_source_is_read_once_more_and_the_lag_is_recorded(tmp_path):
    reads, rows = _run(tmp_path, fresh=True, empty_first=True)
    assert reads == 2 and len(rows) == 1
    row = rows[0]
    assert (row["empty_first"], row["filled"], row["still_empty"]) == (["logs"], ["logs"], [])
    assert row["alert_age_s"] >= 0


def test_no_re_read_when_every_source_answered_or_the_alert_is_old(tmp_path):
    assert _run(tmp_path / "full", fresh=True, empty_first=False) == (1, [])
    assert _run(tmp_path / "old", fresh=False, empty_first=True) == (1, [])
