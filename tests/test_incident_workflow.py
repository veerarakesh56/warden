"""IncidentWorkflow: the same diagnosis as the graph, and nothing readable in Temporal's history."""

from __future__ import annotations

import asyncio
import base64
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio import activity
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import audit, codec
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS, _alert_from
from warden.graph import run as graph_run
from warden.llm import LLMClient
from warden.models import Alert
from warden.workflows import IncidentWorkflow

QUEUE = "incident-test"
KEY = os.urandom(32)


def _decoded(node) -> str:
    """The history as text with every payload base64-DECODED (the JSON form stores payload bytes as
    base64, so a plain text search would find nothing even when a secret is there)."""
    parts = []

    def walk(x):
        if isinstance(x, dict):
            if isinstance(x.get("data"), str) and "metadata" in x:
                parts.append(base64.b64decode(x["data"]).decode("utf-8", "replace"))
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif isinstance(x, str):
            parts.append(x)
    walk(node)
    return "\n".join(parts)


def _run_workflows(alerts, tmp_path, converter):
    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=converter)
        out = {}
        async with env, Worker(env.client, task_queue=QUEUE, workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            for alert in alerts:
                handle = await env.client.start_workflow(IncidentWorkflow.run, alert, id=f"inc-{alert.alert_id}",
                                                         task_queue=QUEUE)
                report = await handle.result()
                history = await handle.fetch_history()
                out[alert.alert_id] = (report, _decoded(history.to_json_dict()))
        return out, log
    return asyncio.run(main())


def _secrets(by_graph):
    found = {v for old in by_graph.values() for v in old.redaction_map.values() if len(v) >= 6}
    assert found, "the bundled incidents must contain something to redact, or the leak tests prove nothing"
    return found


def _leaked(secrets, text):
    return [s for s in secrets if s in text or json.dumps(s)[1:-1] in text]


@pytest.fixture(scope="module")
def by_graph():
    return {a.alert_id: graph_run(a, llm=LLMClient(mock=True)) for a in (_alert_from(n) for n in DEMO_ALERTS)}


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    alerts = [_alert_from(name) for name in DEMO_ALERTS]
    return _run_workflows(alerts, tmp_path_factory.mktemp("inc"), codec.data_converter(KEY))


def test_every_bundled_incident_gets_the_same_verdict_as_the_graph(results, by_graph):
    by_workflow, _ = results
    assert set(by_workflow) == set(by_graph) and len(by_graph) == len(DEMO_ALERTS)
    for alert_id, (report, _) in by_workflow.items():
        old = by_graph[alert_id]
        assert report.verdict == old.verdict, alert_id
        assert report.root_cause == old.root_cause and report.proposal == old.proposal, alert_id
        assert report.halted_reason == old.halted_reason, alert_id
        assert report.redaction_map_size == old.redaction_map_size, alert_id
        assert report.context == old.context and report.alert == old.alert, alert_id
        assert [s["node"] for s in report.audit] == [s["node"] for s in old.audit], alert_id


def test_without_encryption_the_history_would_hold_the_raw_alert(tmp_path, by_graph):
    """Proves the detector below is not vacuous: the alert IS the workflow input, so a plain
    converter writes its identifiers into history."""
    by_workflow, _ = _run_workflows([_alert_from("inc-001")], tmp_path, pydantic_data_converter)
    assert _leaked(_secrets(by_graph), by_workflow["inc-001"][1])


def test_with_encryption_nothing_redacted_is_readable_in_history(results, by_graph):
    by_workflow, _ = results
    secrets = _secrets(by_graph)
    for alert_id, (report, history) in by_workflow.items():
        assert report.redaction_map == {}
        assert not _leaked(secrets, history), alert_id
        assert report.alert.summary not in history, alert_id


def test_every_step_is_in_the_signed_audit_log(results):
    by_workflow, log = results
    for alert_id, (report, _) in by_workflow.items():
        rows = log.entries(alert_id)
        # Plus one row of what the run spent on the model, written failed or not (seventh review: the budget is
        # carried across an incident's runs).
        assert [r["kind"] for r in rows if r["kind"] != "incident.llm_spend"] ==             [f"incident.{s['node']}" for s in report.audit], alert_id
        assert [r["kind"] for r in rows].count("incident.llm_spend") == 1, alert_id


def test_a_prepare_that_keeps_failing_ends_the_incident_instead_of_retrying_forever(tmp_path):
    """Second review: `prepare` ran with the default retry policy (unlimited), so an input that made
    every attempt fail or time out held the incident forever, visible nowhere."""
    from temporalio.client import WorkflowFailureError

    class _Broken(IncidentActivities):
        attempts = 0

        @activity.defn(name="prepare")
        def prepare(self, alert):
            _Broken.attempts += 1
            raise RuntimeError("cannot prepare")

    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = _Broken(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue=QUEUE, workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            handle = await env.client.start_workflow(IncidentWorkflow.run, Alert(**DEMO_ALERTS["inc-002"]),
                                                     id="inc-broken", task_queue=QUEUE)
            with pytest.raises(WorkflowFailureError):
                await asyncio.wait_for(handle.result(), 120)

    asyncio.run(main())
    assert 1 <= _Broken.attempts <= 3
