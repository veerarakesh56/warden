"""Register S15: the trust zones. Every activity belongs to exactly one zone; a workflow on the main queue sends each
to its zone's queue (read: the readers, llm: the model, notify: paging and chat, act: the actors; the audit's own
steps stay with the workflows), and a zone's worker serves only that zone - so a zone's process needs only that zone's
credentials and its own Temporal service account. A workflow on another queue keeps every activity with it."""

from __future__ import annotations

import asyncio
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment

from test_remediation_workflow import FakePlatform
from warden import audit, codec, runtime, workflows
from warden.cli import _alert_from
from warden.llm import LLMClient
from warden.workflows import IncidentWorkflow

EVERY = {"prepare", "investigate", "diagnose", "verify", "notify", "resolve_plan", "gate", "announce", "check_approval",
         "check_passkey", "precheck", "apply", "check_success", "record_result", "rollback", "finish"}


def test_every_activity_is_in_exactly_one_zone_and_the_actors_and_model_are_alone():
    names = [a.__name__ for a in runtime._activities(None, None, None, None, None)]
    assert set(names) == EVERY and len(names) == len(EVERY)
    zoned = [n for z in workflows.ZONES.values() for n in z]
    assert len(zoned) == len(set(zoned)) and set(zoned) <= EVERY
    assert workflows.ZONES["act"] == ("apply", "rollback")  # the only writes, with the only actor roles
    assert workflows.ZONES["llm"] == ("diagnose",)          # the only model call
    # investigate reads more of what the alert names (G9-B): the read zone, with the reader roles.
    assert set(workflows.ZONES["read"]) == {"prepare", "investigate", "resolve_plan", "precheck", "check_success"}


def test_each_zones_worker_serves_only_that_zone():
    async def main():
        env = await WorkflowEnvironment.start_time_skipping()
        async with env:
            seen = {}
            for zone in ("core", *workflows.ZONES):
                ((queue, acts, flows),) = [(w.config()["task_queue"], {a.__name__ for a in w.config()["activities"]},
                                            bool(w.config().get("workflows"))) for w in
                                           runtime.workers(env.client, zone=zone, log=None, policy=None)]
                seen[zone] = (queue, acts, flows)
            return seen

    seen = asyncio.run(main())
    assert seen["core"] == (workflows.MAIN_QUEUE, EVERY - {n for z in workflows.ZONES.values() for n in z}, True)
    for zone, names in workflows.ZONES.items():
        assert seen[zone] == (f"{workflows.MAIN_QUEUE}-{zone}", set(names), False)


def _scheduled(history):
    return [(e.activity_task_scheduled_event_attributes.activity_type.name,
             e.activity_task_scheduled_event_attributes.task_queue.name)
            for e in history.events if e.HasField("activity_task_scheduled_event_attributes")]


def test_a_workflow_on_the_main_queue_runs_each_activity_in_its_zone(tmp_path):
    log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, runtime.serving(env.client, log=log, policy=None, platform=FakePlatform(),
                                        llm_factory=lambda: LLMClient(mock=True)):
            alert = _alert_from("inc-001")
            h = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-zones",
                                                task_queue=workflows.MAIN_QUEUE)
            await asyncio.wait_for(h.result(), 120)
            on_main = await h.fetch_history()
            other = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-zones-q", task_queue="q")
            async with runtime.worker(env.client, log=log, policy=None, platform=FakePlatform(),
                                      llm_factory=lambda: LLMClient(mock=True), task_queue="q"):
                await asyncio.wait_for(other.result(), 120)
            return on_main, await other.fetch_history()

    on_main, on_q = asyncio.run(main())
    ran = _scheduled(on_main)
    assert {n for n, _ in ran} >= {"prepare", "diagnose", "verify", "notify"}
    for name, queue in ran:
        zone = next((z for z, names in workflows.ZONES.items() if name in names), None)
        assert queue == (f"{workflows.MAIN_QUEUE}-{zone}" if zone else workflows.MAIN_QUEUE), (name, queue)
    assert {q for _, q in _scheduled(on_q)} == {"q"}  # a test's own queue keeps everything with it


def test_a_zones_worker_loads_only_its_zones_secrets_and_its_own_temporal_key():
    from warden import settings

    llm, notify = settings.loadable_for("worker", "llm"), settings.loadable_for("worker", "notify")
    assert "ANTHROPIC_API_KEY" in llm and "WARDEN_SLACK_BOT_TOKEN" not in llm and "WARDEN_DB_ADMIN_DSN" not in llm
    assert "WARDEN_SLACK_BOT_TOKEN" in notify and "ANTHROPIC_API_KEY" not in notify
    assert "WARDEN_DB_ADMIN_DSN" in settings.loadable_for("worker", "act")
    everything = settings.loadable_for("worker")
    assert settings.loadable_for("worker", "all") == everything >= llm | notify
    lam = settings.loadable_for("lambda-approval")
    assert not (lam & settings.SECRETS) - settings.LAMBDA_SECRETS and "WARDEN_SLACK_BOT_TOKEN" not in lam

    asked = []

    class Secrets:
        def get_secret_value(self, SecretId):
            asked.append(SecretId)
            return {"SecretString": "x"}

    class Ssm:
        def get_paginator(self, _):
            return type("P", (), {"paginate": lambda self, **kw: [{"Parameters": []}]})()

    import os

    keep = {k: os.environ.pop(k) for k in list(os.environ) if k in settings.SECRETS}
    try:
        settings.load("dev", only=settings.loadable_for("worker", "read"), ssm=Ssm(), secrets=Secrets(), zone="read")
    finally:
        for k in settings.SECRETS:
            os.environ.pop(k, None)
        os.environ.update(keep)
    assert "warden/dev/temporal-api-key-read" in asked and "warden/dev/temporal-api-key" not in asked
    assert not any(a.endswith(("slack-bot-token", "anthropic-api-key", "db-admin-dsn")) for a in asked)
