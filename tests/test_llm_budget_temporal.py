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


def test_one_alert_is_one_incident_with_one_budget():
    """Fifth review (2026-10-01): an incident id was reusable once its run ended, and each new run got a fresh
    model budget. Every workflow start names its workflow as `<Workflow>.run` (an alias could hide one - sixth
    review), and every IncidentWorkflow start allows a new run only after a FAILED one, never terminating one."""
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "src" / "warden"
    starts = []
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") in ("start_workflow", "execute_workflow"):
                kw = {k.arg: ast.unparse(k.value) for k in node.keywords}
                target = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "workflow"),
                                                             None)
                assert isinstance(target, ast.Attribute) and target.attr == "run", (path.name, ast.unparse(node))
                starts.append((path.name, ast.unparse(target), kw))
    incident = [(f, kw) for f, target, kw in starts if target == "IncidentWorkflow.run"]
    assert len(incident) >= 2, starts
    for f, kw in incident:
        assert kw.get("id_reuse_policy", "").endswith("ALLOW_DUPLICATE_FAILED_ONLY"), (f, kw)
        assert "TERMINATE" not in kw.get("id_conflict_policy", ""), (f, kw)


def test_a_failed_incident_may_run_again_but_a_completed_one_may_not():
    """Sixth review (2026-10-01): with REJECT_DUPLICATE, a run that failed (the model down) made the incident
    undiagnosable while its history was retained. Run on Temporal's time-skipping server."""
    from temporalio.common import WorkflowIDReusePolicy
    from temporalio.exceptions import WorkflowAlreadyStartedError

    down = {"now": True}

    class Flaky:
        name, model = "fake", "fake"

        def complete(self, *, system, user, schema=None):
            if down["now"]:
                raise ConnectionError("the provider is down")
            return Completion("not json at all", 10, 10)

    # The ceiling is the incident's, across runs (seventh review) - but the outage run's failed requests reached no
    # model and do not carry (eighth review), so a ceiling of one call still lets the run after it make its call.
    def factory():
        return LLMClient(provider=Flaky(), max_calls=1, max_usd=0.50, mock=not down["now"], call_timeout_s=5)

    async def main():
        log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
        acts = IncidentActivities(audit=log, llm_factory=factory)
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        alert = _alert_from(next(iter(DEMO_ALERTS)))
        policy = WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            first = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-again", task_queue="q",
                                                    id_reuse_policy=policy)
            with contextlib.suppress(Exception):
                await first.result()
            failed = (await first.describe()).status.name
            down["now"] = False  # the provider is back
            second = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-again", task_queue="q",
                                                     id_reuse_policy=policy)
            with contextlib.suppress(Exception):
                await second.result()
            ended = (await second.describe()).status.name
            refused = False
            try:
                await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-again", task_queue="q",
                                                id_reuse_policy=policy)
            except WorkflowAlreadyStartedError:
                refused = True
            return failed, ended, refused

    failed, ended, refused = asyncio.run(main())
    assert failed == "FAILED", failed
    assert ended == "COMPLETED", ended  # a second run after a failure: allowed
    assert refused, "a completed incident was started again - a fresh budget for the same alert"


def test_an_incident_restarted_after_failing_keeps_one_budget():
    """Seventh review (2026-10-01, MED): a failed incident may run again, and each run got a fresh budget - the
    model answering invalid JSON was paid for 10 times over 5 restarts, $3.00 against a $0.50 cap. The spend is
    carried across runs in the audit, so the restarts are admitted but the model is not paid again."""
    from temporalio.common import WorkflowIDReusePolicy

    provider, clients = _NotJson(), []

    def factory():
        client = LLMClient(provider=provider, max_calls=2, max_usd=0.50, mock=False, call_timeout_s=5)
        clients.append(client)
        return client

    async def main():
        log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
        acts = IncidentActivities(audit=log, llm_factory=factory)
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        alert = _alert_from(next(iter(DEMO_ALERTS)))
        ended = []
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            for _ in range(5):
                h = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-restarted", task_queue="q",
                                                    id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY)
                with contextlib.suppress(Exception):
                    await h.result()
                ended.append((await h.describe()).status.name)
        rows = log.entries(alert.alert_id, kinds=("incident.llm_spend",))
        return ended, rows

    ended, rows = asyncio.run(main())
    assert ended == ["FAILED"] * 5, ended  # every restart was admitted ...
    assert provider.calls <= 2, f"the model was called {provider.calls} times for one incident"  # ... none paid again
    assert len(rows) == 5 and sum(r["body"]["calls"] for r in rows) == provider.calls, rows
    assert sum(r["body"]["usd"] for r in rows) < 0.50 + 0.31


def test_a_provider_outage_does_not_use_up_the_incidents_ceiling():
    """Eighth review (2026-10-01, a regression from 8f575b8): three runs during an outage (3 + 3 + 2 failed requests,
    $0) used the whole default ceiling, and every run after the provider recovered failed without a call."""
    import threading as _threading

    from temporalio.common import WorkflowIDReusePolicy

    down = {"now": True}
    lock = _threading.Lock()

    class Flaky:
        name, model = "fake", "fake"

        def complete(self, *, system, user, schema=None):
            with lock:
                if down["now"]:
                    raise ConnectionError("the provider is down")
            return Completion("not json at all", 10, 10)

    def factory():
        return LLMClient(provider=Flaky(), max_calls=8, max_usd=0.50, mock=not down["now"], call_timeout_s=5)

    async def main():
        log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
        acts = IncidentActivities(audit=log, llm_factory=factory)
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        alert = _alert_from(next(iter(DEMO_ALERTS)))
        ended = []
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            for i in range(4):
                down["now"] = i < 3
                h = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-outage", task_queue="q",
                                                    id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY)
                with contextlib.suppress(Exception):
                    await h.result()
                ended.append((await h.describe()).status.name)
        return ended, log.entries(alert.alert_id, kinds=("incident.llm_spend",))

    ended, rows = asyncio.run(main())
    assert ended == ["FAILED", "FAILED", "FAILED", "COMPLETED"], ended
    assert sum(r["body"]["unanswered"] for r in rows[:3]) >= 3 and all(r["body"]["calls"] == 0 for r in rows[:3]), rows


def test_a_timed_out_call_counts_as_a_call():
    """Eighth review: a timed-out call - sent, and possibly billed - counted nowhere, so restarts of a hanging model
    were never bounded by the call ceiling."""
    import time as _time

    import pytest as _pytest

    from warden.llm import ModelCallTimeout
    from warden.models import RootCause

    class Hangs:
        name, model = "fake", "fake"

        def complete(self, *, system, user, schema=None):
            _time.sleep(3)
            return Completion("{}", 10, 10)

    client = LLMClient(provider=Hangs(), max_calls=4, max_usd=0.50, mock=False, call_timeout_s=0.1)
    with _pytest.raises(ModelCallTimeout):
        client.structured(system="s", user="u", schema=RootCause)
    assert client.cost.calls == 1 and client.unanswered == 0


def test_the_next_run_starts_from_both_the_usd_and_the_calls_spent():
    """Eighth review (test strength): carrying only the USD, or only the call count, passed every test."""
    seen = []

    class Records:
        name, model = "fake", "fake"

        def complete(self, *, system, user, schema=None):
            seen.append((clients[-1].cost.calls, round(clients[-1].cost.usd, 6)))
            return Completion("not json at all", 10, 10)

    clients = []

    def factory():
        clients.append(LLMClient(provider=Records(), max_calls=8, max_usd=0.50, mock=False, call_timeout_s=5))
        return clients[-1]

    async def main():
        log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
        alert = _alert_from(next(iter(DEMO_ALERTS)))
        log.append(alert.alert_id, "incident.llm_spend", {"run_id": "earlier", "usd": 0.25, "calls": 3, "unanswered": 0,
                                                           "input_tokens": 0, "output_tokens": 0})
        acts = IncidentActivities(audit=log, llm_factory=factory)
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            h = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-carried", task_queue="q")
            with contextlib.suppress(Exception):
                await h.result()

    asyncio.run(main())
    assert seen and seen[0] == (3, 0.25), seen  # the first call of the new run sees both, carried
