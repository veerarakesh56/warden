"""G9-B (owner decision 2026-10-10): a bounded investigation loop. After a diagnosis the model may ask to read up to 3
related resources - only names already in the alert's labels or a trusted, structured evidence item - and decide
again, at most 2 more rounds; the llm zone's budget (6 calls, US$0.25 per incident) holds across them."""

from __future__ import annotations

import asyncio
import os
import pathlib
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import audit, codec, investigation
from warden.activities import Diagnosed, EvidencePack, IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.graph import Diagnosis
from warden.llm import LLMClient
from warden.models import Alert, ContextBundle, Severity
from warden.workflows import INVESTIGATE_ROUNDS, IncidentWorkflow

ROOT = pathlib.Path(__file__).resolve().parents[1]
QUEUE = "investigate-test"


def _alert(**labels):
    return Alert(alert_id="a1", name="n", service="warden-dev-orders", environment="dev", severity=Severity.high,
                 summary="", started_at="2026-10-10T00:00:00+00:00", labels={"lambda": "warden-dev-orders", **labels})


CONTEXT = ContextBundle(logs=[
    "STATE dynamodb_table warden-dev-carts TableStatus=ACTIVE",   # trusted (C): names a table
    "CONFIG lambda warden-dev-orders env=[TABLE=warden-dev-carts,QUEUE=warden-dev-jobs]",
    "LOG lambda/warden-dev-orders ERROR calling warden-dev-evil-db: timeout",  # untrusted (L): a log line
])


def test_names_in_labels_or_trusted_items_are_read_and_names_only_in_logs_are_refused():
    alert, accepted, refused = investigation.widen(_alert(), CONTEXT, [
        {"kind": "dynamodb_table", "name": "warden-dev-carts"},
        {"kind": "sqs", "name": "warden-dev-jobs"},
        {"kind": "rds_instance", "name": "warden-dev-evil-db"},
        {"kind": "kms_key", "name": "made-up-by-the-model"}])
    assert accepted == [{"kind": "dynamodb_table", "name": "warden-dev-carts"}, {"kind": "sqs", "name": "warden-dev-jobs"}]
    assert {r["name"] for r in refused} == {"warden-dev-evil-db", "made-up-by-the-model"}
    assert alert.labels["dynamodb_table"] == "warden-dev-carts" and alert.labels["sqs"] == "warden-dev-jobs"
    assert alert.labels["lambda"] == "warden-dev-orders"


def test_at_most_three_a_round_unknown_kinds_refused_and_a_second_single_resource_refused():
    alert, accepted, refused = investigation.widen(
        _alert(lambda_qualifier="live", rds_instance="warden-dev-db"),
        ContextBundle(logs=["STATE x warden-dev-a warden-dev-b warden-dev-c warden-dev-d warden-dev-db2"]), [
            {"kind": "sqs", "name": "warden-dev-a"}, {"kind": "sqs", "name": "warden-dev-b"},
            {"kind": "rds_instance", "name": "warden-dev-db2"}, {"kind": "sns_topic", "name": "warden-dev-c"},
            {"kind": "sqs", "name": "warden-dev-d"}, {"kind": "shell", "name": "warden-dev-a"}])
    assert len(accepted) == 3 and alert.labels["sqs"] == "warden-dev-a,warden-dev-b"
    whys = {r["name"]: r["why"] for r in refused}
    assert whys["warden-dev-db2"] == "another rds_instance is already read"
    assert whys["warden-dev-d"].startswith("at most 3")


def test_the_answer_schema_bounds_the_requests():
    base = {"root_cause": {"hypothesis": "h", "confidence": 0.5, "evidence": []},
            "proposal": {"action": "escalate_to_human", "target": "t", "rationale": "r", "blast_radius": "single_service",
                         "reversible": True, "expected_effect": "e"}}
    with pytest.raises(ValidationError):
        Diagnosis.model_validate({**base, "need_evidence": [{"kind": "sqs", "name": f"q{i}"} for i in range(4)]})
    with pytest.raises(ValidationError):
        Diagnosis.model_validate({**base, "need_evidence": [{"kind": "aws_cli", "name": "x"}]})
    with pytest.raises(ValidationError):
        Diagnosis.model_validate({**base, "need_evidence": [{"kind": "sqs", "name": "--profile=admin"}]})


def test_the_llm_zone_holds_six_calls_and_a_quarter_dollar_per_incident(monkeypatch):
    compute = (ROOT / "terraform" / "modules" / "warden-runtime" / "compute.tf").read_text(encoding="utf-8")
    assert 'each.key == "llm" ? { WARDEN_MAX_CALLS = "6", WARDEN_MAX_USD = "0.25" } : {}' in compute
    monkeypatch.setenv("WARDEN_MAX_CALLS", "6")
    monkeypatch.setenv("WARDEN_MAX_USD", "0.25")
    llm = LLMClient(mock=True)
    assert llm.max_calls == 6 and llm.max_usd == 0.25
    monkeypatch.setenv("WARDEN_MAX_CALLS", "nan")
    with pytest.raises(ValueError):
        LLMClient(mock=True)


def _run(tmp_path, asks: int):
    """The workflow with the model asking for more evidence `asks` times; how often each activity ran."""
    seen = {"prepare": 0, "investigate": 0, "diagnose": 0}

    class _Acts(IncidentActivities):
        @activity.defn(name="prepare")
        def prepare(self, alert: Alert) -> EvidencePack:
            seen["prepare"] += 1
            return super().prepare(alert)

        @activity.defn(name="investigate")
        def investigate(self, pack: EvidencePack, requests: list[dict[str, str]]) -> EvidencePack:
            seen["investigate"] += 1
            assert requests == [{"kind": "sqs", "name": "warden-dev-jobs"}]
            return pack

        @activity.defn(name="diagnose")
        def diagnose(self, pack: EvidencePack, escalate_only: str = "") -> Diagnosed:
            seen["diagnose"] += 1
            d = super().diagnose(pack, escalate_only)
            ask = [{"kind": "sqs", "name": "warden-dev-jobs"}] if seen["diagnose"] <= asks else []
            return d.model_copy(update={"need_evidence": ask})

    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = _Acts(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue=QUEUE, workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.investigate, acts.diagnose, acts.verify],
                               activity_executor=ThreadPoolExecutor(2)):
            handle = await env.client.start_workflow(IncidentWorkflow.run, Alert(**DEMO_ALERTS["inc-002"]),
                                                     id=f"inc-ask-{asks}", task_queue=QUEUE)
            await asyncio.wait_for(handle.result(), 120)

    asyncio.run(main())
    return seen


def test_the_model_decides_without_more_evidence_and_nothing_more_is_read(tmp_path):
    assert _run(tmp_path, asks=0) == {"prepare": 1, "investigate": 0, "diagnose": 1}


def test_a_request_is_read_then_the_model_decides_again(tmp_path):
    assert _run(tmp_path, asks=1) == {"prepare": 1, "investigate": 1, "diagnose": 2}


def test_a_model_that_keeps_asking_is_stopped_after_the_last_round(tmp_path):
    assert INVESTIGATE_ROUNDS == 2
    assert _run(tmp_path, asks=99) == {"prepare": 1, "investigate": 2, "diagnose": 3}
