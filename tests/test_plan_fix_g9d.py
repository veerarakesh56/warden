"""G9-D1 (2026-10-10): a proposal the verifier passes for a person opens its fix plan - a RemediationWorkflow that
still waits for a signed human approval. The request is deterministic: the resource from the alert's labels (the
proposal must name it), each reference parameter only from a single known-good value the platform's live read gives,
bounded numbers from the live value. Nothing from text; anything unresolved is a reason, and no plan."""

from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import audit, codec, resolver
from warden.activities import Diagnosed, EvidencePack, IncidentActivities, Verified
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import ActionKind, Alert, RemediationProposal, Severity, Verdict, VerdictStatus
from warden.workflows import IncidentWorkflow, RemediationWorkflow


def _alert(**labels):
    return Alert(alert_id="a1", name="n", service="warden-dev-orders", environment="dev", severity=Severity.high,
                 summary="", started_at="2026-10-10T00:00:00+00:00", labels=labels)


def _proposal(action, target):
    return RemediationProposal(action=action, target=target, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)


def test_a_lambda_rollback_moves_the_alias_to_the_one_known_good_version_the_live_read_gives():
    seen = []

    def live(entry, params):
        seen.append((entry, dict(params)))
        return {"function": {"warden-dev-orders"}, "alias": {"live"}, "to_version": {"3"}}

    req, why = resolver.request_for(_alert(**{"lambda": "warden-dev-orders", "lambda_qualifier": "live"}),
                                    _proposal(ActionKind.rollback_deploy, "warden-dev-orders"), live)
    assert why == "" and req == {"entry": "lambda_move_alias", "service": "warden-dev-orders", "environment": "dev",
                                 "incident_id": "a1",
                                 "params": {"function": "warden-dev-orders", "alias": "live", "to_version": "3"}}
    assert seen == [("lambda_move_alias", {"function": "warden-dev-orders", "alias": "live"})]
    assert resolver.workflow_id(req).startswith("rem-dev-")


def test_no_plan_when_the_target_is_not_the_labelled_resource_or_no_single_known_good_value_was_read():
    labels = {"lambda": "warden-dev-orders", "lambda_qualifier": "live"}
    req, why = resolver.request_for(_alert(**labels), _proposal(ActionKind.rollback_deploy, "warden-prod-orders"),
                                    lambda e, p: {})
    assert req is None and "not a resource the alert's labels name" in why
    for allowed in (set(), {"2", "3"}):
        req, why = resolver.request_for(_alert(**labels), _proposal(ActionKind.rollback_deploy, "warden-dev-orders"),
                                        lambda e, p, allowed=allowed: {"to_version": allowed})
        assert req is None and "no single known-good to_version" in why
    req, why = resolver.request_for(_alert(**{"lambda": "warden-dev-orders"}),
                                    _proposal(ActionKind.rollback_deploy, "warden-dev-orders"), lambda e, p: {})
    assert req is None and "no Lambda alias" in why
    req, why = resolver.request_for(_alert(**labels), _proposal(ActionKind.escalate_to_human, "warden-dev-orders"),
                                    lambda e, p: {})
    assert req is None


def test_bounded_numbers_come_from_the_live_value_conservatively():
    req, _ = resolver.request_for(_alert(dynamodb_table="warden-dev-carts"),
                                  _proposal(ActionKind.scale_up, "warden-dev-carts"),
                                  lambda e, p: {"table": {"warden-dev-carts"}, "current_capacity": 50})
    assert req["entry"] == "dynamodb_raise_capacity" and req["params"]["capacity"] == 100
    req, why = resolver.request_for(_alert(dynamodb_table="warden-dev-carts"),
                                    _proposal(ActionKind.scale_up, "warden-dev-carts"), lambda e, p: {})
    assert req is None and "capacity was not read" in why


def test_an_ecs_rollback_takes_the_previous_steady_task_definition():
    req, _ = resolver.request_for(_alert(ecs_cluster="warden-dev-c", ecs_service="warden-dev-api"),
                                  _proposal(ActionKind.rollback_deploy, "warden-dev-api"),
                                  lambda e, p: {"cluster": {"warden-dev-c"}, "service": {"warden-dev-api"},
                                                "to_task_definition": {"arn:td/api:9"}})
    assert req["entry"] == "ecs_rollback_service"
    assert req["params"] == {"cluster": "warden-dev-c", "service": "warden-dev-api", "to_task_definition": "arn:td/api:9"}


def test_an_approved_diagnosis_opens_its_plan_and_the_plan_waits_for_approval(tmp_path):
    request = {"entry": "events_enable_rule", "params": {"rule": "warden-dev-nightly"}, "service": "warden-dev-nightly",
               "environment": "dev", "incident_id": "inc-002", "workflow_id": "rem-dev-test"}

    class _Acts(IncidentActivities):
        @activity.defn(name="verify")
        def verify(self, pack: EvidencePack, diagnosed: Diagnosed) -> Verified:
            return Verified(verdict=Verdict(status=VerdictStatus.approved_for_human, reasons=["test"]))

        @activity.defn(name="plan_fix")
        def plan_fix(self, alert: Alert, diagnosed: Diagnosed, verified: Verified) -> dict:
            assert alert.alert_id == "inc-002"  # the alarm's own alert, never an investigation's widened one
            return dict(request)

    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = _Acts(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="planfix", workflows=[IncidentWorkflow, RemediationWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify, acts.plan_fix],
                               activity_executor=ThreadPoolExecutor(2)):
            handle = await env.client.start_workflow(IncidentWorkflow.run, Alert(**DEMO_ALERTS["inc-002"]),
                                                     id="inc-planfix", task_queue="planfix")
            await asyncio.wait_for(handle.result(), 120)
            child = await env.client.get_workflow_handle("rem-dev-test").describe()
            return child.workflow_type

    assert asyncio.run(main()) == "RemediationWorkflow"
