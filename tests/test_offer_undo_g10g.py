"""Held by P31 alone, WARDEN offers the undo of the change the proposal left unaddressed (first live fault,
2026-10-11). A person cut a table's write capacity; the model proposed raising it - which WARDEN's bounded raise could
not even reach - P31 held that, and the person received a hand-off and no plan, although the undo of that very change
has an entry. The offer goes through the same resolver and the same live read as a proposed revert, and a person
approves it; beside any other policy nothing is offered."""

from __future__ import annotations

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio import activity
from temporalio.service import RPCError, RPCStatusCode
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import activities, audit, codec
from warden.activities import Diagnosed, EvidencePack, IncidentActivities, Verified
from warden.audit import AuditLog
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient
from warden.models import (
    ActionKind,
    Alert,
    CostRecord,
    RemediationProposal,
    RootCause,
    Severity,
    Verdict,
    VerdictStatus,
)
from warden.workflows import IncidentWorkflow, RemediationWorkflow

TABLE = "warden-dev-lab-orders"
ALARM = "warden-dev-lab-orders-write-throttles"
ALERT = Alert(alert_id="inc-1", name="n", service=TABLE, environment="dev", severity=Severity.high, summary="",
              started_at="2026-10-10T00:00:00+00:00", labels={"dynamodb_table": TABLE, "alarm": ALARM})
P31 = "P31-UNADDRESSED-CHANGE"


def _diag(action=ActionKind.scale_up, target=TABLE):
    proposal = RemediationProposal(action=action, target=target, reasoning="r", expected_effect="e",
                                   blast_radius="single_service", reversible=True)
    return Diagnosed(root_cause=RootCause(hypothesis="h", confidence=0.9), proposal=proposal, cost=CostRecord())


def _held(*policies):
    return Verified(verdict=Verdict(status=VerdictStatus.escalated, reasons=["x"], policy_ids=list(policies)))


class Lab:
    """The platform's live read of the lab's table: the cut's undo is allowed; a raise from 1 unit reaches 2."""

    def __init__(self, refused=""):
        self.refused, self.asked = refused, []

    def live(self, entry, params):
        self.asked.append(entry)
        if entry == "dynamodb_restore_capacity":
            found = not self.refused
            return {"table": {TABLE}, "alarm": {ALARM}, "event": {"e-1"} if found else set(),
                    "throughput": {"5/10"} if found else set(), "refused": self.refused, "environment": "dev",
                    "rollout": "complete"}
        return {"table": {TABLE}, "current_capacity": 1, "autoscaled": False, "environment": "dev",
                "rollout": "complete"}


def _acts(tmp_path, platform):
    return IncidentActivities(audit=AuditLog(tmp_path / f"{id(platform)}.db", key=None), platform=platform)


def test_held_by_p31_alone_the_undo_of_that_change_is_offered(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="warden.incident")
    lab = Lab()
    acts = _acts(tmp_path, lab)
    request = acts.plan_fix(ALERT, _diag(), _held(P31))
    assert request["entry"] == "dynamodb_restore_capacity" and lab.asked == ["dynamodb_restore_capacity"]
    assert request["params"] == {"alarm": ALARM, "table": TABLE, "event": "e-1", "throughput": "5/10"}
    row = acts.audit.entries("inc-1", kinds=("incident.plan_fix",))[-1]["body"]
    assert row["planned"] is True and row["offered"] == activities.OFFERED_UNDO
    line = [r.getMessage() for r in caplog.records if r.name == "warden.incident"][-1]
    assert line == f"inc-1 fix plan opened: dynamodb_restore_capacity ({activities.OFFERED_UNDO})"
    # A verdict that passed is planned as proposed, and says nothing of an offer.
    lab = Lab()
    acts = _acts(tmp_path, lab)
    passed = Verified(verdict=Verdict(status=VerdictStatus.approved_for_human))
    assert acts.plan_fix(ALERT, _diag(), passed)["entry"] == "dynamodb_raise_capacity"
    assert "offered" not in acts.audit.entries("inc-1", kinds=("incident.plan_fix",))[-1]["body"]


@pytest.mark.parametrize("verified", [_held(P31, "P4-LOW-CONFIDENCE"), _held(P31, "P6-BLAST-RADIUS"),
                                      _held("P9-THIN-EVIDENCE"), _held(),
                                      Verified(verdict=Verdict(status=VerdictStatus.rejected, policy_ids=[P31]))])
def test_nothing_is_offered_beside_another_policy_or_when_the_live_read_refuses(tmp_path, verified):
    lab = Lab()
    acts = _acts(tmp_path, lab)
    assert acts.plan_fix(ALERT, _diag(), verified) == {} and lab.asked == []
    row = acts.audit.entries("inc-1", kinds=("incident.plan_fix",))[-1]["body"]
    assert row["why"].startswith("the verdict is") and "offered" not in row
    # Held by P31 alone but the platform may not undo the change (infrastructure as code, a second change, ...): the
    # refusal is the reason, and no plan opens. A target the labels do not name is no resource to undo anything on.
    refusing = Lab(refused="the change was made by infrastructure as code (Terraform): undo it in the code")
    acts = _acts(tmp_path, refusing)
    assert acts.plan_fix(ALERT, _diag(), _held(P31)) == {}
    row = acts.audit.entries("inc-1", kinds=("incident.plan_fix",))[-1]["body"]
    assert "infrastructure as code" in row["why"] and row["offered"] == activities.OFFERED_UNDO
    other = Lab()
    assert _acts(tmp_path, other).plan_fix(ALERT, _diag(target="some-other-table"), _held(P31)) == {}
    assert other.asked == []


@pytest.mark.parametrize("policies, opens", [((P31,), True), ((P31, "P4-LOW-CONFIDENCE"), False)])
def test_the_workflow_opens_the_offered_plan_and_only_for_p31_alone(tmp_path, policies, opens):
    request = {"entry": "events_enable_rule", "params": {"rule": "warden-dev-nightly"}, "service": "warden-dev-nightly",
               "environment": "dev", "incident_id": "inc-002", "workflow_id": "rem-dev-offer"}
    asked = []

    class _Acts(IncidentActivities):
        @activity.defn(name="verify")
        def verify(self, pack: EvidencePack, diagnosed: Diagnosed) -> Verified:
            return _held(*policies)

        @activity.defn(name="plan_fix")
        def plan_fix(self, alert: Alert, diagnosed: Diagnosed, verified: Verified) -> dict:
            asked.append(alert.alert_id)
            return dict(request)

    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = _Acts(audit=log, llm_factory=lambda: LLMClient(mock=True))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="offer", workflows=[IncidentWorkflow, RemediationWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify, acts.second_opinion, acts.plan_fix],
                               activity_executor=ThreadPoolExecutor(2)):
            handle = await env.client.start_workflow(IncidentWorkflow.run, Alert(**DEMO_ALERTS["inc-002"]),
                                                     id="inc-offer", task_queue="offer")
            await asyncio.wait_for(handle.result(), 120)
            try:
                return (await env.client.get_workflow_handle("rem-dev-offer").describe()).workflow_type
            except RPCError as err:  # no such workflow: no plan was opened
                assert err.status == RPCStatusCode.NOT_FOUND, err
                return None

    assert asyncio.run(main()) == ("RemediationWorkflow" if opens else None)
    assert asked == (["inc-002"] if opens else [])
