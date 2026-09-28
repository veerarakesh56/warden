"""Running WARDEN on Temporal: connect, run a worker, read a workflow's state, approve a plan.

Configuration, all from the environment (SSM in the cloud through settings.py):
- WARDEN_TEMPORAL_ADDRESS   the Temporal server, default 127.0.0.1:7233 (the local dev server)
- WARDEN_TEMPORAL_KEY       payload encryption key (codec.py); required
- WARDEN_AUDIT_DB           the audit log, default ~/.warden/audit.db
- WARDEN_AUDIT_KEY          the audit signing key (PEM; passphrase WARDEN_AUDIT_KEY_PASSPHRASE)
- WARDEN_APPROVERS          the approver allowlist (YAML; approvals.py)

The worker holds no approver key and no cloud credential. Phase 2 has no real platform yet, so a
remediation against a live system is refused at planning (`NoPlatform` reads nothing, and a
catalogue entry needs values WARDEN read); Phase 4 adds the platforms with their JIT roles.
"""

from __future__ import annotations

import os
import pathlib
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.client import Client
from temporalio.worker import Worker

from . import approvals, audit, codec
from .activities import IncidentActivities, Plan, RemediationActivities
from .workflows import IncidentWorkflow, RemediationWorkflow

TASK_QUEUE = "warden"


class NoPlatform:
    """No live system is connected: nothing is read, so every catalogue check refuses."""

    def live(self, entry: str, params: dict[str, Any]) -> dict[str, Any]:
        return {}

    def apply(self, entry: str, params: dict[str, Any]) -> str:
        raise RuntimeError("no platform is connected")

    def healthy(self, service: str) -> bool:
        return False

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any]) -> str:
        raise RuntimeError("no platform is connected")


def _path(env: str, default: str | None = None) -> pathlib.Path:
    value = os.environ.get(env) or default
    if not value:
        raise RuntimeError(f"{env} is not set")
    return pathlib.Path(value).expanduser()


def open_audit() -> audit.AuditLog:
    db = _path("WARDEN_AUDIT_DB", "~/.warden/audit.db")
    db.parent.mkdir(parents=True, exist_ok=True)
    passphrase = os.environ.get("WARDEN_AUDIT_KEY_PASSPHRASE", "").encode() or None
    return audit.AuditLog(db, key=audit.load_private_key(_path("WARDEN_AUDIT_KEY"), passphrase))


async def connect(address: str | None = None, key: bytes | None = None) -> Client:
    return await Client.connect(address or os.environ.get("WARDEN_TEMPORAL_ADDRESS", "127.0.0.1:7233"),
                                data_converter=codec.data_converter(key))


def worker(client: Client, *, log: audit.AuditLog, policy: approvals.ApproverPolicy, platform: Any = None,
           backend: Any = None, llm_factory: Any = None, task_queue: str = TASK_QUEUE) -> Worker:
    inc = IncidentActivities(audit=log, backend=backend, llm_factory=llm_factory)
    rem = RemediationActivities(audit=log, policy=policy, platform=platform or NoPlatform())
    return Worker(client, task_queue=task_queue, workflows=[IncidentWorkflow, RemediationWorkflow],
                  activities=[inc.prepare, inc.diagnose, inc.verify,
                              rem.resolve_plan, rem.gate, rem.check_approval, rem.precheck, rem.apply,
                              rem.check_success, rem.record_result, rem.rollback, rem.finish],
                  # ponytail: one thread per activity; the model call is the slow one (one at a time
                  # is what Claude Max allows anyway).
                  activity_executor=ThreadPoolExecutor(4))


async def status(client: Client, workflow_id: str) -> tuple[str, Plan | None]:
    handle = client.get_workflow_handle(workflow_id)
    return (await handle.query(RemediationWorkflow.stage), await handle.query(RemediationWorkflow.plan))


async def approve(client: Client, workflow_id: str, *, plan_hash: str, key: Ed25519PrivateKey,
                  approver: str) -> str:
    """Sign and send an approval of exactly the plan the approver reviewed.

    Refuses (sends nothing) when the workflow is not waiting for approval or its current plan is not
    the one given: approving a plan you have not seen is the failure this whole design exists to stop.
    """
    stage, plan = await status(client, workflow_id)
    if stage != "awaiting_approval" or plan is None:
        raise ValueError(f"{workflow_id} is not waiting for an approval (stage: {stage})")
    if plan.plan_hash != plan_hash:
        raise ValueError("the workflow's plan is not the one you reviewed; run `warden status` again")
    signed = approvals.sign(key, approver=approver, workflow_id=workflow_id, plan_hash=plan.plan_hash,
                            tier=plan.tier)
    await client.get_workflow_handle(workflow_id).signal(RemediationWorkflow.approve, signed)
    return f"approved {plan.entry} {plan.params} ({plan.tier}) as {approver}; the workflow checks it next"
