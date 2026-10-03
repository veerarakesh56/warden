"""Running WARDEN on Temporal: connect, run a worker, read a workflow's state, approve a plan.

Configuration, all from the environment (SSM in the cloud through settings.py):
- WARDEN_TEMPORAL_ADDRESS   the Temporal server, default 127.0.0.1:7233 (the local dev server)
- WARDEN_TEMPORAL_NAMESPACE the namespace, default `default`
- WARDEN_TEMPORAL_API_KEY   the API key of this worker's service account (Temporal Cloud, decision D2; a Secrets
                            Manager secret, one service account per trust zone - register S15). Required for any
                            server that is not on this machine: an unauthenticated remote connection is refused.
- WARDEN_TEMPORAL_KEY       payload encryption key (codec.py); required
- WARDEN_AUDIT_DB           the audit log, default ~/.warden/audit.db
- WARDEN_AUDIT_KEY          the audit signing key (PEM; passphrase WARDEN_AUDIT_KEY_PASSPHRASE)
- WARDEN_APPROVERS          the approver allowlist (YAML; approvals.py)

The worker holds no approver key and no cloud credential. Phase 2 has no real platform yet, so a
remediation against a live system is refused at planning (`NoPlatform` reads nothing, and a
catalogue entry needs values WARDEN read); Phase 4 adds the platforms with their JIT roles.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.client import Client
from temporalio.worker import Worker

from . import approvals, audit, codec
from .activities import IncidentActivities, Plan, RemediationActivities
from .workflows import ClockWorkflow, IncidentWorkflow, RemediationWorkflow

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


def skew_problem(before: datetime, server: datetime, after: datetime,
                 limit: timedelta = approvals.CLOCK_SKEW) -> str:
    """'' if the server's time falls inside [before, after] on this host's clock, give or take `limit`."""
    if server < before - limit or server > after + limit:
        off = (server - after) if server > after else (before - server)
        return (f"this host's clock is {off.total_seconds():.0f}s {'behind' if server > after else 'ahead of'} the "
                f"Temporal server's; approvals expire and bounds windows close by this clock, and the tolerance is "
                f"{limit.total_seconds():.0f}s. Fix the host's time sync (register O6)")
    return ""


async def check_clock(client: Client, task_queue: str = TASK_QUEUE, wait_s: float = 90) -> str:
    """Run once a worker is polling: an approval's expiry, the bounds windows and the daily cap are all judged by
    the activity host's clock, so a worker whose clock is off refuses to start (register O6)."""
    before = datetime.now(UTC)
    try:
        # Bounded here as well: a worker that cannot run its own clock check is not fit to run anything else.
        server = await asyncio.wait_for(client.execute_workflow(
            ClockWorkflow.run, id=f"clock-{secrets.token_hex(6)}", task_queue=task_queue,
            execution_timeout=timedelta(minutes=1)), timeout=wait_s)
    except TimeoutError:
        return "the clock check never ran on this task queue: the worker could not measure its clock (register O6)"
    return skew_problem(before, server, datetime.now(UTC))


TYPED_TIERS = frozenset({"T2", "T3"})


_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


async def connect(address: str | None = None, key: bytes | None = None) -> Client:
    """A client for the configured server. Temporal Cloud authenticates by API key over TLS; any server off this
    machine without a key is refused, never tried (register S15): a worker that talked to a server anyone could
    reach would take its tasks - and its plans - from anyone."""
    target = address or os.environ.get("WARDEN_TEMPORAL_ADDRESS", "127.0.0.1:7233")
    api_key = os.environ.get("WARDEN_TEMPORAL_API_KEY")
    host = target.rsplit(":", 1)[0]  # host:port, or [ipv6]:port
    if host not in _LOOPBACK and not api_key:
        raise RuntimeError(f"refusing an unauthenticated connection to {host}: set WARDEN_TEMPORAL_API_KEY "
                           "(register S15)")
    options: dict[str, Any] = {"namespace": os.environ.get("WARDEN_TEMPORAL_NAMESPACE", "default"),
                               "data_converter": codec.data_converter(key)}
    if api_key:
        options.update(api_key=api_key, tls=True)
    return await Client.connect(target, **options)


def worker(client: Client, *, log: audit.AuditLog, policy: approvals.ApproverPolicy, platform: Any = None,
           backend: Any = None, llm_factory: Any = None, task_queue: str = TASK_QUEUE) -> Worker:
    inc = IncidentActivities(audit=log, backend=backend, llm_factory=llm_factory)
    from .changes import from_environment

    rem = RemediationActivities(audit=log, policy=policy, platform=platform or NoPlatform(), changes=from_environment())
    return Worker(client, task_queue=task_queue, workflows=[IncidentWorkflow, RemediationWorkflow, ClockWorkflow],
                  activities=[inc.prepare, inc.diagnose, inc.verify, inc.notify,
                              rem.resolve_plan, rem.gate, rem.announce, rem.check_approval, rem.check_passkey, rem.precheck, rem.apply,
                              rem.check_success, rem.record_result, rem.rollback, rem.finish],
                  # ponytail: one thread per activity; the model call is the slow one (one at a time
                  # is what Claude Max allows anyway).
                  activity_executor=ThreadPoolExecutor(4))


async def status(client: Client, workflow_id: str) -> tuple[str, Plan | None]:
    handle = client.get_workflow_handle(workflow_id)
    return (await handle.query(RemediationWorkflow.stage), await handle.query(RemediationWorkflow.plan))


async def approve(client: Client, workflow_id: str, *, plan_hash: str, key: Ed25519PrivateKey,
                  approver: str, typed_target: str | None = None) -> str:
    """Sign and send an approval of exactly the plan the approver reviewed.

    Refuses (sends nothing) when the workflow is not waiting for approval or its current plan is not
    the one given: approving a plan you have not seen is the failure this whole design exists to stop.
    """
    stage, plan = await status(client, workflow_id)
    if stage != "awaiting_approval" or plan is None:
        raise ValueError(f"{workflow_id} is not waiting for an approval (stage: {stage})")
    if plan.plan_hash != plan_hash:
        raise ValueError("the workflow's plan is not the one you reviewed; run `warden status` again")
    if plan.tier in TYPED_TIERS and typed_target != plan.target:
        # Register H1: a hash can be pasted without reading; a T2 or T3 approver types what the change touches.
        raise ValueError(f"a {plan.tier} approval needs the plan's target typed exactly (--target, as `warden status` "
                         "shows it)")
    signed = approvals.sign(key, approver=approver, workflow_id=workflow_id, plan_hash=plan.plan_hash,
                            tier=plan.tier)
    await client.get_workflow_handle(workflow_id).signal(RemediationWorkflow.approve, signed)
    return f"approved {plan.entry} {plan.params} ({plan.tier}) as {approver}; the workflow checks it next"
