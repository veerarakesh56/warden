"""The approval Lambda (which also serves the records pages) builds its page without importing the worker, the
activities or the workflows: live, those imports were most of a cold start's 2.5 s page time. It calls the
workflow's query and signals by name instead, and the names are the ones RemediationWorkflow registers."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

from temporalio import workflow

from warden import lambdas
from warden.approvals import Denial, PasskeyAssertion, Plan
from warden.workflows import RemediationWorkflow

# temporalio.client too: runtime_base.connect imports it when called, so a records page (/r) never pays for it.
HEAVY = ("temporalio.worker", "warden.activities", "warden.workflows", "warden.runtime", "temporalio.client")

_CHILD = """
import asyncio, sys
from warden import lambdas, runtime_base
from warden.approvals import Plan

calls = []

class Handle:
    async def query(self, name, result_type=None):
        calls.append(("query", name, result_type == (Plan | None)))
    async def signal(self, name, arg):
        calls.append(("signal", name, arg))

class Client:
    def get_workflow_handle(self, workflow_id):
        return Handle()

async def connect():
    return Client()

runtime_base.connect, runtime_base.approver_policy, runtime_base.open_audit = connect, lambda: None, lambda: None
page = lambdas.approval_page()
page.plan_of("rem-1"); page.signal("rem-1", "a"); page.deny("rem-1", "d")
print(calls)
print([m for m in %r if m in sys.modules])
"""


def test_the_approval_page_is_built_without_the_worker_activities_or_workflows():
    src = pathlib.Path(lambdas.__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(src), "WARDEN_APPROVAL_RP_ID": "approve.example"}
    env.pop("WARDEN_SLACK_CLIENT_ID", None)
    out = subprocess.run([sys.executable, "-c", _CHILD % (HEAVY,)], env=env, capture_output=True, text=True,
                         check=True).stdout.splitlines()
    assert out == ["[('query', 'plan', True), ('signal', 'approve_passkey', 'a'), ('signal', 'deny', 'd')]", "[]"]


def test_the_names_called_are_the_ones_the_workflow_registers():
    d = workflow._Definition.must_from_class(RemediationWorkflow)
    assert d.queries[lambdas.PLAN_QUERY].ret_type == (Plan | None)
    assert d.signals[lambdas.APPROVE_SIGNAL].arg_types == [PasskeyAssertion]
    assert d.signals[lambdas.DENY_SIGNAL].arg_types == [Denial]
    from warden.approvals import SignedApproval

    assert d.signals[lambdas.SIGNED_SIGNAL].arg_types == [SignedApproval]
