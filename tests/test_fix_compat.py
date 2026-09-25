"""Every fix command WARDEN can print for a Wave 4 fault must pass the harness's REAL allow-list.

The report side (src/warden/playbook.py, runbook.py) and the harness (scenarios/ops_fullstack.py)
were built separately against docs/WAVE4-CONTRACT.md. The report's own tests check its commands
against a hand-kept mirror of the allow-list; this test checks them against the harness itself, so
a command WARDEN prints that the harness would refuse - recorded as `fix_not_allowed`, i.e. a fix
that exists but never runs - is found here and not during a paid run.
"""

from __future__ import annotations

import itertools
import re

import pytest
from scenarios import ops_fullstack as fs

from test_playbook_stack import FAULTS, alert
from warden.models import ActionKind, RemediationProposal, RootCause, Verdict, VerdictStatus
from warden.reporting import build_report


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "ap-south-2")


def _stack_ids(context) -> frozenset[str]:
    """Ids the harness would know as the stack's own (it reads them from the live stack)."""
    text = " ".join(context.logs)
    return frozenset(re.findall(r"\bsg-[0-9a-zA-Z]+\b", text))


def _built(fid, action):
    context = FAULTS[fid][1]
    r = build_report(
        alert(), context=context, backend="stack", show_identifiers=False,
        root_cause=RootCause(hypothesis="h", confidence=0.8),
        proposal=RemediationProposal(action=action, target="t", reasoning="r", expected_effect="e",
                                     blast_radius="single_service", reversible=True),
        verdict=Verdict(status=VerdictStatus.approved_for_human, reasons=["r"], policy_ids=[]),
    )
    return r.data["fix_commands"], _stack_ids(context)


@pytest.mark.parametrize("fid,action", list(itertools.product(sorted(FAULTS), list(ActionKind))))
def test_the_harness_accepts_every_fix_warden_prints(fid, action):
    commands, ids = _built(fid, action)
    refused = [(c["command"], fs.check_command(c, stack_ids=ids)) for c in commands]
    refused = [x for x in refused if x[1]]
    assert not refused, (fid, action.value, refused)


def test_every_fault_with_a_printed_fix_reaches_the_harness_as_runnable():
    """The faults whose own pattern prints a command must all be runnable (not fix_not_allowed)."""
    printable = 0
    for fid in sorted(FAULTS):
        commands, ids = _built(fid, ActionKind.escalate_to_human)
        outcome, runnable, rejected = fs.decide_fix({"fix_commands": commands}, "escalated", ids)
        assert outcome in (None, "no_fix_printed"), (fid, outcome, rejected)
        printable += bool(runnable)
    assert printable >= 18, printable
