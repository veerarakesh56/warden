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


def test_every_pattern_suggestion_would_pass_the_harness_allow_list():
    """Pattern commands are suggestions now (Phase 0): never executable by themselves. If a person
    adopts one, it must still be a command the harness allow-list accepts - checked here, not on a
    paid run. And none of them is an IAM grant (WARDEN never writes IAM from a log line)."""
    suggested = 0
    for fid in sorted(FAULTS):
        context = FAULTS[fid][1]
        r = build_report(alert(), context=context, backend="stack", show_identifiers=False)
        for c in r.data["pattern_suggestions"]:
            assert fs.check_command(c, stack_ids=_stack_ids(context)) is None, (fid, c)
            assert "put-role-policy" not in c["command"], (fid, c)
        suggested += bool(r.data["pattern_suggestions"])
        assert r.data["fix_commands"] == [], (fid, "nothing is executable without an approved verdict")
    assert suggested >= 20, suggested  # 20 of 28 faults on 2026-09-27; fewer = a detector lost
