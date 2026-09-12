"""The replay tool, pinned against real published evidence.

Ten lines that tie the action table and the evidence floor to reports a real AWS account produced,
rather than to fixtures written alongside the code they test. If a future edit softens the table or
restores `no_action`'s exemption, these go red against artefacts nobody can quietly adjust.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import replay_gate as rg  # after the sys.path line above

REPORTS = ROOT / "docs" / "bench" / "wave1-2026-09-11T155744Z" / "reports"

pytestmark = pytest.mark.skipif(
    not REPORTS.exists(), reason="the published benchmark run is not in this checkout"
)


def test_a_no_action_on_a_broken_service_is_no_longer_waved_through():
    """ecs-06: an invalid secret ARN, new tasks failing to start, and WARDEN answered `no_action` at
    0.30 confidence. The gate allowed it when this run was measured; it escalates now."""
    old, new, policies = rg.replay_one(REPORTS / "ecs-06-invalid-secret-arn.1.json")
    assert (old, new) == ("auto_safe", "escalated")
    assert "P4-LOW-CONFIDENCE" in policies


def test_the_table_did_not_brick_the_rollbacks():
    """The other half, and the one that matters if the table is ever wrong: a correct rollback on
    good evidence must still reach a human rather than being refused. All 13 rollback runs in this
    published wave keep their verdicts; this pins one of them."""
    old, new, _ = rg.replay_one(REPORTS / "ecs-03-oom-new-revision.1.json")
    assert (old, new) == ("approved_for_human", "approved_for_human")


def test_the_replay_says_plainly_that_it_is_not_a_measurement():
    """The banner is the whole guard against these numbers being quoted as a new wave."""
    assert "NOT A MEASUREMENT" in "\n".join(rg.BANNER)
