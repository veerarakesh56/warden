"""scripts/helios_gate.py's table rows (split out of main for S3776): with a current state, each scenario is also
simulated on it and judged against what the stack fails today; without one, only against the accepted failures."""

from __future__ import annotations

import argparse
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("helios_gate_rows", ROOT / "scripts" / "helios_gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)
PLAN, BASELINE, SCENARIO = pathlib.Path("plan.json"), pathlib.Path("baseline.json"), pathlib.Path("lose-x.json")
FAILS = {"aws_instance.a", "aws_instance.b"}
HEADING = ["### Helios before apply", "", "| Scenario | Verdict | Why |", "|---|---|---|"]


def _rows(monkeypatch, compare_with):
    simulated: list = []

    def simulate(helios, document, scenario):
        simulated.append(document)
        return set(FAILS)

    monkeypatch.setattr(gate, "simulate", simulate)
    args = argparse.Namespace(helios="helios", after=None)
    lines, refused = gate._scenario_rows(args, PLAN, compare_with, {"node-loss": SCENARIO}, ({}, None, {}))
    return lines, refused, simulated


def test_with_a_current_state_what_it_fails_today_is_not_new(monkeypatch):
    lines, refused, simulated = _rows(monkeypatch, BASELINE)
    assert simulated == [BASELINE, PLAN]
    assert lines == [*HEADING, "| node-loss | ok | 2 failure(s), none new |"]
    assert refused is False


def test_without_a_current_state_every_unaccepted_failure_is_new(monkeypatch):
    lines, refused, simulated = _rows(monkeypatch, None)
    assert simulated == [PLAN]
    assert lines == [*HEADING, "| node-loss | refuse | fails what the stack survives today: aws_instance.a, aws_instance.b |"]
    assert refused is True
