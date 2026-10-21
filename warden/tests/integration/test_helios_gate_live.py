"""WARDEN's plan gate (infra/scripts/helios_gate.py, register R56) run for real, on Helios built from this repository's
helios/ - the binary every infra deploy builds and runs (infra/.github/actions/deploy-prepare).

Opt-in: CI · infra's helios-gate job builds Helios, sets HELIOS_BIN and WARDEN_HELIOS_INTEGRATION=1, and fails if
anything here skips. On a machine without that build it skips.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
GATE = ROOT / "infra" / "scripts" / "helios_gate.py"
FIXTURES = ROOT / "helios" / "fixtures"

pytestmark = pytest.mark.skipif(os.environ.get("WARDEN_HELIOS_INTEGRATION") != "1" or not os.environ.get("HELIOS_BIN"),
                                reason="needs Helios built from helios/ (HELIOS_BIN) and WARDEN_HELIOS_INTEGRATION=1")


def _gate(tmp_path: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    # From the repository root: the binary sits under it, one of the places the gate runs Helios from.
    return subprocess.run([sys.executable, str(GATE), "--helios", os.environ["HELIOS_BIN"], "--stack", "fullstack",
                           "--out-dir", str(tmp_path / "scenarios"), *args],
                          cwd=ROOT, capture_output=True, text=True, timeout=1200, check=False)


def test_the_binary_is_the_one_built_from_helios():
    binary = pathlib.Path(os.environ["HELIOS_BIN"]).resolve()
    assert binary.is_relative_to((ROOT / "helios").resolve()), binary
    assert binary.name == "helios" and os.access(binary, os.X_OK)


def test_an_unchanged_stack_passes_the_gate_with_every_scenario_run(tmp_path):
    """WARDEN's real Wave 4 plan, compared with itself: nothing the stack survives today fails, so the change passes -
    every scenario was simulated by the real binary (a row each, none refused for an error)."""
    plan = FIXTURES / "wave4-fullstack" / "plan.json"
    done = _gate(tmp_path, "--plan", str(plan), "--baseline", str(plan))
    assert done.returncode == 0, done.stdout + done.stderr
    rows = [line for line in done.stdout.splitlines() if line.startswith("| ") and not line.startswith("| Scenario")]
    assert rows, done.stdout
    assert not [r for r in rows if "| refuse |" in r], done.stdout
    assert "cannot run it" not in done.stdout


def test_a_plan_that_fails_what_the_stack_survives_is_refused(tmp_path):
    """A plan whose resources fail under its zone outages, with nothing today and nothing accepted for them: the gate
    must refuse it, on the binary's own simulation."""
    plan = FIXTURES / "three-tier-webapp" / "terraform-show.json"
    doc = json.loads(plan.read_text(encoding="utf-8"))
    assert doc.get("values") or doc.get("planned_values"), "the fixture is not a terraform show -json document"
    done = _gate(tmp_path, "--plan", str(plan))
    assert done.returncode == 1, done.stdout + done.stderr
    assert "| refuse |" in done.stdout, done.stdout
    # Refused on the simulation itself: at least one scenario the binary RAN fails (a scenario naming a resource this
    # fixture lacks is refused as "cannot run it" too, which a missing binary would also give).
    simulated = [line for line in done.stdout.splitlines() if "| refuse |" in line and "cannot run it" not in line]
    assert simulated, done.stdout
