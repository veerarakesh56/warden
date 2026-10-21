"""scenarios/runner.py's command line, split into steps (Sonar S3776): what each step refuses, and which harness a
backend gets. Dry runs only - nothing here reaches AWS or a cluster."""

from __future__ import annotations

import pytest
from scenarios import ops, ops_db, ops_k8s, runner


def test_an_arm_that_is_not_k_equals_v_is_refused(tmp_path):
    argv = ["--wave", "1", "--dry-run", "--arm", "NOVALUE", "--out", str(tmp_path)]
    with pytest.raises(SystemExit, match="--arm must be K=V, got 'NOVALUE'"):
        runner.main(argv)


def test_an_arm_pair_keeps_everything_after_the_first_equals_sign():
    assert runner._arm_pairs(["A=1", "B=x=y", "C="]) == {"A": "1", "B": "x=y", "C": ""}


def test_only_that_matches_no_scenario_is_refused(tmp_path):
    argv = ["--wave", "1", "--dry-run", "--only", "nope-", "--out", str(tmp_path)]
    with pytest.raises(SystemExit, match="--only 'nope-' matched no scenario in wave 1"):
        runner.main(argv)


def test_only_keeps_the_scenarios_whose_id_starts_with_a_given_prefix():
    _doc, scenarios = runner._wave_scenarios(1, " ecs-01 , ecs-02,")
    assert [s["id"].split("-")[1] for s in scenarios] == ["01", "02"]


@pytest.mark.parametrize(("kind", "registry"), [("ecs", ops.OPS), ("k8s", ops_k8s.OPS), ("db", ops_db.OPS)])
def test_each_backend_gets_its_own_dry_harness(kind, registry):
    assert runner._harness(kind, dry_run=True, warden_timeout=1.0).registry is registry
