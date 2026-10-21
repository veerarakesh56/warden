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


def test_an_arm_with_an_empty_name_is_refused():
    with pytest.raises(SystemExit, match="--arm must be K=V, got '=1'"):
        runner._arm_pairs(["=1"])


def _resumable_manifest() -> dict:
    return {"catalog_sha256": runner._catalog_sha256(), "scoring_sha256": runner._sha256(runner.SCORING),
            "evidence_isolation": runner._evidence_isolation("ecs")}


def test_a_resume_under_the_same_catalog_and_rubric_goes_on(tmp_path):
    assert runner._refuse_another_rubric(tmp_path, _resumable_manifest(), "ecs") is None


@pytest.mark.parametrize("changed", [{"catalog_sha256": {"wave1.yaml": "0" * 64}}, {"scoring_sha256": "0" * 64}],
                         ids=["catalog", "rubric"])
def test_a_resume_after_the_catalog_or_the_rubric_changed_is_refused(tmp_path, changed):
    manifest = {**_resumable_manifest(), **changed}
    with pytest.raises(SystemExit, match="the scenario catalog or the rubric has changed"):
        runner._refuse_another_rubric(tmp_path, manifest, "ecs")


def test_an_incomplete_attempt_is_returned_as_superseded(tmp_path):
    gt = tmp_path / "ground-truth"
    gt.mkdir()
    (gt / "ecs-01.json").write_text('{"scenario_id": "ecs-01", "status": "error", "runs": []}', encoding="utf-8")
    todo, superseded, forced = runner._left_to_run(tmp_path, [{"id": "ecs-01"}], 1, ())
    assert [s["id"] for s in todo] == ["ecs-01"]
    assert superseded == ["ground-truth/superseded/ecs-01.attempt-1.json"]
    assert forced == []


@pytest.mark.parametrize(("asked", "answer"), [(ops_db.SENTINEL_TABLE, ops_db.SENTINEL_TABLE), ("public.other", None)],
                         ids=["the-sentinel", "another-table"])
def test_the_fake_database_answers_to_regclass_for_the_table_asked(asked, answer):
    cur = runner._FakeDbConn().cursor()
    assert cur.execute("SELECT to_regclass(%s)", (asked,)).fetchone() == (answer,)
