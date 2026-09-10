"""The wave loop, against a stubbed AWS account and a stubbed WARDEN.

⚠ WHAT THESE PROVE, STATED PLAINLY. They prove the wiring: that WARDEN is handed the identity it is
supposed to be limited to, that the account is put back even when things go wrong, and that a wave
stops rather than publishing contaminated results. They prove **nothing** about AWS. A guard that
passes against a fake proves the request was made, not that the outcome was right — this project has
already had a `resourceVersion` precondition pass every unit test and then be rejected by a live
cluster.

The two that matter most are `test_warden_never_sees_the_operators_credentials` and
`test_a_failed_revert_stops_the_wave`, and both are written adversarially: the fake is set up to
fail, and the assertion is about what the runner does about it.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from scenarios import runner
from scenarios.ops import Clients, OpError, Target

OPERATOR_KEY = "AKIAOPERATORKEYDONOTUSE"
READER_ARN = "arn:aws:sts::111122223333:assumed-role/warden-pg-reader/warden-benchmark"


class FakeEcs:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def describe_clusters(self, **kw):
        self.calls.append(("describe_clusters", kw))
        return {"clusters": [{"tags": [{"key": "Project", "value": "warden-proving-ground"}]}]}

    def update_service(self, **kw):
        self.calls.append(("update_service", kw))
        return {}


@pytest.fixture
def target():
    return Target(
        region="ap-south-1", cluster="warden-pg-a1b2", service="checkout",
        log_group="/ecs/checkout",
        baseline_task_definition="arn:aws:ecs:r:1:task-definition/checkout:2",
        warden_role_name="warden-pg-a1b2-reader",
    )


def _harness(target, *, invoke=None, ecs=None, **overrides) -> runner.Harness:
    ecs = ecs or FakeEcs()
    return runner.Harness(
        clients=Clients(ecs=ecs, logs=ecs, ec2=ecs, iam=ecs),
        target=target,
        account="111122223333",
        assume_reader=lambda: {
            "AWS_ACCESS_KEY_ID": "ASIAREADER", "AWS_SECRET_ACCESS_KEY": "s",
            "AWS_SESSION_TOKEN": "t", "arn": READER_ARN,
        },
        invoke_warden=invoke or (lambda env, path: (runner._write_json(path, {"ok": True}), 0, "")[1:]),
        sleep=lambda _s: None,
        **overrides,
    )


SCENARIO = {
    "id": "unit-01",
    "fault_class": "desired_count_zero",
    "fidelity": "real",
    "settle_seconds": 5,
    "inject": [{"op": "ecs_set_desired_count", "count": 0}],
    "revert": [{"op": "ecs_set_desired_count", "count": 2}],
}


# --------------------------------------------------------------------------- the identity


def test_warden_never_sees_the_operators_credentials(monkeypatch, target):
    """⛔ The load-bearing one.

    Scenario `ecs-11` removes an action from the role WARDEN runs as. Under the operator's own
    credentials it would remove a permission nobody was using, and the scenario would pass while
    measuring nothing — a defect this project shipped once and caught. So the environment is built
    from nothing, and the operator's identity must not survive into it by any route: not the keys
    themselves, not `AWS_PROFILE`, and not a home directory that contains `~/.aws/credentials`.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", OPERATOR_KEY)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "operator-secret")
    monkeypatch.setenv("AWS_PROFILE", "operator")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/home/op/.aws/credentials")
    monkeypatch.setenv("HOME", "/home/op")
    monkeypatch.setenv("USERPROFILE", r"C:\Users\op")

    env = runner.warden_env(
        {"AWS_ACCESS_KEY_ID": "ASIAREADER", "AWS_SECRET_ACCESS_KEY": "s",
         "AWS_SESSION_TOKEN": "t", "arn": READER_ARN},
        target, {},
    )

    assert env["AWS_ACCESS_KEY_ID"] == "ASIAREADER"
    assert OPERATOR_KEY not in env.values()
    for leak in ("AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "HOME", "USERPROFILE"):
        assert leak not in env, f"{leak} would let the child fall back to the operator's identity"


def test_the_model_provider_key_does_come_through(monkeypatch, target):
    """The allowlist has to be narrow AND sufficient: WARDEN cannot reason without a key."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    monkeypatch.setenv("WARDEN_PROVIDER", "anthropic")
    env = runner.warden_env(
        {"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b", "AWS_SESSION_TOKEN": "c"},
        target, {},
    )
    assert env["ANTHROPIC_API_KEY"] == "sk-ant-not-a-real-key"
    assert env["WARDEN_PROVIDER"] == "anthropic"
    assert env["WARDEN_BACKEND"] == "aws"
    assert env["WARDEN_AWS_CLUSTER"] == target.cluster


def test_an_arm_can_override_but_is_recorded(target):
    """The ablation arm is just env, so it needs no runner change — but it must be visible."""
    env = runner.warden_env(
        {"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b", "AWS_SESSION_TOKEN": "c"},
        target, {"WARDEN_KNOWLEDGE_IN_PROMPT": "1"},
    )
    assert env["WARDEN_KNOWLEDGE_IN_PROMPT"] == "1"


def test_the_assumed_role_arn_is_recorded_for_every_run(tmp_path, target):
    """"WARDEN ran with four read actions and nothing else" is only checkable if the artefact says
    which identity it ran as."""
    record = runner.run_scenario(_harness(target), SCENARIO, tmp_path, repeat=2, arm={})
    assert [r["assumed_role_arn"] for r in record["runs"]] == [READER_ARN, READER_ARN]


# --------------------------------------------------------------------------- putting it back


def test_the_revert_runs_even_when_warden_fails(tmp_path, target):
    """A benchmark that leaves the account broken on failure is worse than one that never ran."""
    ecs = FakeEcs()

    def exploding(env, path):
        raise RuntimeError("warden fell over")

    record = runner.run_scenario(
        _harness(target, invoke=exploding, ecs=ecs), SCENARIO, tmp_path, repeat=1, arm={},
    )
    assert record["status"] == "error"
    assert "warden fell over" in record["error"]
    assert record["revert_ok"] is True
    desired = [kw.get("desiredCount") for name, kw in ecs.calls if name == "update_service"]
    assert desired == [0, 2], "the service must be put back to 2 even though the run blew up"


def test_a_nonzero_exit_is_recorded_not_skipped(tmp_path, target):
    """`warden.cli` returns 0 for every verdict, so a non-zero exit means the RUN failed. It is
    recorded with its stderr and counts against the totals; a benchmark that quietly drops its
    failures is measuring the runs that happened to work."""
    record = runner.run_scenario(
        _harness(target, invoke=lambda env, path: (1, "BudgetExceeded: $0.50")),
        SCENARIO, tmp_path, repeat=1, arm={},
    )
    assert record["status"] == "ok"
    assert record["runs"][0]["exit_code"] == 1
    assert "BudgetExceeded" in record["runs"][0]["stderr_tail"]
    assert record["runs"][0]["report_written"] is False


def test_a_failed_revert_stops_the_wave(tmp_path, target):
    """⛔ The other load-bearing one.

    Every scenario after a failed revert would be graded against a contaminated account while
    looking like a perfectly normal run, and nothing in the output would say so. So the wave stops,
    loudly, and the scenarios that did complete are still reported.
    """
    class RefusingEcs(FakeEcs):
        def __init__(self):
            super().__init__()
            self.seen = 0

        def update_service(self, **kw):
            self.seen += 1
            if self.seen == 2:  # the revert
                raise OpError("AccessDenied")
            return super().update_service(**kw)

    done: list[dict] = []
    with pytest.raises(runner.RunnerError, match="revert FAILED"):
        runner.run_wave(
            _harness(target, ecs=RefusingEcs()),
            [SCENARIO, {**SCENARIO, "id": "unit-02"}],
            tmp_path, repeat=1, arm={}, log=lambda _m: None, records=done,
        )
    assert [r["scenario_id"] for r in done] == ["unit-01"], "the second scenario must not have run"
    assert not (tmp_path / "ground-truth" / "unit-02.json").exists()


# --------------------------------------------------------------------------- the artefacts


def test_ground_truth_is_written_before_anything_is_injected(tmp_path, target):
    """A run that dies half way must still say what it was in the middle of, or the account is left
    broken with no note of it."""
    seen: list[bool] = []
    gt = tmp_path / "ground-truth" / "unit-01.json"

    class WatchingEcs(FakeEcs):
        def update_service(self, **kw):
            seen.append(gt.exists())
            return super().update_service(**kw)

    runner.run_scenario(_harness(target, ecs=WatchingEcs()), SCENARIO, tmp_path, repeat=1, arm={})
    assert seen and seen[0] is True


def test_repeat_produces_one_report_per_run(tmp_path, target):
    record = runner.run_scenario(_harness(target), SCENARIO, tmp_path, repeat=3, arm={})
    assert [r["index"] for r in record["runs"]] == [1, 2, 3]
    assert sorted(p.name for p in (tmp_path / "reports").glob("*.json")) == [
        "unit-01.1.json", "unit-01.2.json", "unit-01.3.json",
    ]


def test_the_catalog_loads_and_wave_1_is_intact():
    doc, scenarios = runner.load_wave(1)
    assert doc["service"] == "ecs"
    assert len(scenarios) == 14
    assert all(s.get("settle_seconds") for s in scenarios if s["inject"] or True)


def test_an_unknown_wave_is_an_error_not_an_empty_run():
    with pytest.raises(runner.RunnerError, match="no catalog file declares wave"):
        runner.load_wave(99)


def test_terraform_outputs_missing_the_essentials_are_refused():
    with pytest.raises(runner.RunnerError, match="missing"):
        runner.target_from_outputs({"region": "ap-south-1"})


# --------------------------------------------------------------------------- the dry run


def test_the_dry_run_completes_the_whole_wave(tmp_path):
    """⚠ This proves the loop and the artefact layout hold together. It proves nothing about AWS:
    no fault is injected, no permission is removed, and every report is canned."""
    rc = runner.main(["--wave", "1", "--dry-run", "--repeat", "1", "--out", str(tmp_path)])
    assert rc == 0
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["dry_run"] is True
    assert len(manifest["scenarios_completed"]) == 14
    assert manifest["errors"] == []
    assert len(list((tmp_path / "reports").glob("*.json"))) == 14


def test_the_manifest_pins_the_rubric_and_the_catalog(tmp_path):
    """A result is only re-checkable if you know which rubric graded it. `scoring.yaml` is committed
    before the run it grades, and the hash is what ties the two together afterwards."""
    runner.main(["--wave", "1", "--dry-run", "--repeat", "1", "--only", "ecs-01",
                 "--out", str(tmp_path)])
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["scoring_sha256"]) == 64
    assert manifest["catalog_sha256"]["wave1-ecs.yaml"]
    assert manifest["alert"]["name"] == "ECSServiceAlarm"


def test_the_benchmark_alert_names_no_cause():
    """⛔ `graph.py` puts the alert's name and summary straight into the reasoning prompt. An alert
    called `PodOOMKilled` hands the model the answer on every OOM scenario and misleads it on the
    rest, so the one alert every scenario shares must not name a fault."""
    import yaml

    alert = yaml.safe_load(runner.ALERT_FILE.read_text(encoding="utf-8"))
    blob = f"{alert['name']} {alert['summary']}".lower()
    _doc, scenarios = runner.load_wave(1)
    for word in ("oom", "memory", "crash", "pull", "secret", "route", "permission", "denied"):
        assert word not in blob, f"the benchmark alert mentions {word!r} - it names the answer"
    for scenario in scenarios:
        assert scenario["fault_class"] not in blob
        assert scenario["id"] not in blob


def test_the_runner_does_not_import_the_tool_under_test():
    """The same separation `ops.py` has. The harness drives WARDEN as a subprocess; if it could
    import it, a reader would be right to ask what else they share."""
    import ast
    import inspect

    src = pathlib.Path(inspect.getsourcefile(runner)).read_text(encoding="utf-8")
    offenders: list[str] = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            offenders += [a.name for a in node.names if a.name.split(".")[0] == "warden"]
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "warden":
            offenders.append(node.module or "")
    assert not offenders, f"scenarios/runner.py must not import warden; found {offenders}"


def test_a_stale_report_is_not_scored_as_this_runs_answer(tmp_path, target):
    """⛔ `warden.cli` only writes its JSON when it gets far enough to have something to write. So a
    re-used --out directory would leave the PREVIOUS run's answer where this run's should be,
    `report_written` would say True, and the scorer would grade the old report as though it were
    this one. Nothing anywhere would look wrong."""
    stale = tmp_path / "reports" / "unit-01.1.json"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text('{"proposal": {"action": "scale_up"}}', encoding="utf-8")

    record = runner.run_scenario(
        _harness(target, invoke=lambda env, path: (1, "died before writing anything")),
        SCENARIO, tmp_path, repeat=1, arm={},
    )
    assert record["runs"][0]["report_written"] is False
    assert not stale.exists(), "the previous run's report must not survive into this one"


def test_the_abort_message_does_not_claim_something_is_broken_when_nothing_was_injected(
    tmp_path, target
):
    """Two different situations reach the abort. Telling an operator to go repair an account that
    was never touched wastes exactly the time they do not have."""
    class RefusingEcs(FakeEcs):
        def update_service(self, **kw):
            raise OpError("Throttling")

    with pytest.raises(runner.RunnerError, match="may simply have had nothing to restore"):
        runner.run_wave(_harness(target, ecs=RefusingEcs()), [SCENARIO], tmp_path,
                        repeat=1, arm={}, log=lambda _m: None)


def test_the_abort_message_does_say_so_when_something_is_still_broken(tmp_path, target):
    class RefusingRevert(FakeEcs):
        def __init__(self):
            super().__init__()
            self.seen = 0

        def update_service(self, **kw):
            self.seen += 1
            if self.seen == 2:
                raise OpError("AccessDenied")
            return super().update_service(**kw)

    with pytest.raises(runner.RunnerError, match="something IS still broken"):
        runner.run_wave(_harness(target, ecs=RefusingRevert()), [SCENARIO], tmp_path,
                        repeat=1, arm={}, log=lambda _m: None)
