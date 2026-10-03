"""Register R56: Helios checks every Terraform change. scripts/helios_gate.py refuses a plan that fails
anything under a scenario today's stack survives, refuses what Helios cannot run, re-checks on the applied
state what a plan cannot decide, and runs Helios without the job's credentials; the deploy job applies only
the plan Helios checked."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("helios_gate", ROOT / "scripts" / "helios_gate.py")
gate = importlib.util.module_from_spec(_spec)
sys.modules["helios_gate"] = gate
_spec.loader.exec_module(gate)
ACCEPTED = {"az-outage": ["aws_nat_gateway.this"], "redis-loss": ["aws_elasticache_replication_group.redis"]}


def test_a_failure_the_stack_survives_today_refuses_the_change():
    verdict, why = gate.judge("lose-z1", {"aws_nat_gateway.this", "aws_lb.app"}, {"aws_nat_gateway.this"}, {})
    assert verdict == "refuse" and "aws_lb.app" in why


def test_failures_the_stack_has_today_or_that_are_accepted_pass():
    assert gate.judge("lose-z1", {"aws_lb.app"}, {"aws_lb.app"}, {})[0] == "ok"
    assert gate.judge("lose-z1", {"aws_nat_gateway.this"}, None, ACCEPTED)[0] == "ok"  # a first create
    assert gate.judge("redis-loss", {"aws_elasticache_replication_group.redis"}, None, ACCEPTED)[0] == "ok"
    assert gate.judge("redis-loss", {"aws_nat_gateway.this"}, None, ACCEPTED)[0] == "refuse"  # zone acceptance stays per kind


def test_the_accepted_failures_excuse_nothing_once_the_stack_exists():
    """Found by running Helios on the Wave 4 state with the endpoints moved to the second zone: the accepted
    zone failures (the first zone's endpoints) hid the second zone's new ones."""
    verdict, why = gate.judge("lose-z2", {"aws_nat_gateway.this"}, set(), ACCEPTED)
    assert verdict == "refuse" and "aws_nat_gateway.this" in why


def test_what_helios_cannot_run_refuses_and_what_it_cannot_decide_waits_for_the_applied_state():
    assert gate.judge("redis-loss", ("error", "scenario names x"), set(), ACCEPTED)[0] == "refuse"
    assert gate.judge("lose-z1", "inconclusive", set(), ACCEPTED)[0] == "later"


def _doc(*zones, key="planned_values"):
    subnets = [{"type": "aws_subnet", "values": {"availability_zone": z}} for z in zones]
    return {key: {"root_module": {"resources": subnets[:1], "child_modules": [{"resources": subnets[1:]}]}}}


def test_the_zones_come_from_the_document_itself():
    assert gate.zones(_doc("zone-b", "zone-a", "zone-a")) == ["zone-a", "zone-b"]
    assert gate.zones(_doc("zone-c", key="values")) == ["zone-c"]
    assert gate.zones({"format_version": "1.0"}) == []


def _run(tmp_path, monkeypatch, outcomes, *, after=False, baseline=True):
    plan, state = tmp_path / "plan.json", tmp_path / "state.json"
    plan.write_text(json.dumps(_doc("zone-a")), encoding="utf-8")
    state.write_text(json.dumps(_doc("zone-a", key="values") if baseline else {"format_version": "1.0"}), encoding="utf-8")

    def fake(helios, document, scenario):
        return outcomes[(pathlib.Path(document).name, scenario.stem)]
    monkeypatch.setattr(gate, "simulate", fake)
    target = ["--after", str(state)] if after else ["--plan", str(plan)]
    return gate.main(["--helios", "helios", *target, "--baseline", str(state), "--out-dir", str(tmp_path / "s")])


def _all(doc, value):
    names = [p.stem for p in (gate.HELIOS / "scenarios").glob("*.json")] + ["lose-zone-a"]
    return {(doc, n): value for n in names}


def test_main_refuses_a_regressing_plan_and_passes_an_unchanged_one(tmp_path, monkeypatch, capsys):
    same = {**_all("plan.json", set()), **_all("state.json", set())}
    assert _run(tmp_path, monkeypatch, same) == 0
    worse = {**same, ("plan.json", "lose-zone-a"): {"aws_lb.app"}}
    assert _run(tmp_path, monkeypatch, worse) == 1
    assert "| lose-zone-a | refuse |" in capsys.readouterr().out


def test_an_undecided_plan_passes_and_is_refused_if_still_undecided_after_apply(tmp_path, monkeypatch):
    outcomes = {**_all("plan.json", set()), **_all("state.json", set()), ("plan.json", "lose-zone-a"): "inconclusive"}
    assert _run(tmp_path, monkeypatch, outcomes) == 0
    outcomes[("state.json", "lose-zone-a")] = "inconclusive"
    assert _run(tmp_path, monkeypatch, outcomes, after=True) == 1


def test_helios_gets_none_of_the_job_credentials(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
        monkeypatch.setenv(k, "x")
    env = gate._bare_env()
    assert set(env) <= {"PATH", "Path", "SYSTEMROOT", "SystemRoot"} and any(k.upper() == "PATH" for k in env)


def test_a_document_that_is_not_terraform_json_is_refused(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text("{}", encoding="utf-8")
    assert gate.main(["--helios", "h", "--plan", str(bad), "--out-dir", str(tmp_path / "s")]) == 1


def test_every_scenario_and_accepted_failure_names_a_resource_the_stack_declares():
    tf = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "terraform" / "fullstack").glob("*.tf"))
    declared = set(re.findall(r'^resource "(\w+)" "(\w+)"', tf, re.MULTILINE))
    accepted = json.loads((gate.HELIOS / "accepted.json").read_text(encoding="utf-8"))
    ids = [a for v in accepted.values() for a in v]
    ids += [json.loads(p.read_text(encoding="utf-8"))["kind"]["resource_id"] for p in (gate.HELIOS / "scenarios").glob("*.json")]
    for rid in ids:
        kind, name = rid.split("[")[0].split(".")
        assert (kind, name) in declared, rid
    assert set(accepted) == {"az-outage"} | {p.stem for p in (gate.HELIOS / "scenarios").glob("*.json")}


@pytest.fixture
def deploy():
    return (ROOT / ".github" / "workflows" / "_infra-deploy.yml").read_text(encoding="utf-8")


def test_the_deploy_applies_only_the_plan_helios_checked(deploy):
    assert re.search(r"HELIOS_COMMIT: [0-9a-f]{40}\b", deploy)
    assert "--locked" in deploy
    assert deploy.index("Build Helios at a pinned commit") < deploy.index("configure-aws-credentials")
    order = ["show -json > \"$RUNNER_TEMP/before.json\"", "plan -input=false -no-color -out=\"$RUNNER_TEMP/tfplan\"",
             "helios_gate.py --helios \"$HELIOS_BIN\" --plan", "apply -input=false -no-color \"$RUNNER_TEMP/tfplan\"",
             "helios_gate.py --helios \"$HELIOS_BIN\" --after"]
    assert [deploy.index(s) for s in order] == sorted(deploy.index(s) for s in order)
    assert "-auto-approve -no-color\n" not in deploy.split("name: destroy")[0]  # no fresh, unchecked plan is applied
    assert deploy.count("set -o pipefail") >= 2  # tee would hide the gate's exit code
