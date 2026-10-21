"""Each environment's apps deploy onto its own stack only (owner, 2026-10-21): the pipeline names the environment it
deploys (WARDEN_ENV, from the GitHub Environment the job runs in), and demo-app/scripts/deploy_fullstack_apps.py
refuses a stack.json of any other environment before it makes a single AWS client."""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("deploy_apps_isolation", ROOT / "demo-app" / "scripts" / "deploy_fullstack_apps.py")
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


def _stack(tmp_path: pathlib.Path, environment: str | None) -> pathlib.Path:
    doc = {"region": {"value": "ap-south-2", "sensitive": False}, "lambda_functions": {"value": {}, "sensitive": False}}
    if environment is not None:
        doc["environment"] = {"value": environment, "sensitive": False}
    path = tmp_path / "stack.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _aws_that_must_not_be_called(service):
    raise AssertionError(f"an AWS client ({service}) was made for another environment's stack")


@pytest.mark.parametrize("stack_env", ["prod", "ops", None])
def test_a_dev_run_cannot_read_another_environments_stack(tmp_path, monkeypatch, stack_env):
    _stack(tmp_path, stack_env)
    monkeypatch.setenv("WARDEN_ENV", "dev")
    with pytest.raises(SystemExit, match="refused: this run deploys 'dev'"):
        tool.main(["--out", str(tmp_path), "deploy", "lambdas"], aws=_aws_that_must_not_be_called, runner=lambda *a, **k: "")


def test_a_prod_run_cannot_read_devs_stack(tmp_path, monkeypatch):
    _stack(tmp_path, "dev")
    monkeypatch.setenv("WARDEN_ENV", "prod")
    with pytest.raises(SystemExit, match="refused: this run deploys 'prod'"):
        tool.main(["--out", str(tmp_path), "deploy", "lambdas"], aws=_aws_that_must_not_be_called, runner=lambda *a, **k: "")


def test_a_run_deploys_onto_its_own_environments_stack(tmp_path, monkeypatch):
    _stack(tmp_path, "dev")
    monkeypatch.setenv("WARDEN_ENV", "dev")
    made = []
    assert tool.main(["--out", str(tmp_path), "deploy", "lambdas"], aws=lambda s: made.append(s),
                     runner=lambda *a, **k: "") == 0  # no function in this stack: nothing to update


def test_the_deploy_job_names_its_environment_from_the_github_environment_it_runs_in():
    flow = yaml.safe_load((ROOT / ".github" / "workflows" / "demo-app-deploy.yml").read_text(encoding="utf-8"))
    (job,) = flow["jobs"].values()
    assert job["environment"] == "${{ inputs.environment }}"
    assert job["env"]["WARDEN_ENV"] == "${{ inputs.environment }}"
    # Its role, region and state bucket are that environment's own; nothing names one environment's value.
    assert job["env"]["BUCKET"] == "${{ vars.TF_STATE_BUCKET }}"
    assert job["env"]["AWS_REGION"] == "${{ vars.AWS_REGION }}"
    text = (ROOT / ".github" / "workflows" / "demo-app-deploy.yml").read_text(encoding="utf-8")
    assert "role-to-assume: ${{ secrets.AWS_ROLE_ARN }}" in text
