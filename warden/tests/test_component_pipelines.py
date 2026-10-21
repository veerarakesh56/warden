"""The repository's split into components (owner, 2026-10-21): each component's CI/CD steps are its own composite
actions (<component>/.github/actions), the root workflows that run them are named by component, every check run keeps
the name a ruleset or the merge checklist knows, and every deploy runs only after its own pipeline's checks passed on
the same commit, in the same run."""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

import workflow_view
from warden import autonomy

ROOT = workflow_view.ROOT
FLOWS = workflow_view.FLOWS
SHARED = {"scan-workflows.yml", "security-review.yml", "deploy-dev.yml", "deploy-prod.yml", "on-merge-dev.yml",
          "on-merge-prod.yml"}


def _flow(name: str) -> dict:
    return yaml.safe_load((FLOWS / name).read_text(encoding="utf-8"))


def test_every_workflow_belongs_to_a_component_or_is_shared():
    names = {p.name for p in workflow_view.files()}
    loose = {n for n in names - SHARED if not n.startswith(tuple(f"{c}-" for c in workflow_view.COMPONENTS))}
    assert loose == set(), loose


def test_every_step_from_this_repository_uses_the_self_repository_syntax():
    """Scan · workflows (zizmor, the check the dev and prod rulesets require) flags `uses: ./x` (self-repository); main's
    workflows already call their reusable workflows with `$/`. A second checkout's Action (`./vendor/...`) is not this
    repository's, so it keeps `./`."""
    for f in workflow_view.files():
        for line in f.read_text(encoding="utf-8").splitlines():
            if "uses: ./" in line:
                assert "uses: ./vendor/" in line, (f.name, line)


def test_every_local_action_a_workflow_runs_is_a_components_composite_action():
    used = {path for f in workflow_view.files() for path in workflow_view.local_actions_used(f)}
    assert used
    for path in used:
        parts = pathlib.PurePosixPath(path).parts
        assert parts[0] in workflow_view.COMPONENTS and parts[1:3] == (".github", "actions"), path
        action = yaml.safe_load((ROOT / path / "action.yml").read_text(encoding="utf-8"))
        assert action["runs"]["using"] == "composite", path


def test_no_component_action_is_left_unused():
    used = {(ROOT / path / "action.yml").resolve() for f in workflow_view.files()
            for path in workflow_view.local_actions_used(f)}
    unused = [str(p.relative_to(ROOT)) for p in workflow_view.actions() if p.resolve() not in used]
    assert unused == []


def test_every_composite_step_runs_its_shell_as_a_workflow_step_would():
    """A workflow's `run:` gets `bash -e {0}` on Linux; a composite step must name its shell, and plain `bash` adds
    `-o pipefail`, which changes what a pipeline's status is. So each names `bash -e {0}`, unless it was Helios's own
    Action step before (helios/action keeps its own)."""
    for path in workflow_view.actions():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for step in doc["runs"]["steps"]:
            if "run" in step:
                assert step.get("shell") == "bash -e {0}", (str(path.relative_to(ROOT)), step.get("name"))


def test_the_check_names_rulesets_and_the_merge_checklist_know_are_unchanged():
    """The dev and prod rulesets require the check run `zizmor` (Scan · workflows); the merge checklist names CI · tool,
    CI · infra, CI · apps and Scan · workflows. A check run is named by its job: those names, and the workflows', stay."""
    scan = _flow("scan-workflows.yml")
    assert scan["name"] == "Scan · workflows"
    assert "zizmor" in scan["jobs"]
    assert all("paths" not in (scan[True][e] or {}) and "paths-ignore" not in (scan[True][e] or {})
               for e in ("push", "pull_request"))
    tool = _flow("warden-ci.yml")
    assert tool["name"] == "CI · tool"
    assert set(tool["jobs"]) == {"security", "check", "docker", "k8s", "db", "terraform"}
    assert tool["jobs"]["k8s"]["name"] == "k8s-regression (k3d, every push; measured on EKS in tests/fixtures/bench)"
    assert _flow("infra-ci.yml")["name"] == "CI · infra"
    assert "check" in _flow("infra-ci.yml")["jobs"]
    assert _flow("demo-app-ci.yml")["name"] == "CI · apps"
    assert set(_flow("demo-app-ci.yml")["jobs"]) == {"check"}
    # No other workflow that runs on a pull request has a check run named `check` (a job's `name:`, or its id).
    others = [f.name for f in workflow_view.files() if f.name not in ("warden-ci.yml", "infra-ci.yml", "demo-app-ci.yml")
              and "pull_request" in _flow(f.name)[True]
              and any(job.get("name", job_id) == "check" for job_id, job in (_flow(f.name).get("jobs") or {}).items())]
    assert others == [], others


def _calls(flow: dict) -> dict[str, str]:
    return {job_id: str(job.get("uses", "")).rsplit("/", 1)[-1] for job_id, job in flow["jobs"].items()}


@pytest.mark.parametrize("name", ["deploy-dev.yml", "deploy-prod.yml", "on-merge-dev.yml", "on-merge-prod.yml"])
def test_every_deploy_waits_for_its_own_pipelines_check_in_the_same_run(name):
    """Owner, 2026-10-21: a deploy runs only after that same pipeline's CI passed for the same commit - infra after
    infra-validate.yml, the apps after demo-app-check.yml - with no path around it."""
    flow = _flow(name)
    calls = _calls(flow)
    check_for = {"infra-deploy.yml": "infra-validate.yml", "demo-app-deploy.yml": "demo-app-check.yml"}
    deploys = {job: callee for job, callee in calls.items() if callee in check_for}
    assert deploys, name
    for job, callee in deploys.items():
        needs = flow["jobs"][job]["needs"]
        needs = [needs] if isinstance(needs, str) else needs
        assert any(calls.get(n) == check_for[callee] for n in needs), (name, job, needs)
        # The check's own condition never leaves it out of a run whose deploy job runs (a skipped `needs` skips it too:
        # GitHub skips a job whose needed job was skipped unless its `if` says otherwise).
        assert "always()" not in str(flow["jobs"][job].get("if", "")), (name, job)


def test_the_runtime_builds_signs_or_deploys_nothing_before_wardens_own_ci_passed():
    flow = _flow("warden-runtime-deploy.yml")
    jobs = flow["jobs"]
    uses = {job_id: [s.get("uses", "") for s in job.get("steps", [])] for job_id, job in jobs.items()}
    assert "$/warden/.github/actions/check" in uses["ci-check"]
    assert "$/warden/.github/actions/security" in uses["ci-security"]
    for job in ("image", "restart"):
        assert set(jobs[job]["needs"]) == {"ci-check", "ci-security"}, job
        assert "always()" not in str(jobs[job].get("if", "")), job
    assert jobs["deploy"]["needs"] == "image"
    on = flow[True]
    assert set(on) == {"workflow_dispatch"}  # by hand only, and every action it offers runs the CI jobs first


def test_each_deploy_uses_its_own_environment_and_its_values_only():
    for name, job_id in (("infra-deploy.yml", "run"), ("demo-app-deploy.yml", "deploy")):
        job = _flow(name)["jobs"][job_id]
        assert job["environment"] == "${{ inputs.environment }}", name
        assert job["env"]["WARDEN_ENV"] == "${{ inputs.environment }}", name
        assert job["env"]["AWS_REGION"] == "${{ vars.AWS_REGION }}", name
        assert job["env"]["BUCKET"] == "${{ vars.TF_STATE_BUCKET }}", name
    for f in workflow_view.files():
        text = f.read_text(encoding="utf-8")
        assert not re.search(r"arn:aws:iam::\d{12}", text), f.name
        assert not re.search(r"\b\d{12}\b", text), f.name


def test_the_view_writes_each_action_out_where_it_runs():
    """workflow_view is how the pipeline tests read the steps that moved into actions: it must put them back."""
    text = workflow_view.text("warden-ci.yml")
    for path in ("check", "k8s-regression", "db", "docker", "security"):
        action = yaml.safe_load((ROOT / "warden" / ".github" / "actions" / path / "action.yml").read_text(encoding="utf-8"))
        for step in action["runs"]["steps"]:
            if step.get("name"):
                assert step["name"] in text, (path, step["name"])
    assert "uses: $/warden/.github/actions/" not in text
    doc = workflow_view.load("infra-deploy.yml")
    names = [s.get("name") for s in doc["jobs"]["run"]["steps"]]
    assert names.index("The commit was promoted from its upstream branch") < names.index("Build Helios from helios/")


@pytest.mark.parametrize("value", ["src/warden/gate.py", "warden/src/warden/gate.py", "infra/iam/dev/deploy.json",
                                   "iam/dev/deploy.json", "infra/terraform/runtime/main.tf", "terraform/runtime/main.tf",
                                   "warden/docs/safety-pins.sha256", "helios/crates/helios-cli/src/main.rs",
                                   "helios/Cargo.lock"])
def test_neither_warden_nor_eldane_may_approve_a_change_to_a_protected_path_in_either_layout(value):
    """Register R6 holds in the repository's components and in a component split out on its own; Helios - the plan
    gate's code, in this repository since 2026-10-21 - is protected too."""
    assert autonomy.touches_protected(value), value
