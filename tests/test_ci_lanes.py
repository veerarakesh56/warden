"""Every integration test must be claimed by a CI job.

The integration suites each need their own infrastructure — a k3d cluster for the Kubernetes files,
service containers for the database file — so CI runs them in separate jobs, each naming its files
explicitly. That creates a silent-failure mode worth guarding: **a new file in `tests/integration/`
that no job runs**. It would be green everywhere, forever, having never executed.

This is the same failure this repo has been bitten by before — a check that passes because nothing
ran. It cost a real CI failure when `test_live_database.py` was added to a directory the Kubernetes
job ran wholesale with a zero-skips assertion.
"""

from __future__ import annotations

import pathlib

CI = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
INTEGRATION = pathlib.Path(__file__).resolve().parent / "integration"


def test_every_integration_file_is_named_by_a_ci_job():
    workflow = CI.read_text(encoding="utf-8")
    files = sorted(p.name for p in INTEGRATION.glob("test_*.py"))
    assert files, "no integration tests found - has the directory moved?"
    unclaimed = [name for name in files if name not in workflow]
    assert not unclaimed, (
        f"integration test file(s) no CI job runs: {unclaimed}. Add them to a job in ci.yml, or they "
        "will never execute and every run will still be green."
    )


def test_the_database_suite_is_not_run_by_the_cluster_job():
    """The cluster job asserts ZERO skips. If it also collected the database suite, that suite would
    skip (no DSNs in that job) and fail the assertion — which is exactly what happened once."""
    workflow = CI.read_text(encoding="utf-8")
    cluster_step = workflow.split("Integration tests against the live cluster", 1)[1].split("- name:", 1)[0]
    assert "test_live_database.py" not in cluster_step, (
        "the cluster job must not collect the database suite - it has no database service containers, "
        "so those tests would skip and trip the zero-skips guard"
    )
    assert "tests/integration/test_live_cluster.py" in cluster_step, "cluster job lost its own suite"


def test_deploy_workflows_offer_exactly_the_configured_environments():
    """Phase 1.5: a deploy picks one environment; the choices are the keys of environments.yaml, so
    a GitHub Environment (and its role) exists for nothing else, and no workflow uses the old
    shared `fullstack` environment or WARDEN_FS_* variables."""
    import pathlib

    import yaml

    from warden.environments import EnvironmentPolicies

    root = pathlib.Path(__file__).resolve().parents[1]
    envs = list(EnvironmentPolicies.load().known_environments)
    for name in ("infra.yml", "apps.yml"):
        text = (root / ".github" / "workflows" / name).read_text(encoding="utf-8")
        wf = yaml.safe_load(text)
        inputs = wf[True]["workflow_dispatch"]["inputs"]  # PyYAML reads the key `on` as True
        assert inputs["environment"]["options"] == envs, name
        assert "WARDEN_FS_" not in text and "environment: fullstack" not in text, name
        job = next(j for j in wf["jobs"].values() if "id-token" in (j.get("permissions") or {}))
        assert job["environment"] == "${{ inputs.environment }}", name


def test_every_action_is_pinned_to_a_full_commit_sha():
    """A tag can be moved to other code (the tj-actions and Trivy compromises did exactly that); a
    40-character commit id cannot. zizmor checks this in CI; this test makes it a named control."""
    import re

    uses = [(f.name, m.group(1)) for f in CI.parent.glob("*.yml")
            for m in re.finditer(r"^\s*-?\s*uses:\s*(\S+)", f.read_text(encoding="utf-8"), re.MULTILINE)]
    assert uses
    loose = [(f, u) for f, u in uses if not u.startswith("./") and not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u)]
    assert loose == [], loose
