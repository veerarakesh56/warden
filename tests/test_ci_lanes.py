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
