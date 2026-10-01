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
import re

CI = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci-tool.yml"
INTEGRATION = pathlib.Path(__file__).resolve().parent / "integration"


def test_every_integration_file_is_named_by_a_ci_job():
    workflow = CI.read_text(encoding="utf-8")
    files = sorted(p.name for p in INTEGRATION.glob("test_*.py"))
    assert files, "no integration tests found - has the directory moved?"
    unclaimed = [name for name in files if name not in workflow]
    assert not unclaimed, (
        f"integration test file(s) no CI job runs: {unclaimed}. Add them to a job in ci-tool.yml, or they "
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


def test_one_deploy_workflow_per_configured_environment_and_nothing_else():
    """Deploys are separated per environment: deploy-<env>.yml for exactly the keys of
    environments.yaml, so a GitHub Environment (and its role) exists for nothing else. The files are
    identical apart from the environment's name - the steps live in the shared _*.yml workflows."""
    import pathlib

    import yaml

    from warden.environments import EnvironmentPolicies

    flows = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"
    envs = list(EnvironmentPolicies.load().known_environments)
    files = {p.name for p in flows.glob("deploy-*.yml")}
    assert files == {f"deploy-{e}.yml" for e in envs}, sorted(files)
    shapes = set()
    for env in envs:
        text = (flows / f"deploy-{env}.yml").read_text(encoding="utf-8")
        shapes.add(text.replace(env, "<ENV>"))
        wf = yaml.safe_load(text)
        assert set(wf[True]) == {"workflow_dispatch"}, env  # PyYAML reads the key `on` as True; by hand only
        assert wf["concurrency"] == {"group": f"deploy-{env}", "cancel-in-progress": False}, env
        for job in ("infra", "apps"):
            assert wf["jobs"][job]["with"]["environment"] == env, (env, job)
            assert wf["jobs"][job]["permissions"]["id-token"] == "write", (env, job)
        assert "WARDEN_FS_" not in text and "environment: fullstack" not in text, env
    assert len(shapes) == 1, "the deploy workflows differ in more than the environment's name"


def test_deploys_run_from_main_only_and_name_no_region():
    """Audit A-I-10: a deploy from any other branch fails before it assumes a role. No region is
    written into a workflow: each GitHub Environment carries AWS_REGION (the owner's no-hardcoding rule)."""
    import pathlib

    flows = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"
    for name in ("_infra-deploy.yml", "_apps-deploy.yml"):
        text = (flows / name).read_text(encoding="utf-8")
        guard = text.index("Deploys run from main only")
        assert "if: github.ref != 'refs/heads/main'" in text[guard:guard + 200], name
        assert guard < text.index("configure-aws-credentials"), name
        assert "aws-region: ${{ vars.AWS_REGION }}" in text, name
    for f in flows.glob("*.yml"):
        assert not re.search(r"\b(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:gov-)?(?:north|south|east|west|central)"
                             r"(?:east|west)?-\d\b", f.read_text(encoding="utf-8")), f"a region is written into {f.name}"


def test_every_action_is_pinned_to_a_full_commit_sha():
    """A tag can be moved to other code (the tj-actions and Trivy compromises did exactly that); a
    40-character commit id cannot. zizmor checks this in CI; this test makes it a named control."""
    import re

    uses = [(f.name, m.group(1)) for f in CI.parent.glob("*.yml")
            for m in re.finditer(r"^\s*-?\s*uses:\s*(\S+)", f.read_text(encoding="utf-8"), re.MULTILINE)]
    assert uses
    loose = [(f, u) for f, u in uses if not u.startswith("$/") and not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u)]
    assert loose == [], loose


def test_every_test_that_reads_a_path_the_tool_ci_skips_runs_where_that_path_triggers():
    """Fourth review (2026-09-30): the tool CI skips terraform/fullstack and the infra/apps/deploy
    workflows, and three tests that guard those files (the reader role's least privilege among them)
    ran only in the tool CI - a change to reader.tf alone ran none of them."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    flows = root / ".github" / "workflows"
    runs = {
        "terraform/fullstack": (flows / "_infra-validate.yml").read_text(encoding="utf-8"),
        "k8s/fullstack": (flows / "_apps-check.yml").read_text(encoding="utf-8"),
        "scenarios/fullstack/": (flows / "_apps-check.yml").read_text(encoding="utf-8"),
        ".github/workflows": (flows / "scan-workflows.yml").read_text(encoding="utf-8"),
    }
    # Named in a string only, not read: the register's reason for a module-level skip, and this test's
    # own table (it runs in the workflow scan).
    exempt = {"test_register.py", "test_ci_lanes.py"}
    # Joined spellings read as one path: `ROOT / "k8s" / "fullstack"` named no path the table knew, and
    # the test could leave the apps check unnoticed (fifth review, 2026-10-01).
    joined = re.compile(r'''(["'])\s*/\s*(["'])''')
    missing = [(p.name, path) for p in sorted((root / "tests").glob("test_*.py")) if p.name not in exempt
               for path, workflow in runs.items()
               if path in joined.sub("/", p.read_text(encoding="utf-8")) and p.name not in workflow]
    assert not missing, missing


def test_a_run_on_main_is_never_cancelled_by_the_next_push():
    """Fourth review E-6: a group per branch on main cancelled the PENDING run of the commit in between, which
    was then never checked. Each push to main gets its own group; only pull requests cancel."""
    import pathlib

    import yaml

    flows = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"
    checked = 0
    for name in ("ci-tool.yml", "ci-infra.yml", "ci-apps.yml", "scan-workflows.yml"):
        group = yaml.safe_load((flows / name).read_text(encoding="utf-8"))["concurrency"]
        assert group["group"].endswith("${{ github.event_name == 'pull_request' && github.ref || github.sha }}"), name
        assert group["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}", name
        checked += 1
    assert checked == 4
