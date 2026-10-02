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


def test_a_lane_runs_when_a_test_file_its_check_runs_changes():
    """Ninth review CI run (2026-10-01): CI · infra runs six test files but triggered on one, so a check that
    could not work in its environment (the live-count test, without the k8s extra) stayed hidden until that one
    file changed. Every test file a lane's check job runs is one of the lane's trigger paths, push and PR."""
    import re

    import yaml

    flows = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"
    for check, lane in (("_infra-validate.yml", "ci-infra.yml"), ("_apps-check.yml", "ci-apps.yml")):
        text = (flows / check).read_text(encoding="utf-8")
        runs = {f for line in text.splitlines() if line.strip().startswith("- run: pytest ")
                for f in re.findall(r"tests/[\w/]+\.py", line)}
        on = yaml.safe_load((flows / lane).read_text(encoding="utf-8"))[True]  # YAML 1.1 reads `on` as True
        for trigger in ("push", "pull_request"):
            missing = runs - set(on[trigger]["paths"])
            assert runs and not missing, (lane, trigger, sorted(missing))


def test_the_pod_security_check_accepts_only_pod_securitys_own_reason():
    """Ninth review (2026-10-01): it accepted any "forbidden" - on 5fdcff4 the privileged pod was refused because the
    namespace's default ServiceAccount did not exist yet, and the step went green without Pod Security deciding."""
    text = (pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci-tool.yml").read_text(
        encoding="utf-8")
    step = text.split("Pod Security must REJECT a privileged pod", 1)[1].split("- name:", 1)[0]
    greps = re.findall(r"grep [^\n|]*?err\.txt", step)
    assert greps == ['grep -q "violates PodSecurity" err.txt'], greps
    assert "serviceaccount default -n warden" in step


def test_every_workflow_is_scanned_on_every_push_and_pull_request():
    """Audit A-I-15: the security job skipped infra and apps changes. The workflow scan (zizmor) runs on every push to
    main and every pull request, with no path filter, so a change to any workflow is scanned."""
    import yaml

    flows = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"
    scan = yaml.safe_load((flows / "scan-workflows.yml").read_text(encoding="utf-8"))
    on = scan[True]  # YAML 1.1 reads `on` as True
    assert "push" in on and "pull_request" in on, on
    assert all("paths" not in (on[t] or {}) and "paths-ignore" not in (on[t] or {}) for t in ("push", "pull_request"))
    assert any("zizmor" in str(step.get("run", "")) + str(step.get("uses", ""))
               for job in scan["jobs"].values() for step in job.get("steps", []))


def test_every_ci_image_build_uses_the_hosts_network():
    """Audit R5-E3: inside Docker's bridge network the image build's package downloads crawled (48 packages in
    3m49s-4m44s) and the k8s job took 264-320 s; on the host's network it took 97 s. Every docker build in CI keeps it."""
    text = (pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci-tool.yml").read_text(
        encoding="utf-8")
    builds = re.findall(r"docker build[^\n]*", text)
    assert builds and all("--network=host" in b for b in builds), builds
