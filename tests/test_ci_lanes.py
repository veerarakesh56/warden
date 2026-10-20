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
import subprocess

import pytest

CI =pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci-tool.yml"
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


FLOWS = CI.parent
DEPLOYS = ("/_apps-deploy.yml", "/_infra-deploy.yml")
PROMOTION_CHECK = "The commit was promoted from its upstream branch"


def _promotion_order() -> dict[str, str]:
    """{environment: the branch it is promoted from}. Owner, 2026-10-16: main -> dev -> prod, each environment
    deployed only from the branch of its own name; environments.yaml lists the environments in that order."""
    from warden.environments import EnvironmentPolicies

    envs = list(EnvironmentPolicies.load().known_environments)
    return dict(zip(envs, ["main", *envs], strict=False))


def _shape(text: str, env: str) -> str:
    """A per-environment workflow with its two names taken out: the environment's, and its upstream branch's."""
    text = re.sub(r"(?m)^(\s+upstream:) \S+$", r"\1 <UPSTREAM>", text)
    return re.sub(rf"\b{re.escape(env)}\b", "<ENV>", text.replace("/dev/null", "<NULL>"))  # not "production"


def _holds_aws(wf: dict) -> bool:
    """A workflow that can reach AWS: it calls a deploy, assumes a role itself, or asks for an OIDC token."""
    return any(str(job.get("uses", "")).endswith(DEPLOYS) or (job.get("permissions") or {}).get("id-token") == "write"
               or any("aws-actions/configure-aws-credentials@" in str(s.get("uses", "")) for s in job.get("steps", []))
               for job in (wf.get("jobs") or {}).values())


def test_one_deploy_workflow_per_configured_environment_and_nothing_else():
    """Deploys are separated per environment: deploy-<env>.yml for exactly the keys of
    environments.yaml, so a GitHub Environment (and its role) exists for nothing else. The files are
    identical apart from the environment's name and the branch it is promoted from (owner, 2026-10-16) - the steps
    live in the shared _*.yml workflows."""
    import yaml

    order = _promotion_order()
    files = {p.name for p in FLOWS.glob("deploy-*.yml")}
    assert files == {f"deploy-{e}.yml" for e in order}, sorted(files)
    shapes = set()
    for env, upstream in order.items():
        text = (FLOWS / f"deploy-{env}.yml").read_text(encoding="utf-8")
        shapes.add(_shape(text, env))
        wf = yaml.safe_load(text)
        assert set(wf[True]) == {"workflow_dispatch"}, env  # PyYAML reads the key `on` as True; by hand only
        assert wf["concurrency"] == {"group": f"deploy-{env}", "cancel-in-progress": False}, env
        for job in ("infra", "apps"):
            assert wf["jobs"][job]["with"]["environment"] == env, (env, job)
            assert wf["jobs"][job]["with"]["upstream"] == upstream, (env, job)
            assert wf["jobs"][job]["permissions"]["id-token"] == "write", (env, job)
        assert "WARDEN_FS_" not in text and "environment: fullstack" not in text, env
    assert len(shapes) == 1, "the deploy workflows differ in more than the environment's and its upstream's names"


def test_deploys_run_from_their_own_branch_only_after_the_promotion_check_and_name_no_region():
    """Audit A-I-10, owner 2026-10-16: a deploy from any branch but its environment's own fails before it assumes a
    role, and so does a commit that did not come from the upstream branch (main for dev, dev for prod) - both before
    any step that touches a secret. No region is written into a workflow: each GitHub Environment carries AWS_REGION
    (the owner's no-hardcoding rule)."""
    import yaml

    for name in ("_infra-deploy.yml", "_apps-deploy.yml"):
        text = (FLOWS / name).read_text(encoding="utf-8")
        wf = yaml.safe_load(text)
        assert set(wf[True]) == {"workflow_call"}, name
        assert wf[True]["workflow_call"]["inputs"]["upstream"] == {"type": "string", "required": True}, name
        (job,) = wf["jobs"].values()
        steps = job["steps"]
        assert steps[0]["name"] == "Deploys run from their environment's own branch", name
        assert steps[0]["if"] == "github.ref != format('refs/heads/{0}', inputs.environment)", name
        assert "exit 1" in steps[0]["run"], name
        at = {s.get("name") or s.get("uses", "").split("@")[0]: i for i, s in enumerate(steps)}
        check, checkout = at[PROMOTION_CHECK], at["actions/checkout"]
        assert steps[checkout]["with"]["fetch-depth"] == 0, name  # the upstream branch must be there to read
        assert steps[check]["env"] == {"UPSTREAM": "${{ inputs.upstream }}"}, name
        assert checkout < check < at["aws-actions/configure-aws-credentials"], name
        assert all(i > check for i, s in enumerate(steps) if "secrets." in str(s)), name
        assert "aws-region: ${{ vars.AWS_REGION }}" in text, name
    for f in FLOWS.glob("*.yml"):
        assert not re.search(r"\b(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:gov-)?(?:north|south|east|west|central)"
                             r"(?:east|west)?-\d\b", f.read_text(encoding="utf-8")), f"a region is written into {f.name}"


def test_every_action_is_pinned_to_a_full_commit_sha():
    """A tag can be moved to other code (the tj-actions and Trivy compromises did exactly that); a
    40-character commit id cannot. zizmor checks this in CI; this test makes it a named control."""
    import re

    uses = [(f.name, m.group(1)) for f in CI.parent.glob("*.yml")
            for m in re.finditer(r"^\s*-?\s*uses:\s*(\S+)", f.read_text(encoding="utf-8"), re.MULTILINE)]
    assert uses
    # This repository's own workflows - `$/.github/workflows/...`, GitHub's self-repository syntax (zizmor's
    # self-repository audit requires it) - are pinned by the commit that calls them.
    loose = [(f, u) for f, u in uses if not u.startswith(("./", "$/"))
             and not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u)]
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
        "manifests/shop": (flows / "_apps-check.yml").read_text(encoding="utf-8"),
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


def test_each_environment_deploys_on_a_push_to_its_own_branch_and_infra_only_plans_there():
    """Owner, 2026-10-16: a commit promoted onto the branch dev (or prod) reaches that environment with no hand on a
    button - one on-merge-<env>.yml per environment, identical apart from the names, in that environment's queue. Infra
    never applies on a push: it plans, and its apply is a reviewed second step (apply-plan) that applies exactly that
    plan. The push that creates the branch deploys nothing."""
    import yaml

    order = _promotion_order()
    deployers = {}
    for f in FLOWS.glob("*.yml"):
        text = f.read_text(encoding="utf-8")
        wf = yaml.safe_load(text)
        calls = [j for j in (wf.get("jobs") or {}).values() if str(j.get("uses", "")).endswith(DEPLOYS)]
        if calls and "push" in wf[True]:
            deployers[f.name] = (text, wf, calls)
    assert set(deployers) == {f"on-merge-{e}.yml" for e in order}, sorted(deployers)
    shapes = set()
    for env, upstream in order.items():
        text, wf, calls = deployers[f"on-merge-{env}.yml"]
        shapes.add(_shape(text, env))
        assert set(wf[True]) == {"push"}, env
        assert wf[True]["push"]["branches"] == [env], env
        assert wf["concurrency"] == {"group": f"deploy-{env}", "cancel-in-progress": False}, env
        for job in calls:
            assert job["with"]["environment"] == env and job["with"]["upstream"] == upstream, env
            if job["uses"].endswith("/_infra-deploy.yml"):
                assert job["with"]["action"] == "plan", env  # never apply or destroy on a push
            # Every deploying job waits for the changes job, which reports nothing to deploy on a branch creation.
            assert "changes" in job["needs"] and "needs.changes.outputs." in job["if"], env
        what = next(s for s in wf["jobs"]["changes"]["steps"] if s.get("id") == "what")["run"]
        creation = what[what.index('if [[ "$BEFORE" =~ ^0{40}$ ]]; then'):]
        assert creation.split("\n", 2)[1].strip().startswith('files=""; created=1'), env
    assert len(shapes) == 1, "the on-merge workflows differ in more than the environment's and its upstream's names"


def test_nothing_that_can_reach_aws_runs_on_main_or_on_a_pull_request():
    """Owner, 2026-10-16: main deploys nothing. No workflow that can reach AWS starts on a push to main, a pull
    request, a schedule or another workflow's run; the ones that start by hand refuse every branch but their own
    before they assume a role (the deploys: the test above; the runtime: tests/test_runtime_pipeline_s9.py)."""
    import yaml

    order = _promotion_order()
    holders = {}
    for f in sorted(FLOWS.glob("*.yml")):
        wf = yaml.safe_load(f.read_text(encoding="utf-8"))
        if _holds_aws(wf) or "workflow_call" in wf[True]:
            holders[f.name] = wf[True]
    assert {"_infra-deploy.yml", "_apps-deploy.yml", "runtime.yml"} <= set(holders), sorted(holders)
    for name, on in holders.items():
        assert set(on) <= {"workflow_dispatch", "workflow_call", "push"}, (name, sorted(on))
        if "push" in on:
            assert set(on["push"]) <= {"branches", "paths"} and on["push"]["branches"] in ([e] for e in order), name
    # And the other way round: what runs on main and on pull requests asks for no cloud identity at all.
    for f in sorted(FLOWS.glob("*.yml")):
        wf = yaml.safe_load(f.read_text(encoding="utf-8"))
        if {"pull_request", "pull_request_target", "schedule"} & set(wf[True]) or "main" in str(
                (wf[True].get("push") or {}).get("branches")):
            assert not _holds_aws(wf), f.name
            assert "id-token" not in f.read_text(encoding="utf-8"), f.name


def test_ci_runs_on_main_and_on_pull_requests_into_main():
    """Owner, 2026-10-16: dev and prod receive only commits main has already checked, so CI runs on pushes to main and
    on pull requests into main - a dev -> prod pull request does not run the k3d and database suites again. The
    workflow scan alone runs on every pull request: it is the check the dev and prod rulesets require."""
    import yaml

    for name in ("ci-tool.yml", "ci-infra.yml", "ci-apps.yml", "scan-workflows.yml"):
        on = yaml.safe_load((FLOWS / name).read_text(encoding="utf-8"))[True]
        assert on["push"]["branches"] == ["main"], name
        assert (on["pull_request"] or {}).get("branches") == (None if name == "scan-workflows.yml" else ["main"]), name


# A throwaway repository for the promotion check, as the deploy job's checkout sees it (fetch-depth 0): main moved on
# after dev and prod branched, dev was fast-forwarded to it, a stray commit sits on a branch of its own, and three merge
# commits stand for pull requests into prod - one of dev that changes nothing, one of dev that adds a file, one of
# another branch.
_GIT_ID = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_NOSYSTEM": "1"}


def _git(cwd, *args: str) -> str:
    import os
    import subprocess

    env = {**os.environ, **_GIT_ID, "GIT_CONFIG_GLOBAL": str(cwd.parent / "empty.gitconfig")}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


def _promotion_repo(tmp_path) -> dict[str, object]:
    (tmp_path / "empty.gitconfig").write_text("", encoding="utf-8")
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")

    def commit(message: str, name: str) -> str:
        (origin / name).write_text(message + "\n", encoding="utf-8", newline="\n")
        _git(origin, "add", "-A")
        _git(origin, "commit", "-q", "-m", message)
        return _git(origin, "rev-parse", "HEAD")

    commit("a", "f")
    base = commit("b", "f")
    _git(origin, "branch", "dev")
    _git(origin, "branch", "prod")
    tip = commit("c", "f")
    _git(origin, "branch", "-f", "dev", "main")
    _git(origin, "checkout", "-q", "-b", "stray", "dev")
    stray = commit("stray", "g")
    _git(origin, "checkout", "-q", "prod")
    _git(origin, "merge", "-q", "--no-ff", "-m", "merge dev", "dev")
    merge = _git(origin, "rev-parse", "HEAD")
    _git(origin, "checkout", "-q", "-b", "plus", base)
    _git(origin, "merge", "-q", "--no-ff", "--no-commit", "dev")
    plus = commit("merge dev and add a file", "h")
    _git(origin, "checkout", "-q", "-b", "side", base)
    commit("side", "s")
    _git(origin, "checkout", "-q", "-b", "other", base)
    _git(origin, "merge", "-q", "--no-ff", "-m", "merge side", "side")
    other = _git(origin, "rev-parse", "HEAD")
    _git(origin, "checkout", "-q", "main")
    _git(tmp_path, "clone", "-q", str(origin), "clone")
    return {"clone": tmp_path / "clone", "tip": tip, "older": base, "stray": stray, "merge": merge, "plus": plus,
            "other": other}


def _promotion_scripts() -> dict[str, str]:
    import yaml

    found = {}
    for name in ("_infra-deploy.yml", "_apps-deploy.yml", "runtime.yml"):
        for job_id, job in yaml.safe_load((FLOWS / name).read_text(encoding="utf-8"))["jobs"].items():
            for step in job["steps"]:
                if step.get("name") == PROMOTION_CHECK:
                    found[f"{name}:{job_id}"] = step["run"]
    return found


@pytest.mark.parametrize("env, upstream, at, passes", [
    ("dev", "main", "tip", True),         # main fast-forwarded onto dev
    ("dev", "main", "older", True),       # dev behind main: still a commit main checked
    ("dev", "main", "stray", False),      # pushed straight onto dev
    ("prod", "dev", "merge", True),       # the dev -> prod pull request's merge commit
    ("prod", "dev", "tip", True),         # prod fast-forwarded to a dev commit (its creation)
    ("prod", "dev", "plus", False),       # a merge of dev that also adds a file
    ("prod", "dev", "other", False),      # a merge of another branch
    ("dev", "nope", "tip", False),        # no such upstream branch
])
def test_the_promotion_check_deploys_only_what_came_from_the_upstream_branch(tmp_path, env, upstream, at, passes):
    """The check as each workflow runs it, against a real repository: a fast-forward of the upstream branch or a merge
    commit that adds nothing to it passes; anything else fails before a credential is held (owner, 2026-10-16)."""
    import os
    import shutil
    import subprocess

    bash = shutil.which("bash")
    assert bash, "the workflow's step is a bash script: bash must be on PATH to test it"
    scripts = _promotion_scripts()
    assert set(scripts) == {"_infra-deploy.yml:run", "_apps-deploy.yml:deploy", "runtime.yml:image"}, sorted(scripts)
    repo = _promotion_repo(tmp_path)
    clone = repo["clone"]
    _git(clone, "checkout", "-q", "--detach", repo[at])
    for where, script in scripts.items():
        if where.startswith("runtime.yml") and upstream != "main":
            continue  # the runtime names its upstream branch itself (main: it runs from dev)
        env_vars = {**os.environ, **_GIT_ID, "WARDEN_ENV": env, "UPSTREAM": upstream, "GITHUB_SHA": repo[at],
                    "GIT_CONFIG_GLOBAL": str(tmp_path / "empty.gitconfig")}
        done = subprocess.run([bash, "-e", "-c", script], cwd=clone, env=env_vars, capture_output=True, text=True,
                              check=False)
        assert (done.returncode == 0) == passes, (where, done.stdout + done.stderr)


@pytest.mark.parametrize("upstream", ["dev", "a..b", ""])
def test_the_promotion_check_refuses_an_upstream_that_is_no_other_branch(tmp_path, upstream):
    """A caller passing its own environment as the upstream would make every commit on the branch pass."""
    import os
    import shutil
    import subprocess

    bash = shutil.which("bash")
    assert bash
    repo = _promotion_repo(tmp_path)
    _git(repo["clone"], "checkout", "-q", "--detach", repo["tip"])
    for where, script in _promotion_scripts().items():
        if where.startswith("runtime.yml"):
            continue
        env_vars = {**os.environ, **_GIT_ID, "WARDEN_ENV": "dev", "UPSTREAM": upstream, "GITHUB_SHA": repo["tip"],
                    "GIT_CONFIG_GLOBAL": str(tmp_path / "empty.gitconfig")}
        done = subprocess.run([bash, "-e", "-c", script], cwd=repo["clone"], env=env_vars, capture_output=True,
                              text=True, check=False)
        assert done.returncode != 0, (where, done.stdout)
        assert "upstream must name another branch" in done.stdout, (where, done.stdout)


def test_the_database_services_have_no_fixed_password():
    """Naming audit item 17 (2026-10-16): the db job's PostgreSQL, MySQL and SQL Server passwords were fixed strings in
    this file, and a fixed complex-looking one reads as a real credential. One value is made per run; the services, their
    health checks and the DSNs the tests read all use it, and it meets SQL Server's sa password policy."""
    import yaml

    job = yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["db"]
    made = job["env"]["DB_TEST_PASSWORD"]
    assert "${{ github.run_id }}" in made and "${{ github.run_attempt }}" in made, made
    sample = made.replace("${{ github.run_id }}", "18512345678").replace("${{ github.run_attempt }}", "1")
    assert re.fullmatch(r"[A-Za-z0-9]{8,}", sample), sample  # nothing a DSN would need encoded
    assert all(re.search(cls, sample) for cls in ("[A-Z]", "[a-z]", "[0-9]")), sample  # three of SQL Server's four sets
    services = job["services"]
    for name, key in (("postgres", "POSTGRES_PASSWORD"), ("mysql", "MYSQL_ROOT_PASSWORD"), ("mssql", "MSSQL_SA_PASSWORD")):
        assert services[name]["env"][key] == "${{ env.DB_TEST_PASSWORD }}", (name, services[name]["env"][key])
    assert "-p$MYSQL_ROOT_PASSWORD" in services["mysql"]["options"]
    assert "-P $MSSQL_SA_PASSWORD" in services["mssql"]["options"]
    [step] = [s for s in job["steps"] if "WARDEN_TEST_PG_DSN" in s.get("env", {})]
    for var in ("WARDEN_TEST_PG_DSN", "WARDEN_TEST_MYSQL_DSN", "WARDEN_TEST_MSSQL_DSN"):
        assert ":${{ env.DB_TEST_PASSWORD }}@" in step["env"][var], (var, step["env"][var])


def test_the_privileged_pod_stays_a_negative_test_and_no_linter_needs_a_skip():
    """Naming audit item 18 (2026-10-16) and Sonar kubernetes:S6428 (owner, 2026-10-20): the negative test's pod is built
    when the test runs (scripts/negative_pod.py), so no manifest asks for a privileged container and no file carries a
    linter skip. The pod is still what Pod Security must refuse: privileged, as root."""
    import json
    import sys

    root = pathlib.Path(__file__).resolve().parents[1]
    pod = json.loads(subprocess.run([sys.executable, str(root / "scripts" / "negative_pod.py")], capture_output=True,
                                    text=True, check=True).stdout)
    context = pod["spec"]["containers"][0]["securityContext"]
    assert context["privileged"] is True
    assert context["runAsUser"] == 0
    assert not (root / "k8s" / "test" / "privileged-must-fail.yaml").exists()
    skipping = subprocess.run(["git", "grep", "-l", "-e", "checkov.io/skip", "-e", "ignore-check.kube-linter.io", "--",
                               "*.yaml", "*.yml"], cwd=root, capture_output=True, text=True, check=False).stdout.split()
    assert skipping == [], skipping
