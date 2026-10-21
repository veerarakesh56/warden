"""Register B4, phase 4: the autofix-regression job's check of a pull request as GitHub holds it, and auto-merge only
when every condition holds (never prod; Eldane, CodeRabbit, every check)."""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

from warden import code_fix
from warden.code_fix import (
    CodeFixActivities,
    MergeFacts,
    PullState,
    ReviewState,
    ci_check,
    critic_approved,
    merge_refusals,
)
from warden.code_gate import CodeGateError, load_limits
from warden.environments import EnvironmentPolicies

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = "scenarios/fullstack/app/app.py"
BEFORE = "def total(orders):\n    x = 1\n    return sum(orders)\n    # end\n"
AFTER = "def total(orders):\n    x = 1\n    return sum(orders) * 2\n    # end\n"
POLICY = ("version: 1\ndefault:\n  tier: unknown\nenvironments:\n"
          "  dev:\n    tier: nonprod\n    code_fix: {dev}\n  prod:\n    tier: prod\n    code_fix: propose\n")


def policies(tmp_path, dev="propose") -> EnvironmentPolicies:
    path = tmp_path / "env.yaml"
    path.write_text(POLICY.format(dev=dev), encoding="utf-8")
    return EnvironmentPolicies.load(path)


class Repo:
    """A real git repository: a base, the deployed commit, and branches made on it."""

    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        path.mkdir()
        self("init", "-q", "-b", "main")
        self.write({APP: BEFORE, "scenarios/fullstack/app/util.py": "import json\n"})
        self.deployed = self.write({APP: AFTER})
        self.base = self.sha()

    def __call__(self, *args: str) -> str:
        done = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=self.path,
                              capture_output=True, text=True, check=False)
        if done.returncode not in (0, 1):
            raise AssertionError(done.stderr)
        return done.stdout

    def sha(self) -> str:
        return self("rev-parse", "HEAD").strip()

    def write(self, files: dict[str, str | None], message: str = "x") -> str:
        for path, text in files.items():
            f = self.path / path
            if text is None:
                f.unlink()
                continue
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, encoding="utf-8")
        self("add", "-A")
        self("commit", "-q", "-m", message)
        return self.sha()

    def revert_branch(self, name: str, files: dict[str, str | None], message: str | None = None) -> str:
        self("checkout", "-q", "-b", name, self.base)
        return self.write(files, message or f"Revert {self.deployed[:12]}\n\nReverts {self.deployed}. Written by WARDEN.")


def branch(repo: Repo, env: str = "dev") -> str:
    return f"warden/revert/{env}/inc-1-{repo.deployed[:12]}"


def test_a_pull_request_from_another_branch_has_nothing_more_to_check(tmp_path):
    assert ci_check("feature/x", "a" * 40, "b" * 40, lambda *a: pytest.fail("no git"))[0]


def test_warden_s_exact_revert_passes(tmp_path):
    repo = Repo(tmp_path / "r")
    head = repo.revert_branch(branch(repo), {APP: BEFORE})
    ok, notes = ci_check(branch(repo), repo.base, head, repo, policies(tmp_path))
    assert ok, notes
    assert "exactly its inverse" in notes[0]


def test_a_second_commit_on_the_branch_fails(tmp_path):
    repo = Repo(tmp_path / "r")
    repo.revert_branch(branch(repo), {APP: BEFORE})
    head = repo.write({"scenarios/fullstack/app/util.py": "import json\nimport os\n"}, "more")
    ok, notes = ci_check(branch(repo), repo.base, head, repo, policies(tmp_path))
    assert not ok
    assert "2 commits" in notes[0]


def test_a_revert_with_an_extra_line_fails_the_gate(tmp_path):
    repo = Repo(tmp_path / "r")
    head = repo.revert_branch(branch(repo), {APP: BEFORE + "print('hi')\n"})
    ok, notes = ci_check(branch(repo), repo.base, head, repo, policies(tmp_path))
    assert not ok
    assert any(n.startswith("CG10") for n in notes)


def test_a_commit_naming_another_commit_fails(tmp_path):
    repo = Repo(tmp_path / "r")
    head = repo.revert_branch(branch(repo), {APP: BEFORE}, message=f"Reverts {'0' * 40}.")
    ok, notes = ci_check(branch(repo), repo.base, head, repo, policies(tmp_path))
    assert not ok
    assert "names another" in notes[0]


def test_code_fix_off_in_the_environment_fails(tmp_path):
    repo = Repo(tmp_path / "r")
    head = repo.revert_branch(branch(repo), {APP: BEFORE})
    ok, notes = ci_check(branch(repo), repo.base, head, repo, policies(tmp_path, dev='"off"'))
    assert not ok
    assert any(n.startswith("CG0") for n in notes)


@pytest.mark.parametrize("ref", ["warden/fix/x", "warden/revert/inc-1-abc", "warden/revert/dev/inc-1-short"])
def test_a_warden_branch_of_another_shape_fails(ref):
    ok, notes = ci_check(ref, "a" * 40, "b" * 40, lambda *a: pytest.fail("no git"))
    assert not ok
    assert "not a branch WARDEN writes" in notes[0]


def test_the_script_runs_the_check(tmp_path):
    repo = Repo(tmp_path / "r")
    head = repo.revert_branch(branch(repo), {APP: BEFORE + "x = 1\n"})
    env = {"HEAD_REF": branch(repo), "BASE_SHA": repo.base, "HEAD_SHA": head, "PATH": "/usr/bin:/bin",
           "PYTHONPATH": str(ROOT / "src")}
    done = subprocess.run([sys.executable, str(ROOT / "scripts" / "autofix_check.py")], cwd=repo.path, env=env,
                          capture_output=True, text=True, check=False)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "::error::CG10" in done.stdout


# ------------------------------------------------------------------------------------------------ the merge rules

WROTE = "c" * 40


def pull(**kw) -> PullState:
    return PullState(**{"number": 7, "state": "open", "merged": False, "draft": False,
                        "head_ref": "warden/revert/dev/inc-1-cccccccccccc", "head_sha": WROTE, "base_ref": "main",
                        "mergeable": True, **kw})


GH = "github-actions"
GREEN = [("autofix-regression", "completed", "success", GH),
         ("SonarCloud Code Analysis", "completed", "success", "sonarqubecloud"),
         ("check / check", "completed", "success", GH), ("Analyze (python)", "completed", "success", GH),
         ("autofix-gate", "completed", "success", GH), ("zizmor", "completed", "skipped", GH)]
REQUIRED = (("autofix-gate", GH), ("autofix-regression", GH), ("SonarCloud Code Analysis", "sonarqubecloud"),
            ("check / check", GH), ("Analyze (python)", GH))
REVIEWED = ReviewState(reviewed_head=True, changes_requested=False, open_threads=0, flagged=False)


def facts(**kw) -> MergeFacts:
    return MergeFacts(**{"mode": "auto", "tier": "nonprod", "wrote": WROTE, "base": "main", "pull": pull(),
                         "checks": GREEN, "required": REQUIRED, "review": REVIEWED, "critic": True,
                         "rollback": True, **kw})


def refusals(**kw) -> list[str]:
    return merge_refusals(facts(**kw))


def test_everything_green_merges():
    assert refusals() == []


@pytest.mark.parametrize("kw, says", [
    ({"mode": "propose"}, "not auto"),
    ({"mode": "off"}, "not auto"),
    ({"tier": "prod"}, "not auto"),                                      # prod: never, whatever the mode says
    ({"pull": pull(draft=True)}, "draft"),
    ({"pull": pull(state="closed")}, "not open"),
    ({"pull": pull(mergeable=None)}, "cannot merge"),
    ({"pull": pull(head_sha="d" * 40)}, "something was added"),
    ({"pull": pull(base_ref="dev")}, "something was added"),
    ({"pull": pull(head_ref="feature/x")}, "something was added"),
    ({"checks": [*GREEN, ("check", "in_progress", "", GH)]}, "not green yet on cccccccccccc: check"),
    ({"checks": [*GREEN, ("security", "completed", "failure", GH)]}, "not green yet on cccccccccccc: security"),
    ({"checks": GREEN[1:]}, "not passed on cccccccccccc: autofix-regression"),
    ({"checks": [("autofix-regression", "completed", "skipped", GH), *GREEN[1:]]},  # a required job skipped: not green
     "not passed on cccccccccccc: autofix-regression"),
    ({"checks": [*GREEN[:2], ("check / check", "completed", "neutral", GH), *GREEN[3:]]},
     "not passed on cccccccccccc: check / check"),
    # The right name from the wrong app (anything allowed to write checks can post one) is not the required check.
    ({"checks": [("autofix-regression", "completed", "success", "some-app"), *GREEN[1:]]},
     "not passed on cccccccccccc: autofix-regression (github-actions)"),
    ({"checks": [c for c in GREEN if c[0] != "autofix-gate"]}, "not passed on cccccccccccc: autofix-gate"),
    ({"review": ReviewState(False, False, 0, False)}, "CodeRabbit"),
    ({"review": ReviewState(True, True, 0, False)}, "CodeRabbit"),
    ({"review": ReviewState(True, False, 1, False)}, "CodeRabbit"),
    ({"review": ReviewState(True, False, 0, True)}, "found something"),   # findings in the review's body only
    ({"critic": False}, "Eldane"),
    ({"rollback": False}, "rollback plan"),
])
def test_any_one_condition_missing_holds_the_merge(kw, says):
    out = refusals(**kw)
    assert len(out) == 1, out
    assert says in out[0]


@pytest.mark.parametrize("condition, kw", [
    (code_fix.mode_allows, {"tier": "prod"}), (code_fix.pull_is_ready, {"pull": pull(draft=True)}),
    (code_fix.head_is_warden_s, {"pull": pull(head_sha="d" * 40)}),
    (code_fix.checks_green, {"checks": [("x", "completed", "failure", GH)]}),
    (code_fix.checks_present, {"checks": []}), (code_fix.review_clear, {"review": ReviewState(True, False, 2, False)}),
    (code_fix.review_clear, {"review": ReviewState(True, False, 0, True)}),
    (code_fix.sonar_green, {"checks": [c for c in GREEN if c[0] != "SonarCloud Code Analysis"]}),
    (code_fix.sonar_green, {"checks": [*GREEN[:1], ("SonarCloud Code Analysis", "completed", "neutral", "sonarqubecloud")]}),
    (code_fix.sonar_green, {"checks": [*GREEN[:1], ("SonarCloud Code Analysis", "completed", "success", GH)]}),
    (code_fix.critic_agrees, {"critic": False}), (code_fix.rollback_agreed, {"rollback": False})])
def test_each_condition_is_its_own_check(condition, kw):
    assert condition in code_fix.MERGE_CONDITIONS
    assert condition(facts()) == ""
    assert condition(facts(**kw))


def test_every_condition_is_tested_here():
    assert len(code_fix.MERGE_CONDITIONS) == 9


def test_prod_never_merges_itself_whatever_else_is_green():
    """Option A, final: prod never. Refused in code (effective_mode), whatever the mode passed and every other fact."""
    for mode in ("auto", "propose", "off"):
        out = refusals(mode=mode, tier="prod")
        assert out == ["the environment does not merge code fixes on its own (code_fix is not auto, or it is prod)"]


class Audit:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def append(self, incident, kind, body):
        self.rows.append({"incident": incident, "kind": kind, "body": body})
        return "h"

    def entries(self, incident=None, kinds=()):
        return [r for r in self.rows if r["incident"] == incident and r["kind"] in kinds]


def test_eldane_s_approval_must_name_this_head():
    audit = Audit([{"incident": "i", "kind": code_fix.ELDANE_CODE_REVIEW,
                    "body": {"pull_request": 7, "head": WROTE, "verdict": "approve"}}])
    assert critic_approved(audit, "i", 7, WROTE)
    assert not critic_approved(audit, "i", 7, "d" * 40)
    assert not critic_approved(audit, "i", 8, WROTE)
    assert not critic_approved(Audit(), "i", 7, WROTE)  # nothing writes it before Eldane's code review exists


class FakeWriter:
    def __init__(self, state=None, merge_fails=False, merge_refused=False):
        self.state = {"number": 7, "state": "open", "merged": False, "draft": False,
                      "head_ref": "warden/revert/dev/inc-1-cccccccccccc", "head_sha": WROTE, "base_ref": "main",
                      "mergeable": True, **(state or {})}
        self.merged: list = []
        self.asked: list = []
        self.merge_refused = merge_refused

    def pull_state(self, number):
        return dict(self.state)

    def check_runs(self, sha):
        self.asked.append(("checks", sha))
        return GREEN

    def review_state(self, number, head):
        self.asked.append(("review", head))
        return {"reviewed_head": True, "changes_requested": False, "open_threads": 0, "flagged": False}

    def merge(self, number, sha):
        if self.merge_refused:
            from warden.github_app import MergeRefused

            raise MergeRefused(f"merging #{number}: HTTP 405 (GitHub will not merge it this way)")
        self.merged.append((number, sha))


ROLLBACK_PLAN = {"workflow_id": "fix-1", "entry": "k8s_rollout_undo", "plan_hash": "h1", "tier": "T2"}


def approval(approver="ana", **kw) -> dict:
    return {"incident": "inc-1", "kind": code_fix.ACCEPTED_ROW,
            "body": {"workflow_id": "fix-1", "plan_hash": "h1", "approver": approver, "required": 1, "problems": [],
                     **kw}}


def opened_audit(critic=True, rollback=True) -> Audit:
    rows = [{"incident": "inc-1", "kind": code_fix.AUDIT_KIND,
             "body": {"status": "opened", "pull_request": 7, "revert_commit": WROTE, "base": "main"}},
            {"incident": "inc-1", "kind": code_fix.PLAN_ROW, "body": ROLLBACK_PLAN}]
    if critic:
        rows.append({"incident": "inc-1", "kind": code_fix.ELDANE_CODE_REVIEW,
                     "body": {"pull_request": 7, "head": WROTE, "verdict": "approve"}})
    if rollback:
        rows.append(approval())
    return Audit(rows)


def test_the_activity_merges_only_with_everything_green(tmp_path):
    writer, audit = FakeWriter(), opened_audit()
    acts = CodeFixActivities(audit=audit, policies=policies(tmp_path, dev="auto"), app=lambda repo: writer)
    out = acts.code_fix_merge("inc-1", "dev", 7)
    assert out["status"] == "merged"
    assert writer.merged == [(7, WROTE)]
    assert writer.asked == [("checks", WROTE), ("review", WROTE)]  # every fact read for the commit WARDEN wrote
    assert audit.rows[-1]["kind"] == code_fix.MERGE_KIND


def test_without_eldane_it_waits_and_writes_no_row(tmp_path):
    writer, audit = FakeWriter(), opened_audit(critic=False)
    out = CodeFixActivities(audit=audit, policies=policies(tmp_path, dev="auto"),
                            app=lambda repo: writer).code_fix_merge("inc-1", "dev", 7)
    assert out["status"] == "waiting"
    assert writer.merged == []
    assert all(r["kind"] != code_fix.MERGE_KIND for r in audit.rows)


@pytest.mark.parametrize("env, dev, state", [("dev", "propose", {}), ("prod", "auto", {}),
                                             ("dev", "auto", {"head_sha": "d" * 40}), ("dev", "auto", {"state": "closed"})])
def test_what_can_never_merge_is_refused_once(tmp_path, env, dev, state):
    writer, audit = FakeWriter(state), opened_audit()
    out = CodeFixActivities(audit=audit, policies=policies(tmp_path, dev=dev),
                            app=lambda repo: writer).code_fix_merge("inc-1", env, 7)
    assert out["status"] == "refused"
    assert writer.merged == []
    assert audit.rows[-1]["kind"] == code_fix.MERGE_KIND
    assert {sha for _what, sha in writer.asked} <= {WROTE}  # facts are read for WARDEN's commit, never another head


def test_a_pull_request_warden_did_not_open_is_refused(tmp_path):
    out = CodeFixActivities(audit=Audit(), policies=policies(tmp_path, dev="auto"),
                            app=lambda repo: pytest.fail("no App call")).code_fix_merge("inc-1", "dev", 7)
    assert out["status"] == "refused"


def test_an_already_merged_pull_request_is_reported_merged(tmp_path):
    writer = FakeWriter({"merged": True, "state": "closed"})
    out = CodeFixActivities(audit=opened_audit(), policies=policies(tmp_path, dev="auto"),
                            app=lambda repo: writer).code_fix_merge("inc-1", "dev", 7)
    assert out["status"] == "merged"
    assert writer.merged == []


# ------------------------------------------------------------------------------------------ data and wiring

def test_the_shipped_required_checks_hold_the_must_haves():
    from warden.code_gate import MUST_CHECK, default_limits

    assert set(MUST_CHECK) <= set(default_limits().required_checks)


@pytest.mark.parametrize("checks, match", [
    ("[]", "must name"),
    ("[{name: autofix-regression, app: github-actions}]", "must name"),
    (("[{name: autofix-gate, app: github-actions}, {name: autofix-regression, app: some-app},"
      " {name: SonarCloud Code Analysis, app: sonarqubecloud}]"), "autofix-regression \\(github-actions\\)"),
    ("[autofix-regression]", "is {name, app}"),
    ("notalist", "list of {name, app}")])
def test_required_checks_cannot_drop_the_must_haves(checks, match):
    text = ("version: 1\nmax_changed_lines: 1\nmax_revert_lines: 1\nmax_files: 1\nallowed_paths: [a/*.py]\n"
            f"test_paths: [a/test_*.py]\nauto_merge:\n  required_checks: {checks}\n")
    with pytest.raises(CodeGateError, match=match):
        load_limits(text)


def test_the_merge_is_wired_in_the_act_zone_and_asked_once_each_time():
    import inspect

    from warden import runtime, workflows

    assert "code_fix_merge" in workflows.ZONES["act"]
    assert "code_fix_merge" in {a.__name__ for a in runtime._activities(Audit(), None, None, None, None)}
    src = inspect.getsource(workflows.CodeFixMergeWorkflow.run)
    assert "**MERGE_ASK)" in src
    assert workflows.MERGE_ASK["retry_policy"].maximum_attempts == 1
    # No act-zone worker: each ask gives up after two minutes, so the day's tries still end and a person is told.
    assert workflows.MERGE_ASK["schedule_to_start_timeout"].total_seconds() == 120
    assert workflows.MERGE_TRIES * workflows.MERGE_EVERY.total_seconds() <= 24 * 3600
    assert workflows.MERGE_FOR.total_seconds() == 24 * 3600
    assert "deadline = workflow.now() + MERGE_FOR\n" in src
    assert "await IncidentWorkflow._code_fix_merge(first, pack, opened)" in inspect.getsource(
        workflows.IncidentWorkflow._code_fix_revert)
    incident = inspect.getsource(workflows.IncidentWorkflow._code_fix_merge)
    assert 'opened.get("mode") == "auto"' in incident
    assert 'workflow.patched("b4-code-fix-merge")' in incident


# ------------------------------------------------------------------------------------- the workflow (Temporal, CI)

def _merge_run(answers: list[dict], times: list | None = None) -> tuple[dict, int]:
    import asyncio
    import os
    from concurrent.futures import ThreadPoolExecutor

    from temporalio import activity
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from warden import codec
    from warden.workflows import CodeFixMergeWorkflow

    asked: list = []

    @activity.defn(name="code_fix_merge")
    def merge(incident: str, environment: str, number: int) -> dict:
        asked.append((incident, environment, number))
        if times is not None:
            times.append(activity.info().current_attempt_scheduled_time)
        return answers[min(len(asked), len(answers)) - 1]

    async def main() -> dict:
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="merge-test", workflows=[CodeFixMergeWorkflow],
                               activities=[merge], activity_executor=ThreadPoolExecutor(1)):
            return await env.client.execute_workflow(CodeFixMergeWorkflow.run, args=["inc-1", "dev", 7],
                                                     id="codefix-merge-test", task_queue="merge-test")

    return asyncio.run(main()), len(asked)


def test_the_merge_workflow_asks_until_merged():
    out, asked = _merge_run([{"status": "waiting"}, {"status": "waiting"}, {"status": "merged"}])
    assert out["status"] == "merged"
    assert asked == 3


def test_the_merge_workflow_stops_at_a_refusal():
    out, asked = _merge_run([{"status": "refused", "reasons": ["closed"]}])
    assert out["status"] == "refused"
    assert asked == 1


def test_the_merge_workflow_gives_up_after_a_day():
    from warden import workflows

    times: list = []
    out, asked = _merge_run([{"status": "waiting", "reasons": ["Eldane has not approved"]}], times)
    assert out["status"] == "given_up"
    assert asked == workflows.MERGE_TRIES
    assert times[-1] - times[0] < workflows.MERGE_FOR  # asks and waits together stay inside the day



# ------------------------------------------------------------------------------------- second review (2026-10-21)

def test_the_row_kinds_are_the_ones_activities_writes():
    from warden import activities

    assert (code_fix.PLAN_ROW, code_fix.ACCEPTED_ROW) == (activities._PLAN_ROW, activities._ACCEPTED_ROW)


def plan_row(**kw) -> dict:
    return {"incident": "inc-1", "kind": code_fix.PLAN_ROW, "body": {**ROLLBACK_PLAN, **kw}}


@pytest.mark.parametrize("rows, want", [
    ([plan_row(), approval()], True),
    ([plan_row(entry="ecs_rollback_service"), approval()], True),
    ([plan_row(), approval("eldane", ai=True)], False),                       # an AI alone: never
    ([plan_row(), approval(required=2)], False),                              # the tier wants two people
    ([plan_row(), approval(required=2), approval("bo", required=2)], True),
    ([plan_row(), approval(problems=["expired"])], False),                    # a refused approval is not one
    ([plan_row(), approval(plan_hash="other")], False),                       # another plan's approval
    ([plan_row(entry="k8s_restart"), approval()], False),                     # not a rollback
    ([approval()], False),                                                    # no plan at all
    ([plan_row()], False),                                                    # a plan nobody approved (or denied)
])
def test_the_rollback_must_have_a_persons_signed_approval(rows, want):
    assert code_fix.rollback_approved(Audit(rows), "inc-1") is want


def test_a_denied_or_unanswered_rollback_holds_the_merge(tmp_path):
    writer, audit = FakeWriter(), opened_audit(rollback=False)
    out = CodeFixActivities(audit=audit, policies=policies(tmp_path, dev="auto"),
                            app=lambda repo: writer).code_fix_merge("inc-1", "dev", 7)
    assert out["status"] == "waiting"
    assert any("rollback plan" in r for r in out["reasons"])
    assert writer.merged == []


def test_a_merge_github_refuses_is_refused_and_recorded_once(tmp_path):
    writer, audit = FakeWriter(merge_refused=True), opened_audit()
    out = CodeFixActivities(audit=audit, policies=policies(tmp_path, dev="auto"),
                            app=lambda repo: writer).code_fix_merge("inc-1", "dev", 7)
    assert out["status"] == "refused"
    assert "405" in out["reasons"][0]
    assert [r["kind"] for r in audit.rows].count(code_fix.MERGE_KIND) == 1


def test_a_revert_of_a_commit_outside_the_bases_history_fails(tmp_path):
    """A commit only another branch (or a fork) has: its "inverse" would be new code."""
    repo = Repo(tmp_path / "r")
    repo("checkout", "-q", "-b", "side", repo.base)
    side = repo.write({APP: AFTER + "y = 1\n"}, "side")
    repo("checkout", "-q", "-b", f"warden/revert/dev/inc-1-{side[:12]}", repo.base)
    head = repo.write({APP: AFTER + "z = 2\n"}, f"Revert {side[:12]}\n\nReverts {side}. Written by WARDEN.")
    ok, notes = ci_check(f"warden/revert/dev/inc-1-{side[:12]}", repo.base, head, repo, policies(tmp_path))
    assert not ok
    assert "not in the history" in notes[0]


def test_the_gate_job_runs_the_bases_checker_and_no_code_of_the_pull_request():
    import yaml

    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "autofix-regression.yml").read_text(encoding="utf-8"))
    gate = doc["jobs"]["autofix-gate"]
    base, pr = gate["steps"][0], gate["steps"][1]
    assert base["with"]["ref"] == "${{ github.event.pull_request.base.sha }}"
    assert (base["with"]["path"], pr["with"]["path"]) == ("base", "pr")
    runs = [s for s in gate["steps"] if "run" in s]
    assert all(s.get("working-directory") in ("base", "pr") for s in runs)
    install, check = runs
    assert install["working-directory"] == "base"
    assert check["working-directory"] == "pr"
    assert "../base/.venv/bin/python ../base/scripts/autofix_check.py" in check["run"]
    assert check["env"]["PYTHONPATH"] == "../base/src"
    assert doc["jobs"]["autofix-regression"]["needs"] == "autofix-gate"


def test_the_must_have_checks_are_both_autofix_jobs_and_sonar_each_by_its_app():
    from warden.code_gate import MUST_CHECK

    assert set(MUST_CHECK) == {("autofix-gate", "github-actions"), ("autofix-regression", "github-actions"),
                               ("SonarCloud Code Analysis", "sonarqubecloud")}
    text = ("version: 1\nmax_changed_lines: 1\nmax_revert_lines: 1\nmax_files: 1\nallowed_paths: [a/*.py]\n"
            "test_paths: [a/test_*.py]\nauto_merge:\n  required_checks: [{name: autofix-regression, app: github-actions},"
            " {name: SonarCloud Code Analysis, app: sonarqubecloud}]\n")
    with pytest.raises(CodeGateError, match="autofix-gate"):
        load_limits(text)
