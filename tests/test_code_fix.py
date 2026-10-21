"""Revert pull requests (register B4, phase 3): the deployed commit taken back exactly, through the gate, as the App."""

from __future__ import annotations

import subprocess

import pytest

from warden import code_fix
from warden.code_fix import (
    CodeFixActivities,
    RevertError,
    RevertRequest,
    diff_of,
    open_revert,
    revert_target,
    take_back,
)
from warden.code_gate import parse_diff
from warden.github_app import GitHubAppError

SHA = "c" * 40
PARENT = "d" * 40
HEAD = "e" * 40
NEW = "f" * 40
APP = "scenarios/fullstack/app/app.py"
BEFORE = "def total(orders):\n    x = 1\n    return sum(orders)\n    # end\n"
AFTER = "def total(orders):\n    x = 1\n    return sum(orders) * 2\n    # end\n"


def git_diff(tmp_path, before: dict[str, str | None], after: dict[str, str | None]) -> str:
    """The diff real git writes for a commit from `before` to `after` (None: no file)."""
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)

    def run(*args):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=repo,
                              capture_output=True, text=True, check=True).stdout

    run("init", "-q")

    def write(files):
        for path, text in files.items():
            f = repo / path
            if text is None:
                if f.exists():
                    f.unlink()
                continue
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "--allow-empty", "-m", "x")

    write(before)
    write(after)
    return run("diff", "--no-color", "--no-ext-diff", "HEAD~1", "HEAD")


class FakeWriter:
    def __init__(self, diff: str, files: dict[str, str], parents=(PARENT,), fail_commit=False):
        self.diff, self.files, self.parents, self.fail_commit = diff, files, list(parents), fail_commit
        self.calls: list[tuple] = []

    def commit_diff(self, sha):
        self.calls.append(("commit_diff", sha))
        return self.parents, self.diff

    def default_branch(self):
        return "main"

    def head(self, branch):
        self.calls.append(("head", branch))
        return HEAD

    def read_file(self, path, ref):
        assert ref == HEAD
        text = self.files.get(path)
        return None if text is None else text.encode()

    def create_branch(self, branch, sha):
        self.calls.append(("create_branch", branch, sha))

    def delete_branch(self, branch):
        self.calls.append(("delete_branch", branch))

    def commit(self, branch, **kw):
        self.calls.append(("commit", branch, kw))
        if self.fail_commit:
            raise GitHubAppError("createCommitOnBranch: HTTP 502")
        return NEW

    def open_pull_request(self, **kw):
        self.calls.append(("pull", kw))
        return 12, "https://github.com/o/r/pull/12"

    def wrote(self) -> bool:
        return any(c[0] in ("create_branch", "commit", "pull") for c in self.calls)


def request(**kw) -> RevertRequest:
    return RevertRequest(**{"incident": "inc-42", "environment": "dev", "tier": "nonprod", "mode": "propose",
                            "repo": "o/r", "sha": SHA, **kw})


# ------------------------------------------------------------------------------------------------ which commit

@pytest.mark.parametrize("action, deploys, want", [
    ("rollback_deploy", [{"sha": SHA}], SHA),
    ("rollback_deploy", [{"sha": SHA.upper()}], SHA),
    ("rollback_deploy", [{"image": f"repo.example/app:{SHA}"}], SHA),
    ("rollback_deploy", [{"sha": SHA}, {"image": f"x:{SHA}"}], SHA),
    ("rollback_deploy", [{"sha": SHA}, {"sha": PARENT}], ""),          # two candidates: a person chooses
    ("rollback_deploy", [{"sha": SHA[:12]}], ""),                       # not a full commit id
    ("rollback_deploy", [], ""),
    ("rollback_deploy", ["junk", {"sha": None}], ""),
    ("restart_pods", [{"sha": SHA}], ""),                               # only a rollback's deploy is reverted
])
def test_the_one_deployed_commit_of_a_rollback(action, deploys, want):
    assert revert_target(action, deploys) == want


# ------------------------------------------------------------------------------------------- taking a change back

def test_take_back_undoes_a_hunk_where_it_is():
    (change,) = parse_diff(diff_of(APP, BEFORE, AFTER))
    assert take_back(AFTER, change) == BEFORE


def test_take_back_keeps_a_missing_last_newline():
    (change,) = parse_diff(diff_of(APP, BEFORE, AFTER))
    assert take_back(AFTER.rstrip("\n"), change) == BEFORE.rstrip("\n")


def test_take_back_finds_hunks_after_later_lines_moved_them():
    (change,) = parse_diff(diff_of(APP, BEFORE, AFTER))
    later = "import os\n\n\n" + AFTER
    assert take_back(later, change) == "import os\n\n\n" + BEFORE


def test_take_back_refuses_code_that_moved_on():
    (change,) = parse_diff(diff_of(APP, BEFORE, AFTER))
    moved = AFTER.replace("* 2", "* 3")
    with pytest.raises(RevertError, match="no longer there"):
        take_back(moved, change)


def test_take_back_refuses_a_hunk_found_twice():
    (change,) = parse_diff(diff_of(APP, BEFORE, AFTER))
    with pytest.raises(RevertError, match="more than once"):
        take_back(AFTER + AFTER, change)


# ------------------------------------------------------------------------------------------------ the whole step

def test_a_revert_pull_request_is_opened_from_a_real_git_diff(tmp_path):
    diff = git_diff(tmp_path, {APP: BEFORE}, {APP: AFTER})
    writer = FakeWriter(diff, {APP: AFTER})
    out = open_revert(request(), writer=writer)
    assert out.status == "opened", out.reason
    assert (out.pull_request, out.revert_commit, out.head) == (12, NEW, HEAD)
    assert out.branch == f"warden/revert/dev/inc-42-{SHA[:12]}"
    created = [c for c in writer.calls if c[0] == "create_branch"]
    assert created == [("create_branch", out.branch, HEAD)]
    (_, branch, kw), = [c for c in writer.calls if c[0] == "commit"]
    assert branch == out.branch
    assert kw["expected_head"] == HEAD
    assert kw["additions"] == {APP: BEFORE.encode()}
    assert kw["deletions"] == ()
    (_, pull), = [c for c in writer.calls if c[0] == "pull"]
    assert pull["base"] == "main"  # where CI runs: dev receives it by promotion
    assert ("head", "main") in writer.calls
    assert pull["head"] == out.branch
    assert "a person reviews and merges it" in pull["body"]
    assert SHA in pull["body"]


def test_reverting_an_added_file_deletes_it_and_a_deleted_file_brings_it_back(tmp_path):
    gone, new = "scenarios/fullstack/app/old.py", "scenarios/fullstack/app/new.py"
    diff = git_diff(tmp_path, {APP: BEFORE, gone: "a = 1\n"}, {APP: BEFORE, gone: None, new: "b = 2\n"})
    writer = FakeWriter(diff, {APP: BEFORE, new: "b = 2\n"})
    out = open_revert(request(), writer=writer)
    assert out.status == "opened", out.reason
    (_, _, kw), = [c for c in writer.calls if c[0] == "commit"]
    assert kw["additions"] == {gone: b"a = 1\n"}
    assert kw["deletions"] == (new,)


def test_a_commit_that_touched_a_workflow_is_refused_and_nothing_is_written(tmp_path):
    flow = ".github/workflows/ci.yml"
    diff = git_diff(tmp_path, {flow: "on: pull_request\n"}, {flow: "on: push\n"})
    writer = FakeWriter(diff, {flow: "on: push\n"})
    out = open_revert(request(), writer=writer)
    assert out.status == "refused"
    assert {"CG3", "CG4"} <= set(out.rules)
    assert not writer.wrote()


def test_code_that_moved_on_is_refused_and_nothing_is_written(tmp_path):
    diff = git_diff(tmp_path, {APP: BEFORE}, {APP: AFTER})
    writer = FakeWriter(diff, {APP: AFTER.replace("* 2", "* 3")})
    out = open_revert(request(), writer=writer)
    assert out.status == "refused"
    assert "no longer there" in out.reason
    assert not writer.wrote()


def test_a_file_added_and_changed_since_is_refused(tmp_path):
    new = "scenarios/fullstack/app/new.py"
    diff = git_diff(tmp_path, {APP: BEFORE}, {APP: BEFORE, new: "b = 2\n"})
    out = open_revert(request(), writer=(writer := FakeWriter(diff, {new: "b = 3\n"})))
    assert out.status == "refused"
    assert "changed since" in out.reason
    assert not writer.wrote()


@pytest.mark.parametrize("parents", [(), (PARENT, HEAD)])
def test_a_merge_or_root_commit_is_refused(tmp_path, parents):
    writer = FakeWriter(git_diff(tmp_path, {APP: BEFORE}, {APP: AFTER}), {APP: AFTER}, parents=parents)
    out = open_revert(request(), writer=writer)
    assert out.status == "refused"
    assert "merge commit" in out.reason
    assert not writer.wrote()


def test_a_revert_too_large_for_the_gate_is_refused(tmp_path):
    big_before = "".join(f"x{i} = {i}\n" for i in range(150))
    big_after = "".join(f"y{i} = {i}\n" for i in range(150))
    writer = FakeWriter(git_diff(tmp_path, {APP: big_before}, {APP: big_after}), {APP: big_after})
    out = open_revert(request(), writer=writer)
    assert out.status == "refused"
    assert out.rules == ("CG1",)
    assert not writer.wrote()


def test_off_writes_nothing_and_reads_nothing():
    writer = FakeWriter("", {})
    out = open_revert(request(mode="off"), writer=writer)
    assert out.status == "skipped"
    assert writer.calls == []


def test_without_an_app_nothing_is_written(monkeypatch):
    monkeypatch.delenv("WARDEN_CODEFIX_APP_ID", raising=False)
    monkeypatch.delenv("WARDEN_CODEFIX_APP_KEY", raising=False)
    out = open_revert(request())
    assert out.status == "skipped"
    assert "no GitHub App" in out.reason


def test_prod_is_never_auto_even_when_asked(tmp_path):
    writer = FakeWriter(git_diff(tmp_path, {APP: BEFORE}, {APP: AFTER}), {APP: AFTER})
    out = open_revert(request(environment="prod", tier="prod", mode="auto"), writer=writer)
    assert out.mode == "propose"
    assert out.status == "opened"
    (_, pull), = [c for c in writer.calls if c[0] == "pull"]
    assert pull["base"] == "main"
    assert "a person reviews and merges it" in pull["body"]


def test_a_failed_commit_removes_its_branch(tmp_path):
    writer = FakeWriter(git_diff(tmp_path, {APP: BEFORE}, {APP: AFTER}), {APP: AFTER}, fail_commit=True)
    out = open_revert(request(), writer=writer)
    assert out.status == "failed"
    assert "was removed" in out.reason
    assert ("delete_branch", f"warden/revert/dev/inc-42-{SHA[:12]}") in writer.calls
    assert not any(c[0] == "pull" for c in writer.calls)


def test_a_failed_pull_request_removes_its_branch_and_says_what_was_written(tmp_path):
    writer = FakeWriter(git_diff(tmp_path, {APP: BEFORE}, {APP: AFTER}), {APP: AFTER})

    def refused(**kw):
        writer.calls.append(("pull", kw))
        raise GitHubAppError("the pull request into main: HTTP 422")

    writer.open_pull_request = refused
    out = open_revert(request(), writer=writer)
    assert out.status == "failed"
    assert out.revert_commit == NEW
    assert "was not opened" in out.reason
    assert ("delete_branch", f"warden/revert/dev/inc-42-{SHA[:12]}") in writer.calls


def test_an_unexpected_error_is_still_an_audit_row(tmp_path):
    def broken(_repo):
        raise KeyError("x")

    audit = Audit()
    row = CodeFixActivities(audit=audit, app=broken).code_fix_revert("inc-42", "dev", SHA)
    assert row["status"] == "failed"
    assert row["reason"] == "an unexpected error (KeyError)"
    assert [kind for _incident, kind, _body in audit.rows] == [code_fix.AUDIT_KIND]


@pytest.mark.parametrize("sep", ["\r", "\x0c", "\u2028"])
def test_take_back_keeps_other_line_separators_as_they_are(sep):
    current = f"a = 1{sep}\nb = 2\nc = 3\n"
    change = parse_diff("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -2 +2 @@\n-b = 0\n+b = 2\n")[0]
    assert take_back(current, change) == f"a = 1{sep}\nb = 0\nc = 3\n"


def test_a_github_failure_is_an_outcome_not_an_exception():
    def app(_repo):
        raise GitHubAppError("the App's installation on the repository: HTTP 404")

    out = open_revert(request(), app=app)
    assert out.status == "failed"
    assert "HTTP 404" in out.reason


@pytest.mark.parametrize("sha", ["", "abc", SHA.upper()])
def test_only_a_full_commit_id(sha):
    out = open_revert(request(sha=sha), writer=FakeWriter("", {}))
    assert out.status == "refused"


# ---------------------------------------------------------------------------------------------- the activity

class Audit:
    def __init__(self):
        self.rows = []

    def append(self, incident, kind, body):
        self.rows.append((incident, kind, body))
        return "h"


def test_the_activity_records_one_row_per_attempt(tmp_path):
    writer = FakeWriter(git_diff(tmp_path, {APP: BEFORE}, {APP: AFTER}), {APP: AFTER})
    audit = Audit()
    row = CodeFixActivities(audit=audit, app=lambda repo: writer).code_fix_revert("inc-42", "dev", SHA)
    assert row["status"] == "opened"
    assert row["pull_request"] == 12
    assert audit.rows == [("inc-42", code_fix.AUDIT_KIND, row)]


def test_an_unknown_environment_gets_no_code_fix():
    audit = Audit()
    row = CodeFixActivities(audit=audit, app=lambda repo: pytest.fail("no App call")).code_fix_revert(
        "inc-1", "nowhere", SHA)
    assert row["status"] == "skipped"
    assert "off in nowhere" in row["reason"]
    assert len(audit.rows) == 1


def test_the_activity_runs_in_the_act_zone_and_is_registered():
    from warden import runtime, workflows

    assert "code_fix_revert" in workflows.ZONES["act"]
    names = {a.__name__ for a in runtime._activities(Audit(), None, None, None, None)}
    assert "code_fix_revert" in names


def test_the_workflow_asks_for_a_revert_only_after_a_rollback_diagnosis():
    """Read from the workflow's source: run() takes the step, which is patched, one attempt, and guarded by
    revert_target."""
    import inspect

    from warden import workflows

    assert "await self._code_fix_revert(first, pack, diagnosed, verified)" in inspect.getsource(
        workflows.IncidentWorkflow.run)
    src = inspect.getsource(workflows.IncidentWorkflow._code_fix_revert)
    assert 'workflow.patched("b4-code-fix-revert")' in src
    assert "revert_target(diagnosed.proposal.action.value, pack.context.recent_deploys)" in src
    assert workflows.CODE_FIX["retry_policy"].maximum_attempts == 1
    # No act-zone worker: the incident stops waiting after two minutes, it is never held by the step.
    assert workflows.CODE_FIX["schedule_to_start_timeout"].total_seconds() == 120


@pytest.mark.parametrize("status, unavailable, want", [
    ("approved_for_human", "", True),
    ("escalated", "", False),
    ("rejected", "", False),
    ("auto_safe", "", False),
    ("approved_for_human", "the model did not answer", False),
])
def test_a_revert_only_for_a_diagnosis_passed_for_a_persons_approval(status, unavailable, want):
    import inspect
    from types import SimpleNamespace

    from warden import workflows

    diagnosed = SimpleNamespace(model_unavailable=unavailable)
    verified = SimpleNamespace(verdict=SimpleNamespace(status=SimpleNamespace(value=status)))
    assert workflows._revert_wanted(diagnosed, verified) is want
    assert "_revert_wanted(diagnosed, verified)" in inspect.getsource(workflows.IncidentWorkflow._code_fix_revert)


def test_a_deleted_file_that_exists_again_is_refused(tmp_path):
    gone = "scenarios/fullstack/app/old.py"
    diff = git_diff(tmp_path, {APP: BEFORE, gone: "a = 1\n"}, {APP: BEFORE, gone: None})
    writer = FakeWriter(diff, {APP: BEFORE, gone: "a = 2\n"})
    out = open_revert(request(), writer=writer)
    assert out.status == "refused"
    assert "exists again" in out.reason
    assert not writer.wrote()


@pytest.mark.parametrize("diff, says", [
    ((f"diff --git a/{APP} b/scenarios/fullstack/app/moved.py\nsimilarity index 100%\nrename from {APP}\n"
      "rename to scenarios/fullstack/app/moved.py\n"), "renamed file"),
    (f"diff --git a/{APP} b/{APP}\nindex 1..2 100644\nBinary files a/{APP} and b/{APP} differ\n", "binary file"),
])
def test_a_rename_or_a_binary_is_reverted_by_a_person(diff, says):
    writer = FakeWriter(diff, {APP: AFTER})
    out = open_revert(request(), writer=writer)
    assert out.status == "refused"
    assert says in out.reason
    assert not writer.wrote()
