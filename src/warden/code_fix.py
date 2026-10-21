"""Revert pull requests: the first code fix WARDEN writes (register B4, phase 3).

When an incident's diagnosis is "roll back the deploy" and the incident's evidence names exactly one deployed commit,
WARDEN can also open a pull request that reverts that commit - so the next deploy does not bring the fault back. The
pull request goes into the repository's default branch, where CI runs (`main`): an environment's branch receives only
what that branch has checked, so the revert reaches the environment by the same promotion as any other change. The operational fix (the rollback plan) still goes through its own approval; this pull
request is the code-level follow-up, and it is merged by a person (`code_fix: propose`) or, later and only outside the
prod tier, by the checks (`auto`, phase 4).

How the revert is made, with no model involved:

1. The environment's `code_fix` mode (environments.yaml): `off`, or no GitHub App configured, writes nothing.
2. The commit's own diff is read from GitHub as the App (github_app.py) and parsed strictly (code_gate.parse_diff).
   A merge commit, a rename, a binary file or a diff the parser cannot read is refused.
3. Each file of the default branch, as it is NOW, gets the commit's change taken back: every hunk's "after"
   lines (context and added) must be found exactly once and are replaced by its "before" lines (context and removed).
   A hunk found nowhere or twice - the code moved on since - is refused, never guessed.
4. The revert's own diff is made from those contents and put through the code gate as a revert (code_gate.check):
   paths, size, secrets, dependencies, suppressions, and CG10, that it is exactly the inverse of the commit.
5. Only then: a branch `warden/revert/<environment>/inc-<hash of the incident id>-<commit>`, one signed commit at
   the head WARDEN read, and a pull request into the default branch. Every outcome - opened, skipped, refused, failed - is one audit row.
"""

from __future__ import annotations

import difflib
import hashlib
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from temporalio import activity

from .code_gate import (
    ChangeKind,
    CodeFixMode,
    CodeGateError,
    FileChange,
    check,
    effective_mode,
    imports_in,
    parse_diff,
)
from .github_app import AppCredentials, GitHubApp, GitHubAppError, RepoWriter

_SHA = re.compile(r"[0-9a-f]{40}")
AUDIT_KIND = "code_fix"


class RevertError(RuntimeError):
    """The revert cannot be made safely: the reason is said, and nothing is written."""


@dataclass(frozen=True)
class RevertOutcome:
    status: str                      # opened | skipped | refused | failed
    reason: str = ""
    commit: str = ""                 # the commit reverted
    branch: str = ""
    head: str = ""                   # the environment branch's head the revert was made on
    revert_commit: str = ""
    pull_request: int = 0
    url: str = ""
    mode: str = ""
    rules: tuple[str, ...] = field(default=())

    def row(self) -> dict[str, Any]:
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in asdict(self).items()}


def revert_target(action: str, deploys: list[dict[str, Any]]) -> str:
    """The one deployed commit a revert would undo: only for a `rollback_deploy` diagnosis, and only when the evidence
    names exactly one full commit id (a deploy's `sha`, or an image tag that is one). "" otherwise - two candidates is
    a person's choice, never WARDEN's."""
    if action != "rollback_deploy":
        return ""
    found: set[str] = set()
    for d in deploys:
        if not isinstance(d, Mapping):
            continue
        image = str(d.get("image") or "")
        for value in (d.get("sha"), image.rsplit(":", 1)[-1] if ":" in image else ""):
            value = str(value or "").strip().lower()
            if _SHA.fullmatch(value):
                found.add(value)
    return found.pop() if len(found) == 1 else ""


# ------------------------------------------------------------------------------------------- taking a change back

def _sides(hunk: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """A hunk's before (context and removed) and after (context and added) lines."""
    before = [line[1:] for line in hunk if line[:1] in (" ", "-")]
    after = [line[1:] for line in hunk if line[:1] in (" ", "+")]
    return before, after


def _find_once(lines: list[str], block: list[str]) -> int:
    if not block:
        raise RevertError("a hunk with no lines to find it by")
    starts = [i for i in range(len(lines) - len(block) + 1) if lines[i:i + len(block)] == block]
    if len(starts) != 1:
        raise RevertError("the code changed since the commit: a part of it is "
                          + ("no longer there" if not starts else "there more than once"))
    return starts[0]


def _lines(text: str) -> list[str]:
    """A text's lines split at LF only, as parse_diff reads a diff: a CR, a form feed or a Unicode line separator stays
    in its line, so nothing outside the reverted hunks is rewritten (str.splitlines split at each of them)."""
    return text.removesuffix("\n").split("\n") if text else []


def take_back(current: str, change: FileChange) -> str:
    """`current` with `change` (a modified file's hunks, in order) taken back. Each hunk is found by its exact after
    lines, once; the file's last newline is kept as it was."""
    if not change.hunks:
        raise RevertError(f"{change.path}: the commit's change has no hunks to take back")
    lines, ends_newline = _lines(current), current.endswith("\n")
    for hunk in change.hunks:
        before, after = _sides(hunk)
        at = _find_once(lines, after)
        lines[at:at + len(after)] = before
    return "\n".join(lines) + ("\n" if ends_newline and lines else "")


def _text(data: bytes | None, path: str) -> str | None:
    if data is None:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise RevertError(f"{path} is not UTF-8 text") from None


def diff_of(path: str, old: str | None, new: str | None, mode: str = "100644") -> str:
    """A `git diff` of one file from `old` to `new` (None: absent), as code_gate.parse_diff reads it."""
    header = [f"diff --git a/{path} b/{path}"]
    if old is None:
        header.append(f"new file mode {mode}")
    elif new is None:
        header.append(f"deleted file mode {mode}")
    body = difflib.unified_diff(_lines(old or ""), _lines(new or ""), lineterm="", n=3,
                                fromfile=f"a/{path}" if old is not None else "/dev/null",
                                tofile=f"b/{path}" if new is not None else "/dev/null")
    return "\n".join([*header, *body]) + "\n"


@dataclass
class _Plan:
    additions: dict[str, bytes] = field(default_factory=dict)
    deletions: list[str] = field(default_factory=list)
    diffs: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)  # the touched files as they are now


def _delete_added(f: FileChange, current: str | None, plan: _Plan) -> None:
    """The commit added the file: the revert deletes it, if it is still exactly that."""
    if current is None or _lines(current) != list(f.added):
        raise RevertError(f"{f.path}: the file the commit added has changed since, or is gone")
    plan.deletions.append(f.path)
    plan.diffs.append(diff_of(f.path, current, None, f.new_mode or "100644"))


def _restore_deleted(f: FileChange, current: str | None, plan: _Plan) -> None:
    """The commit deleted the file: the revert brings it back, if nothing took its place."""
    if current is not None:
        raise RevertError(f"{f.path}: a file of that name exists again")
    restored = "\n".join(f.removed) + "\n"
    plan.additions[f.path] = restored.encode("utf-8")
    plan.diffs.append(diff_of(f.path, None, restored, f.old_mode or "100644"))


def _take_back_modified(f: FileChange, current: str | None, plan: _Plan) -> None:
    if current is None:
        raise RevertError(f"{f.path}: the file is gone")
    new = take_back(current, f)
    plan.additions[f.path] = new.encode("utf-8")
    plan.diffs.append(diff_of(f.path, current, new))


_BY_STATUS = {"added": _delete_added, "deleted": _restore_deleted, "modified": _take_back_modified}


def _revert_file(writer: RepoWriter, head: str, f: FileChange, plan: _Plan) -> None:
    step = _BY_STATUS.get(f.status)
    if f.binary or step is None:
        raise RevertError(f"{f.path}: a {'binary file' if f.binary else f'{f.status} file'} is reverted by a person")
    current = _text(writer.read_file(f.path, head), f.path)
    step(f, current, plan)
    # CG6's baseline: the touched files as they are now - never the lines the revert restores, so nothing it brings back
    # counts as already imported; a subset of what CI's check reads (every import in the tree), so CI never refuses
    # what passed here.
    plan.sources.append(current or "")


def public_ref(incident: str) -> str:
    """What a public pull request calls an incident: a stable hash of its id, never the id itself (an alert's id can
    carry a monitor number, a resource or an account). The audit row keeps the id; this reference finds it there."""
    return "inc-" + hashlib.sha256(incident.encode("utf-8")).hexdigest()[:12]


def _body(incident: str, sha: str, environment: str, mode: CodeFixMode, files: list[str]) -> str:
    merge = ("a person reviews and merges it" if mode is CodeFixMode.propose
             else "it merges itself only after every required check is green")
    return "\n".join([
        (f"WARDEN's incident `{incident}` in `{environment}` was diagnosed as caused by the deploy of `{sha[:12]}`; "
         "this pull request reverts that commit so the next deploy does not bring the fault back."),
        "",
        f"- Reverted: `{sha}` (exactly its inverse, checked by the code gate, rule CG10)",
        f"- Files: {', '.join(f'`{p}`' for p in files)}",
        f"- Mode: `{mode.value}` - {merge}.",
        "",
        ("The rollback of the running service is a separate plan with its own approval. Written by WARDEN's GitHub "
         "App; no model wrote any line of this change."),
    ])


# ------------------------------------------------------------------------------------------------ the whole step

@dataclass
class RevertRequest:
    incident: str
    environment: str
    tier: str
    mode: str
    repo: str
    sha: str


def open_revert(req: RevertRequest, *, writer: RepoWriter | None = None,
                app: Callable[[str], RepoWriter] | None = None) -> RevertOutcome:
    """Make, check and open one revert pull request. Never raises for a refusal or a GitHub failure: the outcome says
    which. `writer` (tests) or `app` (repo -> writer) replaces the App from the environment."""
    mode = effective_mode(req.mode, req.tier)
    base = RevertOutcome(status="skipped", commit=req.sha, mode=mode.value)
    if mode is CodeFixMode.off:
        return _with(base, reason=f"code fixes are off in {req.environment}")
    if not _SHA.fullmatch(req.sha or ""):
        return _with(base, status="refused", reason="no single deployed commit to revert")
    try:
        writer = writer or (app or _app_writer)(req.repo)
    except GitHubAppError as exc:
        return _with(base, status="failed", reason=str(exc))
    if writer is None:
        return _with(base, reason="no GitHub App is configured (WARDEN_CODEFIX_APP_ID, WARDEN_CODEFIX_APP_KEY)")
    try:
        return _open(req, writer, mode, base)
    except (RevertError, CodeGateError) as exc:
        return _with(base, status="refused", reason=str(exc))
    except GitHubAppError as exc:
        return _with(base, status="failed", reason=str(exc))


def _with(outcome: RevertOutcome, **changes: Any) -> RevertOutcome:
    return RevertOutcome(**{**asdict(outcome), **changes})


def _app_writer(repo: str) -> RepoWriter | None:
    creds = AppCredentials.from_environment()
    return RepoWriter(GitHubApp(creds).installation_token(repo)) if creds else None


def _remove(writer: RepoWriter, branch: str) -> str:
    """A branch whose commit failed holds nothing of WARDEN's: it goes. What happened is said in the outcome."""
    try:
        writer.delete_branch(branch)
    except GitHubAppError:
        return f"the branch {branch} was left behind: delete it"
    return f"the branch {branch} was removed"


def _open(req: RevertRequest, writer: RepoWriter, mode: CodeFixMode, base: RevertOutcome) -> RevertOutcome:
    parents, text = writer.commit_diff(req.sha)
    if len(parents) != 1:
        raise RevertError("a merge commit (or a root commit) is reverted by a person")
    original = parse_diff(text)
    base_branch = writer.default_branch()
    head = writer.head(base_branch)
    plan = _Plan()
    for f in original:
        _revert_file(writer, head, f, plan)
    revert = parse_diff("".join(plan.diffs))
    known = frozenset().union(*(imports_in(s) for s in plan.sources))
    verdict = check(revert, kind=ChangeKind.revert, mode=mode, tier=req.tier, known_imports=known, reverts=req.sha,
                    original=original)
    if not verdict.allowed:
        return _with(base, status="refused", head=head, rules=verdict.rules,
                     reason="; ".join(str(r) for r in verdict.refusals)[:500])
    ref = public_ref(req.incident)
    branch = f"warden/revert/{req.environment}/{ref}-{req.sha[:12]}"
    writer.create_branch(branch, head)
    title = f"Revert {req.sha[:12]}: the deploy behind incident {ref}"
    try:
        oid = writer.commit(branch, expected_head=head, headline=title,
                            body=f"Reverts {req.sha}. Written by WARDEN (incident {ref}).",
                            additions=plan.additions, deletions=tuple(plan.deletions))
    except GitHubAppError as exc:
        raise GitHubAppError(f"{exc}; {_remove(writer, branch)}") from None
    try:
        number, url = writer.open_pull_request(head=branch, base=base_branch, title=title,
                                               body=_body(ref, req.sha, req.environment, mode,
                                                          sorted(f.path for f in original)))
    except GitHubAppError as exc:  # the commit is written but no pull request holds it: the branch goes
        return _with(base, status="failed", head=head, branch=branch, revert_commit=oid,
                     reason=f"the pull request was not opened: {exc}; {_remove(writer, branch)}"[:500])
    return _with(base, status="opened", head=head, branch=branch, revert_commit=oid, pull_request=number, url=url)


# --------------------------------------------------------------------------------------------- the activity

class CodeFixActivities:
    """The act zone's code-fix step: it holds the GitHub App's key (settings.ZONE_SECRETS)."""

    def __init__(self, *, audit: Any, policies: Any = None,
                 app: Callable[[str], RepoWriter | None] | None = None) -> None:
        self.audit, self._policies, self._app = audit, policies, app

    @activity.defn
    def code_fix_revert(self, incident_id: str, environment: str, sha: str) -> dict[str, Any]:
        """Open the revert pull request for `sha`, an incident's in `environment`, or say why not; one audit row."""
        from .environments import default_environment_policies

        policies = self._policies or default_environment_policies()
        policy = policies.for_env(environment)
        repo = os.environ.get("WARDEN_CHANGE_REPO") or policies.github.get("repository", "")
        try:
            outcome = open_revert(RevertRequest(incident=incident_id, environment=policy.name, tier=policy.tier,
                                                mode=policy.code_fix, repo=repo, sha=sha), app=self._app)
        # Every attempt is an audit row: an error open_revert did not expect too, named by its type only.
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
            outcome = RevertOutcome(status="failed", commit=sha, mode=policy.code_fix,
                                    reason=f"an unexpected error ({type(exc).__name__})")
        row = outcome.row()
        self.audit.append(incident_id, AUDIT_KIND, row)
        return row
