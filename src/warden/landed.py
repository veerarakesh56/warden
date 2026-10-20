"""B21: before WARDEN undoes its own fix, it looks for anything else that landed on the target since the fix.

An undo puts back what the plan's snapshot recorded. If a deploy, a merged change or another person's write reached
the target after WARDEN's fix, the undo may write over it - or bring back a state that no longer fits the code now
running. So before a rollback (activities.rollback) WARDEN reads, from the time its fix was applied until now:
- write events on the target in CloudTrail, through the environment's platform reader - any principal but this
  incident's own actor session (its fix, its canary);
- WARDEN's own fixes of the same target by another run (the audit);
- GitHub deployments to the environment and pull requests merged into its branch (WARDEN_CHANGE_REPO, read with
  WARDEN_GITHUB_TOKEN) - only where this worker holds the token.
Anything found, or a source that is configured and cannot be read, and the fix is not undone: a person decides.

Every read is whole or it is unknown: CloudTrail is looked up by the target's own names page by page, GitHub's lists page
by page back to the fix, and a read that runs past its pages is "could not be read". What landed is kept redacted.

Honest limits: CloudTrail can take minutes to show an event, so a write in the last minutes may not be seen yet. A
platform with no change reader (Kubernetes, a database) reads no CloudTrail - the record says so ("unchecked") - and its
undo still refuses on its own when the field it restores moved (the platforms' own checks). The branch a change merges into is taken to be the
environment's name, as WARDEN's own repository is laid out (dev, prod).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from typing import Any

from . import bounds, catalog, identity
from .redaction import redact
from .timeline import _API, _TIMEOUT_S, _when

GITHUB_ERRORS = (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError)


def _aws_errors() -> tuple[type[Exception], ...]:
    """What a read through the platform raises when it fails: botocore's own errors, a refused session, a lost
    connection."""
    errors: list[type[Exception]] = [RuntimeError, OSError, LookupError]
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:  # no AWS extra installed: only the platform's own errors can come
        return tuple(errors)
    return (*errors, BotoCoreError, ClientError)


GITHUB_PAGE = 100  # rows per page GitHub serves at most
GITHUB_PAGES = 5
_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


def _github_rows(url: str, token: str, since: datetime, newest: str, opener: Any) -> list[dict[str, Any]]:
    """Every row of a GitHub list sorted newest first by `newest`, back to `since`. A list that runs past the pages
    WARDEN reads, or an answer that is not a list, raises: a read in part is not a read (B21)."""
    rows: list[dict[str, Any]] = []
    for page in range(1, GITHUB_PAGES + 1):
        req = urllib.request.Request(f"{url}&per_page={GITHUB_PAGE}&page={page}",
                                     headers={"Authorization": f"Bearer {token}", **_HEADERS})
        with opener(req, timeout=_TIMEOUT_S) as resp:  # nosec B310 - a fixed https host (_API)
            got = json.loads(resp.read())
        if not isinstance(got, list):
            raise TypeError("GitHub's answer was not a list")
        rows += got
        oldest = _when(got[-1].get(newest)) if got else None
        if len(got) < GITHUB_PAGE or (oldest is not None and oldest < since):
            return rows
    raise ValueError(f"more than {GITHUB_PAGES * GITHUB_PAGE} rows since the fix")


def deployments(repo: str, token: str, environment: str, since: datetime, until: datetime,
                opener: Any = urllib.request.urlopen) -> list[dict[str, Any]]:
    """Deployments of `repo` to `environment` in the window (newest first, as GitHub lists them): when, the commit,
    who. Raises on a failed or partial read."""
    rows = _github_rows(f"{_API}/repos/{repo}/deployments?environment={environment}", token, since, "created_at",
                        opener)
    return [{"at": at, "source": "deploy", "what": f"{str(d.get('sha', ''))[:12]} ({d.get('ref', '?')})",
             "who": str((d.get("creator") or {}).get("login", "?"))}
            for d in rows if (at := _when(d.get("created_at"))) and since <= at <= until]


def merged_pulls(repo: str, token: str, base: str, since: datetime, until: datetime,
                 opener: Any = urllib.request.urlopen) -> list[dict[str, Any]]:
    """Pull requests of `repo` merged into `base` in the window: when, the number, who merged. Read by last update,
    newest first - a merge updates its pull request, so every merge since `since` is on the pages read. Raises on a
    failed or partial read. Titles are not shown: they are text anyone with push access writes."""
    rows = _github_rows(f"{_API}/repos/{repo}/pulls?state=closed&base={base}&sort=updated&direction=desc", token,
                        since, "updated_at", opener)
    return [{"at": at, "source": "merge", "what": f"pull request #{int(p.get('number') or 0)} into {base}",
             "who": str((p.get("merged_by") or p.get("user") or {}).get("login", "?"))}
            for p in rows if p.get("merged_at") and (at := _when(p["merged_at"])) and since <= at <= until]


def _names(entry: str, params: dict[str, Any]) -> set[str]:
    """The target as CloudTrail names it: each target parameter's value, and its last path part."""
    spec = catalog.CATALOG.get(entry)
    values = [str(params.get(p, "")) for p in (spec.target_params if spec else ())]
    return {n for v in values for n in (v, v.rsplit("/", 1)[-1], v.rsplit(":", 1)[-1]) if n}


# CloudTrail stamps an event to the second, and the fix's own time is finer: a write in the same second can read as
# earlier. The fix's own session is told apart by name, so the window reaches this far back.
SKEW = timedelta(seconds=2)


def _trail(writes: Any, names: set[str], own: str, since: datetime, now: datetime) -> tuple[list[dict], list[str]]:
    """CloudTrail writes on the target (looked up by its names) after `since`, by anyone but this incident's own
    session; an event with no time counts. A failed or partial read is unknown."""
    try:
        found = [c for c in writes(sorted(names), since - SKEW, now) if str(c.get("who", "")) != own
                 and (not isinstance(c.get("at"), datetime) or c["at"] >= since - SKEW)]
    except _aws_errors() as exc:
        return [], [f"CloudTrail ({type(exc).__name__})"]
    return found, []


def _github(environment: str, since: datetime, now: datetime, opener: Any) -> tuple[list[dict], list[str]]:
    """Deployments to the environment and merges into its branch, where this worker holds the token."""
    repo, token = os.environ.get("WARDEN_CHANGE_REPO", "").strip(), os.environ.get("WARDEN_GITHUB_TOKEN", "").strip()
    found: list[dict[str, Any]] = []
    unread: list[str] = []
    if not (repo and token):
        return found, unread
    for name, read in (("GitHub deployments", deployments), ("GitHub merges", merged_pulls)):
        try:
            found += read(repo, token, environment, since, now, opener=opener)
        except GITHUB_ERRORS:
            unread.append(name)
    return found, unread


def since_fix(*, entry: str, params: dict[str, Any], target: str, incident: str, workflow_id: str, environment: str,
              applied_at: datetime, now: datetime, log: Any, writes: Any = None,
              opener: Any = urllib.request.urlopen) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """(what landed on the target after the fix, the configured sources that could not be read, the sources this
    target has none of). `writes(names, since, until)`: CloudTrail's write events naming the target
    (AwsPlatform.writes_on), or None where its platform has no such reader - then nothing is said to be read."""
    landed = [{"at": e["at"], "source": "warden", "what": f"{e['body'].get('action_class', '?')} by fix run "
                                                          f"{e['body'].get('workflow_id', '?')}", "who": "WARDEN"}
              for e in log.entries(kinds=(bounds.APPLIED,), since=applied_at)
              if e["body"].get("service") == target and e["body"].get("workflow_id") != workflow_id]
    unread: list[str] = []
    unchecked = [] if writes is not None else ["CloudTrail (this target's platform has no change reader)"]
    if writes is not None:
        found, lost = _trail(writes, _names(entry, params), identity.correlation(incident), applied_at, now)
        landed, unread = landed + found, unread + lost
    found, lost = _github(environment, applied_at, now, opener)
    landed, unread = landed + found, unread + lost
    landed.sort(key=lambda c: c["at"] if isinstance(c.get("at"), datetime) else applied_at)
    return landed, unread, unchecked


def shown(landed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What landed, as the record keeps it: every text redacted (a CloudTrail actor can be an ARN), one mapping."""
    mapping: dict[str, str] = {}
    return [{k: (redact(v, mapping=mapping).text if isinstance(v, str) else
                 v.isoformat() if isinstance(v, datetime) else v) for k, v in c.items()} for c in landed]


def said(landed: list[dict[str, Any]], unread: list[str]) -> str:
    """Why the fix is not undone, in one line, redacted."""
    if landed:
        first = shown(landed[:1])[0]
        more = f" and {len(landed) - 1} more" if len(landed) > 1 else ""
        when = str(first.get("at") or "an unknown time")[:16].replace("T", " ")
        return (f"not rolled back: {first['source']} {first['what']} by {first['who']} landed on the target at "
                f"{when}Z, after WARDEN's fix{more}; undoing the fix now could undo or break that change - a person "
                "decides")
    return (f"not rolled back: {', '.join(unread)} could not be read, so whether anything landed on the target after "
            "WARDEN's fix is unknown - a person decides")
