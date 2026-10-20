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

Honest limits: CloudTrail can take minutes to show an event, so a write in the last minutes may not be seen yet. A
platform with no change reader (Kubernetes, a database) adds no CloudTrail-style source; its undo still refuses on its
own when the field it restores moved (the platforms' own checks). The branch a change merges into is taken to be the
environment's name, as WARDEN's own repository is laid out (dev, prod).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any

from . import bounds, catalog, identity
from .timeline import _API, _TIMEOUT_S, _when, github_deployments

GITHUB_ERRORS = (urllib.error.URLError, TimeoutError, OSError, ValueError)


def _aws_errors() -> tuple[type[Exception], ...]:
    """What a read through the platform raises when it fails: botocore's own errors, a refused session, a lost
    connection."""
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:  # no AWS extra installed: only the platform's own errors can come
        return (RuntimeError, OSError, LookupError)
    return (BotoCoreError, ClientError, RuntimeError, OSError, LookupError)


def merged_pulls(repo: str, token: str, base: str, since: datetime, until: datetime,
                 opener: Any = urllib.request.urlopen) -> list[dict[str, Any]]:
    """Pull requests of `repo` merged into `base` in the window: when, the number, who merged. Raises on a failed read.
    Titles are not shown: they are text anyone with push access writes."""
    url = f"{_API}/repos/{repo}/pulls?state=closed&base={base}&sort=updated&direction=desc&per_page=30"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                               "X-GitHub-Api-Version": "2022-11-28"})
    with opener(req, timeout=_TIMEOUT_S) as resp:  # nosec B310 - a fixed https host
        rows = json.loads(resp.read())
    out = []
    for p in rows if isinstance(rows, list) else []:
        at = _when(p.get("merged_at")) if p.get("merged_at") else None
        if at and since <= at <= until:
            out.append({"at": at, "source": "merge", "what": f"pull request #{int(p.get('number') or 0)} into {base}",
                        "who": str((p.get("merged_by") or p.get("user") or {}).get("login", "?"))})
    return out


def _names(entry: str, params: dict[str, Any]) -> set[str]:
    """The target as CloudTrail names it: each target parameter's value, and its last path part."""
    spec = catalog.CATALOG.get(entry)
    values = [str(params.get(p, "")) for p in (spec.target_params if spec else ())]
    return {n for v in values for n in (v, v.rsplit("/", 1)[-1], v.rsplit(":", 1)[-1]) if n}


def since_fix(*, entry: str, params: dict[str, Any], target: str, incident: str, workflow_id: str, environment: str,
              applied_at: datetime, now: datetime, log: Any, changes: Any = None,
              opener: Any = urllib.request.urlopen) -> tuple[list[dict[str, Any]], list[str]]:
    """(what landed on the target after the fix, the configured sources that could not be read). `changes(since,
    until)`: the environment's CloudTrail writes (AwsPlatform.changes), or None where the platform has none."""
    landed: list[dict[str, Any]] = []
    unread: list[str] = []
    landed += [{"at": e["at"], "source": "warden", "what": f"{e['body'].get('action_class', '?')} by fix run "
                                                           f"{e['body'].get('workflow_id', '?')}", "who": "WARDEN"}
               for e in log.entries(kinds=(bounds.APPLIED,), since=applied_at)
               if e["body"].get("service") == target and e["body"].get("workflow_id") != workflow_id]
    if changes is not None:
        own, names = identity.correlation(incident), _names(entry, params)
        try:
            for c in changes(applied_at, now):
                on = str(c.get("what", "")).rpartition(" on ")[2]
                if on in names and str(c.get("who", "")) != own and c.get("at") and c["at"] > applied_at:
                    landed.append(c)
        except _aws_errors() as exc:  # a failed read: what landed is unknown
            unread.append(f"CloudTrail ({type(exc).__name__})")
    repo, token = os.environ.get("WARDEN_CHANGE_REPO", "").strip(), os.environ.get("WARDEN_GITHUB_TOKEN", "").strip()
    if repo and token:
        for name, read in (("GitHub deployments", lambda: github_deployments(repo, token, environment, applied_at, now,
                                                                             opener=opener)),
                           ("GitHub merges", lambda: merged_pulls(repo, token, environment, applied_at, now,
                                                                  opener=opener))):
            try:
                landed += read()
            except GITHUB_ERRORS:
                unread.append(name)
    landed.sort(key=lambda c: c["at"])
    return landed, unread


def said(landed: list[dict[str, Any]], unread: list[str]) -> str:
    """Why the fix is not undone, in one line."""
    if landed:
        first = landed[0]
        more = f" and {len(landed) - 1} more" if len(landed) > 1 else ""
        return (f"not rolled back: {first['source']} {first['what']} by {first['who']} landed on the target at "
                f"{first['at']:%Y-%m-%d %H:%M}Z, after WARDEN's fix{more}; undoing the fix now could undo or break "
                "that change - a person decides")
    return (f"not rolled back: {', '.join(unread)} could not be read, so whether anything landed on the target after "
            "WARDEN's fix is unknown - a person decides")
