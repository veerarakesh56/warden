"""Which change broke it (requirement R38): the changes near an alert, for the people reading the incident.

Three sources, each optional, newest first:
- GitHub Deployments to the incident's environment (WARDEN_CHANGE_REPO, read with WARDEN_GITHUB_TOKEN);
- WARDEN's own applied fixes, from its audit;
- write events on that environment's resources in CloudTrail, read through the environment's platform reader.

A change near an alert is a SUSPECT, never the cause: the section says so, and nothing here reaches the model - its
prompt is pinned and qualified (register E6), and evidence of a change is already in it as deploy records. A source
that cannot be read is named, never silently dropped. Commit messages and deployment descriptions are not shown:
they are text anyone with push access writes.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

from .environments import both_times

BEFORE = timedelta(hours=6)  # how far before the alert a change is still a suspect
MOST = 15
_API = "https://api.github.com"
_TIMEOUT_S = 8.0


def _when(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def github_deployments(repo: str, token: str, environment: str, since: datetime, until: datetime,
                       opener: Any = urllib.request.urlopen) -> list[dict[str, Any]]:
    """Deployments of `repo` to `environment` in the window: when, the commit, who. Raises on a failed read."""
    url = f"{_API}/repos/{repo}/deployments?environment={environment}&per_page=30"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                               "X-GitHub-Api-Version": "2022-11-28"})
    with opener(req, timeout=_TIMEOUT_S) as resp:  # nosec B310 - a fixed https host
        rows = json.loads(resp.read())
    out = []
    for d in rows if isinstance(rows, list) else []:
        at = _when(d.get("created_at"))
        if at and since <= at <= until:
            out.append({"at": at, "source": "deploy", "what": f"{str(d.get('sha', ''))[:12]} ({d.get('ref', '?')})",
                        "who": str((d.get("creator") or {}).get("login", "?"))})
    return out


def warden_changes(log: Any, since: datetime, until: datetime) -> list[dict[str, Any]]:
    """WARDEN's own applied fixes in the window, from its audit."""
    from .bounds import APPLIED

    return [{"at": e["at"], "source": "warden", "what": f"{e['body'].get('action_class', '?')} on "
                                                         f"{e['body'].get('service', '?')}", "who": "WARDEN"}
            for e in log.entries(kinds=(APPLIED,), since=since) if e["at"] <= until]


def recent(alert: Any, *, log: Any, platform: Any = None, now: datetime | None = None) -> tuple[list[dict], list[str]]:
    """(changes newest first, at most MOST; the sources that could not be read)."""
    until = now or datetime.now(UTC)
    started = _when(alert.started_at) if getattr(alert, "started_at", "") else None
    since = (started or until) - BEFORE
    changes: list[dict] = []
    unread: list[str] = []
    try:
        changes += warden_changes(log, since, until)
    except Exception:  # noqa: BLE001 - a source that cannot be read is named
        unread.append("WARDEN's audit")
    repo, token = os.environ.get("WARDEN_CHANGE_REPO", "").strip(), os.environ.get("WARDEN_GITHUB_TOKEN", "").strip()
    if repo and token:
        try:
            changes += github_deployments(repo, token, alert.environment, since, until)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            unread.append("GitHub deployments")
    reader = getattr(platform, "for_environment", None)
    if reader is not None:
        try:
            changes += reader(alert.environment).changes(since, until, alert.environment)
        except Exception:  # noqa: BLE001 - a source that cannot be read is named
            unread.append("CloudTrail")
    changes.sort(key=lambda c: c["at"], reverse=True)
    return changes[:MOST], unread


def section(changes: list[dict], unread: list[str]) -> str:
    """The report's section: suspects, not causes."""
    if not changes and not unread:
        return ""
    lines = ["", "### Changes near the alert - suspects, not causes", ""]
    lines += [f"- {both_times(c['at'])} · {c['source']} · {c['what']} · by {c['who']}" for c in changes]
    if not changes:
        lines.append("- none found in the six hours before the alert")
    if unread:
        lines.append(f"- not read: {', '.join(unread)}")
    return "\n".join(lines)
