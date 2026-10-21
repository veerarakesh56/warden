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
import re
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

from . import web
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
                       opener: Any = web.urlopen) -> list[dict[str, Any]]:
    """Deployments of `repo` to `environment` in the window: when, the commit, who. Raises on a failed read."""
    url = f"{_API}/repos/{repo}/deployments?environment={environment}&per_page=30"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                               "X-GitHub-Api-Version": "2022-11-28"})
    with opener(req, timeout=_TIMEOUT_S) as resp:
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
        except (OSError, ValueError):  # URLError and timeouts are OSErrors
            unread.append("GitHub deployments")
    reader = getattr(platform, "for_environment", None)
    if reader is not None:
        try:
            changes += reader(alert.environment).changes(since, until, alert.environment)
        except Exception:  # noqa: BLE001 - a source that cannot be read is named
            unread.append("CloudTrail")
    changes.sort(key=lambda c: c["at"], reverse=True)
    return changes[:MOST], unread


def with_evidence(changes: list[dict], logs: list[str], alert: Any) -> list[dict]:
    """The changes, with the ones WARDEN's own readers recorded for the alert's resources in its evidence (the CHANGE
    lines, by event name). The account-wide read above finds a write by the resource it names, and some services'
    events name none - an EventBridge rule's - so the section listed WARDEN's own earlier fixes and not the
    DisableRule that caused the alarm. Newest first, at most MOST, each change once."""
    from .reporting import _CHANGE

    started = _when(alert.started_at) if getattr(alert, "started_at", "") else None
    found = list(changes)
    seen = {(c["at"].replace(microsecond=0), str(c["what"]).split(" ")[0]) for c in changes}
    for line in logs:
        m = _CHANGE.match(line)
        at = _when(m.group(1)) if m else None
        if at is None or (started and not started - BEFORE <= at <= started + timedelta(minutes=5)):
            continue
        what, _, who = m.group(2).rpartition(" by ")
        if (at.replace(microsecond=0), what.split(" ")[0]) not in seen:
            seen.add((at.replace(microsecond=0), what.split(" ")[0]))
            found.append({"at": at, "source": "cloudtrail", "what": what, "who": who})
    found.sort(key=lambda c: c["at"], reverse=True)
    return found[:MOST]


def section(changes: list[dict], unread: list[str]) -> str:
    """The report's section: suspects, not causes. Every entry is WARDEN's own read (the platform's CloudTrail lookup,
    or a CHANGE line only WARDEN's readers write); a resource or principal name in one is still someone else's word,
    so a command in it is withheld as in the model's prose (G4)."""
    from .gate import withhold_commands

    if not changes and not unread:
        return ""
    lines = ["", "### Changes near the alert - suspects, not causes", ""]
    lines += [f"- {both_times(c['at'])} · {c['source']} · {withhold_commands(str(c['what']))} · by "
              f"{withhold_commands(str(c['who']))}" for c in changes]
    if not changes:
        lines.append("- none found in the six hours before the alert")
    if unread:
        lines.append(f"- not read: {', '.join(unread)}")
    return "\n".join(lines)


# ------------------------------------------------------------------ what changed in the code (register G10-55)
# What WARDEN would miss outside AWS - the code change behind a deploy. For each commit a deploy near
# the alarm carries (an image tag, a deployment's sha), the files it changed and its message, from GitHub. The message
# and the file names are written by people: untrusted lines (GITHUB ...), redacted and quarantined like any log.
# A commit id: 7 to 40 hex characters with at least one letter - never all digits, so an AWS account id (12 digits, in
# an image address) is never taken for one and sent to GitHub.
_SHA = re.compile(r"(?=\d*[a-f])[0-9a-f]{7,40}", re.ASCII)
MAX_COMMITS = 3
MAX_FILES = 15


def deploy_shas(base: Any, alert: Any) -> list[str]:
    """The commits the deploys near the alarm carry, from the base backend's own deploy read (windowed there): a
    deploy's sha, or an image's tag - the part after its last ':' - never the image's address. None read: none."""
    try:
        deploys = base.deploys(alert)
    except Exception:  # noqa: BLE001 - no deploys read: no commits to look up; and the AWS read says why
        deploys = []
    shas: list[str] = []
    for d in deploys if isinstance(deploys, list) else []:
        for v in _commits_of(d):
            if v not in shas:
                shas.append(v)
    return shas


def _commits_of(deploy: Any) -> list[str]:
    """A deploy's own sha and its image's tag, where each is shaped like a commit id."""
    if not isinstance(deploy, dict):
        return []
    image = str(deploy.get("image") or "")
    tag = image.rsplit(":", 1)[-1] if ":" in image else ""
    values = (str(v or "").strip().lower() for v in (deploy.get("sha"), tag))
    return [v for v in values if _SHA.fullmatch(v)]


class CommitReader:
    """The files and message of each commit a deploy near the alarm carries. A public repository needs no token
    (GitHub allows unauthenticated reads); WARDEN_GITHUB_READ_TOKEN, a read-only token, raises the rate limit."""

    source = "github"

    def __init__(self, base: Any, *, repo: str = "", token: str = "", opener: Any = web.urlopen) -> None:
        self.base, self.repo, self.token, self._open = base, repo, token, opener

    def _get(self, path: str) -> Any:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(f"{_API}{path}", headers=headers)
        with self._open(req, timeout=_TIMEOUT_S) as resp:
            return json.loads(resp.read())

    def logs(self, alert: Any) -> list[str]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", self.repo or ""):
            return []
        return [self._commit_line(sha) for sha in deploy_shas(self.base, alert)[:MAX_COMMITS]]

    def _commit_line(self, sha: str) -> str:
        """One deployed commit as an evidence line, or a TOOL-PARTIAL line saying why it was not read."""
        try:
            c = self._get(f"/repos/{self.repo}/commits/{sha}")
        except urllib.error.HTTPError as exc:
            return f"TOOL-PARTIAL github commit {sha[:12]}: HTTP {exc.code} - not read"
        except (OSError, ValueError) as exc:  # URLError and timeouts are OSErrors
            return f"TOOL-PARTIAL github commit {sha[:12]}: {type(exc).__name__} - not read"
        info = c.get("commit") or {}
        when = _when((info.get("committer") or {}).get("date"))
        files = ", ".join(f"{str(f.get('filename'))[:120]}(+{f.get('additions', 0)}/-{f.get('deletions', 0)})"
                          for f in (c.get("files") or [])[:MAX_FILES])
        first = " ".join(str(info.get("message") or "").splitlines()[:1])[:200]
        return (f"GITHUB commit {str(c.get('sha') or sha)[:12]} {when.isoformat() if when else '?'} "
                f"files: {files or '-'} message: {first}")

    def traces(self, alert: Any) -> list[str]:
        # The evidence-source signature: a deploy timeline holds no traces, whatever the alert is.
        return []

    def metrics(self, alert: Any) -> dict[str, float]:
        # The evidence-source signature: a deploy timeline holds no metrics, whatever the alert is.
        return {}
