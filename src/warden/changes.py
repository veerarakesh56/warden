"""A change record for every change WARDEN applied (register O9).

A fix that changed a live system must leave a record where a team already looks for changes, not only in WARDEN's
own audit. After a run that applied something, its end is written as a GitHub issue in a configured repository:
what was changed, where, at which tier, the exact plan hash, who approved it, how it ended, when (UTC and the
display zone), and the audit head to check it against (`warden audit show <incident>`).

The text leaves WARDEN, so it passes the outbound gate first; a gate that blocks it sends nothing. The token is a
Secrets Manager secret (WARDEN_GITHUB_TOKEN, a fine-grained token limited to issues on that one repository), and the
call is bounded by a timeout. A failure is recorded, never raised: the change happened whether or not its record
could be written, and the audit says which.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime

from .environments import both_times
from .gate import enforce

_API = "https://api.github.com"
_TIMEOUT_S = 8.0


def issue_text(*, incident_id: str, end: dict, plan: dict, head: str, at: datetime) -> tuple[str, str]:
    """The issue's title and body, from the run's end row and its plan row."""
    title = f"WARDEN change: {plan.get('entry', '?')} on {plan.get('target', '?')} - {end.get('status', '?')}"
    approvers = ", ".join(end.get("approvers") or []) or "none recorded"
    body = "\n".join([
        f"WARDEN applied a change for incident `{incident_id}`.",
        "",
        (f"- **Change:** `{plan.get('entry', '?')}` on `{plan.get('target', '?')}` ({plan.get('environment', '?')}, "
         f"tier {plan.get('tier', '?')})"),
        f"- **Plan hash:** `{end.get('plan_hash') or plan.get('plan_hash', '?')}`",
        (f"- **Approved by:** {approvers} (required: {end.get('required', '?')}"
         f"{', a single approver' if end.get('single_approver') else ''})"),
        f"- **Ended:** {end.get('status', '?')} at {both_times(at)}",
        f"- **Audit head:** `{head[:16]}`, check with `warden audit show {incident_id}`",
    ])
    return title[:256], body


class GitHubIssues:
    """Opens one issue per applied change in `repo` (owner/name). Never raises."""

    def __init__(self, repo: str, token: str, *, api: str = _API) -> None:
        if repo.count("/") != 1:
            raise ValueError("the change repository is owner/name")
        self.repo, self._token, self.api = repo, token, api.rstrip("/")

    def open(self, title: str, body: str) -> tuple[str | None, str]:
        gated = enforce(f"{title}\n\n{body}")
        if gated.verdict == "BLOCK":
            return None, "withheld by the outbound gate: " + "; ".join(gated.reasons)
        title_out, _, body_out = gated.text.partition("\n\n")
        req = urllib.request.Request(
            f"{self.api}/repos/{self.repo}/issues", method="POST",
            data=json.dumps({"title": title_out, "body": body_out, "labels": ["warden-change"]}).encode(),
            headers={"Authorization": f"Bearer {self._token}", "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # nosec B310 - a fixed https API
                return json.loads(resp.read()).get("html_url"), "opened"
        except urllib.error.HTTPError as exc:
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            return None, f"transport error: {type(exc).__name__}"


def from_environment() -> GitHubIssues | None:
    """The configured recorder, or None: WARDEN_CHANGE_REPO and WARDEN_GITHUB_TOKEN together, or no records."""
    repo, token = os.environ.get("WARDEN_CHANGE_REPO"), os.environ.get("WARDEN_GITHUB_TOKEN")
    return GitHubIssues(repo, token) if repo and token else None
