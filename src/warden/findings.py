"""Code-review findings on the deployed change, as incident evidence (owner, 2026-10-16).

When an incident follows a deploy, what code review flagged on that deploy's pull request is a lead: "this release had
an unresolved SonarCloud finding: possible IndexError in orders.py:212". For each commit a deploy near the alarm
carries (timeline.deploy_shas - so an incident with no deploy in its window reads nothing), WARDEN finds its pull
requests on GitHub and reads, with GET requests only:

- SonarCloud's issues for that pull request (api/issues/search; WARDEN_SONAR_PROJECT, public projects need no token);
- GitHub code scanning's alerts on the pull request's merge ref (CodeQL or another uploader);
- CodeRabbit's review comments and its latest review's state.

All of it is text a pull request's author, or a bot reading their code, wrote: UNTRUSTED. None of it is passed on as
written. Each finding becomes one typed line - tool, rule id, severity, file, line, status, category, each value from
a closed set or a checked shape - and a finding whose rule id or file path fails its shape, or a CodeRabbit comment
whose own prose uses instruction-like or action words, is held back and only counted; a severity, category or line
outside its closed set or range becomes `unknown`, `comment` or no line. SonarCloud's and code scanning's text is a
rule catalogue's fixed wording ("code execution", "privilege escalation") around names from the code: it is never
read for steering words, which would hold back the most serious findings, and it is dropped like every finding's
text. The typed lines are evidence kind R (evidence.py): the model is shown
them between data markers and may cite them; they go through redaction and the tripwire like every item it reads;
grounding never lets one support an action on its own (a finding is a suspect, never proof). A read that fails is
named as not read - never "no findings".
"""

from __future__ import annotations

import json
import re
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .quarantine import _ACTION_WORDS, _plain
from .timeline import _API, _TIMEOUT_S, MAX_COMMITS, deploy_shas
from .tools import PARTIAL_PREFIX, failure_tag

SONAR = "https://sonarcloud.io"
BUDGET_S = 30.0  # the whole read, every pull request: it runs inside the evidence read's own deadline
CODERABBIT = "coderabbitai[bot]"
MAX_PRS, MAX_PER_PR = 2, 20  # defaults of WARDEN_FINDINGS_MAX_PRS and WARDEN_FINDINGS_MAX_PER_PR
# Their ceilings: GitHub's largest page (the reader does not page on, so more would drop alerts silently), and as many
# pull requests as their four reads each fit the read's 30 s budget.
CEILING_PRS, CEILING_PER_PR = 10, 100
_FAILED = (urllib.error.URLError, TimeoutError, OSError, ValueError)
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,79}")
_PATH = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_./-]{0,199}")
STATUSES = ("open", "outdated", "accepted", "fixed")  # most to least worth a look
_SEVERITY_RANK = {s: n for n, s in enumerate(("blocker", "critical", "high", "error", "major", "medium", "warning",
                                               "minor", "low", "note", "trivial", "info", "unknown"))}
CATEGORIES = frozenset({"bug", "vulnerability", "code-smell", "security-hotspot", "reliability", "security",
                        "maintainability", "quality", "potential-issue", "refactor", "nitpick", "comment"})
# Words that address a reader rather than describe code - and WARDEN's own action words. Not quarantine's STEER: it
# holds "you", "should" and "previous", which nearly every review comment uses. A false hold loses one finding, counted.
_HOLD = re.compile(r"(?i)ignor|instruct|disregard|overrid|pretend|forget|jailbreak|system prompt|assistant|"
                   r"approv|execut|propos|rol+\s*back|revert|failover|terminat|redriv|escalat|\bwarden\b|you are|as an ai")
_HOLD_SQUASHED = re.compile(r"ignor|instruct|disregard|overrid|pretend|jailbreak|rol+back|failover")


def held(text: str) -> bool:
    """Whether a finding's own text reads as an instruction (spaced, squashed, or in look-alike characters)."""
    plain = "".join(ch for ch in unicodedata.normalize("NFKC", text) if unicodedata.category(ch) != "Cf")
    squashed = re.sub(r"[^a-z]", "", plain.lower())
    return bool(_HOLD.search(plain) or _HOLD_SQUASHED.search(squashed) or _ACTION_WORDS.search(squashed))


def finding(tool: str, *, rule: str = "", severity: str = "", path: str = "", line: Any = None, status: str = "open",
            category: str = "", text: str = "") -> dict[str, Any] | None:
    """One typed finding, or None when it is held back: its text reads as an instruction, or a field fails its
    shape. The text is checked and then dropped - it never leaves this function."""
    if held(text) or (rule and not (_RULE.fullmatch(rule) and _plain(rule, 80))):
        return None
    if not path or ".." in path or not (_PATH.fullmatch(path) and _plain(path, 200)):
        return None
    severity = severity.lower() if severity.lower() in _SEVERITY_RANK else "unknown"
    category = category.lower() if category.lower() in CATEGORIES else "comment"
    out = {"tool": tool, "rule": rule, "severity": severity, "file": path, "status": status, "category": category,
           "line": line if isinstance(line, int) and 0 < line < 10_000_000 else 0}
    return out


def service_of(path: str, alert: Any) -> str:
    """Best effort: the service the alert names whose own word is a folder or file name in `path`
    (`warden-dev-orders` and `apps/orders/handler.py`). Only a name's last part or the whole name: a project
    prefix (`warden-`) names every service."""
    parts = {re.sub(r"\.[A-Za-z0-9]{1,8}$", "", p).lower() for p in path.split("/")}
    names = [getattr(alert, "service", "")] + [v.strip() for value in getattr(alert, "labels", {}).values()
                                               for v in str(value).split(",")]
    for name in names:
        name = name.strip().lower()
        if name and (name in parts or (len(last := name.rsplit("-", 1)[-1]) >= 4 and last in parts)):
            return name if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,80}", name) else ""
    return ""


def line_of(f: dict[str, Any], pr: int, sha: str, alert: Any) -> str:
    """The R line: `key=value` fields, each value checked, no free text."""
    fields = [f"pr={pr}", f"commit={sha[:12]}"] + ([f"rule={f['rule']}"] if f["rule"] else []) + [
        f"severity={f['severity']}", f"file={f['file']}"] + ([f"line={f['line']}"] if f["line"] else []) + [
        f"status={f['status']}", f"category={f['category']}"]
    service = service_of(f["file"], alert)
    if service:
        fields.append(f"maybe_service={service}")
    return f"FINDING {f['tool']} " + " ".join(fields)


_SONAR_STATUS = {"ACCEPTED": "accepted", "WONTFIX": "accepted", "FALSE_POSITIVE": "accepted", "FIXED": "fixed",
                 "CLOSED": "fixed", "RESOLVED": "fixed"}


def _sonar(issue: dict[str, Any]) -> dict[str, Any] | None:
    impacts = [i for i in issue.get("impacts") or [] if isinstance(i, dict)]
    first = impacts[0] if impacts else {}
    status = str(issue.get("issueStatus") or issue.get("status") or "").upper()
    return finding("sonarcloud", rule=str(issue.get("rule") or ""),
                   severity=str(first.get("severity") or issue.get("severity") or ""),
                   path=str(issue.get("component") or "").split(":", 1)[-1], line=issue.get("line"),
                   status=_SONAR_STATUS.get(status, "open"),
                   category=str(first.get("softwareQuality") or str(issue.get("type") or "").replace("_", "-")))


def _code_scanning(alert: dict[str, Any]) -> dict[str, Any] | None:
    rule = alert.get("rule") or {}
    instance = alert.get("most_recent_instance") or {}
    where = instance.get("location") or {}
    security = rule.get("security_severity_level")
    return finding("codeql" if str((alert.get("tool") or {}).get("name", "")).lower() == "codeql" else "code-scanning",
                   rule=str(rule.get("id") or ""), severity=str(security or rule.get("severity") or ""),
                   path=str(where.get("path") or ""), line=where.get("start_line"),
                   status={"dismissed": "accepted", "fixed": "fixed"}.get(str(alert.get("state")), "open"),
                   category="security" if security else "quality")


_RABBIT_SEVERITY = re.compile(r"(?<![A-Za-z])(Critical|Major|Minor|Trivial)(?![A-Za-z])")  # `_Major_`: no word edge
_RABBIT_KIND = (("potential issue", "potential-issue"), ("refactor suggestion", "refactor"), ("nitpick", "nitpick"))
# CodeRabbit's own marker of a comment's kind, in an HTML comment at its end: `<!-- cr-indicator-types:potential_issue -->`.
_RABBIT_INDICATOR = re.compile(r"cr-indicator-types:(potential_issue|refactor_suggestion|nitpick)")
# CodeRabbit's standard blocks: folded sections (its analysis chain, "Proposed fix", "Committable suggestion", "Prompt
# for AI Agents") and HTML comments. Their words are CodeRabbit's template ("Script executed", "Proposed fix"), not the
# finding, and they held back nearly every real comment (PR 41's review). The innermost fold first, until none is left.
_RABBIT_BLOCK = re.compile(r"<details>(?:(?!<details>).)*?</details>|<!--.*?-->", re.DOTALL | re.IGNORECASE)


def rabbit_prose(body: str) -> str:
    """A CodeRabbit comment without its standard blocks: what the steering check reads."""
    while True:
        stripped = _RABBIT_BLOCK.sub(" ", body)
        if stripped == body:
            return body
        body = stripped


def _coderabbit(comment: dict[str, Any]) -> dict[str, Any] | None:
    body = str(comment.get("body") or "")
    head = body[:300]  # CodeRabbit opens each comment with its kind and severity: `Potential issue | Major`
    sev = _RABBIT_SEVERITY.search(head)
    marked = _RABBIT_INDICATOR.search(body)
    kind = (dict(_RABBIT_KIND)[marked.group(1).replace("_", " ")] if marked
            else next((k for words, k in _RABBIT_KIND if words in head.lower()), "comment"))
    if "addressed in commit" in body.lower():
        status = "fixed"
    elif comment.get("line") is None:
        status = "outdated"
    else:
        status = "open"
    return finding("coderabbit", severity=sev.group(1) if sev else "", path=str(comment.get("path") or ""),
                   line=comment.get("line") or comment.get("original_line"), status=status, category=kind,
                   text=rabbit_prose(body))


class _Tally:
    """One pull request's findings as they are read: the typed ones, how many were seen and held back, which tools
    answered."""

    def __init__(self) -> None:
        self.found: list[dict[str, Any]] = []
        self.read: list[str] = []
        self.seen = self.held = 0

    def take(self, tool: str, rows: Any, parse: Any) -> None:
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                self.seen += 1
                f = parse(row)
                if f is None:
                    self.held += 1
                else:
                    self.found.append(f)
        self.read.append(tool)


_REVIEW_STATES = {"APPROVED": "no-objection", "CHANGES_REQUESTED": "changes-requested", "COMMENTED": "commented"}


class FindingsReader:
    """Code review's findings on the pull requests behind a deploy near the alarm. GET requests only, to
    api.github.com and sonarcloud.io. A public repository needs no token; WARDEN_GITHUB_READ_TOKEN (read-only) raises
    GitHub's rate limit and is needed for code scanning; WARDEN_SONAR_TOKEN only for a private SonarCloud project."""

    source = "findings"

    def __init__(self, base: Any, *, repo: str = "", token: str = "", sonar_project: str = "", sonar_token: str = "",
                 max_prs: int = MAX_PRS, max_per_pr: int = MAX_PER_PR, opener: Any = urllib.request.urlopen,
                 clock: Any = time.monotonic) -> None:
        self.base, self.repo, self.token, self._open, self._clock = base, repo, token, opener, clock
        self.sonar_project, self.sonar_token = sonar_project, sonar_token
        self.max_prs, self.max_per_pr = max(0, max_prs), max(1, max_per_pr)
        self._deadline = 0.0

    def _get(self, url: str, token: str) -> Any:
        left = self._deadline - self._clock()
        if left <= 0:
            raise TimeoutError("the findings read's time is spent")
        github = urllib.parse.urlsplit(url).netloc == urllib.parse.urlsplit(_API).netloc
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"} if github \
            else {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        with self._open(req, timeout=min(_TIMEOUT_S, left)) as resp:  # nosec B310 - two fixed https hosts
            return json.loads(resp.read(4_000_000))

    @staticmethod
    def _unread(exc: BaseException, what: str) -> str:
        return f"{PARTIAL_PREFIX}findings: {failure_tag(exc)} {what} - not read"

    def logs(self, alert: Any) -> list[str]:
        if not _REPO.fullmatch(self.repo or "") or not self.max_prs:
            return []
        shas = deploy_shas(self.base, alert)[:MAX_COMMITS]
        if not shas:
            return []  # no deploy in the window: nothing to read
        self._deadline = self._clock() + BUDGET_S
        out: list[str] = []
        prs = self._pull_requests(shas, out)
        for n, sha in prs:
            out += self._pull_request(alert, n, sha)
        return out

    def _pull_requests(self, shas: list[str], out: list[str]) -> list[tuple[int, str]]:
        """The pull requests of the deployed commits, at most max_prs; a failed lookup is named in `out`."""
        prs: list[tuple[int, str]] = []
        for sha in shas:
            if len(prs) >= self.max_prs:
                break
            try:
                rows = self._get(f"{_API}/repos/{self.repo}/commits/{sha}/pulls?per_page=5", self.token)
            except _FAILED as exc:
                out.append(self._unread(exc, f"pull requests of commit {sha[:12]}"))
                continue
            numbers = [pr.get("number") for pr in (rows if isinstance(rows, list) else []) if isinstance(pr, dict)]
            for n in numbers:
                if isinstance(n, int) and n > 0 and n not in {p for p, _ in prs} and len(prs) < self.max_prs:
                    prs.append((n, sha))
        return prs

    def _sonar_issues(self, n: int) -> Any:
        q = urllib.parse.urlencode({"componentKeys": self.sonar_project, "pullRequest": n,
                                    "issueStatuses": "OPEN,CONFIRMED,ACCEPTED", "ps": self.max_per_pr})
        body = self._get(f"{SONAR}/api/issues/search?{q}", self.sonar_token)
        return body.get("issues") if isinstance(body, dict) else None

    def _scanning_alerts(self, n: int) -> Any:
        # Open alerts only: dismissed and fixed ones filled the page before an open one was read (PR 41's review).
        ref = urllib.parse.quote(f"refs/pull/{n}/merge", safe="")
        return self._get(f"{_API}/repos/{self.repo}/code-scanning/alerts?ref={ref}&state=open"
                         f"&per_page={self.max_per_pr}", self.token)

    def _rabbit_comments(self, n: int) -> list[dict[str, Any]]:
        rows = self._get(f"{_API}/repos/{self.repo}/pulls/{n}/comments?per_page=100", self.token)
        return [c for c in (rows if isinstance(rows, list) else []) if isinstance(c, dict)
                and (c.get("user") or {}).get("login") == CODERABBIT and not c.get("in_reply_to_id")]

    def _rabbit_review(self, n: int) -> str:
        """CodeRabbit's latest review state. APPROVED is said without the word: "approved" is a steering word, and the
        line would lose its trust."""
        rows = self._get(f"{_API}/repos/{self.repo}/pulls/{n}/reviews?per_page=100", self.token)
        states = [str(r.get("state") or "") for r in (rows if isinstance(rows, list) else []) if isinstance(r, dict)
                  and (r.get("user") or {}).get("login") == CODERABBIT]
        return _REVIEW_STATES.get(states[-1], "") if states else ""

    def _pull_request(self, alert: Any, n: int, sha: str) -> list[str]:
        out: list[str] = []
        tally = _Tally()
        reads = [("sonarcloud", self._sonar_issues, _sonar, f"sonarcloud issues for PR #{n}")] if self.sonar_project \
            else []
        reads += [("code-scanning", self._scanning_alerts, _code_scanning, f"code scanning alerts for PR #{n}"),
                  ("coderabbit", self._rabbit_comments, _coderabbit, f"coderabbit review of PR #{n}")]
        review = ""
        for tool, fetch, parse, what in reads:
            try:
                tally.take(tool, fetch(n), parse)
                if tool == "coderabbit":
                    review = self._rabbit_review(n)
            except _FAILED as exc:
                out.append(self._unread(exc, what))
        tally.found.sort(key=lambda f: (STATUSES.index(f["status"]), _SEVERITY_RANK[f["severity"]]))
        shown = tally.found[:self.max_per_pr]
        out += [line_of(f, n, sha, alert) for f in shown]
        out.append(f"FINDINGS pr={n} commit={sha[:12]} read={','.join(tally.read) or 'none'} shown={len(shown)} "
                   f"found={tally.seen} held={tally.held}" + (f" coderabbit_review={review}" if review else ""))
        return out

    def traces(self, _alert: Any) -> list[str]:
        return []

    def metrics(self, _alert: Any) -> dict[str, float]:
        return {}
