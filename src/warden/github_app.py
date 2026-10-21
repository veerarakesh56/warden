"""WARDEN's GitHub App identity, for the code-fix pull requests (register B4, phase 2).

A code fix is written as WARDEN's own GitHub App, never as a person's token: what it may do is the App's installation
permissions, every commit is attributed to the App, and the owner can revoke it in one place. This module holds the
calls and nothing else; whether a change may be written at all is the code gate's (code_gate.py) and the environment's
`code_fix` mode.

- **Identity.** The App's id (or client id) and its private key come from the environment - in the cloud runtime from
  Secrets Manager, the act zone's alone (settings.ZONE_SECRETS). A JSON Web Token signed with the key (RS256, at
  most ten minutes, its issue time a minute back for clock drift: GitHub's documented limits) asks GitHub for an
  installation token. The token is narrowed in the request to ONE repository and two permissions - contents: write,
  pull requests: write - and refused if GitHub grants more; it lasts an hour and is held in memory only.
- **Commits** go through GraphQL `createCommitOnBranch`: GitHub makes and signs the commit itself, so it shows as
  verified and is authored by the App - no signing key of WARDEN's own. `expectedHeadOid` makes the commit fail if the
  branch moved since WARDEN read it.
- **Branches.** WARDEN writes only to branches under `warden/` that it creates; it never commits to, or opens a pull
  request into, a `warden/` branch from anything else, and never writes to any other branch. A pull request's base is
  the repository's default branch, where CI runs (`main`: dev and prod receive only what it has checked), merged by a
  person or, in phase 4 and never for prod, by the checks.
- **The wire.** One fixed host (api.github.com) over HTTPS with the system's certificate checks; every call has a
  timeout; a reply over 4 MB is refused. No token, key or reply text is ever put in an error or a log line.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import ssl
import time
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

API_HOST = "api.github.com"
TIMEOUT_S = 15.0
MAX_REPLY = 4_000_000
MAX_FILE = 1_000_000  # the contents API returns a file's bytes inline up to 1 MB
BRANCH_PREFIX = "warden/"
# What an installation token may do, asked for by name: GitHub adds metadata: read to every token.
PERMISSIONS: Mapping[str, str] = {"contents": "write", "pull_requests": "write"}
_GRANTED_ANYWAY = {"metadata": "read"}
JWT_LIFETIME_S = 540  # under GitHub's ten-minute limit, with room for the minute of back-dating
JWT_BACKDATE_S = 60

_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}")
_APP_ID = re.compile(r"\d{1,12}|Iv[0-9A-Za-z.]{2,40}")  # the App's numeric id, or its client id
_BRANCH = re.compile(r"warden/[a-z0-9][a-z0-9._-]{0,60}(?:/[a-z0-9][a-z0-9._-]{0,60}){0,2}")
_BASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,60}")
_SHA = re.compile(r"[0-9a-f]{40}")
# A headline or title: one line of up to 200 printable characters - what a revert's subject holds (`Revert "Fix the
# cart (#123)"`): quotes, #, brackets, !, +, @, & - and no control character, line break or other whitespace.
_NAMED = re.compile(r"[\w ,.:;()'/\"#\[\]!+@&=*%?<>{}|~^$`-]{1,200}")


class GitHubAppError(RuntimeError):
    """A GitHub App call failed or was refused. Its text names the call and the HTTP status, never a credential."""


@dataclass(frozen=True, repr=False)
class AppCredentials:
    app_id: str
    private_key: str  # PEM

    def __repr__(self) -> str:
        return f"AppCredentials(app_id={self.app_id!r}, private_key=<withheld>)"

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> AppCredentials | None:
        """WARDEN_CODEFIX_APP_ID and WARDEN_CODEFIX_APP_KEY; None when either is unset (no App: no code fixes)."""
        env = os.environ if env is None else env
        app_id, key = env.get("WARDEN_CODEFIX_APP_ID", "").strip(), env.get("WARDEN_CODEFIX_APP_KEY", "")
        if not app_id or not key.strip():
            return None
        if not _APP_ID.fullmatch(app_id):
            raise GitHubAppError("WARDEN_CODEFIX_APP_ID is not a GitHub App id or client id")
        return cls(app_id=app_id, private_key=key)


@dataclass(frozen=True, repr=False)
class InstallationToken:
    token: str
    expires_at: str
    repository: str

    def __repr__(self) -> str:
        return f"InstallationToken(repository={self.repository!r}, expires_at={self.expires_at!r}, token=<withheld>)"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def app_jwt(creds: AppCredentials, *, now: float) -> str:
    """The App's JSON Web Token: RS256 over {iat, exp, iss}, issued a minute back, valid nine minutes."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    try:
        key = serialization.load_pem_private_key(creds.private_key.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise GitHubAppError("WARDEN_CODEFIX_APP_KEY is not an unencrypted PEM private key") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GitHubAppError("WARDEN_CODEFIX_APP_KEY is not an RSA key (GitHub Apps sign with RS256)")
    issued = int(now) - JWT_BACKDATE_S
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = _b64url(json.dumps({"iat": issued, "exp": issued + JWT_LIFETIME_S, "iss": creds.app_id},
                                separators=(",", ":")).encode())
    signed = f"{header}.{claims}".encode("ascii")
    return f"{header}.{claims}." + _b64url(key.sign(signed, padding.PKCS1v15(), hashes.SHA256()))


# ---------------------------------------------------------------------------------------------------- the wire

def _tls() -> ssl.SSLContext:
    """The system's certificate store, the server's certificate and host name checked, TLS 1.2 at least."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _connect(host: str) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection(host, timeout=TIMEOUT_S, context=_tls())


class Api:
    """One JSON call to api.github.com. `connect` is replaced in tests; the host is fixed."""

    def __init__(self, connect: Callable[[str], Any] = _connect) -> None:
        self._connect = connect

    def call(self, method: str, path: str, *, token: str, body: Any = None, diff: bool = False) -> tuple[int, Any]:
        """The reply's status and its JSON - or, with `diff`, its text (GitHub's `application/vnd.github.diff`)."""
        if not path.startswith("/") or "//" in path or "\\" in path:
            raise GitHubAppError(f"{method}: not a path on {API_HOST}")
        accept = "application/vnd.github.diff" if diff else "application/vnd.github+json"
        headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28",
                   "Authorization": f"Bearer {token}", "User-Agent": "warden-code-fix"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        what = f"{method} {path.split('?', 1)[0]}"
        conn = self._connect(API_HOST)
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(MAX_REPLY + 1)
            status = resp.status
        except (OSError, http.client.HTTPException) as exc:
            raise GitHubAppError(f"{what}: GitHub did not answer ({type(exc).__name__})") from None
        finally:
            conn.close()
        if len(raw) > MAX_REPLY:
            raise GitHubAppError(f"{what}: the reply is over {MAX_REPLY} bytes")
        try:
            if diff:
                return status, raw.decode("utf-8")
            return status, json.loads(raw) if raw else None
        except ValueError:
            raise GitHubAppError(f"{what}: the reply is not JSON (HTTP {status})") from None


def _expect(status: int, ok: int, what: str) -> None:
    if status != ok:
        raise GitHubAppError(f"{what}: HTTP {status}")


def _repo(repo: str) -> str:
    if not _REPO.fullmatch(repo or "") or ".." in repo:
        raise GitHubAppError("the repository must be owner/name")
    return repo


# ------------------------------------------------------------------------------------------------- the App

class GitHubApp:
    """The App itself: it asks for installation tokens and does nothing else."""

    def __init__(self, creds: AppCredentials, *, api: Api | None = None, clock: Callable[[], float] = time.time):
        self._creds, self._api, self._clock = creds, api or Api(), clock

    def installation_token(self, repo: str) -> InstallationToken:
        """A token for `repo` alone with PERMISSIONS alone - refused if GitHub's answer grants anything more."""
        repo = _repo(repo)
        jwt = app_jwt(self._creds, now=self._clock())
        status, found = self._api.call("GET", f"/repos/{repo}/installation", token=jwt)
        _expect(status, 200, "the App's installation on the repository")
        installation = found.get("id") if isinstance(found, dict) else None
        if not isinstance(installation, int) or isinstance(installation, bool) or installation <= 0:
            raise GitHubAppError("the App's installation has no id")
        name = repo.split("/", 1)[1]
        status, got = self._api.call("POST", f"/app/installations/{installation}/access_tokens", token=jwt,
                                     body={"repositories": [name], "permissions": dict(PERMISSIONS)})
        _expect(status, 201, "an installation token")
        return _checked_token(got, repo)


def _checked_token(got: Any, repo: str) -> InstallationToken:
    if not isinstance(got, dict) or not isinstance(got.get("token"), str) or not got["token"]:
        raise GitHubAppError("the installation token reply holds no token")
    granted = got.get("permissions")
    if not isinstance(granted, dict) or {k: v for k, v in granted.items() if _GRANTED_ANYWAY.get(k) != v} != PERMISSIONS:
        raise GitHubAppError("the installation token's permissions are not exactly contents and pull requests: write")
    repos = got.get("repositories")
    names = [r.get("full_name") for r in repos if isinstance(r, dict)] if isinstance(repos, list) else None
    if got.get("repository_selection") != "selected" or names != [repo]:
        raise GitHubAppError("the installation token is not limited to the one repository")
    return InstallationToken(token=got["token"], expires_at=str(got.get("expires_at") or ""), repository=repo)


# ------------------------------------------------------------------------------------------- one repository

_COMMIT = """mutation($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid url } }
}"""


def _branch(branch: str) -> str:
    if not _BRANCH.fullmatch(branch or "") or ".." in branch or branch.endswith((".", ".lock")):
        raise GitHubAppError(f"WARDEN writes only to its own branches, under {BRANCH_PREFIX}")
    return branch


def _sha(sha: str, what: str) -> str:
    if not _SHA.fullmatch(sha or ""):
        raise GitHubAppError(f"{what} must be a full commit id")
    return sha


def _line(text: str, what: str) -> str:
    if not _NAMED.fullmatch(text or ""):
        raise GitHubAppError(f"{what} must be one plain line")
    return text


def _paths(paths: Any) -> list[str]:
    from .code_gate import path_refusal

    out = list(paths)
    for path in out:
        if not isinstance(path, str) or path_refusal(path):
            raise GitHubAppError("a file path is not a plain relative path")
    return out


class RepoWriter:
    """Reads and writes one repository with one installation token."""

    def __init__(self, token: InstallationToken, *, api: Api | None = None) -> None:
        self._token, self._api = token, api or Api()
        self.repo = token.repository

    def _call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        return self._api.call(method, f"/repos/{self.repo}{path}", token=self._token.token, body=body)

    def head(self, branch: str) -> str:
        """The commit a branch points at now."""
        if not (_BASE.fullmatch(branch or "") or _BRANCH.fullmatch(branch or "")):
            raise GitHubAppError("not a branch name")
        status, ref = self._call("GET", f"/git/ref/heads/{urllib.parse.quote(branch, safe='/')}")
        _expect(status, 200, f"the head of {branch}")
        sha = ((ref or {}).get("object") or {}).get("sha") if isinstance(ref, dict) else None
        return _sha(str(sha or ""), f"the head of {branch}")

    def read_file(self, path: str, ref: str) -> bytes | None:
        """A file's bytes at commit `ref`; None when the file is not there."""
        (path,) = _paths([path])
        query = urllib.parse.urlencode({"ref": _sha(ref, "the commit read")})
        status, got = self._call("GET", f"/contents/{urllib.parse.quote(path)}?{query}")
        if status == 404:
            return None
        _expect(status, 200, f"the file {path}")
        if not isinstance(got, dict) or got.get("type") != "file" or got.get("encoding") != "base64":
            raise GitHubAppError(f"{path} is not a file GitHub returned inline")
        data = base64.b64decode(str(got.get("content") or ""), validate=False)
        if len(data) > MAX_FILE or len(data) != got.get("size"):
            raise GitHubAppError(f"{path}: the file is over {MAX_FILE} bytes or arrived incomplete")
        return data

    def commit_diff(self, sha: str) -> tuple[list[str], str]:
        """A commit's parents and its diff as `git diff` writes it."""
        status, got = self._call("GET", f"/commits/{_sha(sha, 'the commit')}")
        _expect(status, 200, f"the commit {sha[:12]}")
        parents = [str(p.get("sha") or "") for p in (got.get("parents") or []) if isinstance(p, dict)] \
            if isinstance(got, dict) else []
        status, text = self._api.call("GET", f"/repos/{self.repo}/commits/{sha}", token=self._token.token, diff=True)
        _expect(status, 200, f"the diff of {sha[:12]}")
        return [_sha(p, "a parent commit") for p in parents], text

    def delete_branch(self, branch: str) -> None:
        """Remove one of WARDEN's own branches (a write that failed half way)."""
        status, _ = self._call("DELETE", f"/git/refs/heads/{_branch(branch)}")
        _expect(status, 204, f"deleting {branch}")

    def create_branch(self, branch: str, sha: str) -> None:
        status, _ = self._call("POST", "/git/refs", {"ref": f"refs/heads/{_branch(branch)}",
                                                      "sha": _sha(sha, "the branch's start")})
        _expect(status, 201, f"the branch {branch}")

    def commit(self, branch: str, *, expected_head: str, headline: str, body: str = "",
               additions: Mapping[str, bytes] | None = None, deletions: tuple[str, ...] = ()) -> str:
        """One signed commit on `branch` (createCommitOnBranch); its id. Fails if the branch moved from
        `expected_head`."""
        additions = dict(additions or {})
        if not additions and not deletions:
            raise GitHubAppError("a commit with no change")
        changes = {"additions": [{"path": p, "contents": base64.b64encode(additions[p]).decode("ascii")}
                                 for p in _paths(sorted(additions))],
                   "deletions": [{"path": p} for p in _paths(deletions)]}
        commit_input = {"branch": {"repositoryNameWithOwner": self.repo, "branchName": _branch(branch)},
                        "expectedHeadOid": _sha(expected_head, "the expected head"),
                        "message": {"headline": _line(headline, "the commit headline"), "body": body},
                        "fileChanges": changes}
        status, got = self._api.call("POST", "/graphql", token=self._token.token,
                                     body={"query": _COMMIT, "variables": {"input": commit_input}})
        _expect(status, 200, "createCommitOnBranch")
        if not isinstance(got, dict) or got.get("errors"):
            raise GitHubAppError("createCommitOnBranch refused the commit (the branch moved, or a path is wrong)")
        oid = (((got.get("data") or {}).get("createCommitOnBranch") or {}).get("commit") or {}).get("oid")
        return _sha(str(oid or ""), "the new commit")

    def default_branch(self) -> str:
        """The repository's default branch: where pull requests go and CI runs."""
        status, got = self._call("GET", "")
        _expect(status, 200, "the repository")
        branch = str((got or {}).get("default_branch") or "") if isinstance(got, dict) else ""
        if not _BASE.fullmatch(branch) or branch.startswith(BRANCH_PREFIX.rstrip("/")):
            raise GitHubAppError("the repository's default branch is not a plain branch name")
        return branch

    def open_pull_request(self, *, head: str, base: str, title: str, body: str) -> tuple[int, str]:
        """A pull request from WARDEN's branch into `base`, which must be the repository's default branch (read from
        GitHub here, not trusted from the caller); its number and address."""
        if not _BASE.fullmatch(base or "") or base.startswith(BRANCH_PREFIX.rstrip("/")):
            raise GitHubAppError("a pull request's base must be one of the repository's own branches, never WARDEN's")
        if base != self.default_branch():
            raise GitHubAppError("a pull request's base must be the repository's default branch, where CI runs")
        status, got = self._call("POST", "/pulls", {"head": _branch(head), "base": base,
                                                     "title": _line(title, "the title"), "body": body,
                                                     "maintainer_can_modify": False})
        _expect(status, 201, f"the pull request into {base}")
        number = got.get("number") if isinstance(got, dict) else None
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise GitHubAppError("the pull request reply holds no number")
        return number, str(got.get("html_url") or "")
