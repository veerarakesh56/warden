"""B17: infra_restore_baseline - a Terraform stack back to what its environment's branch declares, through WARDEN's own
Helios-checked infra workflow (owner decision 2026-10-20, option A). WARDEN runs no Terraform itself.

- live: the newest successful "Deploy · <env>" run that kept an infra *plan* of the stack for review (its metadata in the
  private state bucket, `<stack>/plans/<run>.json`: commit, plan sha256, stack, environment). A plan run succeeds only
  when Helios passed it (`_infra-deploy.yml` stops otherwise). Allowed only when that plan was made at the
  environment branch's head, by a run at that same commit: a plan of older code would not be the baseline.
- apply: the same workflow, `infra_action=apply-plan` with that run id and plan sha256 - the path that applies exactly
  the reviewed plan bytes, at the commit they were made at, after Helios checks them again. Both values are the plan's
  parameters, so the approval binds them: they are in the plan hash and on the approval page. Dispatching needs a
  token that may run workflows (WARDEN_GITHUB_ACTIONS_TOKEN, the act zone's alone; the B4 GitHub App can replace it):
  without one nothing is sent, and the plan is refused before anything changes.
- healthy: the apply run that followed the dispatch finished successfully.
- undo: none. T3: an apply is not reversed automatically; a person decides what follows.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime
from typing import Any

from .. import web
from ..catalog import APPLIED_AT
from . import NotConfigured, Unconfigured
from . import PerEnvironment as _PerEnvironment

ENTRY = "infra_restore_baseline"
STACKS = ("fullstack", "undo-lab")  # the stacks _infra-deploy.yml accepts
TOKEN_ENV = "WARDEN_GITHUB_ACTIONS_TOKEN"
READ_TOKEN_ENV = "WARDEN_GITHUB_READ_TOKEN"
BUCKETS_ENV = "WARDEN_TF_STATE_BUCKETS"
API = "https://api.github.com"
TIMEOUT_S = 8.0
RUNS_READ = 20
_RUN_ID = re.compile(r"\d{1,20}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")


def _read_token() -> str:
    """The token a zone reads GitHub with: the read zone's read-only token, or - in the act zone, whose apply re-reads
    the branch and the kept plan just before dispatching - its own Actions token. Neither zone holds the other's."""
    return os.environ.get(READ_TOKEN_ENV, "").strip() or os.environ.get(TOKEN_ENV, "").strip()


class InfraPlatformError(RuntimeError):
    pass


class InfraPlatformRefused(InfraPlatformError):
    """Nothing was sent (activities.apply: refused, not half-made)."""

    nothing_changed = True


def _when(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


class GitHub:
    """The few GitHub REST calls the platform makes, on one repository; a token per call (read or dispatch)."""

    def __init__(self, repo: str, opener: Any = web.urlopen) -> None:  # a redirect never carries the token away
        if not _REPO.fullmatch(repo):
            raise InfraPlatformError(f"{repo!r} is not an owner/repository name")
        self.repo, self._open = repo, opener

    def _call(self, method: str, path: str, token: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   **({"Authorization": f"Bearer {token}"} if token else {})}
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{API}/repos/{self.repo}{path}", data=data, method=method, headers=headers)
        with self._open(req, timeout=TIMEOUT_S) as resp:
            raw = resp.read()
            return getattr(resp, "status", 200), (json.loads(raw) if raw else None)

    def get(self, path: str, token: str = "") -> Any:
        return self._call("GET", path, token)[1]

    def dispatch(self, workflow: str, ref: str, inputs: dict[str, str], token: str) -> int:
        return self._call("POST", f"/actions/workflows/{workflow}/dispatches", token, {"ref": ref, "inputs": inputs})[0]


class InfraPlatform:
    """One watched environment's Terraform stacks, changed only through its own deploy workflow."""

    def __init__(self, *, environment: str, github: GitHub, plan_meta: Callable[[str, str], dict[str, Any] | None],
                 token: Callable[[], str] = lambda: os.environ.get(TOKEN_ENV, "").strip(),
                 read_token: Callable[[], str] = lambda: _read_token()) -> None:
        self.environment, self._gh, self._meta = environment, github, plan_meta
        self._token, self._read_token = token, read_token
        self.workflow = f"deploy-{environment}.yml"

    # ------------------------------------------------------------------ reads

    def live(self, entry: str, params: dict[str, Any]) -> dict[str, Any]:
        stack = params.get("stack")
        if entry != ENTRY or stack not in STACKS:
            return {}
        try:
            return self._live(str(stack))
        except (InfraPlatformError, OSError, ValueError, KeyError, TypeError):  # URLError and timeouts are OSErrors
            return {}  # unread allows nothing: the catalogue refuses

    def _live(self, stack: str) -> dict[str, Any]:
        env, read = self.environment, self._read_token()
        head = str((self._gh.get(f"/branches/{env}", read).get("commit") or {}).get("sha", ""))
        runs = self._gh.get(f"/actions/workflows/{self.workflow}/runs?branch={env}&event=workflow_dispatch"
                            f"&status=success&per_page={RUNS_READ}", read).get("workflow_runs") or []
        state: dict[str, Any] = {"stack": stack, "environment": env, "head": head}
        live: dict[str, Any] = {"stack": {stack}, "plan_run": set(), "plan_sha256": set(), "environment": env,
                                "state": state}
        found = None
        for run in runs:  # newest first, as GitHub lists them
            meta = self._meta(stack, str(run.get("id", "")))
            if meta and meta.get("stack") == stack and meta.get("environment") == env:
                found = (run, meta)
                break
        if found is None:
            return {**live, "refused": f"no kept plan of {stack} in the last {RUNS_READ} successful {self.workflow} "
                                      "runs: plan it first (Deploy · <env>, infra_action plan)"}
        run, meta = found
        run_id, sha, commit = str(run.get("id", "")), str(meta.get("sha256", "")), str(meta.get("commit", ""))
        state.update(plan_run=run_id, plan_sha256=sha, commit=commit, run_url=str(run.get("html_url", "")),
                     planned_at=str(run.get("created_at", "")))
        why = ""
        if not _RUN_ID.fullmatch(run_id) or not _SHA256.fullmatch(sha):
            why = "the kept plan's run id or sha256 is not well formed"
        elif not head or commit != head:
            why = f"the newest kept plan of {stack} was made at {commit[:12]}, not at {env}'s head {head[:12]}: plan again"
        elif str(run.get("head_sha", "")) != commit:
            why = "the plan's run was at another commit than the plan says"
        elif run.get("conclusion") != "success":
            why = "the plan's run did not succeed: Helios did not pass it"
        return {**live, "plan_run": set() if why else {run_id}, "plan_sha256": set() if why else {sha},
                "refused": why}

    def knows(self, *_service: str) -> bool:
        return False  # health is asked by entry (healthy_for), never by a bare name

    def healthy(self, _service: str, entry: str | None = None, params: dict[str, Any] | None = None) -> bool:
        """The apply run the dispatch started finished successfully: the newest dispatched run of the workflow on the
        environment's branch, created after the fix was applied (the workflow's concurrency group runs one at a time)."""
        if entry != ENTRY:
            return False
        since = _when((params or {}).get(APPLIED_AT))
        try:
            runs = self._gh.get(f"/actions/workflows/{self.workflow}/runs?branch={self.environment}"
                                f"&event=workflow_dispatch&per_page=5", self._read_token()).get("workflow_runs") or []
        except (OSError, ValueError):  # URLError and timeouts are OSErrors
            return False
        after = [r for r in runs if since is not None and (_when(r.get("created_at")) or since) >= since]
        return bool(after) and after[0].get("status") == "completed" and after[0].get("conclusion") == "success"

    # ------------------------------------------------------------------ writes

    def apply(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any] | None = None,
              who: dict[str, Any] | None = None) -> str:
        if entry != ENTRY:
            raise InfraPlatformRefused(f"{entry} is not something the infra platform does")
        if not who or not who.get("approvers"):
            raise InfraPlatformRefused("no approvers were handed to the infra platform; nothing was sent")
        token = self._token()
        if not token:
            raise InfraPlatformRefused(f"no token that may run workflows ({TOKEN_ENV}, the slot github-actions-token) "
                                       "is configured; nothing was sent")
        now = self.live(entry, params)
        snap = snapshot or {}
        moved = [k for k in ("head", "commit", "plan_run", "plan_sha256") if (now.get("state") or {}).get(k) != snap.get(k)]
        if moved or params.get("plan_run") not in now.get("plan_run", set()) \
                or params.get("plan_sha256") not in now.get("plan_sha256", set()):
            raise InfraPlatformRefused(f"the kept plan or the branch moved since the plan was approved "
                                       f"({', '.join(moved) or 'no longer allowed'}); nothing was sent")
        inputs = {"part": "infra", "infra_action": "apply-plan", "infra_stack": str(params["stack"]),
                  "plan_run_id": str(params["plan_run"]), "plan_sha256": str(params["plan_sha256"])}
        try:
            status = self._gh.dispatch(self.workflow, self.environment, inputs, token)
        except urllib.error.HTTPError as exc:
            # GitHub answered, and did not start the run: nothing was sent to the stack.
            raise InfraPlatformRefused(f"GitHub refused the dispatch ({exc.code}); nothing was sent") from exc
        if status != 204:
            raise InfraPlatformError(f"GitHub answered {status} to the dispatch: whether the apply started is unknown")
        return (f"dispatched {self.workflow} apply-plan of {params['stack']} in {self.environment}: run "
                f"{params['plan_run']}'s plan (sha256 {str(params['plan_sha256'])[:12]}...), made at "
                f"{str(snap.get('commit', ''))[:12]}")

    def rollback(self, *_plan: Any) -> str:
        return ("nothing to roll back: a Terraform apply is not reversed automatically (T3); a person decides what "
                "follows")


def _no_such_key(exc: BaseException) -> bool:
    return str(((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code", "")) in ("NoSuchKey", "404")


def s3_plan_meta(s3: Callable[[], Any], bucket: str) -> Callable[[str, str], dict[str, Any] | None]:
    """The kept plan's metadata, `<stack>/plans/<run>.json` in the environment's state bucket, read with the platform
    reader; None when there is none (a run that was not a plan of that stack). Any other failed read raises."""
    def read(stack: str, run: str) -> dict[str, Any] | None:
        if stack not in STACKS or not _RUN_ID.fullmatch(run):
            return None
        try:
            body = s3().get_object(Bucket=bucket, Key=f"{stack}/plans/{run}.json")["Body"].read()
        except (RuntimeError, OSError, LookupError, ValueError) as exc:
            raise InfraPlatformError(f"the kept plan of run {run} could not be read") from exc
        except Exception as exc:  # botocore's ClientError: NoSuchKey, and only that, is "no plan in this run"
            if _no_such_key(exc):
                return None
            raise InfraPlatformError(f"the kept plan of run {run} could not be read") from exc
        got = json.loads(body)
        return got if isinstance(got, dict) else None
    return read


def _pairs(text: str) -> dict[str, str]:
    """`env=value[,env=value]`, as WARDEN_EKS_CLUSTERS writes its pairs."""
    pairs = (x.strip().split("=") for x in text.split(","))
    return {kv[0].strip(): kv[1].strip() for kv in pairs if len(kv) == 2 and kv[0].strip() and kv[1].strip()}


class PerEnvironment(_PerEnvironment):
    """One InfraPlatform per watched environment, made when a plan first names it: that environment's state bucket
    (WARDEN_TF_STATE_BUCKETS, `env=bucket`), read with that environment's platform reader (`reader(env)`, a clients
    callable). An environment with no bucket, or no plain owner/repository (WARDEN_CHANGE_REPO), reads and sends
    nothing (platforms.Unconfigured): every plan of it is refused."""

    def __init__(self, reader: Callable[[str], Callable[[str], Any]], repo: str | None = None,
                 buckets: str | None = None, opener: Any = web.urlopen) -> None:
        repo = (repo if repo is not None else os.environ.get("WARDEN_CHANGE_REPO", "")).strip()
        bucket_of = _pairs(buckets if buckets is not None else os.environ.get(BUCKETS_ENV, ""))

        def build(environment: str) -> InfraPlatform:
            bucket = bucket_of.get(environment, "")
            if not bucket:
                raise NotConfigured(f"{environment} has no Terraform state bucket configured ({BUCKETS_ENV})")
            if not _REPO.fullmatch(repo):
                raise NotConfigured("WARDEN_CHANGE_REPO does not name one owner/repository")
            clients = reader(environment)
            return InfraPlatform(environment=environment, github=GitHub(repo, opener),
                                 plan_meta=s3_plan_meta(lambda: clients("s3"), bucket))

        super().__init__(build, "terraform")


def infra_from_environment() -> Any:
    """The infra platform a worker runs (`--platform infra`): only behind WARDEN_TF_STATE_BUCKETS. Unset, it is
    platforms.Unconfigured - it reads nothing and every infra_restore_baseline plan is refused. Each environment's
    kept plans are read in its own platform-reader role (`warden-<env>-platform-reader`, which may read only
    `<state bucket>/<stack>/plans/*.json`)."""
    if not _pairs(os.environ.get(BUCKETS_ENV, "")):
        return Unconfigured(f"{BUCKETS_ENV} is not set: no Terraform stack is read or changed")
    import boto3

    from ..environments import region
    from . import reader_clients, role_arn

    where = region()
    sts = boto3.client("sts", region_name=where)
    return PerEnvironment(lambda env: reader_clients(sts, where, role_arn(env, "platform-reader")))
