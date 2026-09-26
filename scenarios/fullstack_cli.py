"""Wave 4, run by an operator one step at a time (docs/WAVE4-FULLSTACK.md).

    python -m scenarios.fullstack_cli soak               # wait: every component healthy + 30 min
    python -m scenarios.fullstack_cli inject fs-07       # capture prior state, break it, wait for the alarm
    python -m scenarios.fullstack_cli diagnose fs-07     # run WARDEN as the reader identity, save its report
    python -m scenarios.fullstack_cli fix fs-07          # apply the report's fix commands via the allow-list
    python -m scenarios.fullstack_cli verify fs-07       # poll the fault's "fixed when" verifier
    python -m scenarios.fullstack_cli revert fs-07       # put the exact prior state back, wait for baseline
    python -m scenarios.fullstack_cli status             # every fault's steps, and the stack's health now
    python -m scenarios.fullstack_cli watch              # after the last fault: 30 min of health checks
    python -m scenarios.fullstack_cli score              # RESULTS.md over the run directory
    python -m scenarios.fullstack_cli run fs-07          # all five steps chained - only if you ask for it

⛔ OWNER'S DECISIONS (2026-09-25), which shape this module:
  - It never runs terraform and never reads terraform state. The stack description is a JSON file
    the infra pipeline writes with `terraform output -json` ($WARDEN_FS_STACK, default
    ~/warden-fullstack-build/stack.json). Expected keys: see STACK_KEYS.
  - WARDEN is not run by a loop. Each step is a separate command, and everything a later step needs
    is on disk in the run directory ($WARDEN_FS_RUN, default ~/warden-bench-runs/wave4-fullstack),
    OUTSIDE the repository, so steps can be hours apart and survive a reboot.
  - After the last fault, `watch` re-checks everything for a while BEFORE anyone destroys the stack:
    some damage only shows up later (a DLQ that fills after three receives, a rollout that stalls).

⛔ The run directory has the layout `scenarios.score` reads (manifest.json, ground-truth/, reports/),
plus two private folders that must NEVER be published: `saved/` (the exact prior state each inject
replaced - IAM policy documents, queue policies, ConfigMap/Secret data) and `hold/` (the session
holder's control files).

⛔ WARDEN runs with ONLY the reader identity: the assumed role warden-pg-fs-reader, a token-only
kubeconfig for ServiceAccount warden in shop, and DSNs for warden_ro whose IAM token is signed with
THAT role's credentials (its rds-db:connect grant is what lets WARDEN in) - built from nothing, as
in every earlier wave (scenarios/runner.py explains why). There are no database passwords: Aurora
runs in express configuration, IAM authentication only (2026-09-26). The provider comes from the operator's
environment (WARDEN_PROVIDER=claude_cli for a Claude subscription).
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import functools
import json
import os
import pathlib
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any

import yaml

from . import ops_fullstack as fs
from .runner import (
    CATALOG,
    EXHAUSTION_MARKERS,
    PASSTHROUGH,
    ROOT,
    SCORING,
    SYSTEM_ENV,
    _git_commit,
    _now,
    _sha256,
    _write_json,
    load_wave,
    mint_kubeconfig,
)

HERE = pathlib.Path(__file__).resolve().parent
ALERT_TEMPLATE = HERE / "alert-fullstack.yaml"
DEFAULT_RUN = pathlib.Path.home() / "warden-bench-runs" / "wave4-fullstack"
DEFAULT_STACK = pathlib.Path.home() / "warden-fullstack-build" / "stack.json"
DEFAULT_KUBECONFIG = pathlib.Path.home() / "warden-fullstack-build" / "kubeconfig"

# What the stack description file must / may carry: `terraform output -json` of terraform/fullstack,
# either wrapped {"k": {"value": v}} or flat {"k": v}, plus `ecs_baseline_task_definition`, which
# `scripts/deploy_fullstack_apps.py deploy ecs` adds, plus the Aurora keys that
# `terraform/fullstack/aurora_express.py create` merges in. NO PASSWORD exists anywhere:
#   - the harness's admin connection is the master user (db_master_username, `postgres`) with an
#     IAM token signed by the OPERATOR's credentials, fresh for every connection - never given to WARDEN;
#   - WARDEN's warden_ro token is signed with the ASSUMED READER ROLE's credentials (warden_dsns).
STACK_KEYS = {
    "required": ("reader_role_arn", "aurora_writer_endpoint", "aurora_reader_endpoint",
                 "redis_security_group_id", "eks_cluster_name", "ecs_baseline_task_definition"),
    "optional": ("region", "aurora_database", "aurora_port", "aurora_writer_instance", "db_master_username",
                 # any ops_fullstack.Target field name overrides that default, e.g.:
                 "checkout_role", "ecs_exec_role", "slow_index", "orders_sql_table", "config_key"),
}

# Evidence reach of the stack backend, PINNED in WARDEN's environment (fullstack_warden_env), not left
# to WARDEN's defaults: 15 min of logs and k8s events, 10 of metrics, 30 of deploy history. The quiet
# period before each inject outlasts the longest by the same 3-minute margin as runner.QUIET_MARGIN_M.
# ⛔ The deploy window was WARDEN's 6 h default until after fs-00 (2026-09-26): that control run read
# the preflight's rollouts. 30 min still covers every fault's own change (worst case fs-16: the
# reconciler's config change, alarm up to 25 min later).
LOG_LOOKBACK_M, METRIC_WINDOW_M, DEPLOY_WINDOW_M, QUIET_MARGIN_M = 15, 10, 30, 3
QUIET_SECONDS = (max(LOG_LOOKBACK_M, METRIC_WINDOW_M, DEPLOY_WINDOW_M) + QUIET_MARGIN_M) * 60
EVIDENCE_ISOLATION = {"log_lookback_m": LOG_LOOKBACK_M, "metric_window_m": METRIC_WINDOW_M,
                      "deploy_window_m": DEPLOY_WINDOW_M,
                      "quiet_seconds_before_each_inject": QUIET_SECONDS}
WARDEN_EVIDENCE_ENV = {
    "WARDEN_AWS_LOG_LOOKBACK_M": str(LOG_LOOKBACK_M), "WARDEN_AWS_METRIC_WINDOW_M": str(METRIC_WINDOW_M),
    "WARDEN_K8S_LOG_LOOKBACK_M": str(LOG_LOOKBACK_M),
    "WARDEN_AWS_DEPLOY_WINDOW_H": str(DEPLOY_WINDOW_M / 60), "WARDEN_K8S_DEPLOY_WINDOW_H": str(DEPLOY_WINDOW_M / 60),
}
ALARM_POLL_S = 30
VERIFY_POLL_S = 20
HOLD_MAX_S = 3 * 3600  # an orphaned holder closes its sessions by itself after this

_EXTRACT = (
    "import json, sys\n"
    "from warden.models import RunReport\n"
    "from warden.reporting import build_report\n"
    "rec = RunReport.model_validate_json(open(sys.argv[1], encoding='utf-8').read())\n"
    "built = build_report(rec.alert, root_cause=rec.root_cause, proposal=rec.proposal,\n"
    "                     verdict=rec.verdict, context=rec.context, backend='stack',\n"
    "                     show_identifiers=True)\n"
    "open(sys.argv[2], 'w', encoding='utf-8').write(json.dumps(built.data, default=str, indent=2))\n"
)


class StepError(RuntimeError):
    """This step cannot run now. Said plainly, never swallowed."""


# =========================================================================== the environment


@dataclasses.dataclass
class Env:
    """Everything that touches the world, injectable so tests and --dry-run share the real steps."""

    clients: fs.Clients
    target: fs.Target
    alarm: Callable[[str], dict]                      # name -> {"state", "description"}
    assume_reader: Callable[[], dict[str, str]]       # AWS creds + KUBECONFIG + DSNs + "arn"
    invoke_warden: Callable[[dict, pathlib.Path, pathlib.Path], tuple[int, str]]  # env, alert, report
    extract_fix: Callable[[pathlib.Path, pathlib.Path], dict]                     # report -> built data
    execute: Callable[[list[dict]], tuple[list[dict], list[dict]]]
    stack_ids: Callable[[], frozenset[str]]
    faults: dict[str, fs.Fault] = dataclasses.field(default_factory=lambda: dict(fs.FAULTS))
    baseline: Callable[[], list[str]] | None = None   # default: ops_fullstack.check_baseline
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    log: Callable[[str], None] = print
    dry_run: bool = False


def load_stack(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        raise StepError(f"no stack description at {path} - the infra pipeline writes it with "
                        "`terraform output -json`; point WARDEN_FS_STACK at it")
    raw = json.loads(path.read_text(encoding="utf-8"))
    flat = {k: (v.get("value") if isinstance(v, dict) and "value" in v else v) for k, v in raw.items()}
    missing = [k for k in STACK_KEYS["required"] if not flat.get(k)]
    if missing:
        hint = (" - the aurora_* keys come from `python terraform/fullstack/aurora_express.py create`"
                if any(k.startswith("aurora_") for k in missing) else "")
        raise StepError(f"{path} is missing {missing}{hint}")
    return flat


def target_from_stack(stack: dict) -> fs.Target:
    t = fs.Target(
        region=stack.get("region") or fs.REGION,
        writer_endpoint=stack["aurora_writer_endpoint"],
        reader_endpoint=stack["aurora_reader_endpoint"],
        redis_sg_id=stack["redis_security_group_id"],
        ecs_baseline_td=stack.get("ecs_baseline_task_definition") or "",
        database=stack.get("aurora_database") or stack.get("db_name") or "shop",
    )
    if stack.get("aurora_writer_instance"):  # express configuration names the writer itself
        t.writer_instance = stack["aurora_writer_instance"]
    names = {f.name for f in dataclasses.fields(fs.Target)} - {"saved", "persist", "sleep"}
    for key in names & set(stack):
        if key not in ("region", "writer_endpoint", "reader_endpoint", "redis_sg_id") and stack[key]:
            setattr(t, key, stack[key])
    return t


RO_USER = "warden_ro"


def pg_dsn(user: str, password: str, host: str, database: str, port: int | str = 5432) -> str:
    """A libpq URL with the password percent-encoded. ⛔ Lives in memory and in WARDEN's env only."""
    from urllib.parse import quote

    return (f"postgresql://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}/"
            f"{database}?sslmode=require")


def iam_dsn(rds: Any, user: str, host: str, database: str, port: int | str = 5432) -> str:
    """A DSN whose password is an IAM database token (valid 15 min for NEW connections) signed
    locally with `rds`'s credentials. Aurora then checks that identity's rds-db:connect."""
    token = rds.generate_db_auth_token(DBHostname=host, Port=int(port), DBUsername=user,
                                       Region=rds.meta.region_name)
    return pg_dsn(user, token, host, database, port)


def warden_dsns(creds: dict[str, str], target: fs.Target, port: int | str,
                make_client: Callable[..., Any]) -> dict[str, str]:
    """WARDEN's warden_ro DSNs, signed with the ASSUMED READER ROLE's credentials (`creds` is the
    AssumeRole `Credentials`), never the operator's: the reader role's rds-db:connect is the grant
    that is exercised, so a WARDEN that can read the database is one whose role says it may."""
    rds = make_client("rds", region_name=target.region, aws_access_key_id=creds["AccessKeyId"],
                      aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])
    return {"WARDEN_STACK_DB_WRITER_DSN": iam_dsn(rds, RO_USER, target.writer_endpoint, target.database, port),
            "WARDEN_STACK_DB_READER_DSN": iam_dsn(rds, RO_USER, target.reader_endpoint, target.database, port)}


def fullstack_warden_env(creds: dict[str, str], arm: dict[str, str], region: str) -> dict[str, str]:
    """WARDEN's environment, built from nothing (contract A). ⛔ Read runner.py's docstring before
    adding a name here: every entry is a way for the tool to reach more than the reader can."""
    env = {k: os.environ[k] for k in SYSTEM_ENV if k in os.environ}
    env.update({k: os.environ[k] for k in PASSTHROUGH if k in os.environ})
    env.update({
        "AWS_ACCESS_KEY_ID": creds["AWS_ACCESS_KEY_ID"],
        "AWS_SECRET_ACCESS_KEY": creds["AWS_SECRET_ACCESS_KEY"],
        "AWS_SESSION_TOKEN": creds["AWS_SESSION_TOKEN"],
        "AWS_REGION": region,
        "AWS_DEFAULT_REGION": region,
        "KUBECONFIG": creds["KUBECONFIG"],
        "WARDEN_STACK_DB_WRITER_DSN": creds["WARDEN_STACK_DB_WRITER_DSN"],
        "WARDEN_STACK_DB_READER_DSN": creds["WARDEN_STACK_DB_READER_DSN"],
        "WARDEN_BACKEND": "stack",
        **WARDEN_EVIDENCE_ENV,
        # One gather reads every labelled component plus a Lambda code download (builder A).
        "WARDEN_TOOL_TIMEOUT": os.environ.get("WARDEN_TOOL_TIMEOUT", "30"),
    })
    env.update(arm)
    return env


def _subprocess_warden(timeout_s: float) -> Callable[..., tuple[int, str]]:
    def invoke(env: dict, alert: pathlib.Path, report: pathlib.Path) -> tuple[int, str]:
        cmd = [sys.executable, "-m", "warden.cli", "run", "--alert", str(alert),
               "--started-at", "now", "--service", "shop", "--json", str(report)]
        try:
            proc = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=timeout_s, check=False)
        except subprocess.TimeoutExpired:
            return 124, f"timed out after {timeout_s}s"
        return proc.returncode, (proc.stderr or "")[-2000:]
    return invoke


def _subprocess_extract(report: pathlib.Path, built: pathlib.Path, region: str = "") -> dict:
    """build_report over the saved RunReport, in a SUBPROCESS: this harness never imports warden.

    Identifiers are shown (the fix must name real resources); the run directory is outside the
    repository and is redacted by the publish step like every other artefact."""
    env = {k: os.environ[k] for k in SYSTEM_ENV if k in os.environ}
    env["WARDEN_REPORT_SHOW_IDENTIFIERS"] = "1"
    if region:
        # ⛔ build_report puts `--region` on every aws command from AWS_REGION, as WARDEN's own run
        # had it. Without it fs-01's fix came out region-less and the allow-list refused it - a
        # harness artefact charged to WARDEN (2026-09-26).
        env["AWS_REGION"] = env["AWS_DEFAULT_REGION"] = region
    proc = subprocess.run([sys.executable, "-c", _EXTRACT, str(report), str(built)], cwd=str(ROOT),
                          env=env, capture_output=True, text=True, timeout=120, check=False)
    if proc.returncode != 0:
        raise StepError(f"build_report failed: {(proc.stderr or '')[-400:]}")
    return json.loads(built.read_text(encoding="utf-8"))


def load_kubeconfig(kube_config, default: pathlib.Path | None = None) -> str:
    """Load the kubeconfig and return its current context name.

    The apps pipeline writes its kubeconfig next to stack.json; use it unless KUBECONFIG says otherwise.
    The default ~/.kube/config may have no current context at all - that crashed the first real `status`
    with a raw ConfigException (2026-09-26); passing a Path instead of a str crashed the second.
    """
    default = default or DEFAULT_KUBECONFIG
    kubeconfig = os.environ.get("KUBECONFIG") or (str(default) if default.is_file() else None)
    try:
        kube_config.load_kube_config(config_file=kubeconfig)
        context = kube_config.list_kube_config_contexts(config_file=kubeconfig)[1]["name"]
        if kubeconfig:
            # ⛔ The same file for every `kubectl` this process starts (mint_kubeconfig's
            # `create token`): without it kubectl read ~/.kube/config and dialled localhost:8080
            # in the first measured diagnose (2026-09-26).
            os.environ["KUBECONFIG"] = kubeconfig
        return context
    except Exception as exc:  # any kubeconfig problem is an operator setup error
        raise StepError(f"no usable kubeconfig ({type(exc).__name__}: {exc}). Run `python "
                        "scripts/deploy_fullstack_apps.py deploy k8s` (it writes "
                        f"{default}) or set KUBECONFIG.") from exc


def live_env(run: pathlib.Path, *, warden_timeout: float = 900) -> Env:
    try:
        import boto3
        import psycopg
        from kubernetes import client as kube
        from kubernetes import config as kube_config
    except ImportError as exc:  # pragma: no cover - environment, not logic
        raise StepError("Wave 4 needs: pip install -e '.[aws,k8s,postgres]'") from exc

    stack = load_stack(pathlib.Path(os.environ.get("WARDEN_FS_STACK") or DEFAULT_STACK))
    target = target_from_stack(stack)
    session = boto3.Session(region_name=target.region)
    rds = session.client("rds")
    master = stack.get("db_master_username") or "postgres"
    port = stack.get("aurora_port") or 5432
    context = load_kubeconfig(kube_config)
    if stack["eks_cluster_name"] not in context:
        raise StepError(f"kubectl's current context is {context!r}, not the {stack['eks_cluster_name']} "
                        "cluster. Switch context first (aws eks update-kubeconfig ...).")

    def connector(host: str) -> Callable[..., Any]:
        # A fresh token per connection (signing is local): a revert hours after the inject still
        # gets in. ⛔ Timeouts on every harness session: a revert must never wait on a lock forever.
        return lambda **kw: psycopg.connect(
            iam_dsn(rds, master, host, target.database, port), connect_timeout=10, autocommit=True,
            options="-c statement_timeout=60000 -c lock_timeout=15000", **kw)

    sql = connector(target.writer_endpoint)

    c = fs.Clients(**{name: session.client(svc) for name, svc in (
        ("lam", "lambda"), ("sqs", "sqs"), ("ddb", "dynamodb"), ("ec2", "ec2"), ("rds", "rds"),
        ("ecs", "ecs"), ("elbv2", "elbv2"), ("iam", "iam"), ("events", "events"),
        ("secrets", "secretsmanager"), ("cw", "cloudwatch"), ("ec", "elasticache"))},
        apps=kube.AppsV1Api(), core=kube.CoreV1Api(), sql=sql,
        sql_reader=connector(target.reader_endpoint))
    _wire_holder(target, run)
    sts = session.client("sts")

    def assume() -> dict[str, str]:
        resp = sts.assume_role(RoleArn=stack["reader_role_arn"], RoleSessionName="warden-bench-fs")
        cr = resp["Credentials"]
        return {
            "AWS_ACCESS_KEY_ID": cr["AccessKeyId"], "AWS_SECRET_ACCESS_KEY": cr["SecretAccessKey"],
            "AWS_SESSION_TOKEN": cr["SessionToken"],
            "KUBECONFIG": mint_kubeconfig("warden", target.namespace),
            **warden_dsns(cr, target, port, boto3.client),
            "arn": resp["AssumedRoleUser"]["Arn"],
        }

    def alarm(name: str) -> dict:
        found = c.cw.describe_alarms(AlarmNames=[name]).get("MetricAlarms") or []
        if not found:
            return {"state": "MISSING", "description": ""}
        return {"state": found[0].get("StateValue"), "description": found[0].get("AlarmDescription") or ""}

    def stack_ids() -> frozenset[str]:
        ids = {target.redis_sg_id}
        for fn in (target.checkout, target.processor, target.notifier, target.reconciler):
            ids |= {m["UUID"] for m in c.lam.list_event_source_mappings(FunctionName=fn)
                    .get("EventSourceMappings") or []}
        return frozenset(i for i in ids if i)

    return Env(
        clients=c, target=target, alarm=alarm, assume_reader=assume,
        invoke_warden=_subprocess_warden(warden_timeout),
        extract_fix=lambda report, built: _subprocess_extract(report, built, target.region),
        execute=lambda cmds: fs.execute_fix(cmds, sql=sql), stack_ids=stack_ids,
    )


# --------------------------------------------------------------------------- the session holder


def _wire_holder(t: fs.Target, run: pathlib.Path) -> None:
    hold = run / "hold"

    def spawn(fid: str) -> int:
        hold.mkdir(parents=True, exist_ok=True)
        for suffix in ("ready.json", "stop", "exited"):
            (hold / f"{fid}.{suffix}").unlink(missing_ok=True)
        flags = 0
        if os.name == "nt":  # detached, no console window: it must outlive this command
            flags = (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                     | subprocess.CREATE_NO_WINDOW)
        log = open(hold / f"{fid}.log", "a", encoding="utf-8")  # noqa: SIM115 - handed to the child
        proc = subprocess.Popen(
            [sys.executable, "-m", "scenarios.fullstack_cli", "--run", str(run), "_hold", fid],
            cwd=str(ROOT), stdout=log, stderr=log, stdin=subprocess.DEVNULL,
            creationflags=flags, start_new_session=os.name != "nt",
        )
        return proc.pid

    def wait_ready(fid: str, timeout_s: float) -> dict:
        path, deadline = hold / f"{fid}.ready.json", time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
            time.sleep(1)
        return {"ok": False, "error": f"no ready file after {timeout_s:.0f}s (see hold/{fid}.log)"}

    def stop(fid: str) -> None:
        hold.mkdir(parents=True, exist_ok=True)
        (hold / f"{fid}.stop").write_text(_now(), encoding="utf-8")
        # A holder still opening its sessions sees the stop only when it has finished: wait for it,
        # or the revert terminates sessions while new ones are still arriving.
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline and not (hold / f"{fid}.exited").exists():
            time.sleep(1)

    t.spawn_holder, t.wait_holder_ready, t.stop_holder = spawn, wait_ready, stop


def cmd_hold(env: Env, run: pathlib.Path, fid: str) -> int:
    """The detached holder: open the sessions, report ready, hold until told to stop."""
    hold = run / "hold"
    hold.mkdir(parents=True, exist_ok=True)
    held: list = []
    try:
        held, info = fs.HOLDERS[fid](env.clients, env.target, fid)
        _write_json(hold / f"{fid}.ready.json", {"ok": True, **info})
        deadline = time.monotonic() + HOLD_MAX_S
        while time.monotonic() < deadline and not (hold / f"{fid}.stop").exists():
            time.sleep(2)
    except Exception as exc:  # noqa: BLE001 - reported to the waiting inject, then exit
        _write_json(hold / f"{fid}.ready.json", {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
    finally:
        for conn in held:
            try:
                conn.close()
            except Exception:  # noqa: BLE001, S110 - already gone is still gone
                pass
        (hold / f"{fid}.exited").write_text(_now(), encoding="utf-8")
    return 0


# --------------------------------------------------------------------------- dry run


_DRY_REPORT = {
    "alert": {"alert_id": "bench", "name": "StackAlarm", "severity": "high", "service": "shop",
              "environment": "prod", "summary": "dry run", "started_at": "2026-01-01T00:00:00+00:00",
              "labels": {}},
    "redaction_map_size": 0,
    "context": {"logs": ["LOG lambda/warden-pg-fs-checkout 2026-01-01T00:00:00Z dry"],
                "metrics": {"lambda_invocations__checkout": 1.0, "dlq_visible__orders": 0.0},
                "recent_deploys": [], "tool_errors": []},
    "root_cause": {"hypothesis": "dry run", "confidence": 0.8, "evidence": [], "ruled_out": []},
    "proposal": {"action": "escalate_to_human", "target": "shop", "reasoning": "dry",
                 "expected_effect": "dry", "blast_radius": "single_service", "reversible": True},
    "verdict": {"status": "auto_safe", "reasons": ["dry run"], "policy_ids": [],
                "requires_approval": False},
    "cost": {"input_tokens": 0, "output_tokens": 0, "usd": 0.0, "calls": 0},
    "audit": [], "halted_reason": None,
}


def dry_env() -> Env:
    """No AWS, no cluster, no database, no model: proves the steps and the artefacts only."""
    def invoke(env, alert, report):
        _write_json(report, _DRY_REPORT)
        return 0, ""

    def extract(report, built):
        data = {"fix_commands": [{"kind": "shell", "source": "runbook", "command":
                "aws events enable-rule --name warden-pg-fs-reconcile-5m --region ap-south-2"}]}
        _write_json(built, data)
        return data

    firing, now = {"on": False}, [0.0]

    def flip(on: bool) -> dict:
        firing["on"] = on
        return {"dry": True}

    def sleep(seconds: float) -> None:
        now[0] += seconds  # a dry run waits for nothing, but its clock still moves

    stub = fs.Fault(lambda c, t: flip(True), lambda c, t: flip(False),
                    lambda c, t: (True, "dry run"), "rule")
    return Env(
        clients=fs.Clients(), target=fs.Target(),
        alarm=lambda name: {"state": "ALARM" if firing["on"] else "OK", "description": f"dry run: {name}"},
        assume_reader=lambda: {"AWS_ACCESS_KEY_ID": "ASIADRY", "AWS_SECRET_ACCESS_KEY": "dry",
                               "AWS_SESSION_TOKEN": "dry", "KUBECONFIG": "/dry/kubeconfig",
                               "WARDEN_STACK_DB_WRITER_DSN": "postgresql://warden_ro@dry.invalid/shop",
                               "WARDEN_STACK_DB_READER_DSN": "postgresql://warden_ro@dry.invalid/shop",
                               "arn": "arn:aws:sts::111122223333:assumed-role/warden-pg-fs-reader/dry"},
        invoke_warden=invoke, extract_fix=extract,
        execute=lambda cmds: ([{**c, "rc": 0, "stdout_tail": "dry run - not executed"} for c in cmds], []),
        stack_ids=frozenset, faults={fid: stub for fid in fs.FAULTS}, baseline=list,
        sleep=sleep, clock=lambda: now[0], dry_run=True,
    )


# =========================================================================== run-directory state


@functools.cache  # one catalog per process; open_run refuses a run whose catalog hash moved
def _catalog() -> dict[str, dict]:
    _doc, scenarios = load_wave(4)
    return {s["id"]: s for s in scenarios}


def scenario_for(key: str) -> dict:
    fid = fs.fault_of(key)
    match = [s for sid, s in _catalog().items() if sid.startswith(fid)]
    if len(match) != 1:
        raise StepError(f"{key}: no single Wave 4 scenario")
    return match[0]


def open_run(env: Env, run: pathlib.Path) -> dict:
    """Create the manifest on first use; afterwards refuse if the rubric or catalog moved."""
    path = run / "manifest.json"
    catalog_now = {p.name: _sha256(p) for p in sorted(CATALOG.glob("*.yaml"))}
    if path.exists():
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("catalog_sha256") != catalog_now or manifest.get("scoring_sha256") != _sha256(SCORING):
            raise StepError(f"{run}: the catalog or the rubric changed since this run began. One run "
                            "is graded under one rubric - start a new run directory.")
        if bool(manifest.get("dry_run")) != env.dry_run:
            raise StepError(f"{run}: dry_run={manifest.get('dry_run')} run, this command is "
                            f"dry_run={env.dry_run}. Use a different --run directory.")
        if manifest.get("evidence_isolation") != EVIDENCE_ISOLATION:
            # Never silent: the change, when and at which commit, is kept and printed in RESULTS.md.
            manifest.setdefault("evidence_isolation_history", []).append({
                "at": _now(), "git_commit": _git_commit(),
                "from": manifest.get("evidence_isolation"), "to": EVIDENCE_ISOLATION})
            manifest["evidence_isolation"] = EVIDENCE_ISOLATION
            _write_json(path, manifest)
        return manifest
    template = yaml.safe_load(ALERT_TEMPLATE.read_text(encoding="utf-8"))
    manifest = {
        "wave": 4, "dry_run": env.dry_run, "operator_driven": True, "started_at": _now(),
        "repeat": 1, "arm": {}, "alert_file": ALERT_TEMPLATE.relative_to(ROOT).as_posix(),
        "alert": template, "environment_label": template.get("environment"),
        "catalog_sha256": catalog_now, "scoring_sha256": _sha256(SCORING),
        "git_commit": _git_commit(), "target_kind": "fullstack", "region": env.target.region,
        "aurora_cluster": env.target.aurora_cluster, "ecs_cluster": env.target.ecs_cluster,
        "namespace": env.target.namespace, "scenario_ids": list(_catalog()),
        "evidence_isolation": EVIDENCE_ISOLATION,
    }
    _write_json(path, manifest)
    return manifest


def _state(run: pathlib.Path) -> dict:
    path = run / "state.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"active": None}


def _set_state(run: pathlib.Path, **kw: Any) -> None:
    _write_json(run / "state.json", {**_state(run), **kw})


def _gt_path(run: pathlib.Path, sid: str) -> pathlib.Path:
    return run / "ground-truth" / f"{sid}.json"


def _record(run: pathlib.Path, sid: str) -> dict | None:
    path = _gt_path(run, sid)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _save_record(run: pathlib.Path, record: dict) -> None:
    _write_json(_gt_path(run, record["scenario_id"]), record)


def _bind_saved(env: Env, run: pathlib.Path) -> None:
    """Load the prior state earlier steps captured, and persist every new capture immediately."""
    saved = run / "saved"
    for path in saved.glob("*.json") if saved.exists() else []:
        env.target.saved[path.stem] = json.loads(path.read_text(encoding="utf-8"))

    def persist(fid: str) -> None:
        path = saved / f"{fid}.json"
        if fid in env.target.saved:
            _write_json(path, env.target.saved[fid])
        else:
            path.unlink(missing_ok=True)

    env.target.persist = persist


def stack_problems(env: Env) -> list[str]:
    """The whole-stack baseline, plus: no catalog alarm may be in ALARM."""
    problems = (env.baseline or (lambda: fs.check_baseline(env.clients, env.target)))()
    for name in sorted({s["alarm"] for s in _catalog().values() if s.get("alarm")}):
        try:
            state = env.alarm(name).get("state")
        except Exception as exc:  # noqa: BLE001
            state = f"unreadable ({type(exc).__name__})"
        if state not in ("OK", "INSUFFICIENT_DATA"):
            problems.append(f"alarm {name} is {state}")
    return problems


def _poll_until(env: Env, check: Callable[[], Any], timeout_s: float, every_s: float) -> tuple[Any, float]:
    start = env.clock()
    while True:
        result = check()
        waited = env.clock() - start
        if result or waited >= timeout_s:
            return result, waited
        env.sleep(every_s)


# =========================================================================== the steps


def step_inject(env: Env, run: pathlib.Path, key: str, *, skip_quiet: bool = False,
                wait_alarm: bool = True) -> dict:
    scenario = scenario_for(key)
    sid, fid = scenario["id"], fs.fault_of(scenario)
    open_run(env, run)
    _bind_saved(env, run)
    state = _state(run)
    if state.get("active"):
        raise StepError(f"{state['active']} is still injected - revert it first")
    if not state.get("soaked_at"):
        # ⛔ The owner's order: soak (every component healthy for 30 unbroken minutes) BEFORE any fault.
        raise StepError("no soak recorded for this run - run `soak` first")
    existing = _record(run, sid)
    if existing and existing.get("runs"):
        raise StepError(f"{sid} already has a measured run; one run per fault (the owner's choice)")

    # ⛔ Evidence isolation: nothing another fault did may be inside WARDEN's evidence window.
    last = state.get("last_activity_at")
    if last and not skip_quiet:
        idle = (dt.datetime.now(dt.UTC) - dt.datetime.fromisoformat(last)).total_seconds()
        if idle < QUIET_SECONDS:
            raise StepError(f"only {idle / 60:.0f} min since the last fault's revert; WARDEN reads "
                            f"up to {max(LOG_LOOKBACK_M, METRIC_WINDOW_M, DEPLOY_WINDOW_M)} min back. Wait {(QUIET_SECONDS - idle) / 60:.0f} more "
                            "minutes, or pass --skip-quiet (recorded in the ground truth).")
    problems = stack_problems(env)
    if problems:
        raise StepError("the stack is not at baseline, so this fault would be graded against a state "
                        "nobody injected:\n  - " + "\n  - ".join(problems))

    record = {
        "scenario_id": sid, "fault_class": scenario["fault_class"],
        "fidelity": scenario.get("fidelity"), "signature_covered": bool(scenario.get("signature_covered")),
        "settle_seconds": int(scenario.get("settle_seconds") or 0), "status": "injecting",
        "started_at": _now(), "quiet_skipped": bool(skip_quiet and last), "injected": [],
        "reverted": [], "runs": [], "error": None,
    }
    _save_record(run, record)
    _set_state(run, active=sid, last_activity_at=_now())
    try:
        if scenario.get("inject"):
            record["injected"] = [{"op": "fs_inject", "fault": fid,
                                   "result": env.faults[fid].inject(env.clients, env.target)}]
    except Exception as exc:
        record["status"], record["error"] = "inject_failed", f"{type(exc).__name__}: {exc}"
        _save_record(run, record)
        env.log(f"inject FAILED ({record['error']}); reverting now")
        step_revert(env, run, sid)
        raise StepError(f"{sid}: inject failed and was reverted: {record['error']}") from exc
    record["status"] = "injected"
    record["injected_at"] = _now()
    _save_record(run, record)
    env.log(f"{sid}: injected {record['injected']}")

    alarm = {"name": scenario.get("alarm"), "expected": scenario.get("expect_alarm", True)}
    if wait_alarm and alarm["expected"]:
        env.sleep(record["settle_seconds"])
        env.log(f"   waiting up to {scenario.get('alarm_timeout_s')}s for {alarm['name']} -> ALARM")
        fired, waited = _poll_until(
            env, lambda: env.alarm(alarm["name"]).get("state") == "ALARM",
            float(scenario.get("alarm_timeout_s") or 0), ALARM_POLL_S)
        alarm.update({"fired": bool(fired), "never_fired": not fired,
                      "waited_s": round(record["settle_seconds"] + waited)})
        env.log(f"   alarm {'fired' if fired else 'NEVER FIRED'} after {alarm['waited_s']}s")
    elif alarm["expected"]:
        alarm["waited"] = False
    record["alarm"] = {**alarm, "at": _now()}
    _save_record(run, record)
    return record


def _alert_file(env: Env, run: pathlib.Path, scenario: dict, alarm: dict) -> pathlib.Path:
    alert = yaml.safe_load(ALERT_TEMPLATE.read_text(encoding="utf-8"))
    alert["name"] = scenario.get("alarm") or alert["name"]
    alert["summary"] = alarm.get("description") or alert["summary"]
    alert["severity"] = scenario.get("severity") or alert["severity"]
    path = run / "alerts" / f"{scenario['id']}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(alert, sort_keys=False), encoding="utf-8")
    return path


def _require(run: pathlib.Path, sid: str, *, active: bool = True) -> dict:
    record = _record(run, sid)
    if record is None:
        raise StepError(f"{sid} was never injected")
    if active and record.get("revert_ok") is not None:
        raise StepError(f"{sid} was already reverted")
    return record


def step_diagnose(env: Env, run: pathlib.Path, key: str, *, arm: dict[str, str] | None = None,
                  retry_reason: str | None = None) -> dict:
    scenario = scenario_for(key)
    sid = scenario["id"]
    open_run(env, run)
    record = _require(run, sid)
    if record.get("runs"):
        prior = record["runs"][0]
        if prior.get("report_written"):
            raise StepError(f"{sid} already has WARDEN's report; one run per fault")
        if not retry_reason:
            raise StepError(f"{sid}: WARDEN wrote no report (exit {prior.get('exit_code')}). One run per "
                            "fault means one ANSWER: a retry is allowed only with --retry-reason, and the "
                            "failed attempt stays on record and in RESULTS.md section 7.")
        # ⛔ Kept, never replaced: in the record, and listed where a reader of the results sees it.
        # Only an attempt WITHOUT a report may be retried - re-asking until the answer improves is
        # how a benchmark cheats; a crash before any answer measures the tool, not the diagnosis.
        record.setdefault("attempts_without_report", []).append({**prior, "retry_reason": retry_reason})
        record["runs"] = []
        manifest_path = run / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest.setdefault("resumes", []).append({
            "at": _now(), "git_commit": _git_commit(), "rerun": [sid], "superseded": [],
            "forced": [], "reason": f"{sid}: {retry_reason} (the failed attempt is kept in its record)"})
        _write_json(manifest_path, manifest)
        _save_record(run, record)
    live_alarm = env.alarm(scenario.get("alarm") or "")
    alarm = record.setdefault("alarm", {"name": scenario.get("alarm"),
                                        "expected": scenario.get("expect_alarm", True)})
    alarm["state_at_diagnose"] = live_alarm.get("state")
    if alarm.get("expected") and "never_fired" not in alarm:
        alarm["never_fired"] = live_alarm.get("state") != "ALARM"
    alert = _alert_file(env, run, scenario, live_alarm)

    # ⭐ Assumed per run and recorded: "WARDEN read only as warden-pg-fs-reader" must be checkable.
    creds = env.assume_reader()
    report = run / "reports" / f"{sid}.1.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.unlink(missing_ok=True)  # never grade a stale report as this run's answer
    code, stderr_tail = env.invoke_warden(fullstack_warden_env(creds, arm or {}, env.target.region),
                                          alert, report)
    entry = {"index": 1, "assumed_role_arn": creds.get("arn", ""), "report": f"reports/{report.name}",
             "exit_code": code, "report_written": report.exists(),
             "stderr_tail": stderr_tail if code != 0 else "", "at": _now(),
             "alert": f"alerts/{alert.name}", "arm": arm or {}, "alarm": alarm}
    if code != 0 and any(m in (stderr_tail or "") for m in EXHAUSTION_MARKERS):
        entry["provider_exhausted"] = True
    if entry["report_written"]:
        built = run / "reports" / f"{sid}.1.built.json"
        entry["fix_commands"] = len(env.extract_fix(report, built).get("fix_commands") or [])
        entry["built"] = f"reports/{built.name}"
    record["runs"] = [entry]
    record["status"] = "diagnosed"
    _save_record(run, record)
    env.log(f"{sid}: WARDEN exit {code}, report {'written' if entry['report_written'] else 'MISSING'}, "
            f"{entry.get('fix_commands', 0)} fix command(s)")
    return record


def step_fix(env: Env, run: pathlib.Path, key: str) -> dict:
    scenario = scenario_for(key)
    sid = scenario["id"]
    record = _require(run, sid)
    runs = record.get("runs") or []
    if not runs or not runs[0].get("report_written"):
        raise StepError(f"{sid} has no WARDEN report - run diagnose first")
    run0 = runs[0]
    if run0.get("fix"):
        raise StepError(f"{sid}: the fix was already applied ({run0['fix'].get('outcome')})")
    report = json.loads((run / run0["report"]).read_text(encoding="utf-8"))
    built = json.loads((run / run0["built"]).read_text(encoding="utf-8")) if run0.get("built") else {}
    verdict = (report.get("verdict") or {}).get("status")
    outcome, commands, rejected = fs.decide_fix(built, verdict, env.stack_ids())
    fix: dict[str, Any] = {"verdict": verdict, "at": _now()}
    if outcome is None:
        results, effects = env.execute(commands)
        fix.update({"outcome": "applied", "commands": results})
        record["fix_effects"] = effects
        env.log(f"{sid}: applied {len(results)} command(s): "
                + ", ".join(f"rc={r.get('rc')}" for r in results))
    else:
        fix.update({"outcome": outcome, "rejected": rejected})
        env.log(f"{sid}: {outcome}" + "".join(f"\n   {r['command'][:120]!r}: {r['reason']}" for r in rejected))
    run0["fix"] = fix
    record["status"] = "fix_" + fix["outcome"]
    _save_record(run, record)
    return record


def step_verify(env: Env, run: pathlib.Path, key: str, *, timeout_s: float | None = None) -> dict:
    scenario = scenario_for(key)
    sid, fid = scenario["id"], fs.fault_of(scenario)
    _bind_saved(env, run)
    record = _require(run, sid)
    run0 = (record.get("runs") or [{}])[0]
    fix = run0.get("fix") or {}
    applied = fix.get("outcome") == "applied"
    budget = float(timeout_s if timeout_s is not None else (scenario.get("recover_within") or 0) if applied else 0)
    last = {"ok": False, "detail": ""}

    def check() -> bool:
        try:
            ok, detail = env.faults[fid].verify(env.clients, env.target)
        except Exception as exc:  # noqa: BLE001 - an unreadable verifier is "not fixed"
            ok, detail = False, f"verifier failed: {type(exc).__name__}: {exc}"
        last.update(ok=ok, detail=detail)
        return ok

    ok, waited = _poll_until(env, check, budget, VERIFY_POLL_S)
    result = {"ok": bool(ok), "detail": last["detail"], "waited_s": round(waited), "at": _now()}
    record["verify"] = result
    if applied and run0:
        fix["outcome"] = "fixed" if ok else "not_fixed"
        fix["verify"] = result
        record["status"] = "fix_" + fix["outcome"]
    _save_record(run, record)
    env.log(f"{sid}: {'FIXED' if ok else 'not fixed'} after {result['waited_s']}s - {result['detail']}")
    return record


def step_revert(env: Env, run: pathlib.Path, key: str, *, settle_s: float = 1200) -> dict:
    """Undo the fix's database side effects, then the fault's own exact revert, then wait for the
    whole stack to be back at baseline. Idempotent: reverting twice is safe."""
    scenario = scenario_for(key)
    sid, fid = scenario["id"], fs.fault_of(scenario)
    _bind_saved(env, run)
    record = _require(run, sid, active=False)
    try:
        record["fix_effects_undone"] = fs.undo_fix_effects(record.get("fix_effects") or [],
                                                           env.clients.sql)
        record["fix_effects"] = []
        if scenario.get("revert"):
            record["reverted"] = [{"op": "fs_revert", "fault": fid,
                                   "result": env.faults[fid].revert(env.clients, env.target)}]
        record["revert_ok"] = True
    except Exception as exc:
        record["revert_ok"], record["revert_error"] = False, f"{type(exc).__name__}: {exc}"
        _save_record(run, record)
        raise StepError(f"{sid}: revert FAILED ({record['revert_error']}). The stack is not at "
                        "baseline; nothing else may run until it is. Re-run revert, or repair by hand "
                        f"from saved/{fid}.json.") from exc
    _set_state(run, active=None, last_activity_at=_now())
    env.log(f"{sid}: reverted {record['reverted']}; waiting up to {settle_s:.0f}s for baseline")
    problems: list[str] = []

    def clean() -> bool:
        problems[:] = stack_problems(env)
        return not problems

    ok, waited = _poll_until(env, clean, settle_s, 30)
    record["baseline_after"] = {"clean": bool(ok), "problems": problems, "waited_s": round(waited),
                                "at": _now()}
    record["ended_at"] = _now()
    record["status"] = "ok" if record.get("runs") else "reverted_without_run"
    _set_state(run, last_activity_at=_now())
    _save_record(run, record)
    env.log(f"{sid}: baseline {'clean' if ok else 'NOT clean: ' + '; '.join(problems)}")
    return record


def step_soak(env: Env, run: pathlib.Path, *, min_s: float = 1800, max_s: float = 3 * 3600,
              every_s: float = 60) -> bool:
    """Wait until every component has been healthy for `min_s` WITHOUT a break; give up after `max_s`.

    Any unhealthy check restarts the healthy streak: "healthy at minute 30" is not a soak.
    """
    open_run(env, run)
    start = env.clock()
    healthy_since = None
    while True:
        problems = stack_problems(env)
        now = env.clock()
        healthy_since = None if problems else (now if healthy_since is None else healthy_since)
        streak = 0.0 if healthy_since is None else now - healthy_since
        env.log(f"soak {(now - start) / 60:5.1f} min: " + (f"healthy for {streak / 60:.1f} min" if not problems
                                                           else "; ".join(problems)))
        if not problems and streak >= min_s:
            _set_state(run, soaked_at=_now())
            return True
        if now - start >= max_s:
            return False
        env.sleep(every_s)


def step_watch(env: Env, run: pathlib.Path, *, minutes: float = 30, every_s: float = 60) -> bool:
    """After the last fault, BEFORE destroy: keep checking every component for `minutes`.

    Delayed effects of earlier faults (a DLQ filling late, a rollout stalling, an alarm that only
    evaluates after its period) show up here rather than after the evidence is gone."""
    start, seen = env.clock(), []
    while True:
        problems = stack_problems(env)
        elapsed = env.clock() - start
        seen.append({"at": _now(), "elapsed_s": round(elapsed), "problems": problems})
        env.log(f"watch {elapsed / 60:5.1f} min: " + ("healthy" if not problems else "; ".join(problems)))
        if elapsed >= minutes * 60:
            break
        env.sleep(every_s)
    unhealthy = [s for s in seen if s["problems"]]
    _write_json(run / "watch.json", {"minutes": minutes, "checks": seen, "unhealthy_checks": len(unhealthy)})
    return not unhealthy


def step_status(env: Env, run: pathlib.Path, *, check: bool = True) -> list[str]:
    lines = [f"run {run}  active={_state(run).get('active')}"]
    for sid in _catalog():
        r = _record(run, sid)
        if r is None:
            lines.append(f"  {sid:45s} -")
            continue
        run0 = (r.get("runs") or [{}])[0]
        alarm = r.get("alarm") or {}
        lines.append(f"  {sid:45s} {r.get('status'):22s} alarm={'never' if alarm.get('never_fired') else 'ok'} "
                     f"fix={(run0.get('fix') or {}).get('outcome', '-')} revert_ok={r.get('revert_ok')}")
    if check:
        problems = stack_problems(env)
        lines.append("stack: " + ("healthy" if not problems else "; ".join(problems)))
    for line in lines:
        env.log(line)
    return lines


def step_run(env: Env, run: pathlib.Path, key: str, **kw: Any) -> dict:
    """All five steps chained. Only when the operator explicitly asks for it."""
    step_inject(env, run, key, skip_quiet=kw.get("skip_quiet", False))
    try:
        step_diagnose(env, run, key, arm=kw.get("arm"))
        record = _record(run, scenario_for(key)["id"]) or {}
        if (record.get("runs") or [{}])[0].get("report_written"):
            step_fix(env, run, key)
            step_verify(env, run, key)
    finally:
        record = step_revert(env, run, key)
    return record


# =========================================================================== entry point


def _parse_arm(pairs: list[str]) -> dict[str, str]:
    arm = {}
    for pair in pairs:
        k, sep, v = pair.partition("=")
        if not sep or not k:
            raise SystemExit(f"--arm must be K=V, got {pair!r}")
        arm[k] = v
    return arm


def main(argv: list[str] | None = None, *, env: Env | None = None) -> int:
    # ⛔ FIRST, before argparse can print: a Windows console is cp1252 and this output carries ⛔/⚠.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    ap = argparse.ArgumentParser(prog="scenarios.fullstack_cli", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("WARDEN_FS_RUN") or str(DEFAULT_RUN))
    ap.add_argument("--dry-run", action="store_true", help="no AWS, no model: the steps and artefacts only")
    ap.add_argument("--warden-timeout", type=float, default=900)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("soak")
    s.add_argument("--min-minutes", type=float, default=30)
    s.add_argument("--max-minutes", type=float, default=180)
    s = sub.add_parser("inject")
    s.add_argument("fault")
    s.add_argument("--skip-quiet", action="store_true")
    s.add_argument("--no-wait", action="store_true", help="do not wait for the alarm")
    s = sub.add_parser("diagnose")
    s.add_argument("fault")
    s.add_argument("--arm", action="append", default=[], metavar="K=V")
    s.add_argument("--retry-reason", default=None,
                   help="re-run a diagnose that wrote NO report; the failed attempt is kept and listed")
    sub.add_parser("fix").add_argument("fault")
    s = sub.add_parser("verify")
    s.add_argument("fault")
    s.add_argument("--timeout", type=float, default=None)
    s = sub.add_parser("revert")
    s.add_argument("fault")
    s.add_argument("--settle-minutes", type=float, default=20)
    s = sub.add_parser("status")
    s.add_argument("--no-check", action="store_true")
    s = sub.add_parser("watch")
    s.add_argument("--minutes", type=float, default=30)
    sub.add_parser("score")
    s = sub.add_parser("run")
    s.add_argument("fault")
    s.add_argument("--skip-quiet", action="store_true")
    s.add_argument("--arm", action="append", default=[], metavar="K=V")
    sub.add_parser("_hold").add_argument("fault")
    args = ap.parse_args(argv)

    run = pathlib.Path(args.run).expanduser()
    run.mkdir(parents=True, exist_ok=True)
    if args.cmd == "score":
        from . import score
        return score.main(["--run", str(run)])
    try:
        env = env or (dry_env() if args.dry_run else live_env(run, warden_timeout=args.warden_timeout))
        if args.cmd == "_hold":
            return cmd_hold(env, run, fs.fault_of(args.fault))
        if args.cmd == "soak":
            return 0 if step_soak(env, run, min_s=args.min_minutes * 60, max_s=args.max_minutes * 60) else 1
        if args.cmd == "inject":
            step_inject(env, run, args.fault, skip_quiet=args.skip_quiet, wait_alarm=not args.no_wait)
        elif args.cmd == "diagnose":
            step_diagnose(env, run, args.fault, arm=_parse_arm(args.arm), retry_reason=args.retry_reason)
        elif args.cmd == "fix":
            step_fix(env, run, args.fault)
        elif args.cmd == "verify":
            step_verify(env, run, args.fault, timeout_s=args.timeout)
        elif args.cmd == "revert":
            record = step_revert(env, run, args.fault, settle_s=args.settle_minutes * 60)
            return 0 if record["baseline_after"]["clean"] else 1
        elif args.cmd == "status":
            step_status(env, run, check=not args.no_check)
        elif args.cmd == "watch":
            return 0 if step_watch(env, run, minutes=args.minutes) else 1
        elif args.cmd == "run":
            step_run(env, run, args.fault, skip_quiet=args.skip_quiet, arm=_parse_arm(args.arm))
    except (StepError, fs.OpError) as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
