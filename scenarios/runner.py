"""Execute a wave: break the proving ground, run WARDEN against it, put it back.

    python -m scenarios.runner --wave 1 --dry-run          # no AWS, no API key, full pipeline
    python -m scenarios.runner --wave 1                    # the real thing
    python -m scenarios.runner --wave 1 --arm WARDEN_KNOWLEDGE_IN_PROMPT=1

⭐ THE SHAPE THAT MATTERS. For each scenario: inject once, wait `settle_seconds`, run WARDEN
`--repeat` times back to back, revert once, wait for the service to stabilise. Repeating the *model*
against a single injected state costs two extra API calls and no extra AWS time, and it is the only
way to tell a stable answer from a coin flip.

⛔ WARDEN RUNS AS A SUBPROCESS UNDER AN ASSUMED READER ROLE, WITH AN ENVIRONMENT BUILT FROM NOTHING.
Not `os.environ.copy()`, not the operator's credentials, and not `HOME`/`USERPROFILE` — a child
process that can find `~/.aws/credentials` is a child that can quietly run with more permission than
the role it is supposed to be confined to, and scenario `ecs-11` would then pass while measuring
nothing at all. That exact defect was found in this project once already.

⛔ A FAILED REVERT ABORTS THE WAVE. Every later scenario would otherwise be graded against a
contaminated account while looking like a perfectly normal run, and nothing in the output would say
so.

⛔ RUN IT DETACHED, AND IF IT STOPS, RESUME IT. A wave takes around two hours. Twice, the wave was
launched as a child of an interactive Claude Code session and died with it - the second time
because the session ran out of usage, which the wave's own `claude -p` calls had helped exhaust. The
runner now stops cleanly on an exhausted provider, and `--resume DIR` continues from where it
stopped, re-running only incomplete scenarios. Launch it so it does not share the session's life:

    # Windows - through WMI, so its parent is the WMI host and not the session (a child of the
    # session's shell can die with it), and with ShowWindow=0, so no console window pops up on the
    # operator's desktop. Both properties were needed: the first launch used WMI without the second,
    # and put an unexplained cmd window in front of the person whose machine it was.
    $si = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ShowWindow=[uint16]0}
    Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
      CommandLine = 'cmd /c ".venv\\Scripts\\python.exe -u -m scenarios.runner --resume <DIR>
                     > <DIR>\\runner.log 2> <DIR>\\runner.err"'
      CurrentDirectory = '<repo>'; ProcessStartupInformation = $si }
    # Linux / macOS
    setsid nohup python -m scenarios.runner --resume <DIR> > <DIR>/runner.log 2>&1 &

⚠ This module writes RAW artefacts — a task-definition ARN contains the 12-digit account id. They
land OUTSIDE the repository by default (`~/warden-bench-runs/`). Redaction is
`scripts/aws_proof_bundle.py` and the gate is `scripts/check_publishable.py`; duplicating either
here would create two redactors that can disagree about what a secret looks like.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any

import yaml

from . import ops

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
CATALOG = HERE / "catalog"
ALERT_FILE = HERE / "alert.yaml"
SCORING = HERE / "scoring.yaml"
TF_DIR = ROOT / "terraform" / "proving-ground"

# Copied from the operator's shell into WARDEN's, by name. Everything else is dropped. The model
# provider settings and the provider key have to come through — WARDEN cannot reason without them.
PASSTHROUGH = (
    "WARDEN_PROVIDER", "WARDEN_MODEL", "WARDEN_BASE_URL", "WARDEN_MAX_USD", "WARDEN_LLM_TIMEOUT",
    "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
)

# The minimum a Python process needs to start and open a TLS socket, on Windows and on Linux.
# ⛔ HOME and USERPROFILE are deliberately absent. See the module docstring.
SYSTEM_ENV = ("PATH", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "COMSPEC", "PATHEXT", "LANG", "TZ")


class RunnerError(RuntimeError):
    """The wave cannot continue. Never swallowed."""


class ModelExhausted(RuntimeError):
    """The model provider has no capacity left, so every later run would fail identically."""


# Markers in a failed WARDEN run's stderr meaning the provider is out of capacity for the account,
# not that this one call went wrong. `ProviderExhausted` is WARDEN's own error for it; the Gemini
# daily free-tier quota is recognised by its quota id.
EXHAUSTION_MARKERS = ("ProviderExhausted", "GenerateRequestsPerDay")


def check_baseline(clients: ops.Clients, target: ops.Target) -> list[str]:
    """Is the proving ground in the state a wave is entitled to assume? Returns what is wrong.

    ⛔ WHY THIS EXISTS, AND IT IS NOT HYPOTHETICAL. A wave was killed mid-scenario and its `finally`
    never ran, so the account was left on a deliberately-crashing task definition. The ground-truth
    file recorded that honestly — `status: running`, `revert_ok: null` — but nothing stopped the NEXT
    wave from starting against a broken service and producing a full results table that looked
    entirely normal. Every scenario would have been graded against a fault nobody injected.

    ⚠ This checks the state the scenarios manipulate, not everything. A wave that passes here can
    still be contaminated in some way not listed. It is a floor, not a proof.
    """
    problems: list[str] = []

    # ⚠ An absent service must be REPORTED, not crash the check. `["services"][0]` raised IndexError
    # on the day the cluster had been deleted, which is exactly when this check matters most.
    services = clients.ecs.describe_services(
        cluster=target.cluster, services=[target.service],
    ).get("services") or []
    service = next((s for s in services if s.get("status") == "ACTIVE"), None)
    if service is None:
        problems.append(
            f"service {target.service} not found (or not ACTIVE) in cluster {target.cluster} - "
            "the proving ground is not up"
        )
        return problems

    current = (service.get("taskDefinition") or "").split("/")[-1]
    baseline = target.baseline_task_definition.split("/")[-1]
    if current != baseline:
        problems.append(
            f"service is on {current}, not the baseline {baseline} - a previous run did not revert"
        )
    if service["desiredCount"] != 2:
        problems.append(f"desiredCount is {service['desiredCount']}, expected 2")
    if service["runningCount"] != service["desiredCount"] or service["pendingCount"]:
        problems.append(
            f"service is not steady: {service['runningCount']} running, "
            f"{service['pendingCount']} pending, {service['desiredCount']} desired"
        )
    # ⛔ A rollout still in flight. This is the check that was missing, and it is the one that
    # mattered: a healthy control once ran with 2 deployments in flight, 3 of 2 tasks running,
    # still converging from the previous revert. running == desired held on two of its three runs
    # while the service was nowhere near settled, so the steadiness check above cannot catch it.
    in_flight = len(service.get("deployments") or [])
    if in_flight != 1:
        problems.append(
            f"{in_flight} deployments in flight - a rollout has not converged, so the next "
            "scenario would read the previous one's rollout as evidence"
        )

    if not clients.logs.describe_log_groups(
        logGroupNamePrefix=target.log_group,
    ).get("logGroups"):
        problems.append(f"log group {target.log_group} is missing - a previous run deleted it")

    if target.security_group_id:
        groups = clients.ec2.describe_security_groups(
            GroupIds=[target.security_group_id],
        ).get("SecurityGroups") or []
        if not groups:
            problems.append(f"security group {target.security_group_id} not found")
        elif not groups[0].get("IpPermissionsEgress"):
            problems.append("security group has no egress rule - a previous run revoked it")

    if target.route_table_id:
        tables = clients.ec2.describe_route_tables(
            RouteTableIds=[target.route_table_id],
        ).get("RouteTables") or []
        if not tables:
            problems.append(f"route table {target.route_table_id} not found")
        elif not [r for r in tables[0].get("Routes") or []
                  if r.get("DestinationCidrBlock") == "0.0.0.0/0"]:
            problems.append("route table has no default route - a previous run deleted it")

    if target.warden_role_name:
        names = clients.iam.list_role_policies(
            RoleName=target.warden_role_name,
        ).get("PolicyNames") or []
        if names:
            document = clients.iam.get_role_policy(
                RoleName=target.warden_role_name, PolicyName=names[0],
            )["PolicyDocument"]
            actions = document["Statement"][0].get("Action") or []
            if len(actions) != 4:
                problems.append(
                    f"the reader role grants {len(actions)} action(s), expected 4 - a previous run "
                    "shrank it and did not restore it"
                )
    return problems


# --------------------------------------------------------------------------- the catalog


def load_wave(wave: int) -> tuple[dict, list[dict]]:
    """Return (catalog document, scenarios) for one wave, in catalog order."""
    for path in sorted(CATALOG.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if int(doc.get("wave", -1)) == wave:
            return doc, list(doc.get("scenarios") or [])
    raise RunnerError(f"no catalog file declares wave {wave} (looked in {CATALOG})")


def _sha256(path: pathlib.Path) -> str:
    """Hash of the file's CONTENT, independent of the platform's line endings.

    ⛔ This hashed raw bytes, and git on Windows checks text files out with CRLF. So the rubric hash
    recorded in a manifest described this laptop's checkout, not the rubric: anyone re-scoring a
    published bundle from a Linux or macOS clone would get a different hash, and the scorer's drift
    check would announce "THE RUBRIC CHANGED AFTER THIS RUN" about results that were never touched.
    A tamper check that fires on honest data is worse than none. Normalising to LF makes the hash
    the same on every platform. Must stay identical to scenarios/score.py::_content_sha256.
    """
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


# --------------------------------------------------------------------------- the environment


def terraform_outputs(tf_dir: pathlib.Path = TF_DIR) -> dict[str, Any]:
    proc = subprocess.run(
        ["terraform", f"-chdir={tf_dir}", "output", "-json"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise RunnerError(f"terraform output failed: {proc.stderr.strip()[:400]}")
    return {key: value.get("value") for key, value in json.loads(proc.stdout).items()}


def target_from_outputs(out: dict[str, Any]) -> ops.Target:
    required = ("region", "ecs_cluster", "ecs_service", "log_group", "baseline_task_definition")
    missing = [key for key in required if not out.get(key)]
    if missing:
        raise RunnerError(
            f"terraform outputs are missing {missing} - has the proving ground been applied?"
        )
    return ops.Target(
        region=out["region"],
        cluster=out["ecs_cluster"],
        service=out["ecs_service"],
        log_group=out["log_group"],
        baseline_task_definition=out["baseline_task_definition"],
        security_group_id=out.get("service_security_group_id") or "",
        route_table_id=out.get("route_table_id") or "",
        warden_role_name=out.get("warden_reader_role_name") or "",
    )


@dataclasses.dataclass
class Harness:
    """Everything the wave loop touches, injectable so `--dry-run` and the tests share one path.

    The seam is the point. A runner that can only be exercised against a live AWS account is a
    runner nobody checks, and a second "test mode" implementation is a second thing to drift.
    """

    clients: ops.Clients
    target: ops.Target
    account: str
    # () -> {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "arn"}
    assume_reader: Callable[[], dict[str, str]]
    # (env, report_path) -> (exit_code, stderr_tail)
    invoke_warden: Callable[[dict[str, str], pathlib.Path], tuple[int, str]]
    # () -> list of problems; empty means the proving ground is at baseline.
    #
    # ⛔ REQUIRED, deliberately, with no default. `check_baseline` was once written, documented,
    # and cited in a comment as the thing that "catches anything genuinely wrong before the next
    # scenario" - while the wave loop never called it. It ran only when someone ran it by hand. A
    # field that defaults to "no check" is how that happens, so every harness must now say what its
    # baseline check is, even if the answer is "none, this is a dry run".
    baseline: Callable[[], list[str]]
    sleep: Callable[[float], None] = time.sleep
    stabilize: Callable[[], None] = lambda: None


# --------------------------------------------------------------------------- running WARDEN


def warden_env(creds: dict[str, str], target: ops.Target, arm: dict[str, str]) -> dict[str, str]:
    """Build WARDEN's environment from nothing.

    ⛔ Read the module docstring before adding a name to this. Every entry is a way for the tool
    under test to reach something the four-action reader role cannot.
    """
    env = {key: os.environ[key] for key in SYSTEM_ENV if key in os.environ}
    env.update({key: os.environ[key] for key in PASSTHROUGH if key in os.environ})
    env.update(
        {
            "AWS_ACCESS_KEY_ID": creds["AWS_ACCESS_KEY_ID"],
            "AWS_SECRET_ACCESS_KEY": creds["AWS_SECRET_ACCESS_KEY"],
            "AWS_SESSION_TOKEN": creds["AWS_SESSION_TOKEN"],
            "AWS_REGION": target.region,
            "AWS_DEFAULT_REGION": target.region,
            "WARDEN_BACKEND": "aws",
            "WARDEN_AWS_CLUSTER": target.cluster,
            "WARDEN_AWS_LOG_GROUP": target.log_group,
            # A live account is slower than a fixture read. At the 5s default a tool times out and
            # the run measures the timeout instead of the incident.
            "WARDEN_TOOL_TIMEOUT": os.environ.get("WARDEN_TOOL_TIMEOUT", "15"),
        }
    )
    env.update(arm)
    return env


def _subprocess_warden(target: ops.Target, timeout_s: float) -> Callable[..., tuple[int, str]]:
    def invoke(env: dict[str, str], report_path: pathlib.Path) -> tuple[int, str]:
        cmd = [
            sys.executable, "-m", "warden.cli", "run",
            "--alert", str(ALERT_FILE),
            "--started-at", "now",
            "--service", target.service,
            "--label", f"cluster={target.cluster}",
            "--label", f"log_group={target.log_group}",
            "--json", str(report_path),
        ]
        try:
            proc = subprocess.run(
                cmd, cwd=str(ROOT), env=env, capture_output=True, text=True,
                timeout=timeout_s, check=False,
            )
        except subprocess.TimeoutExpired:
            return 124, f"timed out after {timeout_s}s"
        return proc.returncode, (proc.stderr or "")[-2000:]

    return invoke


# --------------------------------------------------------------------------- one scenario


def run_scenario(harness: Harness, scenario: dict, out: pathlib.Path, *, repeat: int,
                 arm: dict[str, str]) -> dict:
    """Inject, measure `repeat` times, revert. Returns the ground-truth record.

    The record is written to disk BEFORE anything is injected, and again after every step, so a run
    that dies half way still says what it was in the middle of instead of leaving a broken account
    and no note of it.
    """
    scenario_id = scenario["id"]
    ground_truth = out / "ground-truth" / f"{scenario_id}.json"
    record: dict[str, Any] = {
        "scenario_id": scenario_id,
        "fault_class": scenario["fault_class"],
        "fidelity": scenario.get("fidelity"),
        "signature_covered": bool(scenario.get("signature_covered")),
        "settle_seconds": int(scenario.get("settle_seconds") or 0),
        "status": "running",
        "started_at": _now(),
        "injected": [],
        "reverted": [],
        "runs": [],
        "error": None,
    }
    _write_json(ground_truth, record)

    try:
        record["injected"] = ops.run_steps(
            harness.clients, harness.target, scenario.get("inject") or [], account=harness.account,
        )
        _write_json(ground_truth, record)

        harness.sleep(record["settle_seconds"])
        record["settled_at"] = _now()

        for index in range(1, repeat + 1):
            # ⭐ Assumed per run and recorded per run, not once per wave. `ecs-11` removes a
            # permission from this exact role, and "WARDEN ran with four read actions and nothing
            # else" is only a checkable claim if the identity it ran as is in the artefact.
            creds = harness.assume_reader()
            report = out / "reports" / f"{scenario_id}.{index}.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            # ⛔ Delete any report already at this path before running. `warden.cli` only writes the
            # file when it gets far enough to have something to write, so re-using an --out directory
            # would otherwise leave a PREVIOUS run's answer sitting where this run's should be, and
            # `report_written` would say True. The scorer would then grade the old report as though
            # it were this one, and nothing anywhere would look wrong.
            report.unlink(missing_ok=True)
            code, stderr_tail = harness.invoke_warden(
                warden_env(creds, harness.target, arm), report,
            )
            record["runs"].append(
                {
                    "index": index,
                    "assumed_role_arn": creds.get("arn", ""),
                    "report": f"reports/{report.name}",
                    "exit_code": code,
                    "report_written": report.exists(),
                    "stderr_tail": stderr_tail if code != 0 else "",
                    "at": _now(),
                }
            )
            _write_json(ground_truth, record)
            # ⛔ Stop at the FIRST sign the model has no capacity left. Carrying on means injecting
            # real faults into the account for runs that cannot succeed, and a results table full of
            # ERROR rows that read like the tool failing. That is what the first Max-plan wave did.
            if code != 0 and any(m in (stderr_tail or "") for m in EXHAUSTION_MARKERS):
                raise ModelExhausted((stderr_tail or "")[-300:])

        record["status"] = "ok"
    except ModelExhausted as exc:
        record["status"] = "exhausted"
        record["error"] = f"model provider exhausted: {exc}"
    except Exception as exc:  # noqa: BLE001 - recorded as an error, never swallowed
        record["status"] = "error"
        record["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        # ⛔ Runs even when the injection or WARDEN itself blew up. A benchmark that leaves the
        # account broken on failure is worse than one that never ran.
        try:
            record["reverted"] = ops.run_steps(
                harness.clients, harness.target, scenario.get("revert") or [],
                account=harness.account,
            )
            record["revert_ok"] = True
        except Exception as exc:  # noqa: BLE001
            record["revert_ok"] = False
            record["revert_error"] = f"{type(exc).__name__}: {exc}"
        record["ended_at"] = _now()
        _write_json(ground_truth, record)

    return record


# --------------------------------------------------------------------------- the wave


def run_wave(harness: Harness, scenarios: list[dict], out: pathlib.Path, *, repeat: int,
             arm: dict[str, str], log: Callable[[str], None] = print,
             records: list[dict] | None = None) -> list[dict]:
    """Run every scenario in order, stopping the wave if any revert fails.

    `records` is appended to as the wave goes, so an aborted wave still reports the scenarios that
    completed before it stopped. A caller that gets a `RunnerError` and its own empty list would
    otherwise publish "0 scenarios ran" for a wave where ten of them did.
    """
    records = [] if records is None else records
    for scenario in scenarios:
        log(f"== {scenario['id']}  ({scenario['fault_class']}, "
            f"settle {scenario.get('settle_seconds')}s)")

        # ⛔ Before EVERY scenario, not once per wave. The state a scenario inherits is whatever the
        # previous one's revert left, and a revert that "succeeded" can still leave a rollout in
        # flight. A scenario that starts there reads its predecessor's rollout as evidence.
        problems = harness.baseline()
        if problems:
            raise RunnerError(
                f"{scenario['id']}: the proving ground is not at baseline, so this scenario would be "
                "graded against a state nobody injected. Stopping the wave.\n  - "
                + "\n  - ".join(problems)
            )

        record = run_scenario(harness, scenario, out, repeat=repeat, arm=arm)
        records.append(record)
        log(f"   {record['status']}, {len(record['runs'])} run(s), "
            f"revert_ok={record.get('revert_ok')}")

        if not record.get("revert_ok", False):
            # Two different situations reach here and the message must not assert the wrong one.
            # If the injection itself failed, the revert may have refused simply because there was
            # nothing saved to restore — in which case the account is probably untouched. Either
            # way the state is now UNKNOWN, and an unknown account must not be scored, so the wave
            # stops in both cases.
            injected_something = bool(record.get("injected"))
            hint = (
                "The injection succeeded and the revert did not, so something IS still broken."
                if injected_something else
                "The injection failed too, so the revert may simply have had nothing to restore "
                "and the account may be untouched - but that is a guess, not a fact."
            )
            raise RunnerError(
                f"{scenario['id']}: revert FAILED ({record.get('revert_error')}). Stopping the "
                f"wave. {hint} Either way the state of the proving ground is now unknown, and every "
                "scenario after this one would be graded against it while looking like a normal "
                "run. Check the account, or destroy and re-apply it, before running anything else."
            )
        if record["status"] == "exhausted":
            raise RunnerError(
                f"{scenario['id']}: the model provider has no capacity left ({record['error'][:160]}). "
                "Stopping the wave: every later run would fail the same way. This scenario was "
                f"reverted. Resume after the limit resets with:  --resume {out}"
            )
        harness.stabilize()
    return records


# --------------------------------------------------------------------------- live wiring


def _live_harness(timeout_s: float) -> Harness:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - an environment problem, not logic
        raise RunnerError("the benchmark needs boto3: pip install -e '.[aws]'") from exc

    outputs = terraform_outputs()
    target = target_from_outputs(outputs)
    session = boto3.Session(region_name=target.region)
    account = str(
        outputs.get("account_id") or session.client("sts").get_caller_identity()["Account"]
    )
    clients = ops.Clients(
        ecs=session.client("ecs"), logs=session.client("logs"),
        ec2=session.client("ec2"), iam=session.client("iam"),
    )
    # ⛔ The healthy control injects nothing, so without an explicit preflight the first scenario of
    # the wave never checks that this really is the proving ground.
    ops._guard_cluster(clients, target)

    role_arn = outputs.get("warden_reader_role_arn") or ""
    if not role_arn:
        raise RunnerError(
            "terraform did not output warden_reader_role_arn. WARDEN must run as the four-action "
            "reader role; under the operator's own credentials scenario ecs-11 measures nothing "
            "while appearing to pass."
        )
    sts = session.client("sts")

    def assume() -> dict[str, str]:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="warden-benchmark")
        creds = resp["Credentials"]
        return {
            "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
            "AWS_SESSION_TOKEN": creds["SessionToken"],
            "arn": resp["AssumedRoleUser"]["Arn"],
        }

    def stabilize() -> None:
        # ⛔ THIS WAIT IS THE COST OF A VALID RESULT, NOT WASTE. An earlier version capped it at 120s
        # and called the time it saved "pure waste". Measured: the rollout after a revert takes a
        # median of ~210s and up to 272s - ECS starting baseline tasks, waiting for health checks,
        # then draining the variant. A 120s cap started the next scenario mid-rollout, and the
        # healthy control then read the previous scenario's rollout as evidence: 2 deployments in
        # flight, 3 of 2 tasks running, and two proposals to roll back a service with nothing wrong.
        #
        # So it waits long enough for a real rollout (8 min covers the 272s max with margin). This
        # is a best-effort WAIT only. The GATE is `baseline()`, which run_wave calls before every
        # scenario and which stops the wave if a rollout is still in flight - so a waiter that gives
        # up here cannot let a contaminated scenario through, it just hands the decision on.
        attempts = int(os.environ.get("WARDEN_BENCH_STABILIZE_ATTEMPTS", "32"))  # 32 x 15s = 8 min
        try:
            clients.ecs.get_waiter("services_stable").wait(
                cluster=target.cluster, services=[target.service],
                WaiterConfig={"Delay": 15, "MaxAttempts": attempts},
            )
        except Exception as exc:  # noqa: BLE001 - the baseline gate decides, not the waiter
            print(f"   (services-stable did not converge in ~{attempts * 15}s: "
                  f"{type(exc).__name__}. The baseline check will decide whether to continue.)")

    return Harness(
        clients=clients, target=target, account=account,
        assume_reader=assume, invoke_warden=_subprocess_warden(target, timeout_s),
        baseline=lambda: check_baseline(clients, target),
        stabilize=stabilize,
    )


# --------------------------------------------------------------------------- dry run
#
# ⚠ WHAT A DRY RUN PROVES, AND WHAT IT DOES NOT. It proves the wave loop, the environment allowlist,
# the artefact layout and the scorer hold together. It proves NOTHING about AWS: no fault is
# injected, no permission is really removed, and the reports are canned. A green dry run is not
# evidence that Wave 1 works.


class _FakeAws:
    """Accepts every call, records it, returns the least surprising shape."""

    def __init__(self, tag: str = "warden-proving-ground") -> None:
        self.calls: list[tuple[str, dict]] = []
        self._tag = tag

    def __getattr__(self, name: str) -> Callable[..., dict]:
        def call(**kwargs: Any) -> dict:
            self.calls.append((name, kwargs))
            return _FAKE_RESPONSES.get(name, lambda tag: {})(self._tag)

        return call


_FAKE_RESPONSES: dict[str, Callable[[str], dict]] = {
    "describe_clusters": lambda tag: {
        "clusters": [{"tags": [{"key": "Project", "value": tag}]}]
    },
    "describe_task_definition": lambda tag: {
        "taskDefinition": {
            "family": "checkout", "cpu": "512", "memory": "512", "networkMode": "awsvpc",
            "requiresCompatibilities": ["FARGATE"],
            "executionRoleArn": "arn:aws:iam::111122223333:role/exec",
            "taskRoleArn": "arn:aws:iam::111122223333:role/task",
            "containerDefinitions": [{
                "name": "checkout",
                "image": "public.ecr.aws/docker/library/python:3.12-alpine",
                "command": ["sh", "-c", "sleep 100000"],
                "logConfiguration": {"logDriver": "awslogs", "options": {}},
            }],
        }
    },
    "register_task_definition": lambda tag: {
        "taskDefinition": {
            "taskDefinitionArn": "arn:aws:ecs:ap-south-2:111122223333:task-definition/checkout:99"
        }
    },
    "list_tasks": lambda tag: {"taskArns": ["arn:aws:ecs:ap-south-2:111122223333:task/fake"]},
    "list_role_policies": lambda tag: {"PolicyNames": ["warden-reader-inline"]},
    "describe_security_groups": lambda tag: {
        "SecurityGroups": [{
            "Tags": [{"Key": "Project", "Value": tag}],
            "IpPermissionsEgress": [{"IpProtocol": "-1"}],
        }]
    },
    "describe_route_tables": lambda tag: {
        "RouteTables": [{
            "Tags": [{"Key": "Project", "Value": tag}],
            "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-fake"}],
        }]
    },
    "get_role_policy": lambda tag: {
        "PolicyDocument": {"Statement": [{
            "Effect": "Allow",
            "Action": ["ecs:DescribeServices", "ecs:DescribeTaskDefinition",
                       "logs:FilterLogEvents", "cloudwatch:GetMetricData"],
            "Resource": "*",
        }]}
    },
}

_DRY_REPORT: dict[str, Any] = {
    "alert": {
        "alert_id": "bench", "name": "ECSServiceAlarm", "severity": "high", "service": "checkout",
        "environment": "prod", "summary": "CloudWatch alarm fired for ECS service checkout",
        "started_at": "2026-01-01T00:00:00Z", "labels": {},
    },
    "redaction_map_size": 0,
    "context": {
        "logs": ["fake stream 0 OutOfMemoryError: Container killed", "fake line 2", "fake line 3"],
        "metrics": {"tasks_running": 1.0, "tasks_desired": 2.0, "tasks_pending": 0.0},
        "recent_deploys": [{"service": "checkout", "revision": "2", "by": "ecs"}],
        "tool_errors": [],
    },
    "root_cause": {"hypothesis": "dry run", "confidence": 0.85, "evidence": [], "ruled_out": []},
    "proposal": {
        "action": "rollback_deploy", "target": "checkout", "reasoning": "dry run",
        "expected_effect": "dry run", "blast_radius": "single_service", "reversible": True,
    },
    "verdict": {
        "status": "approved_for_human", "reasons": ["dry run"], "policy_ids": [],
        "requires_approval": True,
    },
    "cost": {"input_tokens": 0, "output_tokens": 0, "usd": 0.0, "calls": 0},
    "audit": [],
    "halted_reason": None,
}


def _dry_harness() -> Harness:
    target = ops.Target(
        region="ap-south-2", cluster="warden-proving-ground", service="checkout",
        log_group="/ecs/checkout",
        baseline_task_definition="arn:aws:ecs:ap-south-2:111122223333:task-definition/checkout:1",
        security_group_id="sg-fake", route_table_id="rtb-fake", warden_role_name="warden-reader",
    )
    shared = _FakeAws()
    clients = ops.Clients(ecs=shared, logs=shared, ec2=shared, iam=shared)

    def invoke(env: dict[str, str], report_path: pathlib.Path) -> tuple[int, str]:
        _write_json(report_path, _DRY_REPORT)
        return 0, ""

    return Harness(
        clients=clients, target=target, account="111122223333",
        assume_reader=lambda: {
            "AWS_ACCESS_KEY_ID": "ASIADRYRUN", "AWS_SECRET_ACCESS_KEY": "dry",
            "AWS_SESSION_TOKEN": "dry",
            "arn": "arn:aws:sts::111122223333:assumed-role/warden-reader/dry-run",
        },
        invoke_warden=invoke,
        # No real account, so nothing to check. Said explicitly rather than inherited from a default:
        # the field is required precisely so that "no check" is always a visible decision.
        baseline=list,
        sleep=lambda _seconds: None,
    )


# --------------------------------------------------------------------------- entry point


def _git_commit() -> str:
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def is_complete(record: dict, repeat: int) -> bool:
    """A scenario counts only if EVERY repeat produced a report. Otherwise it is re-run whole.

    Never re-run a single missing repeat on its own: the injected state that the other repeats
    measured has been reverted and no longer exists, so a lone re-run would measure a different
    fault instance and be reported as if it were the same one.
    """
    runs = record.get("runs") or []
    return (
        record.get("status") == "ok"
        and len(runs) == repeat
        and all(r.get("exit_code") == 0 and r.get("report_written") for r in runs)
    )


def supersede(out: pathlib.Path, scenario_id: str) -> str:
    """Move an incomplete attempt out of the scored set. Kept, never deleted, never overwritten.

    Superseded attempts go to `ground-truth/superseded/`, which the scorer's non-recursive glob does
    not read - so a re-run scenario is counted once, while the evidence that it WAS re-run, and why,
    stays in the bundle for anyone to read.
    """
    gt_dir = out / "ground-truth"
    current = gt_dir / f"{scenario_id}.json"
    kept = gt_dir / "superseded"
    kept.mkdir(parents=True, exist_ok=True)
    attempt = 1
    while (kept / f"{scenario_id}.attempt-{attempt}.json").exists():
        attempt += 1
    record = json.loads(current.read_text(encoding="utf-8"))
    reports = out / "reports" / "superseded"
    reports.mkdir(parents=True, exist_ok=True)
    for run in record.get("runs") or []:
        name = f"{scenario_id}.attempt-{attempt}.{run['index']}.json"
        src = out / run["report"]
        if src.exists():
            src.replace(reports / name)
        run["report"] = f"reports/superseded/{name}"
    record["superseded"] = {"at": _now(), "attempt": attempt}
    _write_json(kept / f"{scenario_id}.attempt-{attempt}.json", record)
    current.unlink()
    return f"ground-truth/superseded/{scenario_id}.attempt-{attempt}.json"


def _completed_on_disk(out: pathlib.Path, repeat: int) -> list[str]:
    done = []
    for path in sorted((out / "ground-truth").glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if is_complete(record, repeat):
            done.append(record["scenario_id"])
    return done


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scenarios.runner", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--wave", type=int, default=1)
    parser.add_argument("--only", default="",
                        help="comma-separated scenario id prefixes, e.g. ecs-03,ecs-09")
    parser.add_argument("--repeat", type=int, default=3,
                        help="WARDEN runs per injected state. The model is not deterministic, so "
                             "n=1 is a coin flip reported as a result")
    where = parser.add_mutually_exclusive_group()
    where.add_argument("--out", default=None,
                       help="artefact directory (default: ~/warden-bench-runs/<stamp>)")
    where.add_argument("--resume", default=None, metavar="DIR",
                       help="continue an interrupted run in DIR: complete scenarios are kept, the "
                            "rest are re-run whole. Uses that run's wave, repeat and arm")
    parser.add_argument("--rerun", default="", metavar="IDS",
                        help="with --resume: comma-separated scenario id prefixes to re-run even if "
                             "complete. Requires --reason. The superseded attempts are kept")
    parser.add_argument("--reason", default="",
                        help="why --rerun is forcing complete scenarios to run again. Recorded in "
                             "the manifest and printed in RESULTS.md")
    parser.add_argument("--arm", action="append", default=[], metavar="K=V",
                        help="extra env for WARDEN, e.g. --arm WARDEN_KNOWLEDGE_IN_PROMPT=1. "
                             "Recorded in the manifest")
    parser.add_argument("--warden-timeout", type=float, default=300.0)
    parser.add_argument("--dry-run", action="store_true",
                        help="no AWS and no API key: exercises the loop and the artefacts, and "
                             "proves nothing about AWS")
    args = parser.parse_args(argv)

    if args.rerun and not args.resume:
        raise SystemExit("--rerun only makes sense with --resume")
    if args.resume:
        rerun = tuple(x.strip() for x in args.rerun.split(",") if x.strip())
        return _resume(pathlib.Path(args.resume), args.warden_timeout,
                       rerun=rerun, reason=args.reason.strip())

    arm: dict[str, str] = {}
    for pair in args.arm:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise SystemExit(f"--arm must be K=V, got '{pair}'")
        arm[key] = value

    _doc, scenarios = load_wave(args.wave)
    if args.only:
        wanted = tuple(prefix.strip() for prefix in args.only.split(",") if prefix.strip())
        scenarios = [s for s in scenarios if s["id"].startswith(wanted)]
        if not scenarios:
            raise SystemExit(f"--only {args.only!r} matched no scenario in wave {args.wave}")

    stamp = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H%M%SZ")
    default_root = pathlib.Path(
        os.environ.get("WARDEN_BENCH_DIR", pathlib.Path.home() / "warden-bench-runs")
    )
    out = pathlib.Path(args.out) if args.out else default_root / f"wave{args.wave}-{stamp}"
    out.mkdir(parents=True, exist_ok=True)

    harness = _dry_harness() if args.dry_run else _live_harness(args.warden_timeout)
    alert = yaml.safe_load(ALERT_FILE.read_text(encoding="utf-8")) or {}

    manifest = {
        "wave": args.wave,
        "dry_run": bool(args.dry_run),
        "started_at": _now(),
        "repeat": args.repeat,
        "arm": arm,
        "alert_file": ALERT_FILE.relative_to(ROOT).as_posix(),
        "alert": alert,
        # A deliberate choice a reader should be able to argue with: the throwaway account is
        # labelled `prod` so the policy gate under test is the one people actually run.
        "environment_label": alert.get("environment"),
        "catalog_sha256": {p.name: _sha256(p) for p in sorted(CATALOG.glob("*.yaml"))},
        "scoring_sha256": _sha256(SCORING),
        "git_commit": _git_commit(),
        "cluster": harness.target.cluster,
        "service": harness.target.service,
        "region": harness.target.region,
        "scenario_ids": [s["id"] for s in scenarios],
    }
    _write_json(out / "manifest.json", manifest)
    print(f"artefacts -> {out}")
    return _run_and_record(harness, scenarios, out, manifest)


def _resume(out: pathlib.Path, warden_timeout: float, *, rerun: tuple[str, ...] = (),
            reason: str = "") -> int:
    """Continue an interrupted run, refusing anything that would make it two runs posing as one.

    ⛔ `rerun` forces COMPLETE scenarios to run again. That is exactly the mechanism a benchmark
    would use to cheat - re-run a scenario until the answer is a better one, keep that one. So it is
    only available with a written reason, every superseded attempt is kept rather than replaced,
    and both the reason and the attempts are printed in RESULTS.md where a reader will see them.
    """
    if rerun and not reason:
        raise SystemExit(
            "--rerun forces complete scenarios to run again, and needs --reason saying why. "
            "Re-running until an answer improves is how a benchmark cheats; the reason is what "
            "makes a legitimate re-run auditable."
        )
    manifest_path = out / "manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"--resume {out}: no manifest.json - not a runner output directory")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # ⛔ One rubric. A run graded partly under one catalog and partly under another is two
    # measurements stitched together, and the manifest would describe only one of them.
    catalog_now = {p.name: _sha256(p) for p in sorted(CATALOG.glob("*.yaml"))}
    if (manifest.get("catalog_sha256") != catalog_now
            or manifest.get("scoring_sha256") != _sha256(SCORING)):
        raise SystemExit(
            f"--resume {out}: the scenario catalog or the rubric has changed since this run began. "
            "Resuming would grade one run under two rubrics. Start a new run instead."
        )

    harness = _dry_harness() if manifest.get("dry_run") else _live_harness(warden_timeout)
    # ⛔ One environment. A different cluster is a different fault instance entirely.
    if harness.target.cluster != manifest.get("cluster"):
        raise SystemExit(
            f"--resume {out}: this run was on cluster {manifest.get('cluster')!r} and the proving "
            f"ground is now {harness.target.cluster!r}. Start a new run instead."
        )

    repeat = int(manifest["repeat"])
    _doc, catalog = load_wave(int(manifest["wave"]))
    wanted = set(manifest.get("scenario_ids") or [])
    scenarios = [s for s in catalog if s["id"] in wanted]

    unmatched = [p for p in rerun if not any(s["id"].startswith(p) for s in scenarios)]
    if unmatched:
        raise SystemExit(f"--rerun {unmatched} matched no scenario in this run")

    todo, superseded, forced = [], [], []
    for scenario in scenarios:
        gt = out / "ground-truth" / f"{scenario['id']}.json"
        force = scenario["id"].startswith(rerun) if rerun else False
        if gt.exists():
            if is_complete(json.loads(gt.read_text(encoding="utf-8")), repeat) and not force:
                continue
            superseded.append(supersede(out, scenario["id"]))
            if force:
                forced.append(scenario["id"])
        todo.append(scenario)

    manifest.setdefault("resumes", []).append({
        "at": _now(),
        "git_commit": _git_commit(),
        "rerun": [s["id"] for s in todo],
        "superseded": superseded,
        "forced": forced,
        "reason": reason,
    })
    _write_json(manifest_path, manifest)
    print(f"resuming {out.name}: {len(scenarios) - len(todo)} complete, {len(todo)} to run "
          f"({len(superseded)} incomplete attempt(s) kept under ground-truth/superseded/)")
    if not todo:
        print("nothing left to run.")
        return 0
    return _run_and_record(harness, todo, out, manifest, total=len(scenarios))


def _run_and_record(harness: Harness, scenarios: list[dict], out: pathlib.Path, manifest: dict,
                    *, total: int | None = None) -> int:
    arm = manifest.get("arm") or {}
    repeat = int(manifest["repeat"])
    rc = 0
    records: list[dict] = []
    try:
        run_wave(harness, scenarios, out, repeat=repeat, arm=arm, records=records)
    except RunnerError as exc:
        print(f"\nSTOPPED: {exc}", file=sys.stderr)
        rc = 1

    manifest["ended_at"] = _now()
    manifest["scenarios_completed"] = _completed_on_disk(out, repeat)
    manifest["errors"] = [r["scenario_id"] for r in records if r["status"] != "ok"]
    _write_json(out / "manifest.json", manifest)

    print(f"\n{len(manifest['scenarios_completed'])}/{total or len(scenarios)} scenarios "
          "complete. Score them with:")
    print(f"  python -m scenarios.score --run {out}")
    if not manifest.get("dry_run"):
        print("\nThese artefacts contain real ARNs, and so the account id. They are outside the")
        print("repository on purpose. Redact before publishing, then run check_publishable.py.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
