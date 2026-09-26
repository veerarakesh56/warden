"""Wave 4's operator steps (scenarios/fullstack_cli.py) against a fake environment - no AWS.

The order of a fault's life is the thing under test: quiet period -> baseline gate -> inject ->
alarm wait -> WARDEN -> fix (through the allow-list) -> verify -> revert -> baseline. Plus the
honest paths: an alarm that never fires, a fix the gate refused, a fix the allow-list refused, and
the environment WARDEN is given.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib

import pytest
import yaml
from scenarios import fullstack_cli as cli
from scenarios import ops_fullstack as fs
from scenarios import runner, score

OPERATOR_KEY = "AKIAOPERATORKEYDONOTUSE"


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def _soaked(run: pathlib.Path) -> None:
    run.mkdir(parents=True, exist_ok=True)
    (run / "state.json").write_text(json.dumps({"active": None, "soaked_at": "2026-01-01T00:00:00+00:00"}),
                                    encoding="utf-8")


@pytest.fixture(autouse=True)
def _every_run_dir_is_soaked(tmp_path):
    """Inject refuses a run with no soak (the owner's order); the tests start after one."""
    _soaked(tmp_path)


def fake_env(events: list, *, alarm_state="ALARM", verdict="approved_for_human",
             commands=None, verify_ok=True, baseline=None, inject_raises=None,
             firing_before=False) -> cli.Env:
    """`alarm_state` is what the fault's alarm reads WHILE the fault is injected; before it, every
    alarm is OK unless `firing_before`."""
    env = cli.dry_env()
    clock = Clock()
    commands = [{"kind": "shell", "source": "runbook", "command":
                 "aws events enable-rule --name warden-pg-fs-reconcile-5m --region ap-south-2"}] \
        if commands is None else commands

    injected = {"on": firing_before}

    def inject(c, t):
        events.append("inject")
        injected["on"] = True
        if inject_raises:
            raise inject_raises
        return {"ok": True}

    def revert(c, t):
        events.append("revert")
        injected["on"] = False
        return {"ok": True}

    def verify(c, t):
        events.append("verify")
        return verify_ok, "fake verifier"

    def alarm(name):
        events.append("alarm")
        state = alarm_state if injected["on"] else "OK"
        return {"state": state, "description": f"{name}: errors above threshold"}

    def invoke(env_vars, alert, report):
        events.append("warden")
        env.last_env, env.last_alert = env_vars, alert
        report_doc = json.loads(json.dumps(cli._DRY_REPORT))
        report_doc["verdict"]["status"] = verdict
        runner._write_json(report, report_doc)
        return 0, ""

    def extract(report, built):
        data = {"fix_commands": commands}
        runner._write_json(built, data)
        return data

    def execute(cmds):
        events.append("fix")
        return [{**c, "rc": 0} for c in cmds], []

    def base():
        events.append("baseline")
        return list(baseline) if baseline else []

    fault = fs.Fault(inject, revert, verify, "rule")
    env = dataclasses.replace(
        env, alarm=alarm, invoke_warden=invoke, extract_fix=extract, execute=execute,
        faults={fid: fault for fid in fs.FAULTS}, baseline=base, sleep=clock.sleep, clock=clock,
        log=lambda _m: None, dry_run=False,
    )
    return env


def _record(run: pathlib.Path, fid: str) -> dict:
    sid = cli.scenario_for(fid)["id"]
    return json.loads((run / "ground-truth" / f"{sid}.json").read_text(encoding="utf-8"))


def _collapse(events):
    out = []
    for e in events:
        if not out or out[-1] != e:
            out.append(e)
    return out


# --------------------------------------------------------------------------- the order


def test_a_fault_runs_in_the_registered_order(tmp_path):
    events: list[str] = []
    env = fake_env(events)
    cli.step_run(env, tmp_path, "fs-27")
    assert _collapse(events) == [
        "baseline", "alarm",          # the gate before inject: stack + every catalog alarm
        "inject", "alarm",            # wait for THIS fault's alarm
        "warden", "fix", "verify", "revert",
        "baseline", "alarm",          # back at baseline afterwards
    ]
    rec = _record(tmp_path, "fs-27")
    assert rec["status"] == "ok" and rec["revert_ok"] is True
    assert rec["runs"][0]["fix"]["outcome"] == "fixed"
    assert rec["baseline_after"]["clean"] is True


def test_the_steps_can_run_as_separate_commands_hours_apart(tmp_path):
    """State lives in the run directory; each step gets a FRESH environment, as a new process would."""
    events: list[str] = []
    cli.step_inject(fake_env(events), tmp_path, "fs-09")
    cli.step_diagnose(fake_env(events), tmp_path, "fs-09")
    cli.step_fix(fake_env(events), tmp_path, "fs-09")
    cli.step_verify(fake_env(events), tmp_path, "fs-09")
    cli.step_revert(fake_env(events), tmp_path, "fs-09")
    rec = _record(tmp_path, "fs-09")
    assert rec["runs"][0]["fix"]["outcome"] == "fixed" and rec["revert_ok"]
    assert json.loads((tmp_path / "state.json").read_text())["active"] is None


def test_the_saved_prior_state_survives_between_processes(tmp_path):
    env = fake_env([])

    def inject(c, t):
        fs._save(t, "fs-19", {"path": "/health"})
        return {}

    seen = {}

    def revert(c, t):
        seen.update(t.saved)
        fs._done(t, "fs-19")
        return {}

    env.faults["fs-19"] = fs.Fault(inject, revert, lambda c, t: (True, ""), "alb")
    cli.step_inject(env, tmp_path, "fs-19")
    assert json.loads((tmp_path / "saved" / "fs-19.json").read_text()) == {"path": "/health"}
    fresh = fake_env([])
    fresh.faults["fs-19"] = env.faults["fs-19"]
    cli.step_revert(fresh, tmp_path, "fs-19")
    assert seen == {"fs-19": {"path": "/health"}}
    assert not (tmp_path / "saved" / "fs-19.json").exists(), "the prior state is deleted once restored"


# --------------------------------------------------------------------------- the gates


def test_inject_is_refused_on_a_dirty_stack(tmp_path):
    events: list[str] = []
    with pytest.raises(cli.StepError, match="not at baseline"):
        cli.step_inject(fake_env(events, baseline=["checkout reserved concurrency is 0"]), tmp_path, "fs-03")
    assert "inject" not in events


def test_an_alarm_already_firing_blocks_the_next_inject(tmp_path):
    events: list[str] = []
    with pytest.raises(cli.StepError, match="alarm"):
        cli.step_inject(fake_env(events, firing_before=True), tmp_path, "fs-03")
    assert "inject" not in events


def test_inject_waits_out_the_quiet_period(tmp_path):
    env = fake_env([], alarm_state="OK")
    cli._set_state(tmp_path, active=None, last_activity_at=runner._now())
    with pytest.raises(cli.StepError, match="min since the last fault"):
        cli.step_inject(env, tmp_path, "fs-03")
    rec = cli.step_inject(env, tmp_path, "fs-03", skip_quiet=True)
    assert rec["quiet_skipped"] is True, "skipping the quiet period is recorded, never silent"


def test_only_one_fault_is_injected_at_a_time(tmp_path):
    env = fake_env([], alarm_state="OK")
    cli.step_inject(env, tmp_path, "fs-03")
    with pytest.raises(cli.StepError, match="still injected"):
        cli.step_inject(env, tmp_path, "fs-04", skip_quiet=True)


def test_a_fault_is_measured_once(tmp_path):
    env = fake_env([], alarm_state="OK")
    cli.step_run(env, tmp_path, "fs-03")
    with pytest.raises(cli.StepError, match="one run per fault"):
        cli.step_inject(env, tmp_path, "fs-03", skip_quiet=True)


def test_a_failed_inject_is_reverted_at_once(tmp_path):
    events: list[str] = []
    with pytest.raises(cli.StepError, match="inject failed"):
        cli.step_inject(fake_env(events, alarm_state="OK", inject_raises=RuntimeError("boom")),
                        tmp_path, "fs-05")
    assert "revert" in events
    assert _record(tmp_path, "fs-05")["revert_ok"] is True


def test_a_failed_revert_is_loud_and_leaves_the_fault_active(tmp_path):
    env = fake_env([], alarm_state="OK")
    cli.step_inject(env, tmp_path, "fs-05")

    def bad(c, t):
        raise RuntimeError("AccessDenied")
    env.faults["fs-05"] = dataclasses.replace(env.faults["fs-05"], revert=bad)
    with pytest.raises(cli.StepError, match="revert FAILED"):
        cli.step_revert(env, tmp_path, "fs-05")
    assert json.loads((tmp_path / "state.json").read_text())["active"] == cli.scenario_for("fs-05")["id"]


def test_revert_is_idempotent(tmp_path):
    env = fake_env([], alarm_state="OK")
    cli.step_inject(env, tmp_path, "fs-05")
    cli.step_revert(env, tmp_path, "fs-05")
    assert cli.step_revert(env, tmp_path, "fs-05")["revert_ok"] is True


# --------------------------------------------------------------------------- the alarm


def test_an_alarm_that_never_fires_is_recorded_and_warden_still_runs(tmp_path):
    events: list[str] = []
    env = fake_env(events, alarm_state="OK")
    cli.step_run(env, tmp_path, "fs-10")
    rec = _record(tmp_path, "fs-10")
    assert rec["alarm"]["never_fired"] is True
    assert rec["alarm"]["waited_s"] >= cli.scenario_for("fs-10")["alarm_timeout_s"]
    assert "warden" in events, "WARDEN is run at the timeout anyway - honestly"
    assert rec["runs"][0]["alarm"]["never_fired"] is True


def test_the_alert_carries_the_alarm_and_the_same_service_map_for_every_fault(tmp_path):
    maps = set()
    for fid in ("fs-01", "fs-19"):
        env = fake_env([], alarm_state="OK")
        run = tmp_path / fid
        _soaked(run)
        cli.step_inject(env, run, fid, wait_alarm=False)
        cli.step_diagnose(env, run, fid)
        alert = yaml.safe_load(env.last_alert.read_text(encoding="utf-8"))
        sc = cli.scenario_for(fid)
        assert alert["name"] == sc["alarm"]
        assert alert["summary"] == f"{sc['alarm']}: errors above threshold", "the alarm DESCRIPTION"
        assert alert["severity"] == sc["severity"]
        assert "dlq" not in alert["labels"], "DLQs come from RedrivePolicy, never a label"
        maps.add(json.dumps(alert["labels"], sort_keys=True))
    assert len(maps) == 1, "the labels must never point at the broken component"


def test_the_alert_template_names_no_cause():
    template = yaml.safe_load(cli.ALERT_TEMPLATE.read_text(encoding="utf-8"))
    blob = f"{template['name']} {template['summary']}".lower()
    for word in ("oom", "memory", "throttl", "timeout", "denied", "poison", "lock", "failover",
                 "secret", "probe", "image", "disabled", "index", "exhaust"):
        assert word not in blob


# --------------------------------------------------------------------------- the fix outcomes


@pytest.mark.parametrize("kw,outcome,ran", [
    ({}, "fixed", True),
    ({"verify_ok": False}, "not_fixed", True),
    ({"verdict": "rejected"}, "blocked_by_gate", False),
    ({"commands": []}, "no_fix_printed", False),
    ({"commands": [{"kind": "shell", "command": "kubectl -n shop delete deploy catalog-api"}]},
     "fix_not_allowed", False),
    ({"verdict": "escalated"}, "fixed", True),
])
def test_fix_outcomes(tmp_path, kw, outcome, ran):
    events: list[str] = []
    cli.step_run(fake_env(events, **kw), tmp_path, "fs-27")
    fix = _record(tmp_path, "fs-27")["runs"][0]["fix"]
    assert fix["outcome"] == outcome
    assert ("fix" in events) is ran, "nothing may run unless the gate allowed it and every command passed"
    if outcome == "fix_not_allowed":
        assert fix["rejected"][0]["reason"], "the refused command is visible, not silently skipped"


def test_the_fix_is_verified_for_up_to_recover_within(tmp_path):
    events: list[str] = []
    env = fake_env(events, verify_ok=False)
    cli.step_run(env, tmp_path, "fs-27")
    polls = events.count("verify")
    assert polls >= cli.scenario_for("fs-27")["recover_within"] // cli.VERIFY_POLL_S


# --------------------------------------------------------------------------- WARDEN's identity


def test_warden_gets_only_the_reader_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", OPERATOR_KEY)
    monkeypatch.setenv("AWS_PROFILE", "admin")
    monkeypatch.setenv("HOME", "/home/operator")
    monkeypatch.setenv("USERPROFILE", "C:/Users/operator")
    monkeypatch.setenv("WARDEN_PROVIDER", "claude_cli")
    env = fake_env([], alarm_state="OK")
    cli.step_inject(env, tmp_path, "fs-27", wait_alarm=False)
    cli.step_diagnose(env, tmp_path, "fs-27", arm={"WARDEN_KNOWLEDGE_IN_PROMPT": "1"})
    got = env.last_env
    assert got["AWS_ACCESS_KEY_ID"] == "ASIADRY", "the assumed reader's key, not the operator's"
    for leaked in ("AWS_PROFILE", "HOME", "USERPROFILE"):
        assert leaked not in got
    assert OPERATOR_KEY not in json.dumps(got)
    assert got["WARDEN_BACKEND"] == "stack"
    assert got["WARDEN_TOOL_TIMEOUT"] == "30"
    assert got["KUBECONFIG"] and got["WARDEN_STACK_DB_WRITER_DSN"] and got["WARDEN_STACK_DB_READER_DSN"]
    assert got["WARDEN_PROVIDER"] == "claude_cli", "the provider is the operator's choice"
    assert got["WARDEN_KNOWLEDGE_IN_PROMPT"] == "1"
    rec = _record(tmp_path, "fs-27")
    assert "warden-pg-fs-reader" in rec["runs"][0]["assumed_role_arn"]
    assert rec["runs"][0]["arm"] == {"WARDEN_KNOWLEDGE_IN_PROMPT": "1"}


def test_the_dsns_never_reach_the_command_line(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd

        class P:
            returncode, stderr = 0, ""
        return P()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    cli._subprocess_warden(5)({"WARDEN_STACK_DB_WRITER_DSN": "postgresql://warden_ro:pw@x/shop"},
                              tmp_path / "a.yaml", tmp_path / "r.json")
    assert "pw@" not in " ".join(captured["cmd"])
    assert "--json" in captured["cmd"] and "--alert" in captured["cmd"]


def test_the_harness_does_not_import_the_tool_under_test():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(cli))
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [n for n in names if n.split(".")[0] == "warden"]


# --------------------------------------------------------------------------- soak / watch / status


def test_no_fault_is_injected_before_a_soak(tmp_path):
    fresh = tmp_path / "never-soaked"
    with pytest.raises(cli.StepError, match="run `soak` first"):
        cli.step_inject(fake_env([], alarm_state="OK"), fresh, "fs-03", wait_alarm=False)


def test_soak_needs_health_and_the_minimum_time(tmp_path):
    clock = Clock()
    unhealthy = iter([["alarm x is ALARM"]] * 3)
    env = dataclasses.replace(fake_env([], alarm_state="OK"), sleep=clock.sleep, clock=clock,
                              baseline=lambda: next(unhealthy, []))
    assert cli.step_soak(env, tmp_path, min_s=1800, every_s=60) is True
    assert clock.t >= 180 + 1800  # unhealthy at t=0/60/120 s: the streak starts at the first healthy check


def test_a_break_mid_soak_restarts_the_healthy_streak(tmp_path):
    """Healthy for 20 min, one bad minute, then healthy: the soak ends 30 min after the break, not at 30."""
    clock = Clock()
    checks = iter([[]] * 20 + [["alarm x is ALARM"]])
    env = dataclasses.replace(fake_env([], alarm_state="OK"), sleep=clock.sleep, clock=clock,
                              baseline=lambda: next(checks, []))
    assert cli.step_soak(env, tmp_path, min_s=1800, every_s=60) is True
    assert clock.t >= 21 * 60 + 1800


def test_soak_gives_up_at_its_maximum(tmp_path):
    env = fake_env([], firing_before=True)
    assert cli.step_soak(env, tmp_path, min_s=60, max_s=600, every_s=60) is False


def test_watch_reports_a_delayed_effect(tmp_path):
    clock = Clock()
    states = iter([[], [], ["warden-pg-fs-orders-dlq holds 3 message(s)"]])
    env = dataclasses.replace(fake_env([], alarm_state="OK"), sleep=clock.sleep, clock=clock,
                              baseline=lambda: next(states, []))
    assert cli.step_watch(env, tmp_path, minutes=5, every_s=60) is False
    watch = json.loads((tmp_path / "watch.json").read_text())
    assert watch["unhealthy_checks"] == 1


def test_status_lists_every_fault(tmp_path):
    env = fake_env([], alarm_state="OK")
    cli.step_run(env, tmp_path, "fs-27")
    lines = cli.step_status(env, tmp_path)
    assert len([ln for ln in lines if "fs-" in ln]) == len(fs.FAULTS)
    assert any("fs-27" in ln and "fixed" in ln for ln in lines)


# --------------------------------------------------------------------------- the run directory


def test_the_run_directory_scores_with_a_fix_column(tmp_path):
    env = fake_env([], alarm_state="OK")
    cli.step_run(env, tmp_path, "fs-27")
    cli.step_run(fake_env([], alarm_state="OK", verdict="rejected"), tmp_path, "fs-03", skip_quiet=True)
    scored = score.score_run_dir(tmp_path)
    summary = score.summarise(scored)
    assert summary["fix_counts"] == {"fixed": 1, "blocked_by_gate": 1}
    assert summary["alarm_never_fired"] == 2
    markdown = score.render_markdown(scored, summary)
    assert "## 8. Fix" in markdown
    assert scored["rubric_drift"] is False and scored["catalog_drift"] is False


def test_a_changed_rubric_stops_the_next_step(tmp_path):
    env = fake_env([], alarm_state="OK")
    cli.open_run(env, tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    manifest["scoring_sha256"] = "0" * 64
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(cli.StepError, match="rubric changed"):
        cli.step_inject(env, tmp_path, "fs-03")


def test_the_dry_run_runs_every_step_end_to_end(tmp_path):
    rc = cli.main(["--dry-run", "--run", str(tmp_path), "run", "fs-27", "--skip-quiet"])
    assert rc == 0
    assert _record(tmp_path, "fs-27")["runs"][0]["fix"]["outcome"] == "fixed"
    assert json.loads((tmp_path / "manifest.json").read_text())["dry_run"] is True


def test_the_generic_runner_refuses_wave_4_and_points_at_the_operator_cli():
    with pytest.raises(SystemExit, match="fullstack_cli"):
        runner.main(["--wave", "4", "--dry-run"])


def test_stack_description_accepts_terraform_output_json(tmp_path):
    raw = {k: {"value": f"warden-pg-fs-{k}", "sensitive": False, "type": "string"}
           for k in cli.STACK_KEYS["required"]}
    raw["checkout_role"] = {"value": "warden-pg-fs-checkout-role"}
    path = tmp_path / "stack.json"
    path.write_text(json.dumps(raw))
    stack = cli.load_stack(path)
    t = cli.target_from_stack(stack)
    assert t.writer_endpoint == "warden-pg-fs-aurora_writer_endpoint"
    assert t.checkout_role == "warden-pg-fs-checkout-role"
    del raw["reader_role_arn"]
    path.write_text(json.dumps(raw))
    with pytest.raises(cli.StepError, match="reader_role_arn"):
        cli.load_stack(path)


# --------------------------------------------------------------------------- the catalog


def test_every_fault_has_exactly_one_catalog_entry_and_its_fields():
    catalog = cli._catalog()
    assert sorted(fs.fault_of(s) for s in catalog) == sorted(fs.FAULTS)
    rubric = yaml.safe_load(runner.SCORING.read_text(encoding="utf-8"))["fault_classes"]
    for sid, sc in catalog.items():
        for key in ("alarm", "severity", "recover_within", "alarm_timeout_s", "evidence_assertions"):
            assert key in sc, f"{sid} lacks {key}"
        assert sc["fault_class"] in rubric
        assert sc["alarm"].startswith(fs.PREFIX)
        if sc["inject"]:
            assert sc["inject"][0]["fault"] == fs.fault_of(sid) == sc["revert"][0]["fault"]


def test_preflight_plans_by_default_and_applies_every_fault_on_request(tmp_path, capsys):
    import importlib.util

    spec = importlib.util.spec_from_file_location("preflight_fs", runner.ROOT / "scripts" / "preflight_fullstack_ops.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.main(["--only", "fs-07"]) == 0
    assert "PLAN" in capsys.readouterr().out
    assert mod.main(["--apply", "--run", str(tmp_path)], env=cli.dry_env()) == 0
    out = capsys.readouterr().out
    assert out.count("OK   fs-") == len(fs.FAULTS) - 1
    # An interrupted preflight is finished by its own --revert (fullstack_cli's revert refuses it).
    with pytest.raises(SystemExit, match="--revert needs --only"):
        mod.main(["--revert", "--run", str(tmp_path)], env=cli.dry_env())
    assert mod.main(["--revert", "--only", "fs-12", "--run", str(tmp_path)], env=cli.dry_env()) == 0
    assert "revert fs-12" in capsys.readouterr().out


def test_warden_ro_tokens_are_signed_with_the_assumed_reader_role_never_the_operator():
    """No password exists (Aurora express configuration). WARDEN's DSNs carry an IAM token signed
    with the ASSUMED reader role's credentials, so the reader role's rds-db:connect is what lets
    WARDEN in; the token is percent-encoded into the URL."""
    made = []

    class Rds:
        meta = type("M", (), {"region_name": "ap-south-2"})

        def generate_db_auth_token(self, **kw):
            return f"{kw['DBHostname']}:5432/?Action=connect&DBUser={kw['DBUsername']}&X-Amz-Signature=ab/c"

    def make_client(service, **kw):
        made.append((service, kw))
        return Rds()

    t = fs.Target(writer_endpoint="warden-pg-fs-aurora.cluster-x",
                  reader_endpoint="warden-pg-fs-aurora.cluster-ro-x")
    creds = {"AccessKeyId": "ASIAREADER", "SecretAccessKey": "s", "SessionToken": "tok"}
    d = cli.warden_dsns(creds, t, 5432, make_client)
    assert made == [("rds", {"region_name": "ap-south-2", "aws_access_key_id": "ASIAREADER",
                             "aws_secret_access_key": "s", "aws_session_token": "tok"})]
    assert d["WARDEN_STACK_DB_READER_DSN"].startswith(
        "postgresql://warden_ro:warden-pg-fs-aurora.cluster-ro-x%3A5432%2F%3FAction%3Dconnect%26DBUser%3Dwarden_ro")
    assert d["WARDEN_STACK_DB_READER_DSN"].endswith("@warden-pg-fs-aurora.cluster-ro-x:5432/shop?sslmode=require")
    assert "@warden-pg-fs-aurora.cluster-x:5432/shop" in d["WARDEN_STACK_DB_WRITER_DSN"]


def test_the_stack_file_supplies_the_writer_instance_express_chose():
    stack = {"aurora_writer_endpoint": "w", "aurora_reader_endpoint": "r", "redis_security_group_id": "sg-1",
             "aurora_writer_instance": "warden-pg-fs-aurora-instance-1"}
    assert cli.target_from_stack(stack).writer_instance == "warden-pg-fs-aurora-instance-1"
    assert cli.target_from_stack({**stack, "aurora_writer_instance": ""}).writer_instance == "warden-pg-fs-aurora-1"


def test_the_stack_kubeconfig_loads_through_the_real_client(tmp_path, monkeypatch):
    """Two real crashes: ~/.kube/config with no current context, then a Path where the client needs str.
    This goes through the REAL kubernetes loader with a real file."""
    kube = pytest.importorskip("kubernetes")
    cfg = tmp_path / "kubeconfig"
    cfg.write_text(
        "apiVersion: v1\nkind: Config\ncurrent-context: warden-pg-fs-eks\n"
        "clusters:\n- name: c\n  cluster: {server: 'https://example.invalid'}\n"
        "users:\n- name: u\n  user: {token: fake}\n"
        "contexts:\n- name: warden-pg-fs-eks\n  context: {cluster: c, user: u}\n", encoding="utf-8")
    monkeypatch.delenv("KUBECONFIG", raising=False)
    assert cli.load_kubeconfig(kube.config, default=cfg) == "warden-pg-fs-eks"
    monkeypatch.setenv("KUBECONFIG", str(tmp_path / "missing"))
    with pytest.raises(cli.StepError, match="no usable kubeconfig"):
        cli.load_kubeconfig(kube.config, default=cfg)
