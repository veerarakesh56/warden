"""The evidence-tool comparison (scripts/compare_evidence.py) against the harness's fake environment - no AWS, no model.

Under test: the plan, the per-tool environment (one tool per run, its settings in that run only, nothing left behind),
the grading and its aggregation, a failed run kept as failed, and the page escaping what it shows.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import pathlib

import pytest
from scenarios import fullstack_cli as cli
from scenarios import score

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("compare_evidence", ROOT / "scripts" / "compare_evidence.py")
ce = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ce)

FAKE_TOKEN = "fake-grafana-read"
VALUES = {"WARDEN_GRAFANA_READ_TOKEN": FAKE_TOKEN, "WARDEN_GRAFANA_TRACES_URL": "https://traces.example.invalid",
          "WARDEN_DATADOG_SITE": "example.invalid", "WARDEN_DATADOG_API_KEY": "fake-api",
          "WARDEN_DATADOG_APP_KEY": "fake-app"}


def _soaked(run: pathlib.Path) -> None:
    run.mkdir(parents=True, exist_ok=True)
    (run / "state.json").write_text(json.dumps({"active": None, "soaked_at": "2026-01-01T00:00:00+00:00",
                                                "soak_minutes": 30}), encoding="utf-8")


def _report(tool: str) -> dict:
    report = copy.deepcopy(cli._DRY_REPORT)
    report["context"]["logs"] += ["LOG lambda/reconciler connecting to the cache timed out"]
    if tool == "xray":
        report["context"]["logs"] += ["XRAY trace shop 2026-01-01T00:00:00Z GET /x status=500",
                                      "XRAY dependency shop -> master.redis.example.invalid: X-Ray's root cause in 3 of 3"]
    if tool == "grafana":
        report["context"]["logs"] += ["GRAFANA dependency shop -> payments: failing in 2 of 2 traces"]
        report["context"]["tool_errors"] = ["logs: grafana: HTTPError - not read"]
    report["cost"] = {"input_tokens": 1000, "output_tokens": 200, "usd": 0.01, "calls": 2}
    return report


@pytest.fixture
def harness(tmp_path):
    """The harness's dry environment with a WARDEN that records the environment it was given."""
    run, out = tmp_path / "run", tmp_path / "out"
    _soaked(run)
    env = cli.dry_env()
    env.log = lambda *_: None
    seen: list[dict] = []
    fail: dict[str, str] = {}

    def invoke(child_env: dict, alert: pathlib.Path, report: pathlib.Path) -> tuple[int, str]:
        seen.append(dict(child_env))
        tool = child_env["WARDEN_EVIDENCE_TOOLS"]
        if fail.get(tool) == "exit":
            return 1, "provider error"
        if fail.get(tool) == "raise":
            raise RuntimeError("the subprocess could not start")
        cli._write_json(report, _report(tool))
        return 0, ""

    env.invoke_warden = invoke
    return env, run, out, seen, fail


def test_the_plan_names_every_fault_and_rotates_the_order():
    lines = ce.plan(["fs-10", "fs-16"], ["none", "xray", "grafana", "datadog"], {})
    assert lines[0].startswith("compare 2 fault(s) x 4 tool(s) = 8 diagnoses")
    assert "fs-10-redis-unreachable" in lines[1]
    assert "none -> xray -> grafana -> datadog" in lines[1]
    assert "fs-16-aurora-slow-query" in lines[2]
    assert "xray -> grafana -> datadog -> none" in lines[2]
    assert any(line.startswith("  grafana: NOT READY") for line in lines)
    assert ce.order_for(["a", "b", "c"], 4) == ["b", "c", "a"]


def test_a_dry_run_prints_the_plan_and_writes_nothing(tmp_path, capsys):
    out = tmp_path / "out"
    assert ce.main(["--dry-run", "--faults", "fs-10", "--out", str(out), "--run", str(tmp_path / "run")]) == 0
    assert "fs-10-redis-unreachable" in capsys.readouterr().out
    assert not out.exists()
    assert not (tmp_path / "run").exists()


def test_the_default_faults_are_known_and_application_level():
    for key in ce.DEFAULT_FAULTS:
        assert cli.scenario_for(key)
        assert key in ce.FAULTED


def test_unknown_tools_or_faults_are_refused(tmp_path):
    with pytest.raises(SystemExit):
        ce.main(["--dry-run", "--tools", "none,splunk"])
    with pytest.raises(SystemExit):
        ce.main(["--dry-run", "--faults", "fs-99"])


def test_each_run_reads_exactly_one_tool_and_leaves_the_environment_as_it_was(harness, monkeypatch):
    env, run, out, seen, _ = harness
    monkeypatch.setenv("WARDEN_EVIDENCE_TOOLS", "datadog")  # the operator's own value never reaches a run
    before, real = dict(os.environ), env.invoke_warden
    results = ce.compare(env, run, out, ["fs-10"], list(ce.TOOLS), VALUES)

    assert [e["WARDEN_EVIDENCE_TOOLS"] for e in seen] == list(ce.TOOLS)
    for child in seen:
        tool = child["WARDEN_EVIDENCE_TOOLS"]
        assert "," not in tool
        assert ("WARDEN_XRAY" in child) == (tool == "xray")
        assert ("WARDEN_GRAFANA_READ_TOKEN" in child) == (tool == "grafana")
        assert ("WARDEN_DATADOG_API_KEY" in child) == (tool == "datadog")
    assert dict(os.environ) == before
    assert env.invoke_warden is real
    # The secrets are in no file the comparison wrote.
    written = "".join(p.read_text(encoding="utf-8") for p in out.rglob("*") if p.is_file())
    assert FAKE_TOKEN not in written
    assert "fake-api" not in written
    assert results["faults"][0]["baseline_after"]["clean"] is True
    assert cli._state(run)["active"] is None


def test_runs_are_graded_with_the_rubric_and_measured(harness):
    env, run, out, _, _ = harness
    results = ce.compare(env, run, out, ["fs-10"], list(ce.TOOLS), VALUES)
    rows = {r["tool"]: r for r in results["faults"][0]["runs"]}
    assert all(r["status"] == "ok" and r["diagnosis"] == score.CORRECT and r["correct"] for r in rows.values())
    assert rows["none"]["action"] == "escalate_to_human"
    assert rows["none"]["gate_allowed"] is True
    assert rows["xray"]["lines"]["XRAY"] == 2
    assert rows["xray"]["dependency_named"] is True
    assert rows["grafana"]["dependency_named"] is False
    assert rows["grafana"]["tool_read_failures"] == 1
    assert rows["none"]["dependency_named"] is False
    assert rows["none"]["input_tokens"] == 1000
    assert rows["datadog"]["wall_s"] is not None
    saved = json.loads((out / "results.json").read_text(encoding="utf-8"))
    assert [s["tool"] for s in saved["summary"]] == list(ce.TOOLS)
    assert (out / "results.html").is_file()
    # Each tool's directory is a run directory the harness's scorer grades by itself.
    assert score.score_run_dir(out / "xray")["rows"][0]["diagnosis"] == score.CORRECT


def test_a_failed_run_is_recorded_as_failed_never_dropped(harness):
    env, run, out, _, fail = harness
    fail.update(datadog="exit", grafana="raise")
    results = ce.compare(env, run, out, ["fs-10"], list(ce.TOOLS), VALUES)
    rows = {r["tool"]: r for r in results["faults"][0]["runs"]}
    assert len(rows) == 4
    assert rows["datadog"]["status"] == "failed"
    assert rows["datadog"]["diagnosis"] == score.ERROR
    assert "exit 1" in rows["datadog"]["error"]
    assert rows["grafana"]["status"] == "failed"
    assert "could not start" in rows["grafana"]["error"]
    summary = {s["tool"]: s for s in results["summary"]}
    assert summary["datadog"] == {**summary["datadog"], "runs": 1, "correct": 0, "failed": 1, "accuracy": 0.0}
    assert summary["none"]["accuracy"] == 1.0


def test_an_inject_that_cannot_run_keeps_the_fault_with_every_run_failed(harness):
    env, run, out, seen, _ = harness
    (run / "state.json").unlink()  # no soak: step_inject refuses
    results = ce.compare(env, run, out, ["fs-10"], ["none", "xray"], VALUES)
    fault = results["faults"][0]
    assert "no soak" in fault["error"]
    assert not seen
    assert [(r["tool"], r["status"]) for r in fault["runs"]] == [("none", "failed"), ("xray", "failed")]
    assert [s["runs"] for s in results["summary"]] == [1, 1]


def test_summarise_counts_every_run_and_means_only_what_was_measured():
    def row(tool, correct, status="ok", wall=None, usd=None, dep=None):
        return {**ce._row("fs-10", tool), "tool": tool, "correct": correct, "status": status, "wall_s": wall,
                "usd": usd, "dependency_named": dep}

    rows = [row("xray", True, wall=10, usd=0.02, dep=True), row("xray", False, wall=30, usd=0.04, dep=False),
            row("xray", False, status="failed"), row("none", True, wall=5, usd=0.01)]
    xray, none, grafana = ce.summarise(rows, ["xray", "none", "grafana"])
    assert xray == {"tool": "xray", "runs": 3, "correct": 1, "failed": 1, "accuracy": 1 / 3, "mean_wall_s": 20.0,
                    "mean_usd": 0.03, "dependency_found": 1, "dependency_known": 2}
    assert none["accuracy"] == 1.0
    assert none["dependency_known"] == 0
    assert grafana["runs"] == 0
    assert grafana["accuracy"] is None
    assert grafana["mean_wall_s"] is None


def test_the_page_escapes_every_value_and_loads_nothing():
    evil = '<script>alert("x")</script>'
    run = {**ce._row(evil, "xray"), "action": evil, "error": f"<img src=x onerror=alert(1)> {evil}",
           "lines": {"XRAY": 1, "GRAFANA": 0, "DATADOG": 0, "GITHUB": 0}}
    results = {"started_at": evil, "git_commit": "abc", "warnings": [evil], "summary": ce.summarise([run], ["xray"]),
               "faults": [{"fault": evil, "title": evil, "error": evil, "runs": [run]}]}
    page = ce.render_html(results)
    assert "<script" not in page
    assert "<img" not in page
    assert "&lt;script&gt;" in page
    assert "<link" not in page
    assert "@import" not in page
    assert "url(" not in page
    assert "prefers-color-scheme:dark" in page


def test_settings_come_from_the_store_and_the_environment_is_put_back(monkeypatch):
    from warden import settings

    monkeypatch.setenv("WARDEN_ENV", "dev")
    monkeypatch.delenv("WARDEN_DATADOG_API_KEY", raising=False)
    asked = {}

    def load(env, *, only):
        asked["env"], asked["only"] = env, only
        os.environ["WARDEN_DATADOG_API_KEY"] = "from-store"
        return ["WARDEN_DATADOG_API_KEY"]

    monkeypatch.setattr(settings, "load", load)
    before = dict(os.environ)
    assert ce.evidence_settings(["none", "datadog"]) == {}  # no store named: this shell only
    values = ce.evidence_settings(["none", "datadog"], store="ops")
    assert values == {"WARDEN_DATADOG_API_KEY": "from-store"}
    assert asked["env"] == "ops"
    assert asked["only"] == frozenset(ce.SETTINGS["datadog"])
    assert dict(os.environ) == before
    assert ce._missing("datadog", values) == ["WARDEN_DATADOG_SITE", "WARDEN_DATADOG_APP_KEY"]
    assert ce._missing("grafana", {"WARDEN_GRAFANA_READ_TOKEN": "t", "WARDEN_GRAFANA_LOGS_URL": "u"}) == []


def _page_run(tool, **kw):
    r = {**ce._row("fs-10", tool), "status": "ok", "correct": False, "diagnosis": score.SAFE, "action": None,
         "gate_allowed": None, "input_tokens": None, "output_tokens": None, "usd": None, "wall_s": None,
         "lines": {}, "dependency_named": None}
    return {**r, **kw}


def test_the_page_shows_each_outcome_with_its_class():
    """Characterisation (before the cognitive-complexity split of render_html): every row and class the page writes -
    the best accuracy in bold, failed runs in red, a correct / safe / failed / wrong run, gate allowed / refused /
    unknown, tokens, tool lines, dependency named / not / unknown, and a note with failed tool reads."""
    import re

    runs = [_page_run("none", correct=True, diagnosis=score.CORRECT, action="restart", gate_allowed=True,
                      input_tokens=900, output_tokens=80, usd=0.0123, wall_s=41.6, lines={"XRAY": 0},
                      dependency_named=False),
            _page_run("xray", lines={"XRAY": 2, "GRAFANA": 0}, dependency_named=True, tool_read_failures=2,
                      error=" slow "),
            _page_run("grafana", status="failed", diagnosis=score.ERROR, error="exit 1", gate_allowed=False),
            _page_run("datadog", diagnosis="WRONG")]
    summary = [{"tool": "none", "accuracy": 0.5, "correct": 1, "runs": 2, "failed": 0, "mean_wall_s": 41.6,
                "mean_usd": 0.0123, "dependency_found": 0, "dependency_known": 1},
               {"tool": "xray", "accuracy": 0.5, "correct": 1, "runs": 2, "failed": 1, "mean_wall_s": None,
                "mean_usd": None, "dependency_found": 1, "dependency_known": 0},
               {"tool": "splunk", "accuracy": None, "correct": 0, "runs": 0, "failed": 0, "mean_wall_s": None,
                "mean_usd": None, "dependency_found": 0, "dependency_known": 0}]
    page = ce.render_html({"started_at": "T0", "git_commit": "c1", "dry_run": True, "summary": summary,
                           "faults": [{"fault": "fs-10", "title": "cache down", "error": "inject failed",
                                       "runs": runs}, {"fault": "fs-11", "runs": []}]})
    assert "Started T0, commit c1 - DRY RUN, no real evidence</p>" in page
    assert re.findall(r"<tr><td.*?</tr>", page) == [
        ('<tr><td class="best">AWS only</td><td class="best">50%</td><td>1 / 2</td><td>0</td><td>42 s</td>'
         "<td>$0.0123</td><td>0 / 1</td></tr>"),
        ('<tr><td class="best">AWS + X-Ray</td><td class="best">50%</td><td>1 / 2</td><td class="bad">1</td>'
         "<td>-</td><td>-</td><td>-</td></tr>"),
        "<tr><td>splunk</td><td>-</td><td>0 / 0</td><td>0</td><td>-</td><td>-</td><td>-</td></tr>",
        ('<tr><td>AWS only</td><td class="ok">correct</td><td>restart</td><td>allowed</td><td>900 / 80</td>'
         '<td>$0.0123</td><td>42 s</td><td>none</td><td>not named</td><td class="note"></td></tr>'),
        ('<tr><td>AWS + X-Ray</td><td class="warn">safe-but-unhelpful</td><td>-</td><td>-</td><td>-</td><td>-</td>'
         '<td>-</td><td>XRAY 2</td><td>named it</td><td class="note">2 read(s) of the tool failed.  slow</td></tr>'),
        ('<tr><td>AWS + Grafana</td><td class="bad">failed</td><td>-</td><td>refused</td><td>-</td><td>-</td>'
         '<td>-</td><td>none</td><td>-</td><td class="note">exit 1</td></tr>'),
        ('<tr><td>AWS + Datadog</td><td class="bad">wrong</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td>'
         '<td>none</td><td>-</td><td class="note"></td></tr>'),
    ]
    assert re.findall(r"<h2>.*?</p>", page) == ['<h2>fs-10</h2><p class="meta">cache down - inject failed</p>',
                                               '<h2>fs-11</h2><p class="meta"></p>']
    assert page.endswith("</tbody></table></div></main></body></html>")
    zero = ce.render_html({"summary": [{**summary[0], "accuracy": 0.0}]})
    assert 'class="best"' not in zero
    assert "<h2>" not in zero


def test_the_command_line_refuses_repeats_and_a_live_run_without_out(capsys):
    """Characterisation (before the cognitive-complexity split of main): each refusal is argparse's exit 2 with its
    message, before anything is read or written."""
    for argv, message in ((["--dry-run", "--tools", "none,none"], "--tools: each once, from none, xray, grafana, datadog"),
                          (["--dry-run", "--tools", " , "], "--tools: each once"),
                          (["--dry-run", "--faults", "fs-99"], "--faults: "),
                          (["--faults", "fs-10"], "--out is required for a live run")):
        with pytest.raises(SystemExit) as stop:
            ce.main(argv)
        assert stop.value.code == 2
        assert message in capsys.readouterr().err


def test_a_dry_run_names_the_store_it_would_read(capsys):
    assert ce.main(["--dry-run", "--faults", "fs-10", "--tools", "none", "--settings-env", "lab"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("compare 1 fault(s) x 1 tool(s) = 1 diagnoses\n")
    assert out.endswith("  (a live run first loads the missing settings from the lab environment's store)\n")
    assert ce.main(["--dry-run", "--faults", "fs-10", "--tools", "none", "--settings-env", ""]) == 0
    assert "a live run first loads" not in capsys.readouterr().out


def test_a_live_run_stops_before_any_inject_when_a_tool_is_not_ready(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(ce, "evidence_settings", lambda tools, store="": {})
    monkeypatch.setattr(ce, "compare", lambda *a, **k: pytest.fail("must not run"))
    assert ce.main(["--faults", "fs-10", "--tools", "none,grafana,datadog", "--out", str(tmp_path / "o"),
                    "--run", str(tmp_path / "r")]) == 1
    err = capsys.readouterr().err
    assert err.startswith("STOPPED before any inject: grafana needs WARDEN_GRAFANA_")
    assert "; datadog needs WARDEN_DATADOG_" in err
    assert not (tmp_path / "o").exists()


def test_a_live_run_prints_each_tools_summary_or_stops_on_a_step_error(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(ce, "evidence_settings", lambda tools, store="": dict(VALUES))
    got = {}

    def compare(env, run, out, faults, tools, values, *, settle_s):
        got.update(env=env, faults=faults, tools=tools, settle_s=settle_s)
        return {"summary": [{"tool": "xray", "accuracy": 0.5, "correct": 1, "runs": 2, "mean_wall_s": 12.4,
                             "mean_usd": 0.01}]}

    monkeypatch.setattr(ce, "compare", compare)
    out = tmp_path / "o"
    argv = ["--faults", "fs-10", "--tools", "xray", "--out", str(out), "--run", str(tmp_path / "r"),
            "--settle-minutes", "0.5"]
    assert ce.main(argv, env="ENV") == 0
    assert got == {"env": "ENV", "faults": ["fs-10"], "tools": ["xray"], "settle_s": 30.0}
    assert capsys.readouterr().out == ("xray     accuracy  50%  1/2  time 12 s  cost $0.0100\n"
                                       f"results: {out / 'results.json'}  {out / 'results.html'}\n")
    assert out.is_dir()
    assert (tmp_path / "r").is_dir()

    def stopped(*a, **k):
        raise cli.StepError("the alarm never fired")

    monkeypatch.setattr(ce, "compare", stopped)
    assert ce.main(argv, env="ENV") == 1
    assert capsys.readouterr().err == "STOPPED: the alarm never fired\n"
