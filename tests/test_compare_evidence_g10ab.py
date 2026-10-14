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
    assert "fs-10-redis-unreachable" in lines[1] and "none -> xray -> grafana -> datadog" in lines[1]
    assert "fs-16-aurora-slow-query" in lines[2] and "xray -> grafana -> datadog -> none" in lines[2]
    assert any(line.startswith("  grafana: NOT READY") for line in lines)
    assert ce.order_for(["a", "b", "c"], 4) == ["b", "c", "a"]


def test_a_dry_run_prints_the_plan_and_writes_nothing(tmp_path, capsys):
    out = tmp_path / "out"
    assert ce.main(["--dry-run", "--faults", "fs-10", "--out", str(out), "--run", str(tmp_path / "run")]) == 0
    assert "fs-10-redis-unreachable" in capsys.readouterr().out
    assert not out.exists() and not (tmp_path / "run").exists()


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
    assert FAKE_TOKEN not in written and "fake-api" not in written
    assert results["faults"][0]["baseline_after"]["clean"] is True
    assert cli._state(run)["active"] is None


def test_runs_are_graded_with_the_rubric_and_measured(harness):
    env, run, out, _, _ = harness
    results = ce.compare(env, run, out, ["fs-10"], list(ce.TOOLS), VALUES)
    rows = {r["tool"]: r for r in results["faults"][0]["runs"]}
    assert all(r["status"] == "ok" and r["diagnosis"] == score.CORRECT and r["correct"] for r in rows.values())
    assert rows["none"]["action"] == "escalate_to_human" and rows["none"]["gate_allowed"] is True
    assert rows["xray"]["lines"]["XRAY"] == 2 and rows["xray"]["dependency_named"] is True
    assert rows["grafana"]["dependency_named"] is False and rows["grafana"]["tool_read_failures"] == 1
    assert rows["none"]["dependency_named"] is False and rows["none"]["input_tokens"] == 1000
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
    assert rows["datadog"]["status"] == "failed" and rows["datadog"]["diagnosis"] == score.ERROR
    assert "exit 1" in rows["datadog"]["error"]
    assert rows["grafana"]["status"] == "failed" and "could not start" in rows["grafana"]["error"]
    summary = {s["tool"]: s for s in results["summary"]}
    assert summary["datadog"] == {**summary["datadog"], "runs": 1, "correct": 0, "failed": 1, "accuracy": 0.0}
    assert summary["none"]["accuracy"] == 1.0


def test_an_inject_that_cannot_run_keeps_the_fault_with_every_run_failed(harness):
    env, run, out, seen, _ = harness
    (run / "state.json").unlink()  # no soak: step_inject refuses
    results = ce.compare(env, run, out, ["fs-10"], ["none", "xray"], VALUES)
    fault = results["faults"][0]
    assert "no soak" in fault["error"] and not seen
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
    assert none["accuracy"] == 1.0 and none["dependency_known"] == 0
    assert grafana["runs"] == 0 and grafana["accuracy"] is None and grafana["mean_wall_s"] is None


def test_the_page_escapes_every_value_and_loads_nothing():
    evil = '<script>alert("x")</script>'
    run = {**ce._row(evil, "xray"), "action": evil, "error": f"<img src=x onerror=alert(1)> {evil}",
           "lines": {"XRAY": 1, "GRAFANA": 0, "DATADOG": 0, "GITHUB": 0}}
    results = {"started_at": evil, "git_commit": "abc", "warnings": [evil], "summary": ce.summarise([run], ["xray"]),
               "faults": [{"fault": evil, "title": evil, "error": evil, "runs": [run]}]}
    page = ce.render_html(results)
    assert "<script" not in page and "<img" not in page and "&lt;script&gt;" in page
    assert "<link" not in page and "@import" not in page and "url(" not in page
    assert "prefers-color-scheme:dark" in page


def test_settings_come_from_the_store_and_the_environment_is_put_back(monkeypatch):
    from warden import settings

    monkeypatch.setenv("WARDEN_ENV", "dev")
    monkeypatch.delenv("WARDEN_DATADOG_API_KEY", raising=False)
    asked = {}

    def load(*, only):
        asked["only"] = only
        os.environ["WARDEN_DATADOG_API_KEY"] = "from-store"
        return ["WARDEN_DATADOG_API_KEY"]

    monkeypatch.setattr(settings, "load", load)
    before = dict(os.environ)
    values = ce.evidence_settings(["none", "datadog"])
    assert values == {"WARDEN_DATADOG_API_KEY": "from-store"}
    assert asked["only"] == frozenset(ce.SETTINGS["datadog"])
    assert dict(os.environ) == before
    assert ce._missing("datadog", values) == ["WARDEN_DATADOG_SITE", "WARDEN_DATADOG_APP_KEY"]
    assert ce._missing("grafana", {"WARDEN_GRAFANA_READ_TOKEN": "t", "WARDEN_GRAFANA_LOGS_URL": "u"}) == []
