"""scripts/post_bench_reports.py: what it prints and sends for a recorded run (characterisation before the
cognitive-complexity split of main) - a scenario without a report is skipped by name, each post is headed with the
injected fault and the grade, every sink's delivery is printed, and any undelivered post fails the run."""

from __future__ import annotations

import importlib.util
import json
import os
import types

import pytest
from scenarios import fullstack_cli as cli
from scenarios import runner

_spec = importlib.util.spec_from_file_location("post_bench_reports", runner.ROOT / "scripts" / "post_bench_reports.py")
post = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(post)


@pytest.fixture
def recorded(tmp_path, capsys):
    (tmp_path / "state.json").write_text(json.dumps({"active": None, "soaked_at": "2026-01-01T00:00:00+00:00",
                                                     "soak_minutes": 30}), encoding="utf-8")
    env = cli.dry_env()
    cli.step_inject(env, tmp_path, "fs-03", wait_alarm=False)
    cli.step_diagnose(env, tmp_path, "fs-03")
    assert cli.main(["--run", str(tmp_path), "--dry-run", "score"]) == 0
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    manifest["scenario_ids"] = [next(i for i in manifest["scenario_ids"] if i.startswith("fs-03-")), "fs-99"]
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    capsys.readouterr()
    return tmp_path


def _note(**kw):
    return types.SimpleNamespace(**kw)


def test_print_mode_shows_the_first_report_under_its_benchmark_header(recorded, capsys):
    sid = json.loads((recorded / "manifest.json").read_text(encoding="utf-8"))["scenario_ids"][0]
    assert post.main(["--run", str(recorded), "--print"]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"skip fs-99: no report for repeat 1\n**Benchmark scenario `{sid}`** - injected fault: `")
    assert "(WARDEN did not know the injected fault when it wrote this)\n\n" in out
    assert post.main(["--run", str(recorded), "--print", "--repeat", "2"]) == 0
    assert capsys.readouterr().out == (f"skip {sid}: no report for repeat 2\nskip fs-99: no report for repeat 2\n"
                                       "no reports\n")


def test_every_delivery_is_printed_and_one_failed_post_fails_the_run(recorded, capsys, monkeypatch):
    sid = json.loads((recorded / "manifest.json").read_text(encoding="utf-8"))["scenario_ids"][0]
    sent = []

    class Sink:
        def __init__(self, name, ok):
            self.name, self.ok = name, ok

        def send(self, text, meta):
            sent.append((self.name, text))
            return _note(delivered=self.ok, detail=f"{self.name}-detail")

    monkeypatch.setattr(post, "resolve_sinks", lambda: [Sink("slack", True), Sink("teams", False)])
    monkeypatch.setattr(post, "notify", lambda report: [_note(sink="slack", delivered=True, detail="200")])
    assert post.main(["--run", str(recorded)]) == 1
    assert capsys.readouterr().out == ("skip fs-99: no report for repeat 1\n"
                                       "intro -> slack: sent (slack-detail)\n"
                                       "intro -> teams: NOT sent (teams-detail)\n"
                                       f"{sid} -> slack: sent (200)\n")
    assert sent[0][1].startswith(f"# WARDEN benchmark - {recorded.name}\n1 runs over 1 scenarios on fullstack. ")
    assert sent[0][1].endswith("the model output and the gate's verdict are exactly what the run recorded.")
    monkeypatch.setattr(post, "resolve_sinks", lambda: [Sink("slack", True)])
    assert post.main(["--run", str(recorded)]) == 0


def test_the_runs_region_is_used_only_when_none_is_set(recorded, monkeypatch, capsys):
    manifest = json.loads((recorded / "manifest.json").read_text(encoding="utf-8"))
    (recorded / "manifest.json").write_text(json.dumps({**manifest, "region": "region-from-run"}), encoding="utf-8")
    monkeypatch.delenv("AWS_REGION", raising=False)
    assert post.main(["--run", str(recorded), "--print"]) == 0
    assert os.environ["AWS_REGION"] == "region-from-run"
    monkeypatch.setenv("AWS_REGION", "region-from-shell")
    assert post.main(["--run", str(recorded), "--print"]) == 0
    assert os.environ["AWS_REGION"] == "region-from-shell"
