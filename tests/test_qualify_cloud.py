"""scripts/qualify_cloud.py: one command measures a model with the cloud runtime's key and writes the result into the
repository - a qualified row only for a pass on the pinned prompt, an honest NOT QUALIFIED record otherwise. No model
is called here and no key is real (tests/fakes.py)."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import sys

import pytest
import yaml

from fakes import ANTHROPIC_KEY_PREFIX
from test_qualification_claims import SONNET, problems, qualified_now

ROOT = pathlib.Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "qualify_cloud", ROOT / "scripts" / "qualify_cloud.py"
)
qc = importlib.util.module_from_spec(_spec)
sys.modules["qualify_cloud"] = qc
_spec.loader.exec_module(qc)

WHEN = "2026-10-21 14:00"
BENCH = ROOT / "tests" / "fixtures" / "bench"


def _saved_run(tmp_path: pathlib.Path) -> pathlib.Path:
    """A run directory with stored reports (the committed live runs) and a qualification.json that matches them."""
    import qualify_provider

    run = tmp_path / "run"
    for name in qualify_provider.RUNS:
        shutil.copytree(BENCH / name, run / name)
    counts = qualify_provider.tally(run)
    saved = run / "qualification.json"
    saved.write_text(
        json.dumps({**_result(correct=counts["correct"]), **counts, "passed": False}),
        encoding="utf-8",
    )
    return saved


def _files() -> dict[str, str]:
    return {
        "providers": qc.PROVIDERS_YAML.read_text(encoding="utf-8"),
        "benchmarks": qc.BENCHMARKS_MD.read_text(encoding="utf-8"),
        "readme": qc.README_MD.read_text(encoding="utf-8"),
    }


def _result(
    *, correct: int, wrong: int = 0, unanswered: int = 0, prompt: str | None = None
) -> dict:
    doc = yaml.safe_load(qc.PROVIDERS_YAML.read_text(encoding="utf-8"))
    bar = doc["bar"]
    return {
        "provider": "anthropic",
        "model": SONNET,
        "version": "anthropic 1.11.0",
        "measured": "2026-10-21T14:00Z",
        "prompt": prompt or doc["prompt"]["sha"],
        "budget_usd": 2.0,
        "spent_usd": 0.47,
        "correct": correct,
        "runs": 30,
        "wrong_and_allowed": wrong,
        "no_evidence_fixes_allowed": 0,
        "errors": 0,
        "unanswered": unanswered,
        "escalated": 22,
        "slo_breaches": [],
        "passed": wrong <= bar["wrong_and_allowed"]
        and correct >= bar["min_correct"]
        and unanswered == 0,
    }


def _bar() -> dict:
    return yaml.safe_load(qc.PROVIDERS_YAML.read_text(encoding="utf-8"))["bar"]


def test_a_pass_on_the_pinned_prompt_adds_the_qualified_row_and_every_doc_says_so():
    f = _files()
    providers, benchmarks, readme, why = qc.record(
        _result(correct=_bar()["min_correct"]), when=WHEN, **f
    )
    doc = yaml.safe_load(providers)
    assert why == qc.OK_WORDS
    assert qualified_now(doc) == {SONNET}
    live = [r for r in doc["qualified"] if r["model"] == SONNET]
    assert len(live) == 1, "one live row per model: the earlier prompt's row is kept as a comment"
    assert "passed" not in live[0]
    assert "slo_breaches" not in live[0]
    assert f"| {WHEN} | anthropic `{SONNET}` |" in benchmarks
    assert problems(benchmarks, doc) == []
    assert problems(readme, doc) == []


@pytest.mark.parametrize("kind", ["below the bar", "wrong and allowed", "unanswered"])
def test_a_failure_adds_no_qualified_row_and_is_still_recorded(kind):
    bar = _bar()
    result = {
        "below the bar": _result(correct=bar["min_correct"] - 1),
        "wrong and allowed": _result(
            correct=bar["min_correct"] + 3, wrong=bar["wrong_and_allowed"] + 1
        ),
        "unanswered": _result(correct=bar["min_correct"] + 3, unanswered=2),
    }[kind]
    f = _files()
    before = yaml.safe_load(f["providers"])["qualified"]
    providers, benchmarks, readme, why = qc.record(result, when=WHEN, **f)
    doc = yaml.safe_load(providers)
    assert "NOT qualified" in why
    assert doc["qualified"] == before, "a failed run adds or retires no row"
    assert qualified_now(doc) == qualified_now(yaml.safe_load(f["providers"]))
    assert f"# NOT QUALIFIED - measured {WHEN}" in providers
    assert json.dumps(result["correct"]) in providers.split("# NOT QUALIFIED", 1)[1].splitlines()[1]
    row = next(ln for ln in benchmarks.splitlines() if ln.startswith(f"| {WHEN} |"))
    assert "NOT qualified" in row
    assert problems(benchmarks, doc) == []
    assert problems(readme, doc) == []


def test_a_pass_on_another_prompt_qualifies_nothing():
    other = "0" * 64  # not the pinned prompt, whatever it is
    f = _files()
    providers, benchmarks, _readme, why = qc.record(
        _result(correct=_bar()["min_correct"] + 5, prompt=other), when=WHEN, **f
    )
    assert "not the pinned prompt" in why
    assert yaml.safe_load(providers)["qualified"] == yaml.safe_load(f["providers"])["qualified"]
    assert problems(benchmarks, yaml.safe_load(providers)) == []


def test_a_passed_flag_alone_is_not_believed():
    result = {**_result(correct=_bar()["min_correct"] - 1), "passed": True}
    ok, why = qc.verdict(result, yaml.safe_load(qc.PROVIDERS_YAML.read_text(encoding="utf-8")))
    assert not ok, why


def test_from_result_writes_every_file_with_no_key_and_no_model_call(tmp_path, monkeypatch, capsys):
    for name in ("PROVIDERS_YAML", "BENCHMARKS_MD", "README_MD"):
        copy = tmp_path / getattr(qc, name).name
        copy.write_text(getattr(qc, name).read_text(encoding="utf-8"), encoding="utf-8")
        monkeypatch.setattr(qc, name, copy)
    rendered = []
    pins, bill = type(sys)("safety_pins"), type(sys)("sbom")
    pins.main = lambda: rendered.append("pins")
    bill.main = lambda: rendered.append("sbom")
    monkeypatch.setitem(sys.modules, "safety_pins", pins)
    monkeypatch.setitem(sys.modules, "sbom", bill)
    monkeypatch.setattr(qc, "ROOT", tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")  # recorded, so teardown restores whatever was there
    saved = _saved_run(tmp_path)
    assert qc.main(["--from-result", str(saved)]) == 1
    assert rendered == ["pins", "sbom"]
    said = capsys.readouterr().out
    assert "Old against new on the same replay set" in said, (
        "the comparison is printed before anything is written"
    )
    assert (
        "Verdict for new: claude-sonnet-5-5 against the bar: below the bar: NOT qualified" in said
    )
    assert __import__("os").environ["ANTHROPIC_API_KEY"] == "", "no key was read"
    assert "# NOT QUALIFIED - measured 2026-10-21 14:00" in qc.PROVIDERS_YAML.read_text(
        encoding="utf-8"
    )


def test_a_run_needs_a_model_and_a_budget():
    with pytest.raises(SystemExit):
        qc.main(["--model", SONNET])


class _Secrets:
    def __init__(self, value: str) -> None:
        self.value, self.asked = value, []

    def get_secret_value(self, **kwargs):
        self.asked.append(kwargs["SecretId"])
        return {"SecretString": self.value}


def test_the_key_is_the_runtime_slot_and_is_never_said(monkeypatch, capsys):
    monkeypatch.setenv(
        "ANTHROPIC_API_KEY", ""
    )  # recorded, so the fake key never outlives this test
    fake = ANTHROPIC_KEY_PREFIX + "test-" + "x" * 8
    secrets = _Secrets(fake)
    said = qc.model_key("someenv", secrets)
    assert secrets.asked == ["warden/someenv/anthropic-api-key"]
    assert fake not in said
    assert fake not in capsys.readouterr().out
    assert __import__("os").environ["ANTHROPIC_API_KEY"] == fake


def test_an_empty_key_stops_the_run(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    empty = _Secrets("  ")
    with pytest.raises(SystemExit):
        qc.model_key("someenv", empty)


def test_a_failure_on_the_pinned_prompt_retires_that_models_pinned_row():
    """A model qualified on the pinned prompt that then fails on it is no longer qualified (CodeRabbit, PR 173)."""
    f = _files()
    passed, _b, _r, _why = qc.record(_result(correct=_bar()["min_correct"]), when=WHEN, **f)
    assert qualified_now(yaml.safe_load(passed)) == {SONNET}
    failed, benchmarks, readme, why = qc.record(
        _result(correct=_bar()["min_correct"] - 1),
        when=WHEN,
        providers=passed,
        benchmarks=_b,
        readme=_r,
    )
    doc = yaml.safe_load(failed)
    assert "NOT qualified" in why
    assert qualified_now(doc) == set()
    assert problems(readme, doc) == []
    assert problems(benchmarks, doc) == []


def test_a_failure_on_another_prompt_leaves_the_pinned_row():
    f = _files()
    passed, _b, _r, _why = qc.record(_result(correct=_bar()["min_correct"]), when=WHEN, **f)
    failed, *_ = qc.record(
        _result(correct=0, prompt="0" * 64), when=WHEN, providers=passed, benchmarks=_b, readme=_r
    )
    assert qualified_now(yaml.safe_load(failed)) == {SONNET}


def test_the_status_line_comes_from_providers_yaml_alone():
    doc = yaml.safe_load(qc.PROVIDERS_YAML.read_text(encoding="utf-8"))
    line = qc.status_line(doc, "2026-10-21")
    assert line.startswith(qc.STATUS_PREFIX)
    assert ("**none**" in line) is (not qualified_now(doc))


def test_a_mistyped_compare_with_stops_before_any_key_or_spend(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(qc, "measure", lambda *a, **k: called.append("measure"))
    args = ["--model", SONNET, "--budget-usd", "2", "--compare-with", str(tmp_path / "no-such-run")]
    with pytest.raises(SystemExit) as stopped:
        qc.main(args)
    assert stopped.value.code == 2
    assert called == [], "nothing was measured, so nothing was spent"


def test_a_comparison_that_fails_still_records_the_paid_result(tmp_path, monkeypatch, capsys):
    written = []
    monkeypatch.setattr(
        qc, "write", lambda result, when: written.append(result) or "below the bar: NOT qualified"
    )

    def broken(*_a):
        raise ValueError("unreadable run")

    monkeypatch.setattr(qc, "print_comparison", broken)
    saved = _saved_run(tmp_path)
    assert qc.main(["--from-result", str(saved)]) == 2
    assert len(written) == 1
    assert "comparison unavailable" in capsys.readouterr().err


def test_a_saved_result_that_its_reports_do_not_bear_out_is_refused(tmp_path):
    saved = _saved_run(tmp_path)
    edited = json.loads(saved.read_text(encoding="utf-8"))
    edited["wrong_and_allowed"] = 0  # the stored reports say otherwise
    saved.write_text(json.dumps(edited), encoding="utf-8")
    with pytest.raises(SystemExit, match="does not match its own reports"):
        qc.checked_result(saved)


def test_a_saved_result_without_its_reports_is_refused(tmp_path):
    lone = tmp_path / "qualification.json"
    lone.write_text(json.dumps(_result(correct=30)), encoding="utf-8")
    with pytest.raises(SystemExit, match="needs the run's reports"):
        qc.checked_result(lone)


def test_a_run_that_wrote_no_result_says_so(tmp_path, monkeypatch):
    import qualify_provider

    monkeypatch.setattr(qc, "model_key", lambda *_a: "a fake slot")
    monkeypatch.setattr(qualify_provider, "main", lambda _argv: 1)
    for name in ("WARDEN_PROVIDER", "WARDEN_MODEL"):
        monkeypatch.setenv(name, "")
    args = qc.argparse.Namespace(env="someenv", model=SONNET, out=tmp_path, budget_usd=1.0)
    with pytest.raises(SystemExit, match="wrote no"):
        qc.measure(args)


def test_a_command_line_path_outside_the_tools_places_is_refused():
    outside = pathlib.Path("/etc") / "passwd"  # a system file: never a place the tools work in
    with pytest.raises(SystemExit, match="refused"):
        qc.checked_result(outside)
    with pytest.raises(SystemExit, match="refused"):
        qc.compare_with_result(outside)
