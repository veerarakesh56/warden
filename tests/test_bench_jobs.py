"""scripts/bench_jobs.py (owner U3-10): the paid head-to-head and bench, run from the cloud runtime by
scripts/cloud_run.py - estimate first, refused over budget before the key is read, a hard ceiling while it runs, a
dry run that calls nothing paid, rows into docs/BENCHMARKS.md holding only measurements, providers.yaml never written.
Everything here is offline: the mock model, or a fake provider that bills like the real one."""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import sys

import pytest
from tests.fakes import ANTHROPIC_KEY_PREFIX

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import bench_jobs
import cloud_run

from warden.llm import LLMClient
from warden.providers import MAX_OUTPUT_TOKENS, Completion, load_qualified

ROUTE = load_qualified()["routing"]["anthropic"]
A, B = ROUTE["default"], ROUTE["hard"]  # the two models the owner compares, as providers.yaml names them
FAKE_KEY = ANTHROPIC_KEY_PREFIX + "bench" + "x" * 20


class _NoSecrets:
    """Secrets Manager that fails the test if it is asked at all."""

    def __init__(self) -> None:
        self.asked = []

    def get_secret_value(self, SecretId: str) -> dict:
        self.asked.append(SecretId)
        raise AssertionError("the key was read")


class _Secrets(_NoSecrets):
    def get_secret_value(self, SecretId: str) -> dict:
        self.asked.append(SecretId)
        return {"SecretString": FAKE_KEY}


@pytest.fixture
def few(monkeypatch):
    """Three of the hard cases, so a run takes a second; the selection itself is tested on the real sets."""
    cases = bench_jobs.select_cases("headtohead")[:3]
    monkeypatch.setattr(bench_jobs, "select_cases", lambda job: cases)
    return cases


@pytest.fixture
def no_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")  # registered first: whatever model_key sets is undone
    monkeypatch.delenv("ANTHROPIC_API_KEY")


def _files(out: pathlib.Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(out.rglob("*")) if p.is_file())


def test_the_hard_cases_are_every_held_out_case_with_more_than_one_cause_and_the_bench_is_every_case():
    hard = bench_jobs.select_cases("headtohead")
    every = bench_jobs.select_cases("bench")
    assert {c.key["kind"] for c in hard} == {"multi_fault"}
    assert len(hard) == sum(c.key["kind"] == "multi_fault" for c in every)
    assert len(hard) >= 29
    assert {c.set for c in every} == {p.name for p in bench_jobs.held_out_sets()}
    assert len(every) >= 220
    assert not any("correct_actions" in json.dumps(c.doc) for c in every)  # what the model reads holds no key


def test_the_offline_renderer_sees_each_prompt_once_and_sends_nothing(few):
    from warden.llm import _is_transient

    assert _is_transient(bench_jobs._Rendered()) is False  # one attempt, not three: the estimate is not tripled
    chars = bench_jobs.prompt_chars(few)
    assert set(chars) == {f"{c.set}/{c.id}" for c in few}
    assert all(4_000 < n < 40_000 for n in chars.values())


def test_the_estimate_is_each_models_own_listed_price_and_an_unpriced_model_is_refused():
    chars = {"s/a": 30_000, "s/b": 30_000}
    e = bench_jobs.estimate(A, chars, repeats=2)
    p_in, p_out = load_qualified()["prices"][A]
    assert e["answers"] == 4
    assert e["input_tokens"] == 40_000
    assert e["expected_usd"] == round((40_000 * p_in + 4 * bench_jobs.EXPECTED_OUT_TOKENS * p_out) / 1e6, 2)
    assert e["worst_usd"] > e["expected_usd"]
    assert e["reserve_usd"] == round((30_000 / 3 * p_in + MAX_OUTPUT_TOKENS * p_out) / 1e6, 4)
    with pytest.raises(SystemExit, match="no row in providers.yaml"):
        bench_jobs.estimate("a-model-with-no-price", chars, 1)


def test_the_budget_is_split_by_estimate_and_a_run_over_it_is_refused():
    chars = {f"s/{i}": 30_000 for i in range(10)}
    rows, refused = bench_jobs.plan([A, B], chars, 1, 100.0)
    assert refused == ""
    assert rows[0]["budget_usd"] + rows[1]["budget_usd"] == pytest.approx(100.0, abs=1e-3)
    share = rows[1]["budget_usd"] / rows[0]["budget_usd"]
    assert share == pytest.approx(rows[1]["expected_usd"] / rows[0]["expected_usd"], rel=1e-4)  # cents rounded
    total = sum(r["expected_usd"] for r in rows)
    assert "exceeds --budget-usd" in bench_jobs.plan([A, B], chars, 1, total * 0.99)[1]
    # Within the estimate, but a share too small for its estimate plus two calls at the output cap: still refused.
    assert "raise --budget-usd" in bench_jobs.plan([A, B], chars, 1, total + 0.01)[1]
    assert bench_jobs.plan([A], {}, 1, 5.0)[1] == "no case to answer"
    assert "positive" in bench_jobs.plan([A], chars, 1, 0.0)[1]


def test_an_over_budget_run_prints_its_estimate_and_stops_before_the_key_and_before_any_client(
        few, no_key, tmp_path, monkeypatch, capsys):
    def never(model):
        raise AssertionError("a client was made")

    monkeypatch.setattr(bench_jobs, "live_client", never)
    monkeypatch.setattr(bench_jobs, "dry_client", never)
    secrets = _NoSecrets()
    out = tmp_path / "o"
    code = cloud_run.main(["headtohead", "--model", A, "--vs", B, "--budget-usd", "0.05", "--out", str(out)],
                          secrets_client=secrets)
    said = capsys.readouterr().out
    assert code == 2
    assert "expected total $" in said
    assert "REFUSED before any call" in said
    assert secrets.asked == []
    assert not out.exists()


class _BillsTheCap:
    """A provider that bills like the real one at its worst: the whole prompt in, a full answer at the output cap
    out - and the answer is not valid, so llm.structured retries it (each retry billed again)."""

    name, version = "anthropic", "fake"

    def __init__(self, model: str) -> None:
        self.model, self.calls = model, 0

    def complete(self, *, system, user, schema=None):
        self.calls += 1
        return Completion("not json", (len(system) + len(user)) // 4, MAX_OUTPUT_TOKENS)


def test_the_budget_is_a_hard_ceiling_even_when_every_answer_runs_to_the_output_cap(few, tmp_path):
    provider = _BillsTheCap(A)
    chars = bench_jobs.prompt_chars(few)
    reserve = bench_jobs.reserve_usd(A, max(chars.values()))

    def client():
        c = LLMClient(provider=provider, mock=False)
        c.price_in, c.price_out = bench_jobs.listed_price(A)
        return c

    total = 4 * reserve  # room for a few calls, not for every attempt of every case
    budget = bench_jobs.HardBudget(total, reserve, client)
    done = bench_jobs.answer(A, few, 2, tmp_path, budget, log=lambda _: None)
    assert provider.calls >= 2  # it really spent
    assert budget.spent() <= total
    assert "is spent" in done["stopped"]
    s = bench_jobs.summary(A, done, total)
    assert s["answers"] == 6
    assert s["unanswered"] == 6  # nothing valid came back, and nothing was skipped: every row is counted
    with pytest.raises(ValueError):
        bench_jobs.HardBudget(0, reserve, client)


def test_a_dry_run_reads_no_key_and_writes_neither_docs_nor_providers_yaml(few, no_key, tmp_path, capsys):
    docs = bench_jobs.BENCHMARKS_MD.read_bytes()
    providers = bench_jobs.PROVIDERS_YAML.read_bytes()
    secrets = _NoSecrets()
    out = tmp_path / "dry"
    code = cloud_run.main(["headtohead", "--model", A, "--vs", B, "--budget-usd", "5", "--dry-run", "--record",
                           "--out", str(out)], secrets_client=secrets)
    said = capsys.readouterr().out
    assert code == 0
    assert secrets.asked == []
    assert "ANTHROPIC_API_KEY" not in os.environ
    assert bench_jobs.BENCHMARKS_MD.read_bytes() == docs
    assert bench_jobs.PROVIDERS_YAML.read_bytes() == providers
    assert "DRY RUN" in said
    preview = (out / "BENCHMARKS.md").read_text(encoding="utf-8")
    rows = [line for line in preview.splitlines() if "| headtohead (dry run) |" in line]
    assert [r.split(" | ")[2] for r in rows] == [A, B]
    result = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert result["dry_run"] is True
    assert [m["answers"] for m in result["models"]] == [3, 3]
    assert result["models"][1]["compared"]["model"] == A
    assert all(0 < m["spent_usd"] <= m["budget_usd"] for m in result["models"])


def test_a_paid_run_reads_the_key_after_its_estimate_records_the_docs_and_writes_no_secret(
        few, no_key, tmp_path, monkeypatch, capsys):
    docs = tmp_path / "BENCHMARKS.md"
    docs.write_bytes(bench_jobs.BENCHMARKS_MD.read_bytes())
    monkeypatch.setattr(bench_jobs, "BENCHMARKS_MD", docs)
    asked: list[tuple[str, str | None, str | None]] = []

    def paid(model):  # the mock answers; the test checks what the run would send it to, and when
        asked.append((model, os.environ.get("WARDEN_MODEL"), os.environ.get("ANTHROPIC_API_KEY")))
        return bench_jobs.dry_client(model)

    monkeypatch.setattr(bench_jobs, "live_client", paid)
    monkeypatch.setenv("WARDEN_MODEL", "set-by-the-caller")
    secrets = _Secrets()
    out = tmp_path / "paid"
    code = cloud_run.main(["bench", "--model", B, "--repeats", "2", "--budget-usd", "5", "--record",
                           "--out", str(out)], secrets_client=secrets)
    assert code == 0
    assert len(secrets.asked) == 1
    assert {a[:2] for a in asked} == {(B, B)}
    assert {a[2] for a in asked} == {FAKE_KEY}
    assert os.environ["WARDEN_MODEL"] == "set-by-the-caller"  # restored after the answers
    assert "WARDEN_QUALIFYING" not in os.environ
    row = [line for line in docs.read_text(encoding="utf-8").splitlines() if "| bench |" in line]
    assert len(row) == 1
    assert f"| {B} | 6 (3 x 2) |" in row[0]
    written = _files(out) + docs.read_text(encoding="utf-8") + capsys.readouterr().out
    assert FAKE_KEY not in written
    assert ANTHROPIC_KEY_PREFIX not in written


def test_the_paid_client_is_the_named_model_on_the_api_never_the_mock(no_key, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)
    monkeypatch.setenv("WARDEN_MOCK", "1")
    monkeypatch.setenv("WARDEN_PROVIDER", "claude_cli")
    for name in ("WARDEN_QUALIFYING", "WARDEN_PRICE_IN"):
        monkeypatch.delenv(name, raising=False)
    with bench_jobs.measuring(B):
        client = bench_jobs.live_client(B)  # B is not qualified: measuring it is what WARDEN_QUALIFYING is for
        assert (client.provider_name, client.model, client.mock) == ("anthropic", B, False)
        assert (client.price_in, client.price_out) == bench_jobs.listed_price(B)
        with pytest.raises(SystemExit, match="the client is"):
            bench_jobs.live_client(A)
    assert os.environ["WARDEN_MOCK"] == "1"
    assert os.environ["WARDEN_PROVIDER"] == "claude_cli"
    assert "WARDEN_QUALIFYING" not in os.environ


def test_a_bench_that_finds_providers_yaml_changed_fails(few, no_key, tmp_path, monkeypatch):
    pinned = tmp_path / "providers.yaml"
    pinned.write_bytes(bench_jobs.PROVIDERS_YAML.read_bytes())
    monkeypatch.setattr(bench_jobs, "PROVIDERS_YAML", pinned)
    real = bench_jobs.dry_client

    def rerouting(model):
        pinned.write_text(pinned.read_text(encoding="utf-8") + "\n# rerouted\n", encoding="utf-8")
        return real(model)

    monkeypatch.setattr(bench_jobs, "dry_client", rerouting)
    with pytest.raises(SystemExit, match="never changes routing"):
        cloud_run.main(["bench", "--model", A, "--budget-usd", "5", "--dry-run", "--out", str(tmp_path / "o")],
                       secrets_client=_NoSecrets())


def test_results_are_never_written_inside_the_repository(few, no_key, capsys):
    code = cloud_run.main(["bench", "--model", A, "--budget-usd", "5", "--dry-run", "--out", str(ROOT / "bench-out")],
                          secrets_client=_NoSecrets())
    assert code == 2
    assert "refusing to write inside the repository" in capsys.readouterr().out
    assert not (ROOT / "bench-out").exists()


def test_bench_flags_belong_to_the_bench_jobs_and_headtohead_needs_two_models(no_key, tmp_path):
    with pytest.raises(SystemExit):
        cloud_run.main(["qualify", "--model", A, "--dry-run"], secrets_client=_NoSecrets())
    with pytest.raises(SystemExit, match="two models"):
        cloud_run.main(["headtohead", "--model", A, "--dry-run", "--out", str(tmp_path / "o")],
                       secrets_client=_NoSecrets())
    with pytest.raises(SystemExit, match="one model"):
        cloud_run.main(["bench", "--model", A, "--vs", B, "--dry-run", "--out", str(tmp_path / "o")],
                       secrets_client=_NoSecrets())
    with pytest.raises(SystemExit, match="1 to 10"):
        cloud_run.main(["bench", "--model", A, "--repeats", "0", "--dry-run", "--out", str(tmp_path / "o")],
                       secrets_client=_NoSecrets())


def _row(**over) -> dict:
    return {"model": A, "cases": 29, "answers": 58, "repeats": 2, "correct": 40, "pass_k": 18, "cited_cause": 30,
            "outcome_right": 41, "harm_allowed": 0, "unanswered": 1, "spent_usd": 1.234, "budget_usd": 2.0, **over}


WHEN = dt.datetime(2026, 10, 21, 8, 0, tzinfo=dt.UTC)


def test_a_docs_row_holds_only_measurements_in_the_fixed_format():
    row = bench_jobs.docs_row("bench", _row(), WHEN, "d435b59f", None)
    assert row == (f"| 2026-10-21 08:00 UTC (13:30 IST) | bench | {A} | 58 (29 x 2) | 40 | 18 of 29 | 30 | 41 | 0 | 1 "
                   "| 1.23 / 2.00 | - | d435b59f |")
    assert row.count("|") == bench_jobs.HEADER.count("|")
    vs = {"model": A, "fixed": 3, "broke": 1, "p": 0.625}
    assert f"vs {A}: 3 better, 1 worse, p=0.62" in bench_jobs.docs_row("headtohead", _row(model=B), WHEN, "d435b59f", vs)
    for bad in ({"model": "someone@example.com"}, {"model": "Model With Spaces"}, {"model": "not-a-listed-model"},
                {"correct": "40"}, {"correct": -1}, {"spent_usd": "a lot"}):
        with pytest.raises((ValueError, SystemExit)):
            bench_jobs.docs_row("bench", _row(**bad), WHEN, "d435b59f", None)
    with pytest.raises(ValueError):
        bench_jobs.docs_row("bench", _row(), WHEN, "123456789012", None)
    with pytest.raises(ValueError):
        bench_jobs.docs_row("not-a-job", _row(), WHEN, "d435b59f", None)


def test_a_cell_that_could_carry_a_secret_or_an_account_id_is_refused_whatever_let_it_through(monkeypatch):
    # Behind the per-field checks, every cell is scanned on its own: here the model list is made to accept anything.
    monkeypatch.setattr(bench_jobs, "listed_price", lambda model: (1.0, 1.0))
    for model in (ANTHROPIC_KEY_PREFIX + "api03-abc", "acct-123456789012", "my-secret-model", "aws-token-x"):
        with pytest.raises(ValueError, match="refusing a cell"):
            bench_jobs.docs_row("bench", _row(model=model), WHEN, "d435b59f", None)


def test_a_model_cell_is_an_id_not_free_text_even_when_the_price_list_would_accept_it(monkeypatch):
    monkeypatch.setattr(bench_jobs, "listed_price", lambda model: (1.0, 1.0))
    with pytest.raises(ValueError, match="a model id"):
        bench_jobs.docs_row("bench", _row(model="Model With Spaces"), WHEN, "d435b59f", None)
    vs = {"model": "Other Model (2)", "fixed": 0, "broke": 0, "p": 1.0}
    with pytest.raises(ValueError, match="a model id"):
        bench_jobs.docs_row("headtohead", _row(), WHEN, "d435b59f", vs)


def test_rows_go_at_the_end_of_the_one_table_between_its_markers():
    text = bench_jobs.BENCHMARKS_MD.read_text(encoding="utf-8")
    assert bench_jobs.with_rows(text, []) == text  # the committed table has the fixed header and no row yet
    one = bench_jobs.with_rows(text, ["| row 1 |"])
    two = bench_jobs.with_rows(one, ["| row 2 |"])
    body = two.split(bench_jobs.BEGIN)[1].split(bench_jobs.END)[0].splitlines()
    assert body[-2:] == ["| row 1 |", "| row 2 |"]
    assert two.replace("| row 1 |\n| row 2 |\n", "") == text
    with pytest.raises(SystemExit, match="exactly one"):
        bench_jobs.with_rows(text.replace(bench_jobs.END, ""), [])
    with pytest.raises(SystemExit, match="exactly one"):
        bench_jobs.with_rows(text + bench_jobs.BEGIN, [])
    with pytest.raises(SystemExit, match="fixed one"):
        bench_jobs.with_rows(text.replace("| Measured | Job |", "| When | Job |"), [])


def test_pass_k_counts_a_case_only_when_every_repeat_was_right_and_mcnemar_compares_first_answers():
    right = {"grade": "CORRECT", "cited_cause": True, "outcome": "right plan", "harm_allowed": False, "policies": []}
    wrong = {"grade": "WRONG", "cited_cause": False, "outcome": "wrong plan", "harm_allowed": True, "policies": []}
    gone = {"grade": "SAFE", "cited_cause": False, "outcome": "missed fix", "harm_allowed": False,
            "policies": ["P0-MODEL-UNAVAILABLE"]}
    a = {"rows": {"c1": [right, right], "c2": [right, wrong], "c3": [wrong, wrong], "c4": [gone, right]},
         "spent_usd": 0.5, "stopped": ""}
    b = {"rows": {"c1": [wrong, wrong], "c2": [right, right], "c3": [right, right], "c4": [right, right]},
         "spent_usd": 1.0, "stopped": ""}
    s = bench_jobs.summary(A, a, 1.0)
    assert (s["cases"], s["answers"], s["repeats"]) == (4, 8, 2)
    assert (s["correct"], s["pass_k"], s["harm_allowed"], s["unanswered"]) == (4, 1, 3, 1)
    assert s["outcome_right"] == 4
    assert s["usd_per_answer"] == round(0.5 / 7, 4)
    vs = bench_jobs.compared(a, b)
    assert (vs["incidents"], vs["fixed"], vs["broke"]) == (3, 1, 1)  # c4 is not compared: A never answered it
