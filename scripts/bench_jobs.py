"""The paid bench runs behind scripts/cloud_run.py (owner U3-10): one command each, with the cloud runtime's own key.

    python scripts/cloud_run.py headtohead --model <model A> --vs <model B> --budget-usd 4 --record
    python scripts/cloud_run.py bench --model <model> --repeats 3 --budget-usd 25 --record
    ... --dry-run    everything but the paid call: no key is read, the mock model answers at the real model's price

headtohead  two models answer the same hard cases - every held-out case whose key says it has more than one cause
            (`multi_fault`) - and are compared on quality (heldout_bench's grades and outcomes, McNemar on the cases
            both answered) and on cost (USD per answer, each model at its own `prices` row in providers.yaml).
bench       one model answers every case of every held-out set under docs/bench/ (`heldout-*`, 220 cases today),
            `--repeats` times: pass^k (a case counts only when every repeat was right) beside pass@1.

Each case goes through today's redact -> tripwire -> diagnose -> verify exactly as a replay does
(replay_diagnose.rediagnose) and is graded by scripts/heldout_bench.py from the set's answer key alone. The AWS
documentation lookups are off (a replay reads nothing new), so these numbers are not the --docs runs of G10.

Money (no call is made before all of this):
- the estimate is printed first: each case's prompt is rendered offline (no model, no network) and priced at the
  model's own `prices` row; output at EXPECTED_OUT_TOKENS per answer. A model with no price row is refused.
- the run is refused when the estimate exceeds --budget-usd, before the key is read.
- --budget-usd is a hard ceiling while it runs (HardBudget): an answer is asked only while what is left covers two
  calls at the output cap (one to make, one kept back), so no answer can take the run past it; the rest are counted
  unanswered, never skipped.

A bench MEASURES. It never changes which model diagnoses: providers.yaml (`routing`, `roles`, `qualified`) is not
written, and a run that finds it changed fails. Measuring a model that is not qualified needs WARDEN_QUALIFYING, as
scripts/qualify_provider.py sets it; here it is set only around the model's own answers and restored after.

`--record` adds one row per model to the table in docs/BENCHMARKS.md ("Paid bench runs"), in a fixed format built
only from numbers, the job, a model id from providers.yaml `prices` and the prompt's hash - so no secret, account id
or email can be written there. A dry run writes that file's would-be text into --out instead, never into docs/.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import functools
import hashlib
import json
import math
import os
import pathlib
import re
import sys
from collections.abc import Callable, Iterator

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))  # heldout_bench, replay_diagnose, qualify_provider: reused, not copied
BENCH_DIR = ROOT / "docs" / "bench"
BENCHMARKS_MD = ROOT / "docs" / "BENCHMARKS.md"
PROVIDERS_YAML = ROOT / "src" / "warden" / "data" / "providers.yaml"
HARD_KINDS = ("multi_fault",)
# Rendered prompt characters per token, counted low on purpose (llm.py counts 4) so the estimate errs high.
CHARS_PER_TOKEN = 3
# Output tokens (thinking included) per answer. Measured on G10 (providers.yaml, 2026-10-15): Sonnet 5.5 $3.15 and
# Opus 5.5 $9.00 for 172 answers at their prices are about 1,300 and 2,100 output tokens each; 2,500 errs high.
EXPECTED_OUT_TOKENS = 2500
ATTEMPTS = 3  # llm.structured's first try and its two retries: the worst case of one answer
BEGIN, END = "<!-- cloud-run-bench:begin -->", "<!-- cloud-run-bench:end -->"
HEADER = ("| Measured | Job | Model | Answers (cases x repeats) | Correct | pass^k | Cites the cause | Right outcome | "
          "Harm allowed | Unanswered | USD spent / budget | Compared | Prompt |")


@dataclasses.dataclass(frozen=True)
class Case:
    set: str
    id: str
    doc: dict
    key: dict


def held_out_sets() -> list[pathlib.Path]:
    return sorted(p for p in BENCH_DIR.glob("heldout-*") if (p / "incidents").is_dir())


def load_cases(sets: list[pathlib.Path], kinds: tuple[str, ...] | None = None) -> list[Case]:
    """Every case of `sets` (only `kinds`, when given) with its answer-key row; the key never reaches the model."""
    from heldout_bench import answer_key

    out = []
    for s in sets:
        key = answer_key(s)
        for f in sorted((s / "incidents").glob("*.json")):
            doc = json.loads(f.read_text(encoding="utf-8"))
            if kinds is None or key[doc["id"]].get("kind") in kinds:
                out.append(Case(s.name, doc["id"], doc, key[doc["id"]]))
    return out


def select_cases(job: str) -> list[Case]:
    return load_cases(held_out_sets(), HARD_KINDS if job == "headtohead" else None)


# --------------------------------------------------------------------------------------------------- the estimate


class _Rendered(Exception):
    """Raised by the offline renderer once it has seen the prompt: nothing is sent anywhere. A permanent error (a
    4xx status, as llm._is_transient reads one), so the prompt is seen once, not once per retry."""

    status_code = 400


def prompt_chars(cases: list[Case]) -> dict[str, int]:
    """Each case's prompt as the model would get it (system text, evidence and answer schema), rendered by today's
    pipeline with a provider that records its size and answers nothing. Offline: no model, no network."""
    from replay_diagnose import rediagnose

    from warden.llm import LLMClient

    seen: list[int] = []

    class _Renderer:
        name, model, version = "offline-render", "offline-render", "0"

        def complete(self, *, system, user, schema=None):
            """The provider interface's call, by its keyword names; `schema` is not read - only the size is kept."""
            seen.append(len(system) + len(user))
            raise _Rendered  # permanent: llm.structured makes no second attempt; the diagnosis is rules-only

    sizes = {}
    for c in cases:
        seen.clear()
        rediagnose({"alert": c.doc["alert"], "context": c.doc["context"]}, LLMClient(provider=_Renderer(), mock=False))
        sizes[f"{c.set}/{c.id}"] = sum(seen)
    return sizes


def listed_price(model: str) -> tuple[float, float]:
    """The model's own row in providers.yaml `prices` - never a default: an unpriced model cannot be estimated."""
    from warden.providers import load_qualified

    row = (load_qualified().get("prices") or {}).get(model)
    if not (isinstance(row, (list, tuple)) and len(row) == 2):
        raise SystemExit(f"{model} has no row in providers.yaml `prices`: its cost cannot be estimated")
    return float(row[0]), float(row[1])


def reserve_usd(model: str, max_prompt_chars: int) -> float:
    """What one call can cost at most: the largest prompt (counted high) and a full answer at the output cap."""
    from warden.providers import MAX_OUTPUT_TOKENS

    p_in, p_out = listed_price(model)
    return (max_prompt_chars / CHARS_PER_TOKEN) * p_in / 1e6 + MAX_OUTPUT_TOKENS * p_out / 1e6


def estimate(model: str, chars: dict[str, int], repeats: int) -> dict:
    from warden.providers import MAX_OUTPUT_TOKENS

    p_in, p_out = listed_price(model)
    in_tok = sum(chars.values()) / CHARS_PER_TOKEN
    answers = len(chars) * repeats
    expected = (in_tok * repeats * p_in + answers * EXPECTED_OUT_TOKENS * p_out) / 1e6
    worst = ATTEMPTS * (in_tok * repeats * p_in + answers * MAX_OUTPUT_TOKENS * p_out) / 1e6
    return {"model": model, "answers": answers, "price_per_mtok": [p_in, p_out], "input_tokens": round(in_tok * repeats),
            "expected_usd": round(expected, 2), "worst_usd": round(worst, 2),
            "reserve_usd": round(reserve_usd(model, max(chars.values(), default=0)), 4)}


def plan(models: list[str], chars: dict[str, int], repeats: int, budget_usd: float) -> tuple[list[dict], str]:
    """The estimate per model and the reason to refuse ("" when the run may start). Each model gets a share of the
    budget in proportion to its estimate, so the first model can never starve the second."""
    rows = [estimate(m, chars, repeats) for m in models]
    total = sum(r["expected_usd"] for r in rows)
    for r in rows:
        r["budget_usd"] = round(budget_usd * r["expected_usd"] / total, 4) if total else 0.0
    if not math.isfinite(budget_usd) or budget_usd <= 0:  # nan or infinity would switch the ceiling off
        return rows, "the budget must be a positive number of USD"
    if not chars:
        return rows, "no case to answer"
    if total > budget_usd:
        return rows, f"the estimate ${total:.2f} exceeds --budget-usd ${budget_usd:.2f}"
    short = [r["model"] for r in rows if r["budget_usd"] < r["expected_usd"] + 2 * r["reserve_usd"]]
    if short:
        return rows, (f"the budget leaves {', '.join(short)} less than its estimate plus the two calls at the output "
                      "cap HardBudget keeps room for; raise --budget-usd")
    return rows, ""


def say_plan(job: str, rows: list[dict], cases: int, repeats: int, budget_usd: float) -> None:
    print(f"{job}: {cases} cases x {repeats} repeat(s) per model; budget ${budget_usd:.2f} (a hard ceiling)")
    for r in rows:
        print(f"  {r['model']}: {r['answers']} answers, ~{r['input_tokens']:,} input tokens at "
              f"${r['price_per_mtok'][0]:g}/${r['price_per_mtok'][1]:g} per 1M -> expected ${r['expected_usd']:.2f} "
              f"(worst case at the output cap ${r['worst_usd']:.2f}); its share ${r['budget_usd']:.2f}")
    total = sum(r["expected_usd"] for r in rows)
    print(f"  expected total ${total:.2f} of ${budget_usd:.2f}")


# --------------------------------------------------------------------------------------------------- the money cap


class HardBudget:
    """A hard ceiling across every answer of one model. qualify_provider.Budget gives each answer what is left, so
    the call that crosses the ceiling is still made and paid (its output is priced only after it arrives). Here an
    answer may spend what is left LESS one call at the output cap (`reserve`, kept back for that overshoot), and one
    is asked only while that room still holds a whole call: the run ends at or below the ceiling (up to llm.py's
    4-characters-per-token reading of the prompt, which the reserve counts at CHARS_PER_TOKEN)."""

    def __init__(self, total_usd: float, reserve_usd: float, factory: Callable[[], object]) -> None:
        if not math.isfinite(total_usd) or total_usd <= 0 or reserve_usd < 0:
            raise ValueError("the budget must be a positive number of USD")
        self.total, self.reserve, self.factory, self.clients = float(total_usd), float(reserve_usd), factory, []

    def spent(self) -> float:
        return sum(c.cost.usd for c in self.clients)

    def __call__(self):
        from warden.llm import BudgetExceeded

        room = self.total - self.spent() - self.reserve
        if room <= 0 or room < self.reserve:
            raise BudgetExceeded(f"the bench budget of ${self.total:.2f} is spent (kept back ${self.reserve:.2f}: one "
                                 "call at the output cap)")
        client = self.factory()
        client.max_usd = min(client.max_usd, room)
        self.clients.append(client)
        return client


# --------------------------------------------------------------------------------------------------- one model


@contextlib.contextmanager
def measuring(model: str) -> Iterator[None]:
    """The process set to answer as exactly `model` on the Anthropic API at its own price, for the answers only."""
    names = ("WARDEN_PROVIDER", "WARDEN_MODEL", "WARDEN_QUALIFYING", "WARDEN_PRICE_IN", "WARDEN_PRICE_OUT", "WARDEN_MOCK")
    before = {n: os.environ.get(n) for n in names}
    for n in ("WARDEN_PRICE_IN", "WARDEN_PRICE_OUT", "WARDEN_MOCK"):
        os.environ.pop(n, None)
    os.environ.update(WARDEN_PROVIDER="anthropic", WARDEN_MODEL=model, WARDEN_QUALIFYING="1")
    try:
        yield
    finally:
        for n, v in before.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v


def live_client(model: str):
    """The paid client: the Anthropic API as `model`. mock=False on purpose - WARDEN_MOCK in the caller's shell must
    not turn a paid run into a mock one that is recorded as the model's."""
    from warden.llm import LLMClient

    client = LLMClient(mock=False)
    if (client.provider_name, client.model) != ("anthropic", model):
        raise SystemExit(f"asked for anthropic {model}, the client is {client.provider_name} {client.model}")
    return client


def dry_client(model: str):
    """The mock model, charged at `model`'s own listed price: every step but the paid call."""
    from warden.llm import LLMClient

    client = LLMClient(mock=True)
    client.price_in, client.price_out = listed_price(model)
    return client


def answer(model: str, cases: list[Case], repeats: int, out: pathlib.Path, budget: HardBudget,
           log: Callable[[str], None] = print) -> dict:
    """Every case `repeats` times by `model` into out/<model>/r<n>/<set>/<id>.json, graded from the key. An answer
    already on disk is kept (a restarted run pays once; the spend shown is this run's); one the budget did not reach
    is an unanswered row."""
    from heldout_bench import score
    from replay_diagnose import UNAVAILABLE

    rows: dict[str, list[dict]] = {}
    stopped = ""
    for r in range(1, repeats + 1):
        for c in cases:
            dest = out / model / f"r{r}" / c.set / f"{c.id}.json"
            report = _kept(dest)
            if report is None and not stopped:
                report, stopped = _ask(model, r, c, dest, budget, log)
            row = score(report, c.key) if report else {"grade": "UNANSWERED", "policies": [UNAVAILABLE],
                                                         "cited_cause": False, "outcome": "unanswered",
                                                         "harm_allowed": False}
            rows.setdefault(f"{c.set}/{c.id}", []).append(row)
    return {"rows": rows, "spent_usd": round(budget.spent(), 4), "stopped": stopped}


def _kept(dest: pathlib.Path) -> dict | None:
    """The answer already on disk at `dest`, or None: none there, or one the model never gave (unavailable)."""
    from replay_diagnose import UNAVAILABLE

    if not dest.exists():
        return None
    report = json.loads(dest.read_text(encoding="utf-8"))
    if UNAVAILABLE in (report.get("verdict") or {}).get("policy_ids", []):
        return None
    return report


def _ask(model: str, r: int, c: Case, dest: pathlib.Path, budget: HardBudget,
         log: Callable[[str], None]) -> tuple[dict | None, str]:
    """One answer from a client the budget still allows, written to `dest` and read back - or no answer and why the
    budget stopped the run."""
    from replay_diagnose import rediagnose

    from warden.llm import BudgetExceeded

    try:
        client = budget()
    except BudgetExceeded as exc:
        log(f"{model}: {exc}; the rest are unanswered")
        return None, str(exc)
    made = rediagnose({"alert": c.doc["alert"], "context": c.doc["context"]}, client)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(made.model_dump_json(indent=2), encoding="utf-8")
    log(f"{model} r{r} {c.set}/{c.id}: {made.proposal.action.value} {made.verdict.status.value} "
        f"${made.cost.usd:.4f}")
    return json.loads(dest.read_text(encoding="utf-8")), ""


def summary(model: str, done: dict, budget_usd: float) -> dict:
    from heldout_bench import RIGHT_OUTCOMES

    every = [row for runs in done["rows"].values() for row in runs]

    def count(f: Callable[[dict], bool]) -> int:
        return sum(1 for row in every if f(row))

    unanswered = count(lambda row: "P0-MODEL-UNAVAILABLE" in (row.get("policies") or []))
    return {"model": model, "cases": len(done["rows"]), "answers": len(every),
            "repeats": max((len(v) for v in done["rows"].values()), default=0),
            "correct": count(lambda row: row["grade"] == "CORRECT"),
            "pass_k": sum(1 for runs in done["rows"].values() if all(row["grade"] == "CORRECT" for row in runs)),
            "cited_cause": count(lambda row: row["cited_cause"]),
            "outcome_right": count(lambda row: row.get("outcome") in RIGHT_OUTCOMES),
            "harm_allowed": count(lambda row: row["harm_allowed"]), "unanswered": unanswered,
            "spent_usd": done["spent_usd"], "budget_usd": round(budget_usd, 2),
            "usd_per_answer": round(done["spent_usd"] / max(1, len(every) - unanswered), 4), "stopped": done["stopped"]}


def compared(a: dict, b: dict) -> dict:
    """McNemar on the first answer to each case both models answered: did B get right more than it got wrong?"""
    from qualify_provider import mcnemar

    def firsts(done: dict) -> dict[str, bool]:
        return {k: v[0]["grade"] == "CORRECT" for k, v in done["rows"].items()
                if "P0-MODEL-UNAVAILABLE" not in (v[0].get("policies") or [])}

    return mcnemar(firsts(a), firsts(b))


# --------------------------------------------------------------------------------------------------- docs/BENCHMARKS.md


_CELL = re.compile(r"[0-9A-Za-z .:/()^,=+-]{0,80}")
_MODEL = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+){0,8}")
_NEVER = (re.compile(r"@"), re.compile(r"\d{12}"), re.compile(r"(?i)\bsk-|\bAKIA|\bASIA|key|secret|token"))


def both_times(when: dt.datetime) -> str:
    ist = when.astimezone(dt.timezone(dt.timedelta(hours=5, minutes=30)))
    return f"{when:%Y-%m-%d %H:%M} UTC ({ist:%H:%M} IST)"


def _check_row(job: str, s: dict, prompt: str) -> None:
    """A row's model, prompt, job, counts and money each of the one shape it may have; else refused."""
    if not _MODEL.fullmatch(s["model"]):
        raise ValueError("a model id is lowercase words and numbers joined by - or .")
    listed_price(s["model"])  # and one providers.yaml prices: a name WARDEN already lists
    if not re.fullmatch(r"[0-9a-f]{8}", prompt):
        raise ValueError("the prompt is the first 8 hex characters of its fingerprint")
    if job not in JOBS:
        raise ValueError(f"unknown job {job!r}")
    nums = [s[k] for k in ("answers", "cases", "repeats", "correct", "pass_k", "cited_cause", "outcome_right",
                           "harm_allowed", "unanswered")]
    if not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in nums):
        raise ValueError("every count is a whole number")
    if not all(isinstance(s[k], (int, float)) and s[k] >= 0 for k in ("spent_usd", "budget_usd")):
        raise ValueError("money is a number")


def docs_row(job: str, s: dict, when: dt.datetime, prompt: str, vs: dict | None, *, dry_run: bool = False) -> str:
    """One table row, every cell checked against what it may hold: a row that could carry anything else - a secret,
    an account id, an email - is refused, never written."""
    _check_row(job, s, prompt)
    other = "-"
    if vs:
        other = f"vs {vs['model']}: {vs['fixed']} better, {vs['broke']} worse, p={vs['p']:.2f}"
        if not _MODEL.fullmatch(vs["model"]):
            raise ValueError("a model id is lowercase words and numbers joined by - or .")
    cells = [both_times(when), f"{job} (dry run)" if dry_run else job, s["model"],
             f"{s['answers']} ({s['cases']} x {s['repeats']})", str(s["correct"]),
             f"{s['pass_k']} of {s['cases']}" if s["repeats"] > 1 else "-", str(s["cited_cause"]),
             str(s["outcome_right"]), str(s["harm_allowed"]), str(s["unanswered"]),
             f"{s['spent_usd']:.2f} / {s['budget_usd']:.2f}", other, prompt]
    for c in cells:
        if not _CELL.fullmatch(c) or any(p.search(c) for p in _NEVER):
            raise ValueError(f"refusing a cell that could carry something other than a measurement: {c!r}")
    return "| " + " | ".join(cells) + " |"


def with_rows(text: str, rows: list[str]) -> str:
    """docs/BENCHMARKS.md with `rows` added at the end of its bench table, between its two markers."""
    if text.count(BEGIN) != 1 or text.count(END) != 1 or text.index(BEGIN) > text.index(END):
        raise SystemExit(f"docs/BENCHMARKS.md needs exactly one {BEGIN} ... {END} table")
    head, rest = text.split(BEGIN)
    table, tail = rest.split(END)
    lines = [line for line in table.strip("\n").splitlines() if line]
    if lines[:1] != [HEADER]:
        raise SystemExit("the bench table's header is not the fixed one")
    return head + BEGIN + "\n" + "\n".join([*lines, *rows]) + "\n" + END + tail


# --------------------------------------------------------------------------------------------------- the jobs


def _fingerprint(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def same_run(out: pathlib.Path, job: str, dry_run: bool) -> None:
    """--out holds one job's answers of one kind: a restart continues it, and a paid run never takes over a dry run's
    mock answers (nor the reverse) as if they were the model's."""
    mark, kind = out / "run.json", {"job": job, "dry_run": dry_run}
    if mark.exists() and json.loads(mark.read_text(encoding="utf-8")) != kind:
        raise SystemExit(f"{out} holds another run's answers ({mark.read_text(encoding='utf-8').strip()}); "
                         "use a new --out")
    if not mark.exists() and out.exists() and any(out.iterdir()):
        raise SystemExit(f"{out} is not empty and is no bench run's; use a new --out")
    out.mkdir(parents=True, exist_ok=True)
    mark.write_text(json.dumps(kind), encoding="utf-8")


def _models(job: str, a: argparse.Namespace) -> list[str]:
    """The models a job answers with: two different ones for headtohead, one for bench; --repeats 1 to 10."""
    if job == "headtohead" and (not a.vs or a.vs == a.model):
        raise SystemExit("headtohead compares two models: --model A --vs B")
    if job != "headtohead" and a.vs:
        raise SystemExit(f"{job} measures one model; --vs is for headtohead")
    if not 1 <= a.repeats <= 10:
        raise SystemExit("--repeats is 1 to 10")
    return [a.model, a.vs] if job == "headtohead" else [a.model]


def _write_rows(a: argparse.Namespace, table: list[str]) -> None:
    """--record: the rows into docs/BENCHMARKS.md (a dry run's into --out, never docs/); else printed."""
    if not a.record:
        print("\n".join(["the rows --record would add to docs/BENCHMARKS.md:", *table]))
        return
    dest = a.out / "BENCHMARKS.md" if a.dry_run else BENCHMARKS_MD
    dest.write_text(with_rows(BENCHMARKS_MD.read_text(encoding="utf-8"), table), encoding="utf-8", newline="\n")
    print(f"recorded in {dest}" + (" (a dry run never writes docs/)" if a.dry_run else ""))


def run(job: str, a: argparse.Namespace) -> int:
    models = _models(job, a)
    out = a.out
    if ROOT.resolve() in out.parents or out == ROOT.resolve():
        print("refusing to write inside the repository: --out is a new directory outside it")
        return 2
    cases = select_cases(job)
    chars = prompt_chars(cases)
    rows, refused = plan(models, chars, a.repeats, a.budget_usd)
    say_plan(job, rows, len(cases), a.repeats, a.budget_usd)
    if refused:
        print(f"REFUSED before any call: {refused}")
        return 2
    if a.dry_run:
        print("DRY RUN: no key is read; the mock model answers at each model's listed price")
    else:
        a.load_key()
    pinned = _fingerprint(PROVIDERS_YAML)
    from qualify_provider import prompt_fingerprint

    prompt = prompt_fingerprint()[:8]
    same_run(out, job, a.dry_run)
    done, sums = {}, []
    make = dry_client if a.dry_run else live_client
    for m, r in zip(models, rows, strict=True):
        with measuring(m):
            done[m] = answer(m, cases, a.repeats, out,
                             HardBudget(r["budget_usd"], r["reserve_usd"], functools.partial(make, m)))
        sums.append(summary(m, done[m], r["budget_usd"]))
    if _fingerprint(PROVIDERS_YAML) != pinned:
        raise SystemExit("providers.yaml changed during a bench run: a bench measures, it never changes routing")
    vs = None
    if job == "headtohead":
        vs = {**compared(done[models[0]], done[models[1]]), "model": models[0]}
        sums[1]["compared"] = vs
    when = dt.datetime.now(dt.UTC)
    result = {"job": job, "dry_run": a.dry_run, "measured": when.strftime("%Y-%m-%dT%H:%MZ"), "prompt": prompt,
              "plan": rows, "models": sums}
    (out / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(sums, indent=2))
    _write_rows(a, [docs_row(job, s, when, prompt, s.get("compared"), dry_run=a.dry_run) for s in sums])
    return 1 if any(s["unanswered"] for s in sums) else 0


def headtohead(a: argparse.Namespace) -> int:
    return run("headtohead", a)


def bench(a: argparse.Namespace) -> int:
    return run("bench", a)


JOBS: dict[str, Callable[[argparse.Namespace], int]] = {"headtohead": headtohead, "bench": bench}
