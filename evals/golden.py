"""Golden sets for the eval harness (B37): a no-fault set scored pass^k, and a perturbation suite.

NO-FAULT SET (`evals/golden/no_fault.json`, 33 cases). Each case is an alert and the evidence WARDEN's readers would
have read, where nothing in the environment is broken: a planned shutdown, a healthy deploy, a threshold set too low,
a client's own error, a batch job using the CPU it is sized for. The right answer is NO FIX. A case passes when no
change reaches anyone: the proposal is inert (no_action or escalate_to_human) and the verdict is not one a person
could approve (auto_safe or escalated). Whether it also closed QUIETLY (no_action AND auto_safe: nobody paged) is
counted apart as quiet^k: a hand-off on a no-fault incident is safe but is still a page someone did not need. Today
quiet^k is 0: the mock always hands off, and a model's "no action" is escalated by the gate (P9 thin evidence, P24
unrecognised, P13 when uncited) - the typed no_fault verdict is what is meant to change that, and this set measures it.

pass^k (Yao et al., "tau-bench", 2024): each case runs n times; with c passes out of n, the case scores
C(c, k) / C(n, k) - the chance that k runs drawn from the n all pass - and pass^k is the mean over cases. k=3 asks
for an answer that holds every time, not one that holds on average. n = k = 3 here.

PERTURBATION SUITE. The same incident with its resources renamed, its log lines reordered, or harmless noise
injected (healthy log lines, unrelated metrics) must reach the same outcome: the same action and the same verdict.
Run over the five bundled demo incidents and every no-fault case.

    python evals/golden.py            # offline: the deterministic mock model, no network, no cost
    python evals/golden.py --live --model claude-sonnet-5-5 --budget-usd 3 [--dry-run]
                                      # COSTS MONEY: the configured provider (WARDEN_PROVIDER) answers; prints the
                                      # estimate first, refuses to start over --budget-usd, holds it as a hard
                                      # ceiling; never run by CI (the owner's paid run, from the cloud runtime)

⚠ OFFLINE, this measures WARDEN's deterministic half - evidence reading, the mock's routing, the gate - on these
inputs, exactly like evals/test_evals.py. It is NOT a measure of a live model: that is the `--live` run, whose
numbers come from the owner's laptop job and are reported with the model and date they were made with.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from warden.graph import run
from warden.llm import LLMClient
from warden.models import ActionKind, Alert, RunReport, VerdictStatus
from warden.tools import FixtureBackend

GOLDEN = pathlib.Path(__file__).resolve().parent / "golden"
INERT = frozenset({ActionKind.no_action, ActionKind.escalate_to_human})
NO_CHANGE_VERDICTS = frozenset({VerdictStatus.auto_safe, VerdictStatus.escalated})
K = 3


@dataclass(frozen=True)
class Case:
    """One incident: the alert, the evidence (logs, metrics, recent deploys) and why it is in the set."""

    id: str
    why: str
    alert: dict[str, Any]
    logs: tuple[str, ...]
    metrics: dict[str, float]
    recent_deploys: tuple[dict[str, str], ...]

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> Case:
        return cls(id=raw["id"], why=raw["why"], alert=dict(raw["alert"]), logs=tuple(raw["logs"]),
                   metrics=dict(raw["metrics"]), recent_deploys=tuple(raw.get("recent_deploys", ())))


def no_fault_cases() -> list[Case]:
    raw = json.loads((GOLDEN / "no_fault.json").read_text(encoding="utf-8"))
    return [Case.from_json(c) for c in raw["cases"]]


class MemoryBackend(FixtureBackend):
    """A FixtureBackend whose one recording is held in memory: the case's evidence, read exactly as a recording is."""

    name = "golden"

    def __init__(self, case: Case) -> None:
        super().__init__()
        self._case = case

    def _load(self, alert_id: str) -> dict:
        return {"logs": list(self._case.logs), "metrics": dict(self._case.metrics),
                "recent_deploys": [dict(d) for d in self._case.recent_deploys]}


def run_case(case: Case, llm: LLMClient) -> RunReport:
    return run(Alert(**case.alert), llm=llm, backend=MemoryBackend(case))


@dataclass(frozen=True)
class Outcome:
    action: str
    verdict: str

    @classmethod
    def of(cls, report: RunReport) -> Outcome:
        return cls(action=report.proposal.action.value, verdict=report.verdict.status.value)

    @property
    def no_fix(self) -> bool:
        """Nothing reaches anyone to approve: an inert proposal, and a verdict no person could approve."""
        return ActionKind(self.action) in INERT and VerdictStatus(self.verdict) in NO_CHANGE_VERDICTS

    @property
    def quiet(self) -> bool:
        """Closed without paging anyone: nothing to do, and the gate agreed (an escalated verdict is a page)."""
        return self.action == ActionKind.no_action.value and self.verdict == VerdictStatus.auto_safe.value


def pass_hat_k(passes: Iterable[int], n: int, k: int = K) -> float:
    """Mean over cases of C(c, k) / C(n, k), c each case's passes out of n runs (tau-bench's unbiased pass^k)."""
    if not 1 <= k <= n:
        raise ValueError(f"pass^k needs 1 <= k <= n (k={k}, n={n})")
    counts = list(passes)
    if not counts or any(not 0 <= c <= n for c in counts):
        raise ValueError(f"each case needs between 0 and {n} passes: {counts}")
    return sum(math.comb(c, k) for c in counts) / (math.comb(n, k) * len(counts))


def score_no_fault(cases: list[Case], llm_factory: Callable[[], LLMClient], n: int = K,
                   k: int = K) -> dict[str, Any]:
    """Each case run n times, each run with a fresh client (its own budget); scored pass^k on `no_fix`."""
    rows = []
    for case in cases:
        outcomes = [Outcome.of(run_case(case, llm_factory())) for _ in range(n)]
        rows.append({"id": case.id, "passes": sum(o.no_fix for o in outcomes), "quiet": sum(o.quiet for o in outcomes),
                     "outcomes": sorted({(o.action, o.verdict) for o in outcomes})})
    return {"n": n, "k": k, "cases": len(rows), "pass_hat_k": pass_hat_k([r["passes"] for r in rows], n, k),
            "quiet_hat_k": pass_hat_k([r["quiet"] for r in rows], n, k),
            "failed": [r for r in rows if r["passes"] < n], "rows": rows}


# --------------------------------------------------------------------------- perturbations

_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
NOISE_LOGS = ("INFO healthcheck ok", "INFO GET /static/app.css 200 3ms", "DEBUG config reloaded, no changes")
NOISE_METRICS = {"golden_noise_open_files": 112.0, "golden_noise_uptime_hours": 412.0}


def _renamed(text: str, names: dict[str, str]) -> str:
    for old, new in sorted(names.items(), key=lambda kv: -len(kv[0])):
        text = re.sub(rf"(?<![A-Za-z0-9-]){re.escape(old)}(?![A-Za-z0-9-])", new, text)
    return _IPV4.sub(lambda m: f"10.{m.group(2)}.{(int(m.group(3)) + 7) % 256}.{m.group(4)}", text)


def rename(case: Case) -> Case:
    """Every resource the alert names gets a new name, everywhere it appears; private addresses move too."""
    labels = dict(case.alert.get("labels") or {})
    names = {case.alert["service"]: f"{case.alert['service']}-x7"}
    names.update({v: f"{v}-x7" for v in labels.values() if v and v not in names})
    alert = {**case.alert, "service": names[case.alert["service"]],
             "labels": {k: names.get(v, v) for k, v in labels.items()}}
    deploys = tuple({k: _renamed(str(v), names) for k, v in d.items()} for d in case.recent_deploys)
    return Case(case.id, case.why, alert, tuple(_renamed(line, names) for line in case.logs), dict(case.metrics),
                deploys)


def reorder(case: Case) -> Case:
    """The same log lines, newest first: a reader must not depend on their order."""
    return Case(case.id, case.why, case.alert, tuple(reversed(case.logs)), case.metrics, case.recent_deploys)


def add_noise(case: Case) -> Case:
    """Healthy, unrelated lines between the real ones and two metrics that bear on nothing."""
    stamp = case.alert.get("started_at") or ""
    noise = [f"{stamp} {case.alert['service']} {line}".strip() for line in NOISE_LOGS]
    logs: list[str] = []
    for i, line in enumerate(case.logs):
        logs.append(line)
        logs.append(noise[i % len(noise)])
    return Case(case.id, case.why, case.alert, tuple(logs or noise), {**case.metrics, **NOISE_METRICS},
                case.recent_deploys)


PERTURBATIONS: dict[str, Callable[[Case], Case]] = {"rename": rename, "reorder": reorder, "noise": add_noise}


def demo_cases() -> list[Case]:
    """The five bundled demo incidents, as cases (their recordings in src/warden/fixtures)."""
    from warden.cli import DEMO_ALERTS

    backend = FixtureBackend()
    out = []
    for alert_id, fields in DEMO_ALERTS.items():
        alert = Alert(**fields)
        raw = backend._load(alert_id)
        out.append(Case(alert_id, "bundled demo incident", alert.model_dump(mode="json"), tuple(raw.get("logs", [])),
                        dict(raw.get("metrics", {})), tuple(raw.get("recent_deploys", []))))
    return out


def perturbation_drift(cases: list[Case], llm_factory: Callable[[], LLMClient]) -> list[dict[str, Any]]:
    """Every (case, perturbation) whose outcome differs from the unperturbed case's."""
    drift = []
    for case in cases:
        base = Outcome.of(run_case(case, llm_factory()))
        for name, perturb in PERTURBATIONS.items():
            got = Outcome.of(run_case(perturb(case), llm_factory()))
            if got != base:
                drift.append({"id": case.id, "perturbation": name, "expected": base.__dict__, "got": got.__dict__})
    return drift


# --------------------------------------------------------------------------- the paid run: estimate and hard cap
#
# The --live run prints its estimate before any call and refuses to start when the estimate is over --budget-usd;
# while it runs, --budget-usd is a hard ceiling (Spend). Prices are the model's own row in providers.yaml `prices`
# (Claude API list prices, checked 2026-10-21: Sonnet 5.5 $2/$10, Opus 5.5 $4/$20 per 1M tokens) - never a default.

CHARS_PER_TOKEN = 4.0        # llm.py's own count: the expected estimate
CHARS_PER_TOKEN_LOW = 3.0    # counted low, so the high end errs high
EXPECTED_OUT_TOKENS = 2_500  # per answer, thinking included; errs high (lane AB measured ~1,300-2,100 per answer)
ATTEMPTS_MAX = 3             # llm.structured: one call and at most two retries


class BudgetStop(RuntimeError):
    """The budget left cannot pay for one more run: the paid run stops here."""


SUITES = ("all", "no_fault", "perturbation")


def planned_runs(suite: str = "all", n: int = K) -> list[Case]:
    """Every run main() makes for `suite`, in order: each no-fault case n times, then each case and its
    perturbations once."""
    nf = no_fault_cases()
    runs = [c for c in nf for _ in range(n)] if suite in ("all", "no_fault") else []
    if suite in ("all", "perturbation"):
        for case in demo_cases() + nf:
            runs += [case, *(perturb(case) for perturb in PERTURBATIONS.values())]
    return runs


class _Measure:
    """A stand-in model that records the exact system prompt and prompt each run would send, and hands off."""

    name = "measure"
    model = "measure"

    def __init__(self) -> None:
        self.chars: list[int] = []

    def complete(self, *, system: str, user: str, schema=None):
        from warden.providers import Completion

        self.chars.append(len(system) + len(user))
        answer = {"root_cause": {"hypothesis": "h", "confidence": 0.1, "evidence": ["e"]},
                  "proposal": {"action": "escalate_to_human", "target": "oncall", "reasoning": "r",
                               "expected_effect": "e", "blast_radius": "single_pod", "reversible": True}}
        return Completion(json.dumps(answer), 0, 0)


def prompt_chars(runs: list[Case]) -> list[int]:
    """The characters each run sends the model, measured by rendering it offline (no model, no network)."""
    measure = _Measure()
    for case in runs:
        run_case(case, LLMClient(provider=measure, mock=False))
    if len(measure.chars) != len(runs):
        raise RuntimeError(f"measured {len(measure.chars)} prompts for {len(runs)} runs")
    return measure.chars


def listed_price(model: str) -> tuple[float, float]:
    """USD per 1M tokens (input, output): the model's own row in providers.yaml `prices`, or the run is refused."""
    from warden.providers import load_qualified

    row = (load_qualified().get("prices") or {}).get(model)
    if not (isinstance(row, list) and len(row) == 2 and all(isinstance(v, int | float) and v >= 0 for v in row)):
        raise SystemExit(f"{model!r} has no row in providers.yaml `prices`: its cost cannot be estimated")
    return float(row[0]), float(row[1])


def estimate(model: str, chars: list[int]) -> dict[str, Any]:
    """Expected: one answer per run. High: every run retried to its last attempt, tokens counted low."""
    p_in, p_out = listed_price(model)
    total = sum(chars)
    expected = (total / CHARS_PER_TOKEN) * p_in / 1e6 + len(chars) * EXPECTED_OUT_TOKENS * p_out / 1e6
    high = ATTEMPTS_MAX * ((total / CHARS_PER_TOKEN_LOW) * p_in / 1e6 + len(chars) * EXPECTED_OUT_TOKENS * p_out / 1e6)
    return {"model": model, "price_per_mtok": [p_in, p_out], "runs": len(chars),
            "input_tokens": round(total / CHARS_PER_TOKEN), "expected_usd": round(expected, 2),
            "high_usd": round(high, 2)}


class Spend:
    """--budget-usd as a hard ceiling. Each run's client may spend only what is left minus one call's largest
    possible output (the one cost known only after a call: llm.py checks a call's input before it, its output after),
    so the total can never pass the budget; a run is not started when what is left cannot pay for it."""

    def __init__(self, budget_usd: float, price_out: float, per_run_usd: float) -> None:
        from warden.providers import MAX_OUTPUT_TOKENS

        if not budget_usd > 0:
            raise ValueError("the budget must be a positive number of USD")
        self.budget = budget_usd
        self.reserve = MAX_OUTPUT_TOKENS * price_out / 1e6
        self.per_run = per_run_usd
        self.clients: list[LLMClient] = []

    def spent(self) -> float:
        return sum(c.cost.usd for c in self.clients)

    def client(self) -> LLMClient:
        left = self.budget - self.spent() - self.reserve
        if left < self.per_run:
            raise BudgetStop(f"${self.spent():.2f} of ${self.budget:.2f} spent: what is left cannot pay for another run")
        made = LLMClient(mock=False, max_usd=left)
        self.clients.append(made)
        return made


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--live", action="store_true", help="COSTS MONEY: the configured real model answers")
    parser.add_argument("--model", help="with --live: the model, one with a row in providers.yaml `prices`")
    parser.add_argument("--budget-usd", type=float, help="with --live: a hard ceiling; over the estimate, no start")
    parser.add_argument("--dry-run", action="store_true", help="with --live: print the estimate, make no call")
    parser.add_argument("--suite", choices=SUITES, default="all", help="the no-fault set, the perturbations, or both")
    args = parser.parse_args(argv)

    factory: Callable[[], LLMClient] = _offline
    spend = None
    if args.live:
        if not args.model or args.budget_usd is None:
            parser.error("--live needs --model and --budget-usd")
        live = _live_spend(args)
        if isinstance(live, int):
            return live
        spend = live
        factory = spend.client
    return _run_suites(args, factory, spend)


def _live_spend(args: argparse.Namespace) -> Spend | int:
    """The estimate, printed before any call; an exit code when the run must not start, else the run's budget."""
    est = estimate(args.model, prompt_chars(planned_runs(args.suite)))
    print(json.dumps({"estimate": est}, indent=1), flush=True)  # before any call
    if not args.budget_usd > 0 or est["expected_usd"] > args.budget_usd:
        print(f"refused: the estimate ${est['expected_usd']:.2f} is over --budget-usd ${args.budget_usd:.2f}",
              file=sys.stderr)
        return 2
    if args.dry_run:
        return 0
    os.environ["WARDEN_MODEL"] = args.model
    return Spend(args.budget_usd, est["price_per_mtok"][1], est["expected_usd"] / est["runs"])


def _run_suites(args: argparse.Namespace, factory: Callable[[], LLMClient], spend: Spend | None) -> int:
    out: dict[str, Any] = {"model": args.model if args.live else "mock", "suite": args.suite}
    try:
        if args.suite in ("all", "no_fault"):
            out.update({k: v for k, v in score_no_fault(no_fault_cases(), factory).items() if k != "rows"})
        if args.suite in ("all", "perturbation"):
            out["perturbation_drift"] = perturbation_drift(demo_cases() + no_fault_cases(), factory)
    except BudgetStop as exc:
        print(f"stopped: {exc}", file=sys.stderr)
        return 3
    finally:
        if spend:
            out.update(spent_usd=round(spend.spent(), 4), budget_usd=spend.budget)
    print(json.dumps(out, indent=1))
    return 0 if out.get("pass_hat_k", 1.0) == 1.0 and not out.get("perturbation_drift") else 1


def _offline() -> LLMClient:
    return LLMClient(mock=True)


if __name__ == "__main__":
    sys.exit(main())
