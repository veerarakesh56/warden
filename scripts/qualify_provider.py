"""Qualify a provider and model on WARDEN's replay set before it may diagnose (register M20).

    WARDEN_PROVIDER=claude_cli WARDEN_MODEL=claude-sonnet-5-5 \\
        python scripts/qualify_provider.py --out ~/warden-bench-runs/qualify/sonnet-5-5

The recorded evidence of the three published runs (ECS, EKS, databases: 30 incidents) is re-diagnosed through
today's pipeline by the configured model, and each run is scored against its own committed rubric. It passes the bar
in src/warden/data/providers.yaml or it does not; on a pass it prints the entry to add there. Only this script may
run an unqualified model: it sets WARDEN_QUALIFYING for its own process. `--score-only` re-scores a finished run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNS = ("wave1-2026-09-11T155744Z", "wave2-2026-09-24T115746Z", "wave3-2026-09-25T044307Z")


def tally(out: pathlib.Path) -> dict[str, int]:
    """Correct diagnoses, and wrong ones the gate allowed, over the replayed runs under `out`."""
    sys.path.insert(0, str(ROOT))
    from scenarios.score import score_run_dir, summarise

    from warden.verifier import AUTO_SAFE_ACTIONS

    inert = {a.value for a in AUTO_SAFE_ACTIONS}
    counts = {"correct": 0, "runs": 0, "wrong_and_allowed": 0, "no_evidence_fixes_allowed": 0, "errors": 0}
    for name in RUNS:
        run_out = out / name
        scored = score_run_dir(run_out, rubric_path=run_out / "grading" / "scoring.yaml")
        summary = summarise(scored)
        counts["correct"] += int(summary["diagnosis_counts"].get("CORRECT", 0))
        counts["runs"] += int(summary["runs"])
        counts["wrong_and_allowed"] += int(summary["headline_wrong_and_allowed"])
        # Reported beside the bar, not in it: a NO-EVIDENCE row is one whose RECORDING could not prove the fault, so a
        # model giving the rubric's correct fix there would fail a bar that counted it (k8s-05 on 2026-10-02: the
        # rollback both Phase 1 arms also proposed). A person reads this count with the result (audit A-B-M11).
        counts["no_evidence_fixes_allowed"] += sum(
            1 for r in scored["rows"]
            if r["diagnosis"] == "NO-EVIDENCE" and r["gate"] == "allowed" and r["action"] not in inert)
        counts["errors"] += int(summary["errors"])
        counts["escalated"] = counts.get("escalated", 0) + int(summary["escalated"])
        for k, v in summary["act_abstain"].items():
            counts[k] = counts.get(k, 0) + int(v)
    return counts


def slo_breaches(result: dict, slo: dict) -> list[str]:
    """The escalation SLO (register N6), reported beside the bar, never in it: a model that escalates more than the
    measured production model, or acts wrongly at all, is named - a person decides what that means."""
    out = []
    if result.get("escalated", 0) > slo["max_escalated"]:
        out.append(f"escalated {result['escalated']} of {result['runs']}, above the SLO's {slo['max_escalated']}")
    if result.get("acted_wrongly", 0) > slo["acted_wrongly"]:
        out.append(f"acted wrongly {result['acted_wrongly']} time(s); the SLO is {slo['acted_wrongly']}")
    return out


def prompt_fingerprint() -> str:
    """The prompt as a model sees it - system text, answer schema and the rendered evidence of every bundled incident
    - as one hash (register E6). Rendered offline by a capturing provider: no model is called."""
    import hashlib
    import re

    from warden.cli import DEMO_ALERTS
    from warden.graph import run
    from warden.llm import LLMClient
    from warden.models import Alert
    from warden.providers import Completion

    seen: list[list[str]] = []

    class _Capture:
        name, model = "capture", "capture"

        def complete(self, *, system, user, schema=None):
            # The data marker is random per call on purpose (spotlighting: injected text cannot forge the boundary);
            # it is not part of what the prompt says, so it is replaced by a fixed one before hashing.
            user = re.sub(r"<<(END )?DATA [0-9a-f]+>>", r"<<\1DATA nonce>>", user)
            seen.append([system, user, json.dumps(schema.model_json_schema() if schema else None, sort_keys=True)])
            body = {"root_cause": {"hypothesis": "x", "confidence": 0.5, "evidence": []},
                    "proposal": {"action": "escalate_to_human", "target": "x", "reasoning": "x",
                                 "expected_effect": "x", "blast_radius": "single_service", "reversible": True}}
            return Completion(json.dumps(body), 1, 1)

    for incident in sorted(DEMO_ALERTS):
        run(Alert(**DEMO_ALERTS[incident]), llm=LLMClient(provider=_Capture(), mock=False))
    return hashlib.sha256(json.dumps(seen, sort_keys=True).encode()).hexdigest()


def mcnemar(before: dict[str, bool], after: dict[str, bool]) -> dict:
    """Exact McNemar test on the incidents both runs graded: did the change fix more than it broke, or is the
    difference within chance? (register E6) Two-sided binomial p over the discordant pairs."""
    from math import comb

    shared = sorted(set(before) & set(after))
    fixed = sum(1 for k in shared if after[k] and not before[k])
    broke = sum(1 for k in shared if before[k] and not after[k])
    n = fixed + broke
    tail = sum(comb(n, i) for i in range(min(fixed, broke) + 1)) / 2 ** n if n else 1.0
    return {"incidents": len(shared), "fixed": fixed, "broke": broke, "p": min(1.0, 2 * tail)}


class Budget:
    """A hard ceiling on what one qualification run may spend, in USD, across every incident it replays. Each
    incident's client gets what is left (never more than its own per-incident ceiling); once it is gone, the next
    incident is an ERROR row - counted, never silently skipped - and no further call is made."""

    def __init__(self, total_usd: float, factory=None) -> None:
        if not total_usd > 0:
            raise ValueError("the budget must be a positive number of USD")
        from warden.llm import LLMClient

        self.total, self.factory, self.clients = float(total_usd), factory or LLMClient, []

    def spent(self) -> float:
        return sum(c.cost.usd for c in self.clients)

    def __call__(self):
        from warden.llm import BudgetExceeded

        left = self.total - self.spent()
        if left <= 0:
            raise BudgetExceeded(f"the qualification budget of ${self.total:.2f} is spent")
        client = self.factory()
        client.max_usd = min(client.max_usd, left)
        self.clients.append(client)
        return client


def reverify(out: pathlib.Path) -> int:
    """Re-run today's verifier over every stored report under `out`; return how many verdicts changed."""
    from warden.models import Alert, ContextBundle, RemediationProposal, RootCause
    from warden.verifier import verify

    changed = 0
    for f in sorted(out.glob("*/reports/*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        if not d.get("proposal") or not d.get("root_cause"):
            continue
        v = verify(Alert(**d["alert"]), ContextBundle(**d["context"]), RootCause(**d["root_cause"]),
                   RemediationProposal(**d["proposal"]))
        if v.model_dump(mode="json") != d["verdict"]:
            changed += 1
            d["verdict"] = v.model_dump(mode="json")
            f.write_text(json.dumps(d, indent=2), encoding="utf-8")
    return changed


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", required=True, type=pathlib.Path, help="a NEW directory outside the repository")
    p.add_argument("--score-only", action="store_true", help="re-score a finished run; no model is called")
    p.add_argument("--reverify", action="store_true",
                   help="with --score-only: put each stored diagnosis through today's gate first (deterministic, no "
                        "model call), so a gate fix made after the run counts")
    p.add_argument("--budget-usd", type=float, default=None,
                   help="a hard ceiling on what this run may spend in total (paid providers; WARDEN_PRICE_IN/OUT must "
                        "be the model's real prices)")
    a = p.parse_args(argv)
    out = a.out.expanduser().resolve()
    if ROOT.resolve() in out.parents:
        print("refusing to write inside the repository")
        return 2
    os.environ["WARDEN_QUALIFYING"] = "1"
    sys.path.insert(0, str(ROOT / "scripts"))
    from replay_diagnose import replay

    from warden.providers import load_qualified

    if a.score_only:
        result = json.loads((out / "qualification.json").read_text(encoding="utf-8"))
        if a.reverify:
            result["reverified"] = reverify(out)
    else:
        from warden.llm import LLMClient

        probe = LLMClient()
        budget = Budget(a.budget_usd) if a.budget_usd is not None else None
        for name in RUNS:
            replay(ROOT / "docs" / "bench" / name, out / name, per_scenario=1, only=None,
                   **({"llm_factory": budget} if budget else {}))
        result = {"provider": probe.provider_name, "model": probe.model, "version": probe.provider_version,
                  "measured": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%MZ"), "prompt": prompt_fingerprint()}
        if budget:
            result.update(budget_usd=budget.total, spent_usd=round(budget.spent(), 4))
    result.update(tally(out))
    doc = load_qualified()
    bar = doc["bar"]
    if "slo" in doc:
        result["slo_breaches"] = slo_breaches(result, doc["slo"])
    result["passed"] = result["wrong_and_allowed"] <= bar["wrong_and_allowed"] and result["correct"] >= bar["min_correct"]
    (out / "qualification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if result["passed"]:
        print("\nadd to src/warden/data/providers.yaml under `qualified:`")
        print(f"  - {json.dumps({k: v for k, v in result.items() if k not in ("passed", "slo_breaches")})}")
        return 0
    print("\nNOT QUALIFIED: the bar is wrong_and_allowed <= "
          f"{bar['wrong_and_allowed']} and correct >= {bar['min_correct']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
