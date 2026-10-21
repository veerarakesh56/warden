"""Re-diagnose a published run's recorded evidence with today's pipeline, then score it the same way.

    python warden/scripts/replay_diagnose.py --run warden/tests/fixtures/bench/wave1-2026-09-11T155744Z \\
        --out ~/warden-bench-runs/replay/wave1-baseline
    python -m scenarios.score --run ~/warden-bench-runs/replay/wave1-baseline \\
        --rubric ~/warden-bench-runs/replay/wave1-baseline/grading/scoring.yaml

⚠ A REPLAY IS NOT A MEASUREMENT of the live system. The evidence is what WARDEN read then; the model
answers now, through today's redact -> diagnose -> verify. It answers one question: on the SAME
evidence, did a pipeline change (grounding, one call, quarantine) change what gets decided? Two
replays of one run differ only by the pipeline and the model's own variance, so compare arms run
back to back, and never mix a replay's numbers with a live wave's.

The model is whatever WARDEN_PROVIDER selects (claude_cli on Claude Max: no per-call cost).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import shutil
import sys

from warden.graph import node_diagnose, node_redact, node_tripwire, node_verify
from warden.llm import LLMClient
from warden.models import Alert, ContextBundle, RunReport

ROOT = pathlib.Path(__file__).resolve().parents[2]


def rediagnose(report: dict, llm: LLMClient) -> RunReport:
    """redact -> tripwire -> diagnose -> verify over a recorded context, as production runs them (audit A-B-M16:
    the tripwire was skipped, so a replay could never show P16). gather is skipped: its output IS the recorded
    context, byte for byte, which re-reading through a backend would not guarantee."""
    state: dict = {"alert": Alert(**report["alert"]), "context": ContextBundle(**report["context"]),
                   "llm": llm, "audit": []}
    for node in (node_redact, node_tripwire, node_diagnose, node_verify):
        out = node(state)
        state["audit"] = state["audit"] + out.pop("audit", [])
        state.update(out)
    return RunReport(alert=state["alert"], redaction_map_size=len(state["redaction_map"]),
                     context=state["context"], root_cause=state["root_cause"],
                     proposal=state["proposal"], verdict=state["verdict"], cost=llm.cost,
                     audit=state["audit"])


UNAVAILABLE = "P0-MODEL-UNAVAILABLE"  # the gate's rules-only answer: the model was never heard


def _answered(path: pathlib.Path) -> bool:
    if not path.exists():
        return False
    report = json.loads(path.read_text(encoding="utf-8"))
    return UNAVAILABLE not in ((report.get("verdict") or {}).get("policy_ids") or [])


def replay(src: pathlib.Path, out: pathlib.Path, *, per_scenario: int, only: set[str] | None,
           llm_factory=LLMClient, log=print, resume: bool = False, quota: dict | None = None) -> None:
    """Re-diagnose every recorded run of `src` into `out`. With `resume` an existing `out` is kept: a run the model
    already answered is not asked again, and only the unanswered ones are (a free tier's quota, spread over days).
    `quota` ({"stop_after": n}) stops asking after n refusals in a row - the day's quota is gone - and leaves the rest
    unanswered for the next resume; it is shared across the runs of one qualification."""
    if not (resume and out.exists()):
        _start(src, out)
    quota = quota if quota is not None else {}
    for gt_path in sorted((src / "ground-truth").glob("*.json")):
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        if only and gt["scenario_id"] not in only:
            continue
        kept = _kept(out / "ground-truth" / gt_path.name) if resume else {}
        runs = _replay_runs(src, out, gt, kept, per_scenario, quota, llm_factory, log)
        (out / "ground-truth" / gt_path.name).write_text(json.dumps({**gt, "runs": runs}, indent=2),
                                                         encoding="utf-8")


def _replay_runs(src: pathlib.Path, out: pathlib.Path, gt: dict, kept: dict, per_scenario: int, quota: dict,
                 llm_factory, log) -> list[dict]:
    """The rows of one scenario's first `per_scenario` recorded runs: kept as they are, or asked again."""
    rows = []
    for run in (gt.get("runs") or [])[:per_scenario]:
        row = _row_without_asking(out, gt["scenario_id"], run, kept.get(run.get("index")), quota, log)
        rows.append(row if row is not None else _ask(src, out, gt["scenario_id"], run, quota, llm_factory, log))
    return rows


def _start(src: pathlib.Path, out: pathlib.Path) -> None:
    """A new replay directory: the run's grading, its manifest marked as a replay, empty ground-truth and reports."""
    out.mkdir(parents=True)
    shutil.copytree(src / "grading", out / "grading")
    manifest = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    manifest["replay"] = {"of": src.name, "at": dt.datetime.now(dt.UTC).isoformat(),
                          "note": "a replay, not a measurement: recorded evidence, today's pipeline"}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (out / "ground-truth").mkdir()
    (out / "reports").mkdir()


def _kept(before: pathlib.Path) -> dict:
    """{run index: row} from an earlier replay's ground truth for this scenario ({} when there is none)."""
    if not before.exists():
        return {}
    return {r.get("index"): r for r in json.loads(before.read_text(encoding="utf-8")).get("runs") or []}


def _row_without_asking(out: pathlib.Path, scenario: str, run: dict, prior: dict | None, quota: dict,
                        log) -> dict | None:
    """The row for a run the model is not asked about - failed in the recorded wave, answered on an earlier day, or
    past the quota - or None when it must be asked."""
    if not run.get("report_written"):
        # A run that failed in the recorded wave stays an ERROR row (audit A-B-M16): dropping it changed the
        # denominators, and a replay looked steadier than the run it replays.
        log(f"{scenario}.{run.get('index')}: ERROR in the recorded run, kept")
        return run
    if prior and prior.get("report_written") and _answered(out / run["report"]):
        return prior  # answered on an earlier day: kept, not asked again
    if quota.get("refused", 0) >= quota.get("stop_after", 10**9):
        return prior or {**run, "exit_code": 1, "report_written": False,
                         "stderr_tail": "not asked: the model's quota refused the calls before it"}
    return None


def _ask(src: pathlib.Path, out: pathlib.Path, scenario: str, run: dict, quota: dict, llm_factory, log) -> dict:
    """Re-diagnose one recorded run, write its report and count a refusal toward the quota; the run's row."""
    report = json.loads((src / run["report"]).read_text(encoding="utf-8"))
    try:
        new = rediagnose(report, llm_factory())
        quota["refused"] = quota.get("refused", 0) + 1 if UNAVAILABLE in new.verdict.policy_ids else 0
        (out / run["report"]).write_text(new.model_dump_json(indent=2), encoding="utf-8")
        log(f"{scenario}.{run['index']}: {new.proposal.action.value} "
            f"{new.verdict.status.value} {new.verdict.policy_ids} calls={new.cost.calls}")
        return {**run, "exit_code": 0, "report_written": True, "stderr_tail": ""}
    except Exception as exc:  # noqa: BLE001  # a failed replay is an ERROR row; never skipped
        log(f"{scenario}.{run['index']}: ERROR {exc}")
        return {**run, "exit_code": 1, "report_written": False, "stderr_tail": str(exc)[:500]}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run", required=True, type=pathlib.Path, help="a published run directory")
    p.add_argument("--out", required=True, type=pathlib.Path, help="a NEW directory outside the repository's docs folders and warden/tests/fixtures/")
    p.add_argument("--runs-per-scenario", type=int, default=1)
    p.add_argument("--only", nargs="*", help="scenario ids to replay (default: all)")
    a = p.parse_args(argv)
    out = a.out.expanduser().resolve()
    if any((ROOT / d).resolve() in out.parents for d in ("docs", "warden/docs", "infra/docs", "demo-app/docs",
                                                         "fault-lab/docs", "warden/tests/fixtures")):
        print("refusing to write a replay inside a docs folder or warden/tests/fixtures/: it would sit beside published "
              "measurements")
        return 2
    replay(a.run, out, per_scenario=a.runs_per_scenario, only=set(a.only) if a.only else None)
    print(f"\nscore: python -m scenarios.score --run {out} --rubric {out / 'grading' / 'scoring.yaml'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
