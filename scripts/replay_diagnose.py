"""Re-diagnose a published run's recorded evidence with today's pipeline, then score it the same way.

    python scripts/replay_diagnose.py --run docs/bench/wave1-2026-09-11T155744Z \\
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

ROOT = pathlib.Path(__file__).resolve().parents[1]


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


def replay(src: pathlib.Path, out: pathlib.Path, *, per_scenario: int, only: set[str] | None,
           llm_factory=LLMClient, log=print) -> None:
    out.mkdir(parents=True)
    shutil.copytree(src / "grading", out / "grading")
    manifest = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    manifest["replay"] = {"of": src.name, "at": dt.datetime.now(dt.UTC).isoformat(),
                          "note": "a replay, not a measurement: recorded evidence, today's pipeline"}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (out / "ground-truth").mkdir()
    (out / "reports").mkdir()
    for gt_path in sorted((src / "ground-truth").glob("*.json")):
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        if only and gt["scenario_id"] not in only:
            continue
        runs = []
        for run in (gt.get("runs") or [])[:per_scenario]:
            if not run.get("report_written"):
                # A run that failed in the recorded wave stays an ERROR row (audit A-B-M16): dropping it changed the
                # denominators, and a replay looked steadier than the run it replays.
                runs.append(run)
                log(f"{gt['scenario_id']}.{run.get('index')}: ERROR in the recorded run, kept")
                continue
            report = json.loads((src / run["report"]).read_text(encoding="utf-8"))
            try:
                new = rediagnose(report, llm_factory())
                (out / run["report"]).write_text(new.model_dump_json(indent=2), encoding="utf-8")
                runs.append({**run, "exit_code": 0, "report_written": True, "stderr_tail": ""})
                log(f"{gt['scenario_id']}.{run['index']}: {new.proposal.action.value} "
                    f"{new.verdict.status.value} {new.verdict.policy_ids} calls={new.cost.calls}")
            except Exception as exc:  # noqa: BLE001 - a failed replay is an ERROR row, never skipped
                runs.append({**run, "exit_code": 1, "report_written": False, "stderr_tail": str(exc)[:500]})
                log(f"{gt['scenario_id']}.{run['index']}: ERROR {exc}")
        (out / "ground-truth" / gt_path.name).write_text(json.dumps({**gt, "runs": runs}, indent=2),
                                                         encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run", required=True, type=pathlib.Path, help="a published run directory")
    p.add_argument("--out", required=True, type=pathlib.Path, help="a NEW directory outside docs/bench")
    p.add_argument("--runs-per-scenario", type=int, default=1)
    p.add_argument("--only", nargs="*", help="scenario ids to replay (default: all)")
    a = p.parse_args(argv)
    out = a.out.expanduser().resolve()
    if (ROOT / "docs").resolve() in out.parents:
        print("refusing to write a replay inside docs/: it would sit beside published measurements")
        return 2
    replay(a.run, out, per_scenario=a.runs_per_scenario, only=set(a.only) if a.only else None)
    print(f"\nscore: python -m scenarios.score --run {out} --rubric {out / 'grading' / 'scoring.yaml'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
