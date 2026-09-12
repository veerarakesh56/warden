"""Replay published benchmark reports through the CURRENT gate.

    python scripts/replay_gate.py --reports docs/bench/wave1-2026-09-11T155744Z/reports

⛔ THIS IS NOT A MEASUREMENT, AND MUST NEVER BE PRESENTED AS ONE. It re-decides OLD evidence with
NEW policy. Every alert, context, hypothesis and proposal is read verbatim from artefacts that were
already published; nothing is re-run, no model is called, no AWS account is touched. It answers
exactly one question - "what would today's gate have done with what was already recorded" - and
says nothing about whether the model's diagnoses were any good. Re-scoring its output as though it
were a new wave would be the "grade after seeing the numbers" move this project refuses elsewhere.

⛔ IT CALLS THE REAL VERIFIER. `warden.verifier.verify` decides here, exactly as it does in
production. Re-implementing the policies to "simulate" them is how a replay quietly drifts from the
code it claims to describe - and a hand-rolled copy of the gate is the same mistake this change was
made to fix, in a new place.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from warden.models import (  # after the sys.path line above, deliberately
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
)
from warden.verifier import verify

BANNER = (
    "=" * 78,
    "REPLAY - NOT A MEASUREMENT.",
    "Old evidence, today's policy. Nothing was re-run and no model was called; every alert,",
    "context, hypothesis and proposal below was read verbatim from published artefacts.",
    "It cannot tell you whether a diagnosis was right - only what the gate would now do with it.",
    "=" * 78,
)


def _git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                             text=True, check=False)
        return (out.stdout or "").strip()[:12] or "unknown"
    except OSError:  # pragma: no cover - git absent
        return "unknown"


def replay_one(path: pathlib.Path) -> tuple[str, str, list[str]]:
    """Return (old verdict, new verdict, policies that fired now) for one published report."""
    d = json.loads(path.read_text(encoding="utf-8"))
    verdict = verify(
        Alert(**d["alert"]),
        ContextBundle(**d["context"]),
        RootCause(**d["root_cause"]),
        RemediationProposal(**d["proposal"]),
    )
    return d["verdict"]["status"], verdict.status.value, verdict.policy_ids


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reports", required=True, help="a published run's reports/ directory")
    parser.add_argument("--json", default=None, metavar="PATH",
                        help="also write the replay as JSON. Refused inside the run directory: a "
                             "file sitting next to results.json is how a replay gets mistaken for "
                             "a score")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    reports = pathlib.Path(args.reports)
    paths = sorted(reports.glob("*.json"))
    if not paths:
        print(f"no reports in {reports}")
        return 2

    run_dir = reports.parent
    if args.json:
        out_path = pathlib.Path(args.json).resolve()
        if run_dir.resolve() in out_path.parents:
            raise SystemExit(
                f"refusing to write {out_path} inside {run_dir}: a replay must not sit beside the "
                "run's own results, where a reader would take it for a measurement."
            )

    for line in BANNER:
        print(line)
    manifest = run_dir / "manifest.json"
    recorded = "unknown"
    if manifest.exists():
        recorded = str(json.loads(manifest.read_text(encoding="utf-8")).get("git_commit", ""))[:12]
    print(f"\nreports  : {reports}")
    print(f"measured at commit {recorded} · replayed by the gate at commit {_git_commit()}\n")

    rows, matrix, skipped = [], collections.Counter(), []
    for path in paths:
        try:
            old, new, policies = replay_one(path)
        except Exception as exc:  # noqa: BLE001 - a finding, never papered over
            # A report the current models cannot parse predates a schema change. Say so and move on;
            # guessing at the missing fields would invent evidence.
            skipped.append(f"{path.name}: {type(exc).__name__}: {str(exc)[:120]}")
            continue
        rows.append({"report": path.name, "old": old, "new": new, "policies": policies})
        matrix[(old, new)] += 1
        if old != new:
            print(f"  {path.name:46} {old:18} -> {new:18} {', '.join(policies) or '-'}")

    changed = sum(1 for r in rows if r["old"] != r["new"])
    print(f"\n{len(rows)} report(s) replayed, {changed} verdict(s) changed, {len(skipped)} skipped")
    print("\n| old verdict | new verdict | runs |\n|---|---|---|")
    for (old, new), count in sorted(matrix.items()):
        print(f"| {old} | {new} | {count} |")
    for line in skipped:
        print(f"  SKIPPED {line}")

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(
            {"replay_not_a_measurement": True, "reports": str(reports),
             "measured_at_commit": recorded, "replayed_at_commit": _git_commit(),
             "rows": rows, "skipped": skipped}, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 1 if skipped else 0


if __name__ == "__main__":
    raise SystemExit(main())
