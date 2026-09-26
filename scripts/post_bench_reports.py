"""Post a benchmark run's reports to ChatOps - the same report WARDEN would have sent, one per scenario.

    python scripts/post_bench_reports.py --run ~/warden-bench-runs/wave2-...          # print only
    WARDEN_CHATOPS_LIVE=1 WARDEN_SLACK_WEBHOOK=... python scripts/post_bench_reports.py --run ...

The benchmark runs WARDEN with `--json` and no ChatOps, on purpose: a Slack post is not part of what
is measured. This re-renders each recorded run through the real `build_report` + `notify` path, so
the post is exactly what an operator would have received for that incident.

⚠ WHAT IS AND IS NOT RE-DONE. The model output, the evidence and the gate's verdict are read from the
run's own report file - nothing is re-asked of the model. Only the rendering is current code, so a
report posted today carries today's evidence sections. Each post says which scenario was injected and
how the run was graded, which WARDEN itself did not know when it produced the report.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from warden.chatops import notify, resolve_sinks
from warden.models import RunReport
from warden.redaction import redact
from warden.reporting import build_report

_BACKEND = {"k8s": "k8s", "db": "postgres", "ecs": "aws", "fullstack": "stack"}  # WARDEN_BACKEND each wave ran with


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True, type=pathlib.Path)
    ap.add_argument("--repeat", type=int, default=1, help="which repeat to post per scenario (default 1)")
    ap.add_argument("--print", dest="show", action="store_true", help="print the first report, send nothing")
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    run = args.run.expanduser()
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    results = json.loads((run / "results.json").read_text(encoding="utf-8"))
    rows = {(r["scenario_id"], r["index"]): r for r in results["rows"]}
    backend = _BACKEND.get(manifest.get("target_kind", "ecs"))
    s = results["summary"]

    reports = []
    for sid in manifest["scenario_ids"]:
        path = run / "reports" / f"{sid}.{args.repeat}.json"
        if not path.exists():
            print(f"skip {sid}: no report for repeat {args.repeat}")
            continue
        rec = RunReport.model_validate(json.loads(path.read_text(encoding="utf-8")))
        built = build_report(rec.alert, root_cause=rec.root_cause, proposal=rec.proposal,
                             verdict=rec.verdict, context=rec.context, backend=backend)
        row = rows.get((sid, args.repeat), {})
        header = (f"**Benchmark scenario `{sid}`** - injected fault: `{row.get('fault_class', '?')}` | "
                  f"graded **{row.get('diagnosis', '?')}**, gate **{row.get('gate', '?')}** "
                  f"(WARDEN did not know the injected fault when it wrote this)\n\n")
        reports.append((sid, dataclasses.replace(built, markdown=header + built.markdown)))

    if args.show:
        print(reports[0][1].markdown if reports else "no reports")
        return 0

    intro = (f"# WARDEN benchmark - {run.name}\n"
             f"{s['runs']} runs over {s['scenarios']} scenarios on "
             f"{manifest.get('target_kind', '?')}. Diagnosis: {s['diagnosis_counts']}. "
             f"**Wrong diagnosis and gate allowed: {s['headline_wrong_and_allowed']}.**\n"
             f"Below: repeat {args.repeat} of each scenario, re-rendered from the recorded run - the "
             f"model output and the gate's verdict are exactly what the run recorded.")
    failed = 0
    for sink in resolve_sinks():
        note = sink.send(redact(intro).text, {})
        print(f"intro -> {sink.name}: {'sent' if note.delivered else 'NOT sent'} ({note.detail})")
        failed += not note.delivered
    for sid, report in reports:
        for note in notify(report):
            print(f"{sid} -> {note.sink}: {'sent' if note.delivered else 'NOT sent'} ({note.detail})")
            failed += not note.delivered
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
