"""Old against new on the same replay set: the model qualified now (or the last recorded row) beside a candidate, per
incident and in total, with the verdict against the bar (owner, 2026-10-21: rehearse every model upgrade on real
inputs before switching production; docs/OPERATIONS.md "Upgrading the model").

No model is called. Each side is what was recorded: a run directory written by scripts/qualify_provider.py --out
(per incident, scored again here by scenarios/score.py against each run's committed rubric), its qualification.json
(totals), or a providers.yaml row (totals only). Latency is printed where a report records it; replay reports today
record cost but no latency, and the comparison says so rather than inventing one.
"""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ESCALATE = "escalate_to_human"
NOT_GRADED = ("NO-EVIDENCE", "ERROR")
TOTALS = ("correct", "wrong_and_allowed", "unanswered", "escalated", "acted_wrongly", "spent_usd")


def runs() -> tuple[str, ...]:
    """The replay set's runs: one list, kept in the script that replays them."""
    sys.path.insert(0, str(ROOT / "scripts"))
    from qualify_provider import RUNS

    return RUNS


def _outcome(row: dict) -> str:
    if row["diagnosis"] == "CORRECT":
        return "right"
    return "not graded" if row["diagnosis"] in NOT_GRADED else "wrong"


def _report_field(run_out: pathlib.Path, row: dict, *path: str):
    report = run_out / "reports" / f"{row['scenario_id']}.{row['index']}.json"
    if not report.exists():
        return None
    value = json.loads(report.read_text(encoding="utf-8"))
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def incidents(out: pathlib.Path) -> dict[str, dict]:
    """Per incident of a run directory: right / wrong / not graded, whether it went to a person, cost and latency."""
    sys.path.insert(0, str(ROOT))
    from scenarios.score import score_run_dir

    found: dict[str, dict] = {}
    for name in runs():
        run_out = out / name
        if not (run_out / "grading" / "scoring.yaml").exists():
            continue
        for row in score_run_dir(run_out, rubric_path=run_out / "grading" / "scoring.yaml")["rows"]:
            found[f"{row['scenario_id']}.{row['index']}"] = {
                "outcome": _outcome(row),
                "escalated": row["gate"] == "refused" or row["action"] == ESCALATE,
                "usd": _report_field(run_out, row, "cost", "usd"),
                "latency_s": _report_field(run_out, row, "latency_s"),
            }
    return found


def side(label: str, totals: dict, run_dir: pathlib.Path | None = None) -> dict:
    """One side of the comparison: its name, its recorded totals and, from a run directory, its incidents."""
    return {"label": label, "totals": totals, "incidents": incidents(run_dir) if run_dir else None}


def _cell(i: dict | None) -> str:
    if i is None:
        return "-"
    return i["outcome"] + (", escalated" if i["escalated"] else "")


def _money(v) -> str:
    return "not recorded" if v is None else f"${float(v):.2f}"


def _latency(per: dict | None) -> str:
    seen = [
        i["latency_s"] for i in (per or {}).values() if isinstance(i.get("latency_s"), (int, float))
    ]
    return f"{sum(seen) / len(seen):.1f} s average" if seen else "not recorded"


def _moved(a: dict | None, b: dict | None) -> str:
    """What changed for one incident from old to new: fixed, broke, changed, or nothing."""
    if a is None or b is None or a["outcome"] == b["outcome"]:
        return ""
    if b["outcome"] == "right":
        return "fixed"
    return "broke" if a["outcome"] == "right" else "changed"


def _incident_lines(old: dict, new: dict) -> list[str]:
    o, n = old["incidents"], new["incidents"]
    if not (o or n):
        return ["Per incident: neither side has a run directory, so totals only."]
    lines = [
        "",
        "| Incident | " + old["label"] + " | " + new["label"] + " | |",
        "|---|---|---|---|",
    ]
    for key in sorted(set(o or {}) | set(n or {})):
        a, b = (o or {}).get(key), (n or {}).get(key)
        lines.append(f"| {key} | {_cell(a)} | {_cell(b)} | {_moved(a, b)} |")
    if o is None:
        lines.append(f"({old['label']}: totals only - pass its run directory for each incident)")
    return lines


def render(old: dict, new: dict, verdict: str) -> str:
    """The comparison as text (Markdown tables), totals first, then each incident, then the verdict."""
    lines = [
        f"Old against new on the same replay set ({len(runs())} recorded runs):",
        "",
        f"| | {old['label']} | {new['label']} |",
        "|---|---|---|",
    ]
    for key in TOTALS:
        a, b = old["totals"].get(key), new["totals"].get(key)
        if key == "spent_usd":
            a, b = _money(a), _money(b)
        lines.append(
            f"| {key.replace('_', ' ')} | {'-' if a is None else a} | {'-' if b is None else b} |"
        )
    lines.append(
        f"| prompt | `{str(old['totals'].get('prompt'))[:8]}` | `{str(new['totals'].get('prompt'))[:8]}` |"
    )
    lines.append(f"| latency | {_latency(old['incidents'])} | {_latency(new['incidents'])} |")
    lines += _incident_lines(old, new)
    lines += ["", f"Verdict for {new['label']} against the bar: {verdict}"]
    return "\n".join(lines)


def current_row(doc: dict, provider: str | None) -> dict | None:
    """The row to compare against: one qualified on the pinned prompt (that provider's first), else the newest row."""
    pinned = (doc.get("prompt") or {}).get("sha")
    rows = [r for r in doc.get("qualified") or [] if isinstance(r, dict)]
    live = [r for r in rows if pinned and r.get("prompt") == pinned]
    pool = live or rows
    pool = [r for r in pool if r.get("provider") == provider] or pool
    return max(pool, key=lambda r: str(r.get("measured", ""))) if pool else None


def old_side(doc: dict, provider: str | None, compare_with: pathlib.Path | None) -> dict | None:
    """The old side: --compare-with (a run directory or its qualification.json), else the providers.yaml row."""
    if compare_with:
        run_dir = compare_with if compare_with.is_dir() else compare_with.parent
        result = run_dir / "qualification.json"
        totals = json.loads(result.read_text(encoding="utf-8")) if result.exists() else {}
        return side(f"old: {totals.get('model', run_dir.name)}", totals, run_dir)
    row = current_row(doc, provider)
    if row is None:
        return None
    pinned = (doc.get("prompt") or {}).get("sha")
    when = "pinned prompt" if row.get("prompt") == pinned else "earlier prompt"
    return side(f"old: {row.get('model')} ({when}, {row.get('measured')})", row)
