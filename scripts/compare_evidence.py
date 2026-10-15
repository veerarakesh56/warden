"""Which observability tool helps WARDEN most? The same fault diagnosed four times, one tool beside AWS each time.

    python scripts/compare_evidence.py --dry-run                      # the plan; touches nothing
    python scripts/compare_evidence.py --out ~/warden-bench-runs/compare-evidence/2026-10-14
    python scripts/compare_evidence.py --faults fs-10,fs-16 --tools none,xray --out DIR

Owner, 2026-10-14: "use all 3 of them (X-Ray, Grafana, Datadog) and compare and show which is better".

Per fault, on the test stack (terraform/fullstack), with the Wave 4 harness's own steps (scenarios/fullstack_cli.py):
inject it and wait for its alarm (step_inject), then diagnose the SAME injected state once per tool - evidence from
AWS alone ("none"), AWS + X-Ray, AWS + Grafana, AWS + Datadog - by setting WARDEN_EVIDENCE_TOOLS in WARDEN's
environment (src/warden/tools.py evidence_tools), each diagnosis through step_diagnose in its own run directory
(<out>/<tool>/, which scenarios.score can grade on its own), then revert (step_revert). Each run is graded with the
harness's rubric (scenarios/score.py score_one) and measured: correct or not, the action and whether the gate let it
through, tokens and cost (the report's CostRecord), the wall time of WARDEN's process, and what the tool added (its
XRAY / GRAFANA / DATADOG / GITHUB lines, and whether a dependency line named the faulted component).

The order of the tools rotates from fault to fault, so no tool is always the one that reads the fault the latest.

The tools' settings: WARDEN's environment is built from nothing (runner.py), so the chosen tool's settings are added to
that one run's environment only, never recorded on disk. They come from this shell, or from the
--settings-env environment's SSM parameters and Secrets Manager secrets (default the WARDEN runtime's - environments.yaml `runtime` - where
scripts/observability_setup.py keeps them; src/warden/settings.py load), read with this shell's credentials; this process's environment is put back afterwards.

Before a live run: the stack soaked (`python -m scenarios.fullstack_cli soak`), WARDEN_PROVIDER and its key set, as
for any Wave 4 diagnose. The run directory (--run) is the harness's, outside the repository.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import html
import json
import os
import pathlib
import re
import statistics
import sys
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import yaml
from scenarios import fullstack_cli as cli
from scenarios import ops_fullstack as fs
from scenarios import score

from warden import environments

TOOLS = ("none", "xray", "grafana", "datadog")

# Application-level faults where a request trace should help: a bad deploy (fs-01), a timeout (fs-02), a failing
# downstream call (fs-10 the cache, fs-12 the database), a slow query (fs-16) and a memory limit hit (fs-20).
DEFAULT_FAULTS = ("fs-01", "fs-02", "fs-10", "fs-12", "fs-16", "fs-20")

# What each tool's reader needs in WARDEN's environment (settings.LOADABLE names). X-Ray needs only its switch, which
# the run itself sets, and the reader role's xray:GetTraceSummaries.
SETTINGS = {
    "none": (),
    "xray": (),
    "grafana": ("WARDEN_GRAFANA_LOGS_URL", "WARDEN_GRAFANA_LOGS_USER", "WARDEN_GRAFANA_TRACES_URL",
                "WARDEN_GRAFANA_TRACES_USER", "WARDEN_GRAFANA_METRICS_URL", "WARDEN_GRAFANA_METRICS_USER",
                "WARDEN_GRAFANA_READ_TOKEN"),
    "datadog": ("WARDEN_DATADOG_SITE", "WARDEN_DATADOG_API_KEY", "WARDEN_DATADOG_APP_KEY"),
}

# The evidence lines each source writes (xray.py, grafana.py, datadog.py, timeline.py).
PREFIXES = ("XRAY", "GRAFANA", "DATADOG", "GITHUB")

# The component each fault breaks, as a dependency line would name it (lower case, any of). A fault not here gets
# "unknown", never "not found".
FAULTED = {
    "fs-01": ("checkout",), "fs-02": ("checkout",), "fs-04": ("dynamodb",), "fs-09": ("dynamodb",),
    "fs-10": ("redis", "elasticache"), "fs-11": ("redis", "elasticache"),
    "fs-12": ("postgres", "aurora", "rds"), "fs-13": ("postgres", "aurora", "rds"),
    "fs-14": ("postgres", "aurora", "rds"), "fs-15": ("postgres", "aurora", "rds"),
    "fs-16": ("postgres", "aurora", "rds"), "fs-20": ("orders-api",), "fs-21": ("postgres", "aurora", "rds"),
}


def _missing(tool: str, values: dict[str, str]) -> list[str]:
    """The settings a tool's reader still needs (grafana.configured, datadog.configured), by name."""
    if tool == "grafana":
        urls = [n for n in SETTINGS["grafana"] if n.endswith("_URL")]
        need = [] if values.get("WARDEN_GRAFANA_READ_TOKEN") else ["WARDEN_GRAFANA_READ_TOKEN"]
        return need + ([] if any(values.get(n) for n in urls) else ["one of " + ", ".join(urls)])
    return [n for n in SETTINGS.get(tool, ()) if not values.get(n)]


@contextlib.contextmanager
def _environ_restored():
    saved = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def evidence_settings(tools: list[str], *, store: str = "") -> dict[str, str]:
    """The chosen tools' settings, from this shell or - with `store` - from that environment's SSM and Secrets
    Manager: the WARDEN runtime's (`ops`, where scripts/observability_setup.py keeps them), not the stack's own."""
    names = frozenset(n for t in tools for n in SETTINGS[t])
    with _environ_restored():
        if store and names:
            from warden import settings

            settings.load(store, only=names)
        return {n: os.environ[n] for n in names if os.environ.get(n, "").strip()}


def order_for(tools: list[str], index: int) -> list[str]:
    k = index % len(tools)
    return tools[k:] + tools[:k]


def queried_services() -> list[str]:
    """The names the readers ask each tool about for the harness's alert (grafana.services) - nothing to compare if
    none of them is a traced workload."""
    from warden.grafana import services
    from warden.models import Alert

    alert = yaml.safe_load(cli.ALERT_TEMPLATE.read_text(encoding="utf-8"))
    alert["labels"] = {k: v.replace("warden-__ENV__-", fs.PREFIX) if isinstance(v, str) else v
                       for k, v in alert["labels"].items()}
    return services(Alert.model_validate(alert))


def traced_services() -> list[str]:
    """The workloads the test stack sends traces from (OTEL_SERVICE_NAME in manifests/shop)."""
    text = "".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / "manifests" / "shop" / "base").glob("*.yaml")))
    return sorted(set(re.findall(r"name: OTEL_SERVICE_NAME\s+value: ([\w.-]+)", text)))


def warnings() -> list[str]:
    """What would make the comparison measure nothing, found before any fault is injected."""
    out = []
    try:
        asked, traced = queried_services(), traced_services()
        if not set(asked) & set(traced):
            out.append(f"the readers ask about {', '.join(asked) or 'nothing'}, but traces come only from "
                       f"{', '.join(traced) or 'nothing'}: the tools' traces will not be read")
    except Exception as exc:  # noqa: BLE001 - a warning that cannot be computed is still said
        out.append(f"could not work out which services the readers ask about ({type(exc).__name__})")
    reader = (ROOT / "terraform" / "fullstack" / "reader.tf").read_text(encoding="utf-8")
    if "xray:GetTraceSummaries" not in reader:
        out.append("the harness's reader role (terraform/fullstack/reader.tf) has no xray:GetTraceSummaries: "
                   "every X-Ray read will be refused")
    return out


# --------------------------------------------------------------------------- one run


def _row(sid: str, tool: str) -> dict[str, Any]:
    return {"fault": sid, "tool": tool, "status": "failed", "diagnosis": score.ERROR, "correct": False,
            "evidence_ok": None, "action": None, "verdict": None, "gate": None, "gate_allowed": None,
            "input_tokens": None, "output_tokens": None, "usd": None, "calls": None, "wall_s": None,
            "lines": dict.fromkeys(PREFIXES, 0), "dependencies": [], "dependency_named": None,
            "tool_read_failures": 0, "report": None, "error": ""}


def measure(row: dict, report: dict, faulted: tuple[str, ...]) -> None:
    """Cost and what the tool added, from WARDEN's report."""
    cost = report.get("cost") or {}
    row.update(input_tokens=cost.get("input_tokens"), output_tokens=cost.get("output_tokens"),
               usd=cost.get("usd"), calls=cost.get("calls"))
    context = report.get("context") or {}
    logs = [str(x) for x in context.get("logs") or []]
    row["lines"] = {p: sum(1 for x in logs if x.startswith(p + " ")) for p in PREFIXES}
    deps = [x for x in logs if any(x.startswith(f"{p} dependency ") for p in PREFIXES)]
    row["dependencies"] = deps[:10]
    peers = [x.split("->", 1)[1].split(":", 1)[0].strip().lower() for x in deps if "->" in x]
    row["dependency_named"] = any(k in p for p in peers for k in faulted) if faulted else None
    # A read of the tool that failed: a tool that answered nothing is not a tool that found nothing.
    tool = row["tool"]
    row["tool_read_failures"] = 0 if tool == "none" else sum(
        1 for e in context.get("tool_errors") or [] if str(e).lower().startswith(f"logs: {tool}"))


def diagnose_with(env: cli.Env, run: pathlib.Path, out: pathlib.Path, key: str, tool: str,
                  values: dict[str, str], rubric: dict) -> dict:
    """One diagnosis of the injected fault with one tool beside AWS. Never raises: a failure is a row."""
    scenario = cli.scenario_for(key)
    sid = scenario["id"]
    row = _row(sid, tool)
    tool_run = out / tool
    arm = {"WARDEN_EVIDENCE_TOOLS": tool, **({"WARDEN_XRAY": "1"} if tool == "xray" else {})}
    extra = {n: values[n] for n in SETTINGS[tool] if n in values}  # this run's environment only, never on disk
    real = env.invoke_warden

    def invoke(child_env: dict, alert: pathlib.Path, report: pathlib.Path) -> tuple[int, str]:
        start = time.monotonic()
        try:
            return real({**child_env, **extra}, alert, report)
        finally:
            row["wall_s"] = round(time.monotonic() - start, 1)

    env.invoke_warden = invoke
    try:
        # The injected fault's record, as step_inject left it, in this tool's own run directory.
        record = json.loads((run / "ground-truth" / f"{sid}.json").read_text(encoding="utf-8"))
        cli._write_json(tool_run / "ground-truth" / f"{sid}.json", {**record, "runs": []})
        entry = cli.step_diagnose(env, tool_run, key, arm=arm)["runs"][0]
        graded = score.score_one(entry, scenario, tool_run, rubric)
        row.update(diagnosis=graded["diagnosis"], correct=graded["diagnosis"] == score.CORRECT,
                   evidence_ok=graded["evidence"], action=graded["action"], verdict=graded["verdict"],
                   gate=graded["gate"], gate_allowed=None if graded["gate"] is None else graded["gate"] == "allowed",
                   error=graded["note"])
        if entry.get("report_written"):
            row["status"], row["report"] = "ok", f"{tool}/{entry['report']}"
            report = json.loads((tool_run / entry["report"]).read_text(encoding="utf-8"))
            measure(row, report, FAULTED.get(fs.fault_of(scenario), ()))
    except Exception as exc:  # noqa: BLE001 - a failed run is recorded as failed, never dropped
        row["error"] = f"{type(exc).__name__}: {exc}"[:500]
    finally:
        env.invoke_warden = real
    return row


# --------------------------------------------------------------------------- the comparison


def summarise(rows: list[dict], tools: list[str]) -> list[dict]:
    """Per tool: accuracy over EVERY run (a failed one counts as not correct), mean time and cost, and how often a
    dependency line named the faulted component, over the runs where that is known."""
    out = []
    for tool in tools:
        mine = [r for r in rows if r["tool"] == tool]
        times = [r["wall_s"] for r in mine if r["wall_s"] is not None]
        costs = [r["usd"] for r in mine if r["usd"] is not None]
        known = [r for r in mine if r["dependency_named"] is not None]
        correct = sum(1 for r in mine if r["correct"])
        out.append({
            "tool": tool, "runs": len(mine), "correct": correct, "failed": sum(1 for r in mine if r["status"] != "ok"),
            "accuracy": correct / len(mine) if mine else None,
            "mean_wall_s": round(statistics.fmean(times), 1) if times else None,
            "mean_usd": round(statistics.fmean(costs), 6) if costs else None,
            "dependency_found": sum(1 for r in known if r["dependency_named"]), "dependency_known": len(known),
        })
    return out


def _wait_quiet(env: cli.Env, run: pathlib.Path) -> None:
    """step_inject refuses an inject inside the previous fault's evidence window; wait it out instead."""
    last = cli._state(run).get("last_activity_at")
    if last:
        idle = (dt.datetime.now(dt.UTC) - dt.datetime.fromisoformat(last)).total_seconds()
        if idle < cli.QUIET_SECONDS:
            env.log(f"waiting {(cli.QUIET_SECONDS - idle) / 60:.0f} min for the previous fault to leave the evidence")
            env.sleep(cli.QUIET_SECONDS - idle + 5)


def compare(env: cli.Env, run: pathlib.Path, out: pathlib.Path, faults: list[str], tools: list[str],
            values: dict[str, str], *, settle_s: float = 1200) -> dict:
    rubric = score.load_rubric()
    results: dict[str, Any] = {
        "started_at": cli._now(), "git_commit": cli._git_commit(), "run": str(run), "tools": tools,
        "dry_run": env.dry_run, "warnings": warnings(), "faults": [], "summary": [],
    }

    def save() -> None:
        rows = [r for f in results["faults"] for r in f["runs"]]
        results["summary"] = summarise(rows, tools)
        results["finished_at"] = cli._now()
        cli._write_json(out / "results.json", results)
        (out / "results.html").write_text(render_html(results), encoding="utf-8")

    for i, key in enumerate(faults):
        scenario = cli.scenario_for(key)
        order = order_for(tools, i)
        entry = {"fault": scenario["id"], "title": scenario.get("title", ""), "order": order, "error": "", "runs": []}
        results["faults"].append(entry)
        try:
            if not env.dry_run:
                _wait_quiet(env, run)
            cli.step_inject(env, run, key, skip_quiet=env.dry_run)
        except Exception as exc:  # the fault stays in the results, its runs as failed
            entry["error"] = f"inject: {type(exc).__name__}: {exc}"[:500]
            entry["runs"] = [{**_row(scenario["id"], t), "error": entry["error"]} for t in order]
            save()
            if cli._state(run).get("active"):
                raise  # a fault still injected (its own revert failed): nothing else may run on this stack
            continue
        try:
            for tool in order:
                entry["runs"].append(diagnose_with(env, run, out, key, tool, values, rubric))
                save()
        finally:
            # A failed revert raises here and stops the comparison: nothing may run on a stack not at baseline.
            reverted = cli.step_revert(env, run, key, settle_s=settle_s)
            entry["baseline_after"] = reverted.get("baseline_after")
            save()
    return results


# --------------------------------------------------------------------------- the page


def _pct(v: float | None) -> str:
    return "-" if v is None else f"{v * 100:.0f}%"


def _secs(v: float | None) -> str:
    return "-" if v is None else f"{v:.0f} s"


def _usd(v: float | None) -> str:
    return "-" if v is None else f"${v:.4f}"


def _cell(text: Any, cls: str = "") -> str:
    return f'<td class="{cls}">{html.escape(str(text))}</td>' if cls else f"<td>{html.escape(str(text))}</td>"


_LABEL = {"none": "AWS only", "xray": "AWS + X-Ray", "grafana": "AWS + Grafana", "datadog": "AWS + Datadog"}

_CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1b;--muted:#6b6b66;--card:#fff;--line:#e3e2dd;--ok:#1f7a3f;--okbg:#e5f3ea;
--bad:#a3261b;--badbg:#f8e6e3;--warn:#8a5a00;--warnbg:#fbf0d9}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--muted:#9a9993;--card:#1f1f1d;--line:#33332f;
--ok:#7fd49b;--okbg:#1d3326;--bad:#f0948a;--badbg:#3a201d;--warn:#e8c06a;--warnbg:#352a14}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}h1{font-size:26px;margin:0 0 4px}
h2{font-size:18px;margin:36px 0 4px}p.meta{color:var(--muted);margin:0 0 20px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}td.note{white-space:normal;color:var(--muted);font-size:13px;min-width:220px}
.ok{color:var(--ok);background:var(--okbg)}.bad{color:var(--bad);background:var(--badbg)}
.warn{color:var(--warn);background:var(--warnbg)}.best{font-weight:700}
.note-box{padding:10px 14px;border-radius:8px;margin:0 0 12px}
"""


def render_html(results: dict) -> str:
    """One self-contained page: no script, no external font, every value escaped."""
    summary = results.get("summary") or []
    ranked = [s for s in summary if s["accuracy"] is not None]
    best = max((s["accuracy"] for s in ranked), default=None)
    meta = (f"WARDEN on the test stack, the same fault diagnosed once per tool. Started {results.get('started_at', '')}"
            f", commit {results.get('git_commit', '')}" + (" - DRY RUN, no real evidence" if results.get("dry_run") else ""))
    parts = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             "<title>Evidence tool comparison</title><style>", _CSS, "</style></head><body><main>",
             "<h1>Evidence tool comparison</h1>", f'<p class="meta">{html.escape(meta)}</p>',
             *(f'<p class="warn note-box">{html.escape(w)}</p>' for w in results.get("warnings") or []),
             ('<div class="wrap"><table><thead><tr><th>Evidence</th><th>Accuracy</th><th>Correct / runs</th>'
              "<th>Failed runs</th><th>Mean time</th><th>Mean cost</th><th>Dependency found</th></tr></thead><tbody>")]
    for s in summary:
        cls = "best" if best is not None and s["accuracy"] == best and best > 0 else ""
        dep = f"{s['dependency_found']} / {s['dependency_known']}" if s["dependency_known"] else "-"
        parts.append("<tr>" + _cell(_LABEL.get(s["tool"], s["tool"]), cls) + _cell(_pct(s["accuracy"]), cls)
                     + _cell(f"{s['correct']} / {s['runs']}") + _cell(s["failed"], "bad" if s["failed"] else "")
                     + _cell(_secs(s["mean_wall_s"])) + _cell(_usd(s["mean_usd"])) + _cell(dep) + "</tr>")
    parts.append("</tbody></table></div>")
    for f in results.get("faults") or []:
        parts.append(f"<h2>{html.escape(f['fault'])}</h2><p class=\"meta\">{html.escape(f.get('title', ''))}"
                     + (f" - {html.escape(f['error'])}" if f.get("error") else "") + "</p>")
        parts.append('<div class="wrap"><table><thead><tr><th>Evidence</th><th>Result</th><th>Action</th>'
                     "<th>Gate</th><th>Tokens in / out</th><th>Cost</th><th>Time</th><th>Tool lines</th>"
                     "<th>Dependency</th><th>Note</th></tr></thead><tbody>")
        for r in f.get("runs") or []:
            result = "failed" if r["status"] != "ok" else ("correct" if r["correct"] else r["diagnosis"].lower())
            rcls = "ok" if r["correct"] else ("bad" if r["status"] != "ok" or r["diagnosis"] != score.SAFE else "warn")
            gate = {True: "allowed", False: "refused"}.get(r["gate_allowed"], "-")
            tokens = "-" if r["input_tokens"] is None else f"{r['input_tokens']} / {r['output_tokens']}"
            lines = ", ".join(f"{p} {n}" for p, n in (r.get("lines") or {}).items() if n) or "none"
            dep = {True: "named it", False: "not named", None: "-"}[r["dependency_named"]]
            note = r.get("error") or ""
            if r.get("tool_read_failures"):
                note = f"{r['tool_read_failures']} read(s) of the tool failed. {note}"
            parts.append("<tr>" + _cell(_LABEL.get(r["tool"], r["tool"])) + _cell(result, rcls)
                         + _cell(r["action"] or "-") + _cell(gate) + _cell(tokens) + _cell(_usd(r["usd"]))
                         + _cell(_secs(r["wall_s"])) + _cell(lines) + _cell(dep) + _cell(note.strip(), "note")
                         + "</tr>")
        parts.append("</tbody></table></div>")
    parts.append("</main></body></html>")
    return "".join(parts)


# --------------------------------------------------------------------------- entry point


def plan(faults: list[str], tools: list[str], values: dict[str, str]) -> list[str]:
    lines = [f"compare {len(faults)} fault(s) x {len(tools)} tool(s) = {len(faults) * len(tools)} diagnoses"]
    for i, key in enumerate(faults):
        s = cli.scenario_for(key)
        lines.append(f"  {s['id']}: inject, wait for {s.get('alarm')} (up to {s.get('alarm_timeout_s')}s); "
                     f"diagnose with {' -> '.join(order_for(tools, i))}; revert, wait for baseline")
    for tool in tools:
        missing = _missing(tool, values)
        lines.append(f"  {tool}: " + (f"NOT READY - missing {', '.join(missing)}" if missing else
                                     f"settings {', '.join(sorted(n for n in SETTINGS[tool] if n in values)) or 'none needed'}"))
    return lines + [f"  WARNING: {w}" for w in warnings()]


def main(argv: list[str] | None = None, *, env: cli.Env | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    ap = argparse.ArgumentParser(prog="compare_evidence", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--faults", default=",".join(DEFAULT_FAULTS), help="comma-separated fault ids (fs-NN)")
    ap.add_argument("--tools", default=",".join(TOOLS), help="comma-separated, from: " + ", ".join(TOOLS))
    ap.add_argument("--out", default=None, help="where results.json, results.html and each tool's runs go")
    ap.add_argument("--run", default=os.environ.get("WARDEN_FS_RUN") or str(cli.DEFAULT_RUN),
                    help="the harness's run directory (its soak and the faults' saved prior state)")
    ap.add_argument("--dry-run", action="store_true", help="print the plan; touch nothing")
    ap.add_argument("--settings-env", default=environments.default_environment_policies().runtime_environment or "",
                    help="the environment whose store holds the tools' settings (default: the WARDEN runtime's, "
                         "environments.yaml `runtime`; '' for this shell only)")
    ap.add_argument("--warden-timeout", type=float, default=900)
    ap.add_argument("--settle-minutes", type=float, default=20)
    args = ap.parse_args(argv)

    tools = [t.strip().lower() for t in args.tools.split(",") if t.strip()]
    unknown = [t for t in tools if t not in TOOLS]
    if unknown or not tools or len(set(tools)) != len(tools):
        ap.error(f"--tools: each once, from {', '.join(TOOLS)}")
    faults = [f.strip() for f in args.faults.split(",") if f.strip()]
    try:
        for f in faults:
            cli.scenario_for(f)
    except (cli.StepError, fs.OpError) as exc:
        ap.error(f"--faults: {exc}")

    if args.dry_run:
        # Names only, and from this shell only: a dry run reads no store.
        print("\n".join(plan(faults, tools, evidence_settings(tools))))
        if args.settings_env:
            print(f"  (a live run first loads the missing settings from the {args.settings_env} environment's store)")
        return 0
    if not args.out:
        ap.error("--out is required for a live run")

    values = evidence_settings(tools, store=args.settings_env)
    not_ready = {t: _missing(t, values) for t in tools if _missing(t, values)}
    if not_ready:
        print("STOPPED before any inject: " + "; ".join(f"{t} needs {', '.join(m)}" for t, m in not_ready.items()),
              file=sys.stderr)
        return 1
    out = pathlib.Path(args.out).expanduser()
    run = pathlib.Path(args.run).expanduser()
    run.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    try:
        env = env or cli.live_env(run, warden_timeout=args.warden_timeout)
        results = compare(env, run, out, faults, tools, values, settle_s=args.settle_minutes * 60)
    except (cli.StepError, fs.OpError) as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        return 1
    for s in results["summary"]:
        print(f"{s['tool']:8s} accuracy {_pct(s['accuracy']):>4s}  {s['correct']}/{s['runs']}  "
              f"time {_secs(s['mean_wall_s'])}  cost {_usd(s['mean_usd'])}")
    print(f"results: {out / 'results.json'}  {out / 'results.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
