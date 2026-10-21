"""Helios checks every Terraform change before it is applied (register R56).

For each scenario - an outage of every zone the stack uses, plus the resource losses in
terraform/fullstack/helios/scenarios/ - Helios (github.com/veerarakesh56/helios) simulates the saved
plan and the current state. The change is refused when the plan fails anything under a scenario that
today's stack survives, or that terraform/fullstack/helios/accepted.json does not accept (the accepted
set matters only for a first create, when there is no state to compare with - and, after a first
create that stopped part-way, for the resources today's state does not hold yet). A scenario Helios
cannot run refuses the change; one it cannot decide on a plan (exit 3: a value unknown until apply)
is listed and checked again on the applied state with `--after`, which then fails the job on any
regression - the change is applied by then, and the job says so. A regression the owner chose (a stack's
helios/regressions.json, by scenario, reviewed in the pull request that adds it) passes and is named in the summary.

    helios_gate.py --helios BIN --plan plan.json --baseline before.json --out-dir DIR      # before apply
    helios_gate.py --helios BIN --after state.json --baseline before.json --out-dir DIR    # after apply

Exit 0: allowed. Exit 1: refused (or, after apply, a regression). The summary is markdown on stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess  # nosec B404 - runs the pinned Helios binary with fixed arguments
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))  # warden.paths is stdlib only: the deploy job installs no package

from warden import paths  # after the sys.path line above, deliberately

HELIOS = ROOT / "terraform" / "fullstack" / "helios"
INCONCLUSIVE = 3
AZ = "az-outage"


def _resources(module: dict):
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _resources(child)


def _root(doc: dict) -> dict | None:
    values = doc.get("planned_values") or doc.get("values")
    return values.get("root_module") if values else None


def zones(doc: dict) -> list[str]:
    """Every availability zone a subnet of the stack is in, read from the document itself."""
    root = _root(doc)
    found = {r.get("values", {}).get("availability_zone") for r in _resources(root or {}) if r.get("type") == "aws_subnet"}
    return sorted(z for z in found if isinstance(z, str) and z)


def scenarios(doc: dict, out_dir: pathlib.Path, helios_dir: pathlib.Path = HELIOS) -> dict[str, pathlib.Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    found = {p.stem: p for p in sorted((helios_dir / "scenarios").glob("*.json"))}
    for z in zones(doc):
        path = out_dir / f"lose-{z}.json"
        path.write_text(json.dumps({"name": f"lose-{z}", "kind": {"type": AZ, "az": z}}), encoding="utf-8")
        found[f"lose-{z}"] = path
    return found


def _bare_env() -> dict[str, str]:
    """Helios runs in a job that holds deploy credentials: it gets none of them, only what finds programs."""
    return {k: v for k, v in os.environ.items() if k.upper() in ("PATH", "SYSTEMROOT")}


HELIOS_NAMES = ("helios", "helios.exe")  # the binary the infra job builds (target/release/helios), by name
# The characters a path handed to Helios may hold: letters, digits and _ . - + / (a drive's : and \\ on Windows).
# A quote, $, ;, a newline or any other character refuses the path: nothing else reaches the command line.
SAFE_PATH = re.compile(r"[A-Za-z0-9_.+/:\\-]+")


def _safe(path: pathlib.Path, what: str) -> str:
    text = str(path)
    if not path.is_absolute() or text.startswith("-") or not SAFE_PATH.fullmatch(text):
        raise ValueError(f"{what} {text!r}: not an absolute path of safe characters")
    return text


def _helios_argv(helios: list[str], document: pathlib.Path, scenario: pathlib.Path) -> list[str]:
    """Helios's command line, every part checked (Sonar pythonsecurity:S8705, 2026-10-20/21): the program is one
    executable file named helios where the tools work (RUNNER_TEMP in the job); the document and the scenario are
    existing files, resolved, absolute and made of safe characters only. The scenario goes as `--scenario=<path>` and
    the document after `--`, so neither can be read as an option (Helios's clap CLI: `simulate <INPUT> --scenario
    <PATH> --json`). Anything else is a ValueError, before anything runs."""
    if len(helios) != 1:
        raise ValueError("--helios names one program, with no arguments")
    exe = pathlib.Path(helios[0]).expanduser().resolve()
    roots = [b for b in (pathlib.Path(r).expanduser().resolve() for r in paths.work_roots()) if b.parent != b]
    if exe.name not in HELIOS_NAMES or not exe.is_file() or not os.access(exe, os.X_OK) \
            or not any(exe.is_relative_to(b) for b in roots):
        raise ValueError(f"{helios[0]} is not the Helios binary (an executable named helios where the tools work)")
    files = []
    for what, given in (("document", document), ("scenario", scenario)):
        real = pathlib.Path(given).resolve()
        if not real.is_file():
            raise ValueError(f"{what} {given} is not a file Helios may read")
        files.append(_safe(real, what))
    return [_safe(exe, "program"), "simulate", f"--scenario={files[1]}", "--json", "--", files[0]]


def simulate(helios: list[str], document: pathlib.Path, scenario: pathlib.Path):
    """A set of failed resource addresses, "inconclusive", or ("error", why)."""
    try:
        argv = _helios_argv(helios, document, scenario)
    except ValueError as e:
        return ("error", str(e)[:300])
    r = subprocess.run(argv,  # nosec B603
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, check=False,
                       env=_bare_env())
    if r.returncode == INCONCLUSIVE:
        return "inconclusive"
    if r.returncode in (0, 1):
        try:
            return {f["id"] for f in json.loads(r.stdout)["failures"]}
        except (ValueError, KeyError, TypeError):
            pass
    return ("error", (r.stderr.strip().splitlines() or [f"exit {r.returncode}"])[-1][:300])


def judge(name: str, now, before, accepted: dict[str, list[str]], existing: set[str] | None = None,
          regressions: dict[str, list[str]] | None = None) -> tuple[str, str]:
    """("ok" | "refuse" | "later", why) for one scenario: `now` on the plan or applied state, `before` on the
    current state (None when there is none); `existing`, the addresses the current state holds; `regressions`, the
    failures the owner chose to take on although the stack survives them today (a stack's helios/regressions.json,
    reviewed in its pull request - 2026-10-17: one EKS node and one cache node to stretch the last credits)."""
    if isinstance(now, tuple):
        return "refuse", f"Helios cannot run it: {now[1]}"
    if now == "inconclusive":
        return "later", "inconclusive on the plan (a value unknown until apply): checked on the applied state"
    # Today's failures when the stack exists; the accepted ones only when there is nothing to compare with - or for a
    # resource today's state does not hold yet: a first create that stopped part-way (2026-10-14, the EKS node group
    # refused by IAM) is compared with today for what exists and with the accepted failures for the rest.
    key = AZ if name.startswith("lose-") else name
    ok = set(accepted.get(key, []))
    if not isinstance(before, set):
        allowed = ok
    elif existing is not None:
        allowed = before | (ok - existing)
    else:
        allowed = before
    taken = sorted((now - allowed) & set((regressions or {}).get(key, [])))
    new = sorted(now - allowed - set(taken))
    if new:
        return "refuse", "fails what the stack survives today: " + ", ".join(new)
    return "ok", f"{len(now)} failure(s), none new" + (f"; taken on by the owner: {', '.join(taken)}" if taken else "")


def _load(path: pathlib.Path | None) -> dict | None:
    if path is None or not path.exists():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc if _root(doc) is not None else None


def _regressions(taken: pathlib.Path) -> dict | None:
    """The stack's regressions.json ({} when there is none), or None when it is not an object of scenario kind to a
    list of resource addresses."""
    try:
        regressions = json.loads(taken.read_text(encoding="utf-8")) if taken.is_file() else {}
    except ValueError:
        return None
    if not (isinstance(regressions, dict) and all(
            isinstance(v, list) and all(isinstance(a, str) for a in v) for v in regressions.values())):
        return None
    return regressions


def _scenario_rows(args: argparse.Namespace, document: pathlib.Path, compare_with: pathlib.Path | None,
                   cases: dict[str, pathlib.Path], judged_by: tuple) -> tuple[list[str], bool]:
    """(the report's heading and one table row per scenario, whether any was refused). `judged_by` is (accepted,
    existing, regressions) as judge() takes them."""
    accepted, existing, regressions = judged_by
    helios = [args.helios]
    refused = False
    lines = [f"### Helios {'after apply' if args.after else 'before apply'}", "",
             "| Scenario | Verdict | Why |", "|---|---|---|"]
    for name, path in cases.items():
        before = simulate(helios, compare_with, path) if compare_with is not None else None
        verdict, why = judge(name, simulate(helios, document, path), before, accepted, existing, regressions)
        if args.after and verdict == "later":
            verdict, why = "refuse", "inconclusive on the applied state"
        refused |= verdict == "refuse"
        lines.append(f"| {name} | {verdict} | {why.replace('|', '/')} |")
    return lines, refused


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--helios", required=True)
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--plan", type=pathlib.Path)
    target.add_argument("--after", type=pathlib.Path)
    ap.add_argument("--baseline", type=pathlib.Path)
    ap.add_argument("--out-dir", type=pathlib.Path, required=True)
    # Each stack is judged by its OWN scenarios and accepted failures (terraform/<stack>/helios): the undo lab's first
    # plan was refused for not holding the full stack's node group, queue and cache (2026-10-11).
    ap.add_argument("--stack", default="fullstack")
    args = ap.parse_args(argv)
    helios_dir = ROOT / "terraform" / args.stack / "helios"
    if not args.stack.replace("-", "").isalnum() or not (helios_dir / "accepted.json").is_file():
        print(f"refused: terraform/{args.stack}/helios/accepted.json does not exist - a stack says what it accepts, "
              "even when that is nothing")
        return 1
    # Every file it reads, writes or hands Helios lies where the job works (RUNNER_TEMP, the checkout): a path from the
    # command line names nothing else, and an absolute path is never read as one of Helios's options.
    try:
        document = paths.inside(args.plan or args.after)
        baseline_path = paths.inside(args.baseline) if args.baseline else None
        out_dir = paths.inside(args.out_dir)
    except ValueError as e:
        print(f"refused: {e}")
        return 1
    doc = _load(document)
    if doc is None:
        print(f"refused: {document} is not a `terraform show -json` document")
        return 1
    baseline = _load(baseline_path)
    existing = {r.get("address") for r in _resources(_root(baseline))} if baseline is not None else None
    accepted = json.loads((helios_dir / "accepted.json").read_text(encoding="utf-8"))
    regressions = _regressions(helios_dir / "regressions.json")
    if regressions is None:
        print(f"refused: terraform/{args.stack}/helios/regressions.json must be an object of scenario kind to a list "
              "of resource addresses")
        return 1
    # The current state is simulated only when it is a document Helios can read.
    compare_with = baseline_path if baseline is not None else None
    lines, refused = _scenario_rows(args, document, compare_with, scenarios(doc, out_dir, helios_dir),
                                    (accepted, existing, regressions))
    if len(lines) == 4:
        lines += ["", f"terraform/{args.stack} declares no scenario it must survive and has no subnet: nothing to run."]
    if baseline is None:
        lines += ["", "No current state: a first create, compared with the accepted failures only."]
    if refused and args.after:
        lines += ["", "**The change is applied and regresses a scenario: review it, and revert it if it should not stand.**"]
    print("\n".join(lines))
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
