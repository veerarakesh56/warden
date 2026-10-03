"""Helios checks every Terraform change before it is applied (register R56).

For each scenario - an outage of every zone the stack uses, plus the resource losses in
terraform/fullstack/helios/scenarios/ - Helios (github.com/veerarakesh56/helios) simulates the saved
plan and the current state. The change is refused when the plan fails anything under a scenario that
today's stack survives, or that terraform/fullstack/helios/accepted.json does not accept (the accepted
set matters only for a first create, when there is no state to compare with). A scenario Helios
cannot run refuses the change; one it cannot decide on a plan (exit 3: a value unknown until apply)
is listed and checked again on the applied state with `--after`, which then fails the job on any
regression - the change is applied by then, and the job says so.

    helios_gate.py --helios BIN --plan plan.json --baseline before.json --out-dir DIR      # before apply
    helios_gate.py --helios BIN --after state.json --baseline before.json --out-dir DIR    # after apply

Exit 0: allowed. Exit 1: refused (or, after apply, a regression). The summary is markdown on stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess  # nosec B404 - runs the pinned Helios binary with fixed arguments
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
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


def scenarios(doc: dict, out_dir: pathlib.Path) -> dict[str, pathlib.Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    found = {p.stem: p for p in sorted((HELIOS / "scenarios").glob("*.json"))}
    for z in zones(doc):
        path = out_dir / f"lose-{z}.json"
        path.write_text(json.dumps({"name": f"lose-{z}", "kind": {"type": AZ, "az": z}}), encoding="utf-8")
        found[f"lose-{z}"] = path
    return found


def _bare_env() -> dict[str, str]:
    """Helios runs in a job that holds deploy credentials: it gets none of them, only what finds programs."""
    return {k: v for k, v in os.environ.items() if k.upper() in ("PATH", "SYSTEMROOT")}


def simulate(helios: list[str], document: pathlib.Path, scenario: pathlib.Path):
    """A set of failed resource addresses, "inconclusive", or ("error", why)."""
    r = subprocess.run([*helios, "simulate", str(document), "--scenario", str(scenario), "--json"],  # nosec B603
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


def judge(name: str, now, before, accepted: dict[str, list[str]]) -> tuple[str, str]:
    """("ok" | "refuse" | "later", why) for one scenario: `now` on the plan or applied state, `before` on the
    current state (None when there is none)."""
    if isinstance(now, tuple):
        return "refuse", f"Helios cannot run it: {now[1]}"
    if now == "inconclusive":
        return "later", "inconclusive on the plan (a value unknown until apply): checked on the applied state"
    # Today's failures when the stack exists; the accepted ones only when there is nothing to compare with.
    allowed = before if isinstance(before, set) else set(accepted.get(AZ if name.startswith("lose-") else name, []))
    new = sorted(now - allowed)
    if new:
        return "refuse", "fails what the stack survives today: " + ", ".join(new)
    return "ok", f"{len(now)} failure(s), none new"


def _load(path: pathlib.Path | None) -> dict | None:
    if path is None or not path.exists():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc if _root(doc) is not None else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--helios", required=True)
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--plan", type=pathlib.Path)
    target.add_argument("--after", type=pathlib.Path)
    ap.add_argument("--baseline", type=pathlib.Path)
    ap.add_argument("--out-dir", type=pathlib.Path, required=True)
    args = ap.parse_args(argv)
    document = args.plan or args.after
    doc = _load(document)
    if doc is None:
        print(f"refused: {document} is not a `terraform show -json` document")
        return 1
    baseline = _load(args.baseline)
    accepted = json.loads((HELIOS / "accepted.json").read_text(encoding="utf-8"))
    helios = [args.helios]
    refused = False
    lines = [f"### Helios {'after apply' if args.after else 'before apply'}", "",
             "| Scenario | Verdict | Why |", "|---|---|---|"]
    for name, path in scenarios(doc, args.out_dir).items():
        before = simulate(helios, args.baseline, path) if baseline is not None else None
        verdict, why = judge(name, simulate(helios, document, path), before, accepted)
        if args.after and verdict == "later":
            verdict, why = "refuse", "inconclusive on the applied state"
        refused |= verdict == "refuse"
        lines.append(f"| {name} | {verdict} | {why.replace('|', '/')} |")
    if baseline is None:
        lines += ["", "No current state: a first create, compared with the accepted failures only."]
    if refused and args.after:
        lines += ["", "**The change is applied and regresses a scenario: review it, and revert it if it should not stand.**"]
    print("\n".join(lines))
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
