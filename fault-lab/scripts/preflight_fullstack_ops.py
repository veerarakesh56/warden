"""Before the Wave 4 faults are run for real: every inject + revert once, against the real stack.

    python fault-lab/scripts/preflight_fullstack_ops.py                   # prints the plan, touches nothing
    python fault-lab/scripts/preflight_fullstack_ops.py --apply           # inject + revert each fault
    python fault-lab/scripts/preflight_fullstack_ops.py --apply --only fs-07,fs-19
    python fault-lab/scripts/preflight_fullstack_ops.py --revert --only fs-12  # finish an interrupted one

For each fault: the stack must be at baseline, the inject runs at minimum size (small cache fill,
no alarm wait, no WARDEN), the fault's own area must then SHOW the fault (reported - a CloudWatch-
based symptom takes minutes, so an absent symptom is a warning, not a failure), the revert runs, and
the same whole-stack baseline the operator CLI gates on must come back clean. Non-zero exit on any
failure.

⛔ WHY (the lesson of fault-lab/scripts/preflight_db_ops.py and preflight_k8s_ops.py): fakes accept what the
real APIs reject. A revert that fails for the first time in the middle of a measured run leaves the
stack broken under every later fault. The state is written to its own run directory, so an
interrupted preflight is reverted with `--revert --only fs-NN` (fullstack_cli's own `revert` refuses:
the preflight records no inject step in the run state).
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from scenarios import fullstack_cli as cli
from scenarios import ops_fullstack as fs

DEFAULT_RUN = pathlib.Path.home() / "warden-bench-runs" / "wave4-preflight"


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="really inject and revert (default: plan only)")
    ap.add_argument("--only", default="", help="comma-separated fault ids, e.g. fs-07,fs-19")
    ap.add_argument("--run", default=str(DEFAULT_RUN))
    ap.add_argument("--settle-minutes", type=float, default=15)
    ap.add_argument("--revert", action="store_true",
                    help="only revert the --only faults from their saved state, then wait for baseline")
    return ap.parse_args(argv)


def _selected_faults(args: argparse.Namespace) -> list[str]:
    """The fault ids --only names (every one but fs-00 when it names none); refuses an --only that matches nothing,
    and a --revert without --only."""
    wanted = tuple(x.strip() for x in args.only.split(",") if x.strip())
    faults = [fid for fid in fs.FAULTS if fid != "fs-00" and (not wanted or fid.startswith(wanted))]
    if not faults:
        raise SystemExit(f"--only {args.only!r} matched no fault")
    if args.revert and not wanted:
        raise SystemExit("--revert needs --only: say which fault to put back")
    return faults


def _print_plan(faults: list[str]) -> None:
    print("PLAN (nothing touched; add --apply):")
    for fid in faults:
        sc = cli.scenario_for(fid)
        print(f"  {fid}  {sc['fault_class']:34s} inject -> check area '{fs.FAULTS[fid].area}' "
              f"-> revert -> whole-stack baseline")


def _settled(env: cli.Env, settle_minutes: float) -> list[str]:
    """What still keeps the stack from its baseline after waiting up to `settle_minutes` for it to come back."""
    deadline = time.monotonic() + settle_minutes * 60
    while (left := cli.stack_problems(env)) and time.monotonic() < deadline:
        env.sleep(30)
    return left


def _revert_only(env: cli.Env, faults: list[str], settle_minutes: float) -> int:
    """--revert: put back each fault from its saved state, then wait for the baseline."""
    for fid in faults:
        print(f"revert {fid}: {env.faults[fid].revert(env.clients, env.target)}")
    left = _settled(env, settle_minutes)
    print("baseline clean" if not left else f"NOT AT BASELINE: {left}")
    return 1 if left else 0


def _inject(env: cli.Env, fault: fs.Fault) -> tuple[list[str], str]:
    """(what the fault's own area shows after the inject, the inject's error or "")."""
    try:
        fault.inject(env.clients, env.target)
        env.sleep(10)
        return (fs.check_baseline(env.clients, env.target, [fault.area]) if not env.dry_run else ["dry"]), ""
    except Exception as exc:  # noqa: BLE001  # reported; then reverted regardless
        return [], f"inject raised {type(exc).__name__}: {exc}"


def _preflight_one(env: cli.Env, fid: str, run: pathlib.Path, settle_minutes: float) -> bool | None:
    """Inject one fault, revert it and wait for the baseline. True when it is OK, False when it failed, None when the
    run must stop: the revert raised, or the stack did not come back (the next fault would start from it dirty)."""
    fault = env.faults[fid]
    landed, error = _inject(env, fault)
    try:
        fault.revert(env.clients, env.target)
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL {fid}: {error + '; then ' if error else ''}REVERT raised "
              f"{type(exc).__name__}: {exc} - stopping; the stack is not at baseline "
              f"(saved state: {run / 'saved' / (fid + '.json')})")
        return None
    left = _settled(env, settle_minutes)
    ok = not error and not left
    shown = "landed: " + ("; ".join(landed) if landed else "NOT VISIBLE YET (warning)")
    print(f"{'OK  ' if ok else 'FAIL'} {fid}: {error or shown}; after revert "
          f"{'baseline clean' if not left else left}")
    if left:
        print("stopping: the next fault would start from a dirty stack")
        return None
    return ok


def main(argv: list[str] | None = None, *, env: cli.Env | None = None) -> int:
    # ⛔ FIRST, before argparse can print: a Windows console is cp1252 and this output carries ⛔/⚠.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    args = _arguments(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)

    faults = _selected_faults(args)
    if not args.apply and not args.revert:
        _print_plan(faults)
        return 0

    run = pathlib.Path(args.run).expanduser()
    run.mkdir(parents=True, exist_ok=True)
    env = env or cli.live_env(run)
    env.target.redis_fill_mb = 50  # minimum size: proves fill + flush, not the memory alarm
    cli._bind_saved(env, run)
    if args.revert:
        return _revert_only(env, faults, args.settle_minutes)
    problems = cli.stack_problems(env)
    if problems:
        print(f"NOT AT BASELINE before starting: {problems}")
        return 1

    failed = 0
    for fid in faults:
        ok = _preflight_one(env, fid, run, args.settle_minutes)
        if ok is None:
            return 1
        failed += not ok

    print("\nALL FAULTS INJECTED AND REVERTED ON THE REAL STACK" if not failed
          else f"\n{failed} FAILED - do not run the wave")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
