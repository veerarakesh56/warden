"""Before the Wave 4 faults are run for real: every inject + revert once, against the real stack.

    python scripts/preflight_fullstack_ops.py                   # prints the plan, touches nothing
    python scripts/preflight_fullstack_ops.py --apply           # inject + revert each fault
    python scripts/preflight_fullstack_ops.py --apply --only fs-07,fs-19

For each fault: the stack must be at baseline, the inject runs at minimum size (small cache fill,
no alarm wait, no WARDEN), the fault's own area must then SHOW the fault (reported - a CloudWatch-
based symptom takes minutes, so an absent symptom is a warning, not a failure), the revert runs, and
the same whole-stack baseline the operator CLI gates on must come back clean. Non-zero exit on any
failure.

⛔ WHY (the lesson of scripts/preflight_db_ops.py and preflight_k8s_ops.py): fakes accept what the
real APIs reject. A revert that fails for the first time in the middle of a measured run leaves the
stack broken under every later fault. The state is written to its own run directory, so an
interrupted preflight is reverted with `fullstack_cli --run <dir> revert fs-NN`.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from scenarios import fullstack_cli as cli
from scenarios import ops_fullstack as fs

DEFAULT_RUN = pathlib.Path.home() / "warden-bench-runs" / "wave4-preflight"


def main(argv: list[str] | None = None, *, env: cli.Env | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="really inject and revert (default: plan only)")
    ap.add_argument("--only", default="", help="comma-separated fault ids, e.g. fs-07,fs-19")
    ap.add_argument("--run", default=str(DEFAULT_RUN))
    ap.add_argument("--settle-minutes", type=float, default=15)
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)

    wanted = tuple(x.strip() for x in args.only.split(",") if x.strip())
    faults = [fid for fid in fs.FAULTS if fid != "fs-00" and (not wanted or fid.startswith(wanted))]
    if not faults:
        raise SystemExit(f"--only {args.only!r} matched no fault")
    if not args.apply:
        print("PLAN (nothing touched; add --apply):")
        for fid in faults:
            sc = cli.scenario_for(fid)
            print(f"  {fid}  {sc['fault_class']:34s} inject -> check area '{fs.FAULTS[fid].area}' "
                  f"-> revert -> whole-stack baseline")
        return 0

    run = pathlib.Path(args.run).expanduser()
    run.mkdir(parents=True, exist_ok=True)
    env = env or cli.live_env(run)
    env.target.redis_fill_mb = 50  # minimum size: proves fill + flush, not the memory alarm
    cli._bind_saved(env, run)
    problems = cli.stack_problems(env)
    if problems:
        print(f"NOT AT BASELINE before starting: {problems}")
        return 1

    failed = 0
    for fid in faults:
        fault = env.faults[fid]
        landed, error = [], ""
        try:
            fault.inject(env.clients, env.target)
            env.sleep(10)
            landed = fs.check_baseline(env.clients, env.target, [fault.area]) if not env.dry_run else ["dry"]
        except Exception as exc:  # noqa: BLE001 - reported, then reverted regardless
            error = f"inject raised {type(exc).__name__}: {exc}"
        try:
            fault.revert(env.clients, env.target)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {fid}: REVERT raised {type(exc).__name__}: {exc} - stopping; the stack is "
                  f"not at baseline (saved state: {run / 'saved' / (fid + '.json')})")
            return 1
        deadline = time.monotonic() + args.settle_minutes * 60
        while (left := cli.stack_problems(env)) and time.monotonic() < deadline:
            env.sleep(30)
        ok = not error and not left
        failed += not ok
        shown = "landed: " + ("; ".join(landed) if landed else "NOT VISIBLE YET (warning)")
        print(f"{'OK  ' if ok else 'FAIL'} {fid}: {error or shown}; after revert "
              f"{'baseline clean' if not left else left}")
        if left:
            print("stopping: the next fault would start from a dirty stack")
            return 1

    print("\nALL FAULTS INJECTED AND REVERTED ON THE REAL STACK" if not failed
          else f"\n{failed} FAILED - do not run the wave")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
