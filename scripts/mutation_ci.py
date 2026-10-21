"""Mutation testing in CI (B37): which safety modules to mutate, and the score, for .github/workflows/mutation.yml.

    git diff --name-only <base>...HEAD | python scripts/mutation_ci.py shard <module>
        # "run" or "skip" for one shard of the workflow's matrix (one safety module per job): a pull request
        # mutates only the modules it changed, or all of them when it changed the setup
    git diff --name-only <base>...HEAD | python scripts/mutation_ci.py targets
        # the mutmut name patterns to run on a pull request: the safety modules it changed (`warden.gate*` ...),
        # or nothing - every safety module - when it changed the mutation setup itself (pyproject, lock, workflow)
    python scripts/mutation_ci.py summary mutants/mutmut-cicd-stats.json [--min-score 0.8]
        # the score as Markdown for the job summary; with --min-score, exit 1 below it (not used yet: the job is
        # non-blocking until the first full runs show where the suite stands)

The safety modules are pyproject.toml's [tool.mutmut] only_mutate - one list, read here, never repeated.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
# A change to any of these changes how every module is mutated: the whole set runs.
SETUP_FILES = frozenset({"pyproject.toml", "uv.lock", ".github/workflows/mutation.yml", "scripts/mutation_ci.py"})
# Counted against the suite: a mutant no test killed, one that hung, or one that crashed the interpreter oddly.
NOT_KILLED = ("survived", "timeout", "suspicious", "segfault")
SUMMARY_TITLE = "## Mutation testing - safety modules\n\n"


def safety_modules(pyproject: pathlib.Path = ROOT / "pyproject.toml") -> list[str]:
    return list(tomllib.loads(pyproject.read_text(encoding="utf-8"))["tool"]["mutmut"]["only_mutate"])


def targets(changed: list[str], modules: list[str]) -> list[str]:
    """mutmut name patterns for the changed safety modules; [] (= all) when the setup changed or none did."""
    changed = [c.strip() for c in changed if c.strip()]
    if any(c in SETUP_FILES for c in changed):
        return []
    hit = [m for m in modules if m in changed]
    return [f"warden.{pathlib.PurePosixPath(m).stem}*" for m in hit]


def shard_runs(module: str, changed: list[str], modules: list[str]) -> bool:
    """Whether the matrix job for `module` (a safety module's stem) mutates it: every job does on a schedule or by
    hand (nothing changed is passed) and when the setup changed; on a pull request, only a changed module's job."""
    wanted = targets(changed, modules)
    return not wanted or f"warden.{module}*" in wanted


def score(stats: dict[str, int]) -> float | None:
    """Killed over every mutant a test ran against; None when no mutant was tested."""
    tested = stats.get("killed", 0) + sum(stats.get(k, 0) for k in NOT_KILLED)
    return stats.get("killed", 0) / tested if tested else None


def summary(stats: dict[str, int]) -> str:
    s = score(stats)
    rows = "\n".join(f"| {k} | {stats.get(k, 0)} |" for k in ("killed", *NOT_KILLED, "no_tests", "skipped", "total"))
    head = f"Mutation score: **{s:.1%}**" if s is not None else "Mutation score: **no mutant was tested**"
    return (f"{SUMMARY_TITLE}{head} (killed / tested)\n\n| mutants | count |\n|---|---|\n"
            f"{rows}\n\nA survivor is a change to a guard that no test noticed: `mutmut results` lists them, "
            "`mutmut show <name>` shows one.\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("targets")
    sh = sub.add_parser("shard")
    sh.add_argument("module")
    s = sub.add_parser("summary")
    s.add_argument("stats", type=pathlib.Path)
    s.add_argument("--min-score", type=float)
    args = parser.parse_args(argv)
    if args.cmd == "targets":
        print(" ".join(targets(sys.stdin.read().splitlines(), safety_modules())))
        return 0
    if args.cmd == "shard":
        modules = safety_modules()
        if args.module not in {pathlib.PurePosixPath(m).stem for m in modules}:
            parser.error(f"{args.module} is not a safety module in pyproject.toml [tool.mutmut]")
        print("run" if shard_runs(args.module, sys.stdin.read().splitlines(), modules) else "skip")
        return 0
    if not args.stats.is_file():
        # mutmut stopped before it wrote any result (a failed install or run): the summary says so, never a score.
        print(f"{SUMMARY_TITLE}Mutation score: **unavailable** - no mutation data was produced ({args.stats.name} "
              "is missing); see the run step's log.\n")
        return 1 if args.min_score is not None else 0
    stats = json.loads(args.stats.read_text(encoding="utf-8"))
    print(summary(stats))
    if args.min_score is not None:
        got = score(stats)
        if got is None or got < args.min_score:
            print(f"below the minimum mutation score {args.min_score:.0%}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
