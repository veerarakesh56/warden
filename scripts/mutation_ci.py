"""Mutation testing in CI (B37): which safety modules to mutate, and the score, for .github/workflows/mutation.yml.

    git diff --name-only <base>...HEAD | python scripts/mutation_ci.py shard <module>
        # "run" or "skip" for one shard of the workflow's matrix (one safety module per job): a pull request
        # mutates only the modules it changed, or all of them when it changed the setup
    python scripts/mutation_ci.py warm-temporal
        # fetch Temporal's time-skipping test server once, retried with backoff: eight jobs fetching it at once were
        # answered 429 Too Many Requests (PR 179), and every Temporal test in that job's run then failed
    python scripts/mutation_ci.py narrow <module>
        # in a CI job's own checkout: pyproject's only_mutate becomes that one module, so a plain `mutmut run` mutates
        # it. (A name pattern - `mutmut run "warden.gate*"` - makes mutmut run its clean tests by node id, and ids
        # of tests parametrized with newlines or brackets broke that command on CI, PR 179.)
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
import re
import sys
import time
import tomllib
from collections.abc import Callable

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


def narrowed(pyproject_text: str, module: str) -> str:
    """pyproject.toml's text with [tool.mutmut] only_mutate reduced to one safety module (its stem)."""
    path = next((m for m in safety_modules_from(pyproject_text) if pathlib.PurePosixPath(m).stem == module), None)
    if path is None:
        raise ValueError(f"{module} is not a safety module in pyproject.toml [tool.mutmut]")
    block = re.compile(r"^only_mutate = \[[^\]]*\]", re.MULTILINE)
    if len(block.findall(pyproject_text)) != 1:
        raise ValueError("pyproject.toml must hold exactly one only_mutate list")
    return block.sub(f'only_mutate = ["{path}"]', pyproject_text)


def safety_modules_from(pyproject_text: str) -> list[str]:
    return list(tomllib.loads(pyproject_text)["tool"]["mutmut"]["only_mutate"])


def warm_temporal(start: Callable[[], None], attempts: int = 5, wait_s: float = 30.0,
                  sleep: Callable[[float], None] = time.sleep) -> int:
    """Run `start` (fetch and start the test server once) until it succeeds, waiting longer after each failure;
    the attempt that succeeded, or RuntimeError after the last one."""
    for attempt in range(1, attempts + 1):
        try:
            start()
            return attempt
        except RuntimeError as exc:
            if attempt == attempts:
                raise RuntimeError(f"Temporal's test server could not be fetched after {attempts} attempts") from exc
            print(f"attempt {attempt}: {exc}; trying again in {wait_s * attempt:.0f} s", file=sys.stderr)
            sleep(wait_s * attempt)
    raise AssertionError("unreachable")


def _start_test_server() -> None:
    import asyncio

    from temporalio.testing import WorkflowEnvironment

    async def once() -> None:
        env = await WorkflowEnvironment.start_time_skipping()
        await env.shutdown()

    asyncio.run(once())


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


def _targets(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    print(" ".join(targets(sys.stdin.read().splitlines(), safety_modules())))
    return 0


def _narrow(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    pyproject = ROOT / "pyproject.toml"
    try:
        pyproject.write_text(narrowed(pyproject.read_text(encoding="utf-8"), args.module), encoding="utf-8")
    except ValueError as exc:
        parser.error(str(exc))
    return 0


def _shard(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    modules = safety_modules()
    if args.module not in {pathlib.PurePosixPath(m).stem for m in modules}:
        parser.error(f"{args.module} is not a safety module in pyproject.toml [tool.mutmut]")
    print("run" if shard_runs(args.module, sys.stdin.read().splitlines(), modules) else "skip")
    return 0


def _summary(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
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


def _warm(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    print(f"Temporal's test server is ready (attempt {warm_temporal(_start_test_server)})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("targets")
    sub.add_parser("shard").add_argument("module")
    sub.add_parser("narrow").add_argument("module")
    sub.add_parser("warm-temporal")
    s = sub.add_parser("summary")
    s.add_argument("stats", type=pathlib.Path)
    s.add_argument("--min-score", type=float)
    args = parser.parse_args(argv)
    run = {"targets": _targets, "narrow": _narrow, "shard": _shard, "summary": _summary,
           "warm-temporal": _warm}[args.cmd]
    return run(args, parser)


if __name__ == "__main__":
    sys.exit(main())
