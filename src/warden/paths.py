"""Where a path named on a command line may point (Sonar pythonsecurity:S8707, 2026-10-16).

An agent can drive WARDEN's command line and the repository's scripts, so a path taken from argv is untrusted: after
`..` and symlinks are resolved it must lie inside a place these tools work in - the working directory (the checkout),
the temp folder (and a CI job's RUNNER_TEMP), or one of the tools' own output folders in the home directory (bench runs,
AWS proof runs, the Wave 4 build). ~/.ssh, ~/.aws, /etc or a synced folder are refused, whichever way the path is
spelled - also by a tool run from the home directory, which is then no working place. Key files have a folder of
their own (audit.key_path). Stdlib only: the deploy jobs import this without installing the package, and the benchmark
harness loads this one file by its path without importing the tool under test. The tool names nothing of the harness
in return (tests/test_no_scenario_leakage.py).
"""

from __future__ import annotations

import os
import pathlib
import tempfile

BENCH_DIR_ENV = "WARDEN_BENCH_DIR"
# The tools' output folders under the home directory (the bench runner, scripts/aws_proof.sh,
# scripts/deploy_fullstack_apps.py), and the variables that move the first two elsewhere.
HOME_FOLDERS = ("warden-bench-runs", "warden-proof-runs", "warden-fullstack-build")
FOLDER_ENVS = (BENCH_DIR_ENV, "WARDEN_PROOF_DIR", "RUNNER_TEMP")


def bench_dir() -> pathlib.Path:
    """Where the bench runner writes its runs: WARDEN_BENCH_DIR, or ~/warden-bench-runs."""
    return pathlib.Path(os.environ.get(BENCH_DIR_ENV) or pathlib.Path.home() / HOME_FOLDERS[0]).expanduser()


def work_roots() -> list[pathlib.Path]:
    """The working directory - unless it is the home directory or holds it: run from ~, a tool would otherwise read and
    write ~/.ssh and ~/.aws (CodeRabbit, PR 46) - the temp folder, the tools' own folders and the folders set for
    them."""
    home = pathlib.Path.home()
    cwd = pathlib.Path.cwd().resolve()
    here = [] if home.expanduser().resolve().is_relative_to(cwd) else [cwd]
    return [*here, pathlib.Path(tempfile.gettempdir()), *(home / f for f in HOME_FOLDERS),
            *(pathlib.Path(os.environ[e]) for e in FOLDER_ENVS if os.environ.get(e))]


def inside(path: str | os.PathLike, roots: list[pathlib.Path] | None = None) -> pathlib.Path:
    """The real (absolute, resolved) location of `path` when it lies inside one of `roots` (default: work_roots());
    else ValueError. Absolute, so it can never be read as an option by a program it is passed to. A root that is a
    whole filesystem (`/`, `C:\\`) counts as none."""
    real = pathlib.Path(path).expanduser().resolve()
    # A filesystem root holds everything (a container's working directory is often `/`): it is never a place.
    bases = [b for b in (pathlib.Path(r).expanduser().resolve() for r in (roots or work_roots())) if b.parent != b]
    for base in bases:
        if real.is_relative_to(base):
            return real
    raise ValueError(f"{path} is outside the places WARDEN's tools work in ({', '.join(map(str, bases))}): a path "
                     "from the command line must lie inside the working directory, the temp folder or a tool's "
                     "output folder")
