"""CI · autofix, step 2 (register B4, phase 4): the code gate over a pull request's own diff and commits, as GitHub
holds them. A pull request from a `warden/` branch must be one commit on its base that exactly reverts the commit its
message names, and pass the gate in its environment's mode; any other pull request has nothing more to check here.

Reads HEAD_REF, BASE_SHA and HEAD_SHA from the environment (the workflow passes the event's values that way, never in
the shell's text). Exit 0: passes; exit 1: refused, each reason printed."""

from __future__ import annotations

import os
import subprocess
import sys


def git(*args: str) -> str:
    # `git grep` exits 1 when nothing matches: no import lines is an answer, not an error.
    done = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if done.returncode not in (0, 1) or (done.returncode == 1 and args[0] != "grep"):
        raise SystemExit(f"git {args[0]} failed: {done.stderr.strip()[:300]}")
    return done.stdout


def main() -> int:
    from warden.code_fix import ci_check

    ok, notes = ci_check(os.environ.get("HEAD_REF", ""), os.environ.get("BASE_SHA", ""), os.environ.get("HEAD_SHA", ""),
                         git)
    for note in notes:
        print(("" if ok else "::error::") + note)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
