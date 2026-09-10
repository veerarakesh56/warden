"""Turn a benchmark run directory into something safe to commit.

    python scripts/publish_bench_run.py --run ~/warden-bench-runs/wave1-... --into docs/bench

A wave writes RAW artefacts outside the repository on purpose: a task-definition ARN contains the
12-digit account id, and so does every assumed-role ARN. This copies a run in, redacted, and refuses
to complete if anything that must not be published survives the copy.

⛔ THE ORDER MATTERS AND IS THE WHOLE POINT. Redact into a staging directory, VERIFY the staging
directory with the same scanner that guards the repo, and only then copy into the working tree.
"The redactor ran" and "the redactor worked" are different claims, and only the second one is worth
anything. A failed verification leaves the repo untouched.

⚠ It cannot invent honesty. It republishes what the run recorded — every ERROR, every NO-EVIDENCE,
every disagreement between repeats. There is no path in this file that turns a failure into a pass.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# The same shapes scripts/aws_proof_bundle.py masks. Deliberately duplicated in behaviour but kept
# to one implementation here by importing it, so the two cannot drift into disagreeing about what a
# secret looks like.
sys.path.insert(0, str(ROOT / "scripts"))
from aws_proof_bundle import _redact


def _redact_tree(src: pathlib.Path, dst: pathlib.Path, account: str) -> int:
    """Copy src -> dst, redacting every text file on the way. Returns files copied."""
    copied = 0
    for path in sorted(src.rglob("*")):
        if path.is_dir():
            continue
        target = dst / path.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix.lower() in (".json", ".md", ".txt", ".log", ".yaml", ".yml"):
            target.write_text(
                _redact(path.read_text(encoding="utf-8", errors="replace"), account),
                encoding="utf-8",
            )
        else:
            # ⛔ Anything not known to be text is NOT copied. A binary artefact cannot be redacted by
            # a regex over its decoded bytes, and copying it unredacted is the failure this whole
            # script exists to prevent.
            print(f"  skipped (not a redactable text file): {path.relative_to(src)}")
            continue
        copied += 1
    return copied


def _account_from(run: pathlib.Path) -> str:
    """The account id to mask, taken from the run's own manifest rather than from the environment."""
    manifest = run / "manifest.json"
    if manifest.exists():
        text = manifest.read_text(encoding="utf-8")
        found = re.findall(r"\b\d{12}\b", text)
        if found:
            return found[0]
    for path in (run / "ground-truth").glob("*.json"):
        found = re.findall(r"\b\d{12}\b", path.read_text(encoding="utf-8"))
        if found:
            return found[0]
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", required=True, help="a directory written by scenarios.runner")
    parser.add_argument("--into", default="docs/bench", help="destination inside the repo")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8")  # a Windows console is cp1252 and cannot print ⛔
    run = pathlib.Path(args.run).resolve()
    if not (run / "manifest.json").exists():
        print(f"{run} has no manifest.json - not a runner output directory")
        return 1
    if not (run / "RESULTS.md").exists():
        print("no RESULTS.md - score the run first:  python -m scenarios.score --run <dir>")
        return 1

    account = _account_from(run)
    print(f"run     : {run.name}")
    print(f"masking : {'a 12-digit account id' if account else 'no account id found in the manifest'}")

    staging = run.parent / f"{run.name}-redacted"
    if staging.exists():
        shutil.rmtree(staging)
    copied = _redact_tree(run, staging, account)
    print(f"redacted: {copied} file(s) -> {staging}")

    # ⛔ Verify INDEPENDENTLY, before anything enters the working tree.
    print("\nverifying the redacted copy with the repo's own scanner:")
    check = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_publishable.py"), "--dir", str(staging)],
        capture_output=True, text=True, check=False,
    )
    print(check.stdout.rstrip() or check.stderr.rstrip())
    if check.returncode != 0:
        print("\n⛔ THE REDACTED COPY DID NOT PASS. Nothing was copied into the repo.")
        print(f"   Inspect it at: {staging}")
        return 1

    dest = ROOT / args.into / run.name
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(staging, dest)
    print(f"\ncopied into the repo: {dest.relative_to(ROOT)}")

    summary = json.loads((run / "results.json").read_text(encoding="utf-8"))["summary"]
    print(f"  {summary['runs']} runs over {summary['scenarios']} scenarios")
    print(f"  DIAGNOSIS WRONG AND GATE ALLOWED: {summary['headline_wrong_and_allowed']}")
    print("\nNow run:  python scripts/check_publishable.py --staged   (after git add)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
