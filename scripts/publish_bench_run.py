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
import hashlib
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


def _content_sha256(data: bytes) -> str:
    """LF-normalised, exactly as scenarios/runner.py hashes it - see there for why."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _from_commit(commit: str, repo_path: str) -> bytes:
    out = subprocess.run(["git", "show", f"{commit}:{repo_path}"], cwd=ROOT,
                         capture_output=True, check=False)
    if out.returncode != 0:
        raise SystemExit(
            f"⛔ cannot read {repo_path} at commit {commit[:12]}: {out.stderr.decode(errors='replace').strip()}\n"
            "   The bundle must carry the rubric the run was graded under. Publishing without it "
            "would produce numbers nobody can reproduce."
        )
    return out.stdout


def _freeze_grading_inputs(run: pathlib.Path, staging: pathlib.Path, account: str) -> list[str]:
    """Copy the rubric and catalog AS OF THE RUN'S COMMIT into the bundle, and prove it by hash.

    ⛔ WHY THIS EXISTS. `scenarios/scoring.yaml` is one file for every wave, so the day Wave 2 adds
    a fault class, its hash stops matching every already-published run - and re-scoring those runs
    raises "THE RUBRIC CHANGED AFTER THIS RUN", which is the loudest warning this project has. The
    warning would be true and useless: the entries those runs were graded by had not changed at all.
    A bundle that carries its own rubric can always be re-scored exactly:

        python -m scenarios.score --run docs/bench/<run> --rubric docs/bench/<run>/grading/scoring.yaml

    ⛔ FROM THE COMMIT, NOT THE WORKING TREE. Freezing whatever happens to be on disk at publish
    time would silently ship a rubric the run was never graded under, which is the very substitution
    the hash check exists to catch. The manifest records both the commit and the rubric's hash, so
    the frozen bytes are verified against it and publishing REFUSES on a mismatch.
    """
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    commit = str(manifest.get("git_commit") or "")
    if not commit:
        raise SystemExit("⛔ the manifest records no git_commit, so the rubric cannot be frozen.")

    frozen: list[str] = []
    grading = staging / "grading"
    grading.mkdir(parents=True, exist_ok=True)

    rubric = _from_commit(commit, "scenarios/scoring.yaml")
    recorded = str(manifest.get("scoring_sha256") or "")
    actual = _content_sha256(rubric)
    if recorded and actual != recorded:
        raise SystemExit(
            f"⛔ the rubric at commit {commit[:12]} hashes to {actual[:12]}, but the run recorded "
            f"{recorded[:12]}. Refusing to publish a bundle whose rubric is not the one it was "
            "graded under."
        )
    (grading / "scoring.yaml").write_text(
        _redact(rubric.decode("utf-8", errors="replace"), account), encoding="utf-8")
    frozen.append(f"grading/scoring.yaml ({actual[:12]}, verified against the manifest)")

    # The catalog is frozen for INSPECTION, not for re-scoring: score.py always reads the catalog
    # from the working tree. Said plainly here rather than implied, so nobody assumes otherwise.
    for name, recorded_hash in (manifest.get("catalog_sha256") or {}).items():
        blob = _from_commit(commit, f"scenarios/catalog/{name}")
        got = _content_sha256(blob)
        if recorded_hash and got != recorded_hash:
            raise SystemExit(
                f"⛔ catalog {name} at commit {commit[:12]} hashes to {got[:12]}, recorded "
                f"{recorded_hash[:12]}. Refusing."
            )
        (grading / name).write_text(
            _redact(blob.decode("utf-8", errors="replace"), account), encoding="utf-8")
        frozen.append(f"grading/{name} ({got[:12]}, verified)")
    return frozen


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
    for line in _freeze_grading_inputs(run, staging, account):
        print(f"  froze {line}")

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
