"""Eldane's review of a saved Terraform plan, for `.github/workflows/_infra-deploy.yml` action `eldane-apply` (B3; dev only).

  review: python scripts/eldane_plan_review.py review --plan plan.json --tfplan tfplan --environment ENV --stack STACK
          --run-id RUN --commit SHA --out eldane.json
          Writes the review (src/warden/plan_review.py) and prints what it decided; exit 0 when Eldane approved exactly
          this plan, 3 when a person reviews it (apply-plan with the run id and sha256 printed), 2 for bad arguments.
  check:  python scripts/eldane_plan_review.py check --review eldane.json --tfplan tfplan --environment ENV
          --stack STACK --run-id RUN --commit SHA
          Right before apply: exit 0 only when the review approved exactly this file (its sha256 now), run, commit,
          stack and environment; 1 otherwise.

It runs with no cloud credentials (the workflow unsets them for this step) and reads the plan's JSON only to make the
redacted summary Eldane is shown. Every file it reads or writes is inside the run's temporary folder (RUNNER_TEMP, or
the current folder when that is not set).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from warden import plan_review  # after the sys.path line above: it runs from a checkout


def _inside(path: str) -> pathlib.Path:
    """`path`, resolved, when it is inside the run's own folder; else ValueError (no file elsewhere is read or written)."""
    base = pathlib.Path(os.environ.get("RUNNER_TEMP") or os.getcwd()).resolve(strict=True)
    real = pathlib.Path(path).resolve()
    if not real.is_relative_to(base) or real == base:
        raise ValueError(f"{path} is outside {base}")
    return real


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _critic():
    """Eldane's provider and identity as the step configures it (eldane.Critic.from_environment), or (None, "")."""
    from warden import eldane

    critic = eldane.Critic.from_environment()
    if critic is None:
        return None, ""
    model = critic.models[0]
    # Its identity with the infrastructure prompt it is asked with (plan_review.SYSTEM), not a fix plan's.
    return critic.provider(model), f"{critic.name}/{model}@{plan_review.PROMPT_SHA}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("review", "check"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--tfplan", required=True)
        cmd.add_argument("--environment", required=True)
        cmd.add_argument("--stack", required=True)
        cmd.add_argument("--run-id", required=True)
        cmd.add_argument("--commit", required=True)
        if name == "review":
            cmd.add_argument("--plan", required=True)
            cmd.add_argument("--out", required=True)
        else:
            cmd.add_argument("--review", required=True)
    args = parser.parse_args(argv)
    try:
        tfplan = _inside(args.tfplan)
        bound = {"environment": args.environment, "stack": args.stack, "run_id": args.run_id,
                 "sha256": _sha256(tfplan), "commit": args.commit}
        if args.command == "check":
            problems = plan_review.approval(_inside(args.review).read_text(encoding="utf-8"), **bound)
            for p in problems:
                print(f"::error::not applied: {p}")
            return 1 if problems else 0
        plan = json.loads(_inside(args.plan).read_text(encoding="utf-8"))
        out = _inside(args.out)
    except (OSError, ValueError) as exc:
        print(f"::error::{exc}")
        return 2
    provider, critic = _critic()
    got = plan_review.review(plan, provider=provider, critic=critic, **bound)
    out.write_text(got.to_json(), encoding="utf-8")
    head = "approves exactly this plan" if got.approved else "does not approve this plan: a person reviews it"
    print(f"### {got.label} {head}")
    print(f"run `{got.run_id}` · commit `{got.commit}` · plan sha256 `{got.sha256}` · critic `{got.critic or 'none'}`")
    for why in got.why:
        print(f"- {why}")
    if not got.approved:
        print(f"A person applies it with Deploy · {got.environment} → infra_action apply-plan, run id {got.run_id} "
              f"and sha256 {got.sha256}, after reading it.")
    return 0 if got.approved else 3


if __name__ == "__main__":
    sys.exit(main())
