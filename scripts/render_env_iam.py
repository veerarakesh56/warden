"""Render the per-environment IAM files from iam/templates/ - one boundary, deploy policy and trust
policy per environment in src/warden/data/environments.yaml (v2 Phase 1.5).

    python scripts/render_env_iam.py            # write iam/<env>/{boundary,deploy,trust}.json
    python scripts/render_env_iam.py --account   # also trust.local.json with the real account id
                                                 # (gitignored; for pasting into the console)

The rendered files are COMMITTED: the owner pastes them from GitHub, IAM Access Analyzer validates
exactly these bytes, and tests/test_env_iam.py fails if a file drifts from its template. The
committed trust.json carries `<ACCOUNT_ID>`, never the account id.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import string
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from warden.environments import EnvironmentPolicies

TEMPLATES = ROOT / "iam" / "templates"
KINDS = ("boundary", "deploy", "trust")


def render(env: str, account: str = "<ACCOUNT_ID>") -> dict[str, str]:
    """{kind: JSON text} for one environment. substitute() fails on any unknown placeholder."""
    out = {}
    for kind in KINDS:
        text = string.Template((TEMPLATES / f"{kind}.json").read_text(encoding="utf-8"))
        rendered = json.loads(text.substitute(env=env, account=account))
        out[kind] = json.dumps(rendered, indent=2) + "\n"
    return out


def environments() -> tuple[str, ...]:
    return EnvironmentPolicies.load().known_environments


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--account", action="store_true",
                   help="also write gitignored trust.local.json files with this account's id")
    args = p.parse_args(argv)
    account = None
    if args.account:
        import boto3

        account = boto3.client("sts").get_caller_identity()["Account"]
    for env in environments():
        d = ROOT / "iam" / env
        d.mkdir(parents=True, exist_ok=True)
        for kind, text in render(env).items():
            (d / f"{kind}.json").write_text(text, encoding="utf-8")
        if account:
            (d / "trust.local.json").write_text(render(env, account)["trust"], encoding="utf-8")
    print(f"rendered {len(environments())} environments into iam/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
