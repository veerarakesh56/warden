"""Render the per-environment IAM files from iam/templates/ - one boundary, deploy policy and trust
policy per environment in src/warden/data/environments.yaml (v2 Phase 1.5).

    python scripts/render_env_iam.py            # write iam/<env>/{boundary,deploy,deploy-ec2,trust,actor,...}.json
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
import re
import string
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from warden.environments import EnvironmentPolicies, names

TEMPLATES = ROOT / "iam" / "templates"
# The deploy role's permissions are two managed policies: one is near IAM's 6,144-character limit. The actor and
# platform-reader roles are WARDEN's own per-environment identities for its AWS platform (G6, audit A-P-5): the
# runtime worker assumes the reader to read, and the actor - for one approved plan - to write.
KINDS = ("boundary", "deploy", "deploy-ec2", "deploy-guard", "trust", "actor", "actor-trust", "platform-reader", "platform-diagnose",
         "platform-reader-trust", "kill-switch")
TRUSTS = ("trust", "actor-trust", "platform-reader-trust")
# WARDEN's own runtime environment (`runtime:` in environments.yaml) gets no application IAM: its deploy role - the one
# runtime.yml assumes - and the boundary on every role terraform/runtime makes come from the runtime-* templates (G6).
RUNTIME_KINDS = ("boundary", "deploy", "deploy-ec2", "deploy-guard", "trust")
# The benchmark harness and the undo lab run only where environments.yaml `fault_environments` says, as the operator
# on the laptop (owner, 2026-10-02; audit A-I-18) - the list is configuration, never named here.
HARNESS_ENVS = EnvironmentPolicies.load().fault_environments


def _install() -> dict[str, str]:
    """What every template may name beside its own environment: WARDEN's runtime environment (whose zone roles the
    reader and actor trust), this repository as GitHub's OIDC token names it, and the branch the runtime pipeline runs
    from (2026-10-16; an application environment's trust names its own branch, `${env}`) - all from environments.yaml."""
    cfg = EnvironmentPolicies.load()
    return {"runtime": cfg.runtime_environment or "", "github_repository": cfg.github.get("repository", ""),
            "github_subject": cfg.github.get("subject", ""), "runtime_branch": cfg.github.get("runtime_branch", "")}


ACCOUNT_PLACEHOLDER = "<ACCOUNT_ID>"  # what a committed file holds where the account goes


def render(env: str, account: str = ACCOUNT_PLACEHOLDER, cluster: str = "<CLUSTER_RESOURCE_ID>") -> dict[str, str]:
    """{kind: JSON text} for one environment. substitute() fails on any unknown placeholder. `cluster` is the
    environment's Aurora cluster resource id (stack.json `aurora_cluster_resource_id`), for the harness policy."""
    out = {}
    for kind in (*KINDS, "harness", "harness-lab", "harness-trust") if env in HARNESS_ENVS else KINDS:
        text = string.Template((TEMPLATES / f"{kind}.json").read_text(encoding="utf-8"))
        # env_sql: the environment as a database user name has it - `_` for `-` (audit A-I-1/A-I-2).
        rendered = json.loads(text.substitute(env=env, env_sql=env.replace("-", "_"), account=account,
                                              cluster_resource_id=cluster, region=names(env).region,
                                              global_region=EnvironmentPolicies.load().aws_global_region,
                                              **_install()))
        out[kind] = json.dumps(rendered, indent=2) + "\n"
    return out


def environments() -> tuple[str, ...]:
    return EnvironmentPolicies.load().known_environments


def runtime_environment() -> str:
    return EnvironmentPolicies.load().runtime_environment


def render_runtime(env: str, account: str = ACCOUNT_PLACEHOLDER) -> dict[str, str]:
    """{kind: JSON text} for the runtime environment, from iam/templates/runtime-<kind>.json."""
    out = {}
    for kind in RUNTIME_KINDS:
        text = string.Template((TEMPLATES / f"runtime-{kind}.json").read_text(encoding="utf-8"))
        out[kind] = json.dumps(json.loads(text.substitute(env=env, account=account, region=names(env).region,
                                                          **_install())), indent=2) + "\n"
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--account", action="store_true",
                   help="also write gitignored trust.local.json files with this account's id")
    p.add_argument("--cluster-resource-id", metavar="ID",
                   help="also write a gitignored harness.local.json naming this Aurora cluster (cluster-...)")
    args = p.parse_args(argv)
    account = None
    if args.account:
        import boto3

        account = boto3.client("sts").get_caller_identity()["Account"]
    # Every file is written with LF, as the repository stores it (.gitattributes, 2026-10-16): on Windows a render
    # wrote CRLF, and every rendered file showed as changed.
    for env in environments():
        d = ROOT / "iam" / env
        d.mkdir(parents=True, exist_ok=True)
        for kind, text in render(env).items():
            (d / f"{kind}.json").write_text(text, encoding="utf-8", newline="\n")
        if account:
            # Every file that names the account (the trusts, and the actor's rds-db:connect - review, PR 48) gets a
            # git-ignored render with it; the committed one keeps <ACCOUNT_ID>.
            mine = render(env, account)
            for kind, text in render(env).items():
                if ACCOUNT_PLACEHOLDER in text and kind not in ("harness", "harness-trust"):
                    (d / f"{kind}.local.json").write_text(mine[kind], encoding="utf-8", newline="\n")
            if env in HARNESS_ENVS:
                (d / "harness-trust.local.json").write_text(render(env, account)["harness-trust"], encoding="utf-8", newline="\n")
        if args.cluster_resource_id and env in HARNESS_ENVS:
            if not re.fullmatch(r"cluster-[A-Z0-9]{10,40}", args.cluster_resource_id):
                p.error("--cluster-resource-id must look like cluster-ABC123... (the cluster's Resource ID)")
            (d / "harness.local.json").write_text(render(env, cluster=args.cluster_resource_id)["harness"],
                                                  encoding="utf-8", newline="\n")
    runtime = runtime_environment()
    d = ROOT / "iam" / runtime
    d.mkdir(parents=True, exist_ok=True)
    for kind, text in render_runtime(runtime).items():
        (d / f"{kind}.json").write_text(text, encoding="utf-8", newline="\n")
    if account:
        (d / "trust.local.json").write_text(render_runtime(runtime, account)["trust"], encoding="utf-8", newline="\n")
    print(f"rendered {len(environments())} environments and the runtime ({runtime}) into iam/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
