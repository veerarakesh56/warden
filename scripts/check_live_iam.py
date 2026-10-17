"""Every WARDEN policy and trust, live, against its file in iam/ - so a paste into the wrong policy is caught the same
day (2026-10-15: the boundary's statements had been pasted into WardenPlatformReader-dev on 2026-10-14, and the cloud
read role was no longer read-only).

    AWS_PROFILE=warden python scripts/check_live_iam.py [--env NAME ...]

Read-only: iam:GetPolicy, GetPolicyVersion, GetRole by name (the operator may not list policies). A file with
placeholders is compared through its git-ignored `.local.json` render when there is one. Exit 1 when anything
differs; a policy that does not exist in the account is reported, not counted as a difference. Prints names and
verdicts only, never a document or an account id.
"""

from __future__ import annotations

import argparse
import functools
import json
import pathlib
import sys
import urllib.parse
from collections.abc import Callable
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
# (live policy name, file kind) per environment; the env is filled in.
POLICIES = (("WardenEnvBoundary-{env}", "boundary"), ("WardenEnvDeploy-{env}", "deploy"),
            ("WardenEnvDeployEc2-{env}", "deploy-ec2"), ("WardenPlatformReader-{env}", "platform-reader"),
            ("WardenPlatformDiagnose-{env}", "platform-diagnose"), ("WardenActor-{env}", "actor"),
            ("WardenHarness-{env}", "harness"), ("WardenDeployGuard-{env}", "deploy-guard"))
# (live role name, trust file kind).
TRUSTS = (("warden-{env}-deploy", "trust"), ("warden-{env}-platform-reader", "platform-reader-trust"),
          ("warden-{env}-actor", "actor-trust"), ("warden-{env}-harness", "harness-trust"),
          ("warden-{env}-reader", "reader-trust"))


def norm(doc: Any) -> Any:
    """A policy document with key order and list order made irrelevant: IAM evaluates statements, actions and
    condition values as sets, and the console may reorder them."""
    if isinstance(doc, dict):
        return {k: norm(v) for k, v in sorted(doc.items())}
    if isinstance(doc, list):
        return sorted((norm(v) for v in doc), key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(doc, str) and doc.startswith("%7B"):
        return norm(json.loads(urllib.parse.unquote(doc)))
    return doc


def _file(env: str, kind: str) -> pathlib.Path | None:
    for name in (f"{kind}.local.json", f"{kind}.json"):
        p = ROOT / "iam" / env / name
        if p.is_file():
            return p
    return None


def _doc(value: Any) -> Any:
    return json.loads(urllib.parse.unquote(value)) if isinstance(value, str) else value


def _verdict(path: pathlib.Path, read_live: Callable[[], Any]) -> str:
    """MATCHES, DIFFERS, NOT IN ACCOUNT, UNREADABLE (...) or FILE HAS PLACEHOLDERS for one file and its live document."""
    want = path.read_text(encoding="utf-8")
    if "<" in want and ">" in want and not path.name.endswith(".local.json"):
        return "FILE HAS PLACEHOLDERS"
    try:
        live = read_live()
    except Exception as exc:  # noqa: BLE001 - one missing policy does not stop the rest
        return ("NOT IN ACCOUNT" if "NoSuchEntity" in type(exc).__name__ + str(exc) else
                f"UNREADABLE ({type(exc).__name__})")
    return "MATCHES" if norm(_doc(live)) == norm(json.loads(want)) else "DIFFERS"


def _live_policy(iam: Any, account: str, name: str) -> Any:
    arn = f"arn:aws:iam::{account}:policy/{name}"
    version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    return iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]


def _live_trust(iam: Any, name: str) -> Any:
    return iam.get_role(RoleName=name)["Role"]["AssumeRolePolicyDocument"]


def check(iam: Any, account: str, envs: list[str]) -> list[tuple[str, str]]:
    """(name, verdict) for every policy and trust whose file exists: MATCHES, DIFFERS, NOT IN ACCOUNT, or FILE HAS
    PLACEHOLDERS (no `.local.json` render to compare)."""
    out = []
    for env in envs:
        for template, kind in POLICIES:
            path, name = _file(env, kind), template.format(env=env)
            if path is not None:
                out.append((name, _verdict(path, functools.partial(_live_policy, iam, account, name))))
        for template, kind in TRUSTS:
            path, name = _file(env, kind), template.format(env=env)
            if path is not None:
                out.append((f"{name} trust", _verdict(path, functools.partial(_live_trust, iam, name))))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--env", action="append", default=[], help="an environment folder under iam/ (default: every one with a boundary.json)")
    args = ap.parse_args(argv)
    import boto3

    session = boto3.Session()
    account = session.client("sts").get_caller_identity()["Account"]
    envs = args.env or sorted(p.parent.name for p in (ROOT / "iam").glob("*/boundary.json"))
    iam, results = session.client("iam"), []
    for env in envs:
        found = check(iam, account, [env])
        # By default only the environments made in this account: one with nothing in it was never created.
        if args.env or any(v != "NOT IN ACCOUNT" for _, v in found):
            results += found
    for name, verdict in results:
        print(f"{verdict:22} {name}")
    return 1 if any(v in ("DIFFERS",) or v.startswith("UNREADABLE") for _, v in results) else 0


if __name__ == "__main__":
    sys.exit(main())
