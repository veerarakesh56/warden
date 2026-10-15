"""The bench approver (owner, 2026-10-15): Claude's own test identity - its own Ed25519 key, `dev` only, T1/T2 - shown an
incident's waiting plan and approving it through the approval page's signed path (approval_page._signed_request).

    python scripts/bench_approve.py --new-key --environment <env>  # once: makes the key, prints the approver entry
    python scripts/bench_approve.py --incident <id>                # shows the plan this approver may approve
    python scripts/bench_approve.py --incident <id> --approve      # signs and sends the approval
    python scripts/bench_approve.py --record <id|latest>           # reads a record (dev only, read only)

The key lives at WARDEN_BENCH_KEY (default ~/.warden-bench/bench-approver.pem), never in the repository. The approval
domain comes from the runtime's settings (SSM /warden/<runtime env>/tf/approval_domain) unless --domain names it. Every approval it sends is
on the record as `bench`, the name the approver list shows as "bench approver (Claude), test".
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import urllib.request
from datetime import UTC, datetime

NAME = "bench"


def _key_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get("WARDEN_BENCH_KEY") or pathlib.Path.home() / ".warden-bench" / "bench-approver.pem")


def new_key(environment: str) -> str:
    """Make the key (refuses to overwrite one) and return the approver list's entry for it: `environment` only."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = _key_path()
    if path.exists():
        raise SystemExit(f"{path} exists: one bench key; delete it first to make another")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    import yaml

    return yaml.safe_dump({NAME: {"name": "bench approver (Claude), test", "tiers": ["T1", "T2"],
                                  "environments": [environment], "public_key": pem}}, sort_keys=False)


def _post(domain: str, step: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(f"https://{domain}/a/signed/{step}", data=json.dumps(body).encode(),  # nosec B310
                                 method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310 - https to the approval domain only
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--new-key", action="store_true")
    ap.add_argument("--environment", default="", help="with --new-key: the one environment the bench may approve in")
    ap.add_argument("--incident", default="")
    ap.add_argument("--approve", action="store_true")
    ap.add_argument("--domain", default="")
    ap.add_argument("--record", default="", help="read an incident's record, or `latest` for the newest ones")
    args = ap.parse_args(argv)
    if args.new_key:
        if not args.environment:
            ap.error("--new-key needs --environment")
        print(new_key(args.environment))
        return 0
    if not (args.incident or args.record):
        ap.error("--incident or --record is needed")
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(_key_path().read_bytes(), password=None)
    domain = args.domain
    if not domain:
        import boto3

        from warden.environments import default_environment_policies

        runtime = default_environment_policies().runtime_environment
        domain = boto3.client("ssm").get_parameter(Name=f"/warden/{runtime}/tf/approval_domain")["Parameter"]["Value"]
    from warden import approvals

    issued = datetime.now(UTC).isoformat()
    if args.record:
        wanted = "" if args.record == "latest" else args.record
        status, got = _post(domain, "record", {
            "approver": NAME, "incident": wanted, "issued_at": issued,
            "signature": key.sign(approvals.record_request(NAME, wanted, issued)).hex()})
        print(json.dumps(got, indent=2) if status == 200 else f"no record ({status}): {got.get('error', '')}")
        return 0 if status == 200 else 1
    status, plan = _post(domain, "plan", {"approver": NAME, "incident": args.incident, "issued_at": issued,
                                          "signature": key.sign(approvals.plan_request(NAME, args.incident, issued)).hex()})
    if status != 200:
        print(f"no plan to approve ({status}): {plan.get('error', '')}")
        return 1
    print(f"plan {plan['workflow_id']}: {plan['entry']} on {plan['target']} - tier {plan['tier']}, {plan['environment']}")
    if not args.approve:
        return 0
    a = approvals.sign(key, approver=NAME, workflow_id=plan["workflow_id"], plan_hash=plan["plan_hash"], tier=plan["tier"])
    status, got = _post(domain, "approve", json.loads(a.model_dump_json()))
    print("approved as the bench approver" if status == 202 else f"refused ({status}): {got.get('error', '')}")
    return 0 if status == 202 else 1


if __name__ == "__main__":
    sys.exit(main())
