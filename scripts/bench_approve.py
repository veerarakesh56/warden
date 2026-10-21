"""The bench approver (owner, 2026-10-15): Claude's own test identity - its own Ed25519 key, `dev` only, T1/T2 - shown an
incident's waiting plan and approving it through the approval page's signed path (approval_page._signed_request).

    python scripts/bench_approve.py --new-key --environment <env>  # once: makes the key, prints the approver entry
    python scripts/bench_approve.py --incident <id>                # shows the plan this approver may approve
    python scripts/bench_approve.py --incident <id> --approve      # signs and sends the approval
    python scripts/bench_approve.py --record <id|latest>           # reads a record (dev only, read only)
    python scripts/bench_approve.py --incident <id> --deny "<why>"  # denies the waiting plan, with the reason

The key is bench-approver.pem in WARDEN_BENCH_KEY_DIR (default ~/.warden-bench), never in the repository. The approval
domain comes from the runtime's settings (SSM /warden/<runtime env>/tf/approval_domain) only: a signed approval is sent
to no host a command line names (Sonar pythonsecurity:S8703, 2026-10-16 - `--domain` was that; an agent driving this
script could have posted a valid signature anywhere). Every approval it sends is on the record as `bench`, the name the
approver list shows as "bench approver (Claude), test".

The key at rest (2026-10-16, naming audit item 4: it was always written in the clear, with default permissions). A new
key is encrypted with WARDEN_BENCH_KEY_PASSPHRASE, and written in the clear only with --unencrypted. It is created
once, never over another file, mode 0600 on POSIX. Windows ignores the mode: what keeps other accounts out there is the
profile folder's ACL (only the user, SYSTEM and Administrators) - and the passphrase. A key made before then is still
read, with a warning. Windows DPAPI was weighed and not used: it ties the key to one Windows login, which a run on
another machine cannot use, and any process of that same user decrypts it anyway - the reach a passphrase in that
user's environment has too.
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
PASSPHRASE_ENV = "WARDEN_BENCH_KEY_PASSPHRASE"
# What the clear-key warning tells a person to set: the variable's name, printed; never its value.
UNLOCK_VARIABLE = "WARDEN_BENCH_KEY_PASSPHRASE"  # = PASSPHRASE_ENV (tests/test_key_at_rest.py holds them equal)


KEY_NAME = "bench-approver.pem"


def _key_dir() -> pathlib.Path:
    """The one folder the bench key is written in (audit.write_private_key refuses any other place)."""
    return pathlib.Path(os.environ.get("WARDEN_BENCH_KEY_DIR") or pathlib.Path.home() / ".warden-bench").expanduser()


def _key_path() -> pathlib.Path:
    return _key_dir() / KEY_NAME


def new_key(environment: str, *, unencrypted: bool = False) -> str:
    """Make the key (refuses to overwrite one) and return the approver list's entry for it: `environment` only."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from warden import audit
    from warden.environments import default_environment_policies

    policies = default_environment_policies()
    nonprod = [e for e in policies.known_environments if policies.for_env(e).tier == "nonprod"]
    if environment not in nonprod:
        raise SystemExit(f"no key was written: the bench approver is for a nonprod environment only "
                         f"({', '.join(nonprod) or 'none in environments.yaml'}), not {environment!r}")
    path = _key_path()
    if path.exists():
        raise SystemExit(f"{path} exists: one bench key; delete it first to make another")
    passphrase = os.environ.get(PASSPHRASE_ENV, "").encode()
    if not passphrase and not unencrypted:
        raise SystemExit(f"no key was written: set {PASSPHRASE_ENV} (the key is encrypted with it), or pass "
                         "--unencrypted to write it in the clear")
    if not passphrase:
        print(f"WARNING: --unencrypted: {path} is written IN THE CLEAR; anyone who can read it can approve as the "
              "bench approver", file=sys.stderr)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    encryption = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    audit.write_private_key(path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    encryption), _key_dir())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    import yaml

    return yaml.safe_dump({NAME: {"name": "bench approver (Claude), test", "tiers": ["T1", "T2"],
                                  "environments": [environment], "public_key": pem}}, sort_keys=False)


def load_key():
    """The bench key: decrypted with PASSPHRASE_ENV, or - a key made before 2026-10-16 - read in the clear, with a
    warning."""
    from cryptography.hazmat.primitives import serialization

    path = _key_path()
    pem = path.read_bytes()
    try:
        clear = serialization.load_pem_private_key(pem, password=None)
    except TypeError:  # cryptography's answer for an encrypted key read without its passphrase
        clear = None
    if clear is not None:
        print(f"WARNING: {path} is not encrypted: anyone who can read it can approve as the bench approver. Make an "
              f"encrypted one: set {UNLOCK_VARIABLE}, delete the file, run --new-key and replace the approver entry",
              file=sys.stderr)
        return clear
    passphrase = os.environ.get(PASSPHRASE_ENV, "").encode()
    if not passphrase:
        raise SystemExit(f"{path} is encrypted: set {PASSPHRASE_ENV}")
    return serialization.load_pem_private_key(pem, password=passphrase)


def _post(domain: str, step: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(f"https://{domain}/a/signed/{step}", data=json.dumps(body).encode(),  # nosec B310
                                 method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310 - https to the approval domain only
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _read_record(domain: str, key, record: str) -> int:
    """Print one incident's record (or the newest ones for `latest`), as the bench approver may read it."""
    from warden import approvals

    issued = datetime.now(UTC).isoformat()
    wanted = "" if record == "latest" else record
    status, got = _post(domain, "record", {
        "approver": NAME, "incident": wanted, "issued_at": issued,
        "signature": key.sign(approvals.record_request(NAME, wanted, issued)).hex()})
    print(json.dumps(got, indent=2) if status == 200 else f"no record ({status}): {got.get('error', '')}")
    return 0 if status == 200 else 1


def _deny(domain: str, key, plan: dict, reason: str) -> int:
    """Deny the waiting plan with this reason, signed as the bench approver."""
    from warden import approvals

    issued = datetime.now(UTC).isoformat()
    status, got = _post(domain, "deny", {
        "approver": NAME, "workflow_id": plan["workflow_id"], "plan_hash": plan["plan_hash"], "reason": reason,
        "issued_at": issued, "signature": key.sign(approvals.deny_request(
            NAME, plan["workflow_id"], plan["plan_hash"], reason, issued)).hex()})
    print("denied as the bench approver" if status == 202 else f"refused ({status}): {got.get('error', '')}")
    return 0 if status == 202 else 1


def _approve(domain: str, key, plan: dict) -> int:
    """Approve the waiting plan at its tier, signed as the bench approver."""
    from warden import approvals

    a = approvals.sign(key, approver=NAME, workflow_id=plan["workflow_id"], plan_hash=plan["plan_hash"], tier=plan["tier"])
    status, got = _post(domain, "approve", json.loads(a.model_dump_json()))
    print("approved as the bench approver" if status == 202 else f"refused ({status}): {got.get('error', '')}")
    return 0 if status == 202 else 1


def _decide_on_plan(domain: str, key, args: argparse.Namespace) -> int:
    """Show the incident's waiting plan, then deny it, approve it, or (neither asked) only show it."""
    from warden import approvals

    issued = datetime.now(UTC).isoformat()
    status, plan = _post(domain, "plan", {"approver": NAME, "incident": args.incident, "issued_at": issued,
                                          "signature": key.sign(approvals.plan_request(NAME, args.incident, issued)).hex()})
    if status != 200:
        print(f"no plan to approve ({status}): {plan.get('error', '')}")
        return 1
    print(f"plan {plan['workflow_id']}: {plan['entry']} on {plan['target']} - tier {plan['tier']}, {plan['environment']}")
    if args.deny is not None:
        return _deny(domain, key, plan, args.deny)
    if not args.approve:
        return 0
    return _approve(domain, key, plan)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--new-key", action="store_true")
    ap.add_argument("--environment", default="", help="with --new-key: the one environment the bench may approve in")
    ap.add_argument("--unencrypted", action="store_true",
                    help=f"with --new-key: write the key in the clear (refused otherwise without {PASSPHRASE_ENV})")
    ap.add_argument("--incident", default="")
    ap.add_argument("--approve", action="store_true")
    ap.add_argument("--deny", default=None, help="deny the waiting plan, with this reason")
    ap.add_argument("--record", default="", help="read an incident's record, or `latest` for the newest ones")
    args = ap.parse_args(argv)
    if args.new_key:
        if not args.environment:
            ap.error("--new-key needs --environment")
        print(new_key(args.environment, unencrypted=args.unencrypted))
        return 0
    if not (args.incident or args.record):
        ap.error("--incident or --record is needed")
    key = load_key()
    import boto3

    from warden.environments import default_environment_policies

    runtime = default_environment_policies().runtime_environment
    domain = boto3.client("ssm").get_parameter(Name=f"/warden/{runtime}/tf/approval_domain")["Parameter"]["Value"]
    if args.record:
        return _read_record(domain, key, args.record)
    return _decide_on_plan(domain, key, args)


if __name__ == "__main__":
    sys.exit(main())
