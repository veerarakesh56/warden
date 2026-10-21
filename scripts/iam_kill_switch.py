"""WARDEN's second kill switch (B18): an IAM deny on the role that applies fixes, outside WARDEN's own code.

The first switch lives in WARDEN's audit database (bounds.py) and is honoured by WARDEN's own gate. This one does not
depend on WARDEN: the managed policy WardenKillSwitch-<env> (iam/<env>/kill-switch.json), attached to the actor role
warden-<env>-actor, denies every action unless the role carries the tag `warden-kill-switch` = `off`. AWS itself
then refuses every fix, whatever WARDEN's code, its database or its model do.

    python scripts/iam_kill_switch.py status --env dev     # anyone who may read the role (the operator may)
    python scripts/iam_kill_switch.py on --env dev         # a person with iam:TagRole (the console or CloudShell)
    python scripts/iam_kill_switch.py off --env dev --confirm

- Fail closed: no tag, or any value other than `off`, is ON. Removing the tag stops every fix too.
- Only a person turns it: the role is hand-made (the deploy role may not tag it, deploy-guard), the policy denies the
  role tagging itself, and its trust lets a session carry only the approver/incident/plan tags, so no session can
  override the role's own tag.
- Honest limit: IAM authorises AWS API calls. A Kubernetes fix is authorised by the cluster (EKS access entry and
  RBAC); the token is signed with sts:GetCallerIdentity, which no deny can stop. WARDEN's first switch still covers
  that path.

Prints the role name and the switch state only, never a credential or an account id.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from warden.environments import EnvironmentPolicies, names

TAG = "warden-kill-switch"
OFF = "off"


def role_name(env: str) -> str:
    return f"{names(env).prefix}-actor"


def policy_name(env: str) -> str:
    return f"WardenKillSwitch-{env}"


def state(iam: Any, env: str) -> tuple[bool, bool]:
    """(switch on, deny policy attached). On unless the role's tag says exactly `off` - fail closed."""
    role = iam.get_role(RoleName=role_name(env))["Role"]
    tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}
    attached = iam.list_attached_role_policies(RoleName=role_name(env))["AttachedPolicies"]
    return tags.get(TAG) != OFF, any(p["PolicyName"] == policy_name(env) for p in attached)


def describe(on: bool, attached: bool, env: str) -> str:
    if not attached:
        return (f"{role_name(env)}: kill switch {'ON' if on else 'off'} by its tag, BUT {policy_name(env)} is not "
                "attached - AWS refuses nothing; attach it (docs in this script)")
    return f"{role_name(env)}: kill switch {'ON - AWS refuses every fix' if on else 'off - fixes allowed'}"


def main(argv: list[str] | None = None, *, iam: Any = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("action", choices=("status", "on", "off"))
    ap.add_argument("--env", required=True, choices=EnvironmentPolicies.load().known_environments)
    ap.add_argument("--confirm", action="store_true", help="required to turn the switch off (fixes resume)")
    args = ap.parse_args(argv)
    if args.action == "off" and not args.confirm:
        ap.error("turning the switch off lets WARDEN apply fixes again: pass --confirm")
    if iam is None:
        import boto3

        iam = boto3.client("iam")
    if args.action != "status":
        value = OFF if args.action == "off" else "on"
        iam.tag_role(RoleName=role_name(args.env), Tags=[{"Key": TAG, "Value": value}])
    on, attached = state(iam, args.env)
    print(describe(on, attached, args.env))
    # status: 0 when the switch does what it says; an unattached policy is a problem whichever way it is set.
    return 0 if attached else 1


if __name__ == "__main__":
    raise SystemExit(main())
