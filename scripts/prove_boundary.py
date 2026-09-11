"""Live proof that the permissions boundary holds even when the operator grants itself escalation.

    python scripts/prove_boundary.py      # as warden-operator; changes nothing it does not restore

1. Control BEFORE: sqs:ListQueues (boundary allows, operator policy does not) -> must be denied.
2. Self-edit a temporary version = repo policy + a statement granting: sqs:ListQueues (control),
   iam:CreatePolicyVersion on the BOUNDARY, iam:PutUserPermissionsBoundary on this user.
3. Wait until the control SUCCEEDS - proof the temporary grant is in effect, so any denial after it
   comes from the boundary and not from propagation delay.
4. Escalation probes, each must be AccessDenied:
     a. write a new version of the boundary (non-default, identical document: harmless even if it worked)
     b. re-set this user's boundary to the same policy (a no-op even if it worked)
     c. create a warden-pg-* role WITHOUT the boundary (deleted at once if it worked)
5. Legit path must work: create a warden-pg-* role WITH the boundary, then delete it.
6. Restore: previous default back, temporary version deleted, live == repo verified.
Prints codes only - AWS error messages carry the account id.
"""
import json
import pathlib
import time
import urllib.parse

import boto3
from botocore.exceptions import ClientError

REPO = pathlib.Path(__file__).resolve().parents[1] / "terraform" / "proving-ground"
s = boto3.Session(region_name="ap-south-2")
iam, sqs = s.client("iam"), s.client("sqs")
acct = s.client("sts").get_caller_identity()["Account"]
OP = f"arn:aws:iam::{acct}:policy/WardenProvingGroundOperator"
BOUNDARY = f"arn:aws:iam::{acct}:policy/WardenProvingGroundBoundary"
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
    "Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
TAGS = [{"Key": "Project", "Value": "warden-proving-ground"}, {"Key": "Purpose", "Value": "boundary-probe"}]
results = []


def attempt(label, fn, expect_denied, cleanup=None):
    try:
        fn()
        outcome = "ALLOWED"
        if cleanup:
            cleanup()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        outcome = "DENIED" if code in ("AccessDenied", "AccessDeniedException") else f"ERROR {code}"
    ok = (outcome == "DENIED") == expect_denied and not outcome.startswith("ERROR")
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {outcome} (expected {'DENIED' if expect_denied else 'ALLOWED'})")
    return outcome


def control():
    sqs.list_queues()


print("1. control before the grant")
attempt("sqs:ListQueues with the normal policy", control, True)

print("2. temporary self-grant")
repo_doc = json.loads((REPO / "operator-policy.json").read_text(encoding="utf-8"))
probe_doc = json.loads(json.dumps(repo_doc))
probe_doc["Statement"].append({
    "Sid": "TemporaryEscalationProbe", "Effect": "Allow",
    "Action": ["sqs:ListQueues", "iam:CreatePolicyVersion", "iam:PutUserPermissionsBoundary"],
    "Resource": "*",
})
versions = iam.list_policy_versions(PolicyArn=OP)["Versions"]
previous = next(v["VersionId"] for v in versions if v["IsDefaultVersion"])
if len(versions) >= 5:
    oldest = min((v for v in versions if not v["IsDefaultVersion"]), key=lambda v: v["CreateDate"])
    iam.delete_policy_version(PolicyArn=OP, VersionId=oldest["VersionId"])
temp = iam.create_policy_version(PolicyArn=OP, PolicyDocument=json.dumps(probe_doc),
                                 SetAsDefault=True)["PolicyVersion"]["VersionId"]
print(f"  temporary version {temp} is default (previous {previous})")

try:
    print("3. waiting for the grant to take effect (the control must now SUCCEED)")
    for _ in range(24):
        try:
            control()
            print("  control allowed - the temporary grant is live")
            break
        except ClientError:
            time.sleep(5)
    else:
        raise SystemExit("control never succeeded - cannot tell a boundary denial from propagation")

    print("4. escalation probes")
    boundary_doc = (REPO / "operator-policy-boundary.json").read_text(encoding="utf-8")
    attempt("write a new version of the boundary",
            lambda: iam.create_policy_version(PolicyArn=BOUNDARY, PolicyDocument=boundary_doc,
                                              SetAsDefault=False), True)
    attempt("re-set my own permissions boundary",
            lambda: iam.put_user_permissions_boundary(UserName="warden-operator",
                                                      PermissionsBoundary=BOUNDARY), True)
    attempt("create a warden-pg-* role WITHOUT the boundary",
            lambda: iam.create_role(RoleName="warden-pg-probe-nobound", AssumeRolePolicyDocument=TRUST,
                                    Tags=TAGS), True,
            cleanup=lambda: iam.delete_role(RoleName="warden-pg-probe-nobound"))

    print("5. the legitimate path")
    attempt("create a warden-pg-* role WITH the boundary",
            lambda: iam.create_role(RoleName="warden-pg-probe-bounded", AssumeRolePolicyDocument=TRUST,
                                    PermissionsBoundary=BOUNDARY, Tags=TAGS), False,
            cleanup=lambda: iam.delete_role(RoleName="warden-pg-probe-bounded"))
finally:
    print("6. restore")
    iam.set_default_policy_version(PolicyArn=OP, VersionId=previous)
    iam.delete_policy_version(PolicyArn=OP, VersionId=temp)
    live = iam.get_policy_version(PolicyArn=OP, VersionId=previous)["PolicyVersion"]["Document"]
    live = json.loads(urllib.parse.unquote(live)) if isinstance(live, str) else live
    left = [v["VersionId"] for v in iam.list_policy_versions(PolicyArn=OP)["Versions"]]
    print(f"  default back to {previous}; temporary {temp} deleted; versions now {sorted(left)}; "
          f"live identical to repo: {live == repo_doc}")
    for name in ("warden-pg-probe-nobound", "warden-pg-probe-bounded"):
        try:
            iam.get_role(RoleName=name)
            print(f"  !! {name} STILL EXISTS")
        except ClientError as e:
            print(f"  {name}: gone ({e.response['Error']['Code']})")

print(f"\n{sum(results)}/{len(results)} checks passed")
