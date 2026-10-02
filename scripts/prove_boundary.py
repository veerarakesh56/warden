"""Live proof that the permissions boundary holds even when the operator grants itself escalation.

    python scripts/prove_boundary.py      # as warden-operator; changes nothing it does not restore

0. Recover first: a run killed mid-way (Ctrl-C ends in the restore below; a SIGKILL or a closed
   terminal does not) left the operator policy's default on the temporary grant. That version is
   found by its Sid, the newest other version is made default again, and the temporary ones deleted.
1. Control BEFORE: sqs:ListQueues (boundary allows, operator policy does not) -> must be denied.
2. Self-edit a temporary version = repo policy + a statement granting: sqs:ListQueues (control),
   iam:CreatePolicyVersion on the BOUNDARY, iam:PutUserPermissionsBoundary on this user. Created
   NOT default, and made default only inside the block whose `finally` restores (audit A-B-L21: it
   was created as default before that block, so an interruption between the two left it in place).
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
import subprocess
import time
import urllib.parse

from botocore.exceptions import ClientError

REPO = pathlib.Path(__file__).resolve().parents[1] / "terraform" / "proving-ground"
PROBE_SID = "TemporaryEscalationProbe"
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
    "Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def _document(iam, arn: str, version: str) -> dict:
    doc = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]
    return json.loads(urllib.parse.unquote(doc)) if isinstance(doc, str) else doc


def recover(iam, arn: str) -> list[str]:
    """Undo what a killed run left: every version carrying the probe's Sid is deleted, and if one was the default,
    the newest other version is made default first. Returns the versions removed."""
    versions = iam.list_policy_versions(PolicyArn=arn)["Versions"]
    probes = [v for v in versions if any(st.get("Sid") == PROBE_SID
                                         for st in _document(iam, arn, v["VersionId"]).get("Statement", []))]
    if not probes:
        return []
    if any(v["IsDefaultVersion"] for v in probes):
        keep = max((v for v in versions if v not in probes), key=lambda v: v["CreateDate"])
        iam.set_default_policy_version(PolicyArn=arn, VersionId=keep["VersionId"])
    for v in probes:
        iam.delete_policy_version(PolicyArn=arn, VersionId=v["VersionId"])
    return sorted(v["VersionId"] for v in probes)


def main() -> int:
    import boto3

    from warden.environments import region

    s = boto3.Session(region_name=region())
    iam, sqs = s.client("iam"), s.client("sqs")
    acct = s.client("sts").get_caller_identity()["Account"]
    op = f"arn:aws:iam::{acct}:policy/WardenProvingGroundOperator"
    boundary = f"arn:aws:iam::{acct}:policy/WardenProvingGroundBoundary"
    # The stack's own tags (terraform output `resource_tags`), never literals (owner rule: no hardcoding).
    tags = json.loads(subprocess.run(["terraform", "output", "-json", "resource_tags"], cwd=REPO, check=True,
                                     capture_output=True, text=True).stdout)
    tags = [{"Key": k, "Value": v} for k, v in tags.items()] + [{"Key": "Purpose", "Value": "boundary-probe"}]
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

    print("0. recovering what a killed run may have left")
    removed = recover(iam, op)
    print(f"  {'removed the temporary grant ' + str(removed) if removed else 'nothing left behind'}")

    print("1. control before the grant")
    attempt("sqs:ListQueues with the normal policy", control, True)

    print("2. temporary self-grant")
    repo_doc = json.loads((REPO / "operator-policy.json").read_text(encoding="utf-8"))
    probe_doc = json.loads(json.dumps(repo_doc))
    probe_doc["Statement"].append({
        "Sid": PROBE_SID, "Effect": "Allow",
        "Action": ["sqs:ListQueues", "iam:CreatePolicyVersion", "iam:PutUserPermissionsBoundary"],
        "Resource": "*",
    })
    versions = iam.list_policy_versions(PolicyArn=op)["Versions"]
    previous = next(v["VersionId"] for v in versions if v["IsDefaultVersion"])
    if len(versions) >= 5:
        oldest = min((v for v in versions if not v["IsDefaultVersion"]), key=lambda v: v["CreateDate"])
        iam.delete_policy_version(PolicyArn=op, VersionId=oldest["VersionId"])
    temp = iam.create_policy_version(PolicyArn=op, PolicyDocument=json.dumps(probe_doc),
                                     SetAsDefault=False)["PolicyVersion"]["VersionId"]

    try:
        iam.set_default_policy_version(PolicyArn=op, VersionId=temp)
        print(f"  temporary version {temp} is default (previous {previous})")
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
                lambda: iam.create_policy_version(PolicyArn=boundary, PolicyDocument=boundary_doc,
                                                  SetAsDefault=False), True)
        attempt("re-set my own permissions boundary",
                lambda: iam.put_user_permissions_boundary(UserName="warden-operator",
                                                          PermissionsBoundary=boundary), True)
        attempt("create a warden-pg-* role WITHOUT the boundary",
                lambda: iam.create_role(RoleName="warden-pg-probe-nobound", AssumeRolePolicyDocument=TRUST,
                                        Tags=tags), True,
                cleanup=lambda: iam.delete_role(RoleName="warden-pg-probe-nobound"))

        print("5. the legitimate path")
        attempt("create a warden-pg-* role WITH the boundary",
                lambda: iam.create_role(RoleName="warden-pg-probe-bounded", AssumeRolePolicyDocument=TRUST,
                                        PermissionsBoundary=boundary, Tags=tags), False,
                cleanup=lambda: iam.delete_role(RoleName="warden-pg-probe-bounded"))
    finally:
        print("6. restore")
        iam.set_default_policy_version(PolicyArn=op, VersionId=previous)
        iam.delete_policy_version(PolicyArn=op, VersionId=temp)
        live = _document(iam, op, previous)
        left = [v["VersionId"] for v in iam.list_policy_versions(PolicyArn=op)["Versions"]]
        print(f"  default back to {previous}; temporary {temp} deleted; versions now {sorted(left)}; "
              f"live identical to repo: {live == repo_doc}")
        for name in ("warden-pg-probe-nobound", "warden-pg-probe-bounded"):
            try:
                iam.get_role(RoleName=name)
                print(f"  !! {name} STILL EXISTS")
            except ClientError as e:
                print(f"  {name}: gone ({e.response['Error']['Code']})")

    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
