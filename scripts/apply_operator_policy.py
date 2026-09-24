"""The operator editing its own policy - the self-edit the permissions boundary makes safe.

    python scripts/apply_operator_policy.py [DOC.json] [POLICY_NAME]

Defaults to operator-policy.json -> WardenProvingGroundOperator, run as the operator itself.
To push the BOUNDARY instead, name both:

    python scripts/apply_operator_policy.py \
        terraform/proving-ground/operator-policy-boundary.json WardenProvingGroundBoundary

⛔ THE SECOND FORM CANNOT BE RUN BY warden-operator, and that is the point. The boundary denies
the operator every write to the boundary itself (`DenyTouchingThisBoundary`), so raising the
ceiling requires an identity outside it. Run it with the admin credentials that created the
boundary; running it as the operator fails with AccessDenied and changes nothing.

Pushes the document as the new default version of WardenProvingGroundOperator and checks the live
document is byte-for-byte the repo's. Run `pytest tests/test_operator_policy.py` and
`scripts/validate_policies.py` first; the boundary is the ceiling, those are the review.

Prints version ids and error CODES only: AWS error messages carry the account id.
Keeps the previous default as the rollback; deletes the oldest non-default only if all 5 are used.
"""
import json
import pathlib
import sys
import urllib.parse

import boto3
from botocore.exceptions import ClientError

DOC = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else (
    pathlib.Path(__file__).resolve().parents[1] / "terraform" / "proving-ground" / "operator-policy.json")
s = boto3.Session(region_name="ap-south-2")
iam = s.client("iam")
POLICY = sys.argv[2] if len(sys.argv) > 2 else "WardenProvingGroundOperator"
arn = f"arn:aws:iam::{s.client('sts').get_caller_identity()['Account']}:policy/{POLICY}"
doc = json.loads(DOC.read_text(encoding="utf-8"))
try:
    versions = iam.list_policy_versions(PolicyArn=arn)["Versions"]
    default = next(v["VersionId"] for v in versions if v["IsDefaultVersion"])
    print("before:", sorted(v["VersionId"] for v in versions), "default", default)
    if len(versions) >= 5:
        oldest = min((v for v in versions if not v["IsDefaultVersion"]), key=lambda v: v["CreateDate"])
        iam.delete_policy_version(PolicyArn=arn, VersionId=oldest["VersionId"])
        print("deleted oldest", oldest["VersionId"])
    new = iam.create_policy_version(PolicyArn=arn, PolicyDocument=json.dumps(doc), SetAsDefault=True)
    vid = new["PolicyVersion"]["VersionId"]
    live = iam.get_policy_version(PolicyArn=arn, VersionId=vid)["PolicyVersion"]["Document"]
    live = json.loads(urllib.parse.unquote(live)) if isinstance(live, str) else live
    print("now default:", vid, "| live identical to", DOC.name, ":", live == doc, "| rollback:", default)
except ClientError as e:
    sys.exit(f"FAILED: {e.response['Error']['Code']} on {e.operation_name}")
