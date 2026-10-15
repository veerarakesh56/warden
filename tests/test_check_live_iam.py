"""scripts/check_live_iam.py: a policy pasted into the wrong place is caught (2026-10-15: the boundary's statements had
been pasted into WardenPlatformReader-dev the day before)."""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACCOUNT = "0" * 12  # built from parts, never an id-shaped literal
sys.path.insert(0, str(ROOT / "scripts"))

import check_live_iam as c


class NoSuchEntity(Exception):
    pass


class _Iam:
    def __init__(self, policies, trusts):
        self.policies, self.trusts = policies, trusts

    def get_policy(self, PolicyArn):
        name = PolicyArn.rsplit("/", 1)[1]
        if name not in self.policies:
            raise NoSuchEntity(name)
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        return {"PolicyVersion": {"Document": self.policies[PolicyArn.rsplit("/", 1)[1]]}}

    def get_role(self, RoleName):
        if RoleName not in self.trusts:
            raise NoSuchEntity(RoleName)
        return {"Role": {"AssumeRolePolicyDocument": self.trusts[RoleName]}}


def _load(kind):
    return json.loads((c._file("dev", kind)).read_text(encoding="utf-8"))


def test_a_policy_holding_another_files_statements_differs_and_a_reordered_one_matches():
    reader, boundary = _load("platform-reader"), _load("boundary")
    shuffled = {"Statement": list(reversed(reader["Statement"])), "Version": reader["Version"]}
    iam = _Iam({"WardenPlatformReader-dev": shuffled, "WardenEnvBoundary-dev": boundary}, {})
    got = dict(c.check(iam, ACCOUNT, ["dev"]))
    assert got["WardenPlatformReader-dev"] == "MATCHES" and got["WardenEnvBoundary-dev"] == "MATCHES"
    iam.policies["WardenPlatformReader-dev"] = boundary  # the 2026-10-14 paste
    got = dict(c.check(iam, ACCOUNT, ["dev"]))
    assert got["WardenPlatformReader-dev"] == "DIFFERS"
    assert got["WardenEnvDeploy-dev"] == "NOT IN ACCOUNT"


def test_the_order_of_a_policys_string_lists_does_not_matter_but_their_content_does():
    a = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}]}
    b = {"Statement": [{"Resource": "*", "Action": ["s3:ListBucket", "s3:GetObject"], "Effect": "Allow"}]}
    assert c.norm(a) == c.norm(b)
    b["Statement"][0]["Action"].append("s3:PutObject")
    assert c.norm(a) != c.norm(b)
