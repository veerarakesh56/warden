"""infra/scripts/check_live_iam.py: a policy pasted into the wrong place is caught (2026-10-15: the boundary's statements had
been pasted into WardenPlatformReader-dev the day before)."""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ACCOUNT = "0" * 12  # built from parts, never an id-shaped literal
sys.path.insert(0, str(ROOT / "infra" / "scripts"))

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
    assert got["WardenPlatformReader-dev"] == "MATCHES"
    assert got["WardenEnvBoundary-dev"] == "MATCHES"
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


def test_every_verdict_for_policies_and_trusts_in_order(tmp_path, monkeypatch):
    """Characterisation (before the cognitive-complexity split of check): each verdict for a policy and for a trust -
    placeholders without a render, a `.local.json` render compared even when it holds `<`/`>`, matches (a trust given
    URL-encoded as IAM returns it), differs, not in the account, unreadable - in POLICIES then TRUSTS order."""
    folder = tmp_path / "infra" / "iam" / "lab"
    folder.mkdir(parents=True)
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    angled = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*", "Sid": "x<y>"}]}
    files = {"boundary.json": {"Statement": [{"Resource": "arn:aws:s3:::<bucket>"}]},
             "deploy.json": {"Statement": [{"Resource": "<placeholder>"}]}, "deploy.local.json": angled,
             "actor.json": doc, "harness.json": doc, "deploy-guard.json": doc,
             "trust.json": {"Statement": [{"Principal": "<account>"}]}, "actor-trust.json": doc,
             "harness-trust.json": doc, "reader-trust.json": doc, "platform-reader-trust.json": doc}
    for name, body in files.items():
        (folder / name).write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setattr(c, "ROOT", tmp_path)

    class Broken(_Iam):
        def get_policy(self, PolicyArn):
            if PolicyArn.endswith("WardenHarness-lab"):
                raise RuntimeError("throttled")
            return super().get_policy(PolicyArn)

        def get_role(self, RoleName):
            if RoleName == "warden-lab-platform-reader":
                raise TimeoutError("slow")
            return super().get_role(RoleName)

    import urllib.parse
    iam = Broken({"WardenEnvDeploy-lab": angled, "WardenActor-lab": doc, "WardenDeployGuard-lab": angled},
                 {"warden-lab-harness": angled, "warden-lab-reader": urllib.parse.quote(json.dumps(doc))})
    assert c.check(iam, ACCOUNT, ["lab"]) == [
        ("WardenEnvBoundary-lab", "FILE HAS PLACEHOLDERS"),
        ("WardenEnvDeploy-lab", "MATCHES"),
        ("WardenActor-lab", "MATCHES"),
        ("WardenHarness-lab", "UNREADABLE (RuntimeError)"),
        ("WardenDeployGuard-lab", "DIFFERS"),
        ("warden-lab-deploy trust", "FILE HAS PLACEHOLDERS"),
        ("warden-lab-platform-reader trust", "UNREADABLE (TimeoutError)"),
        ("warden-lab-actor trust", "NOT IN ACCOUNT"),
        ("warden-lab-harness trust", "DIFFERS"),
        ("warden-lab-reader trust", "MATCHES"),
    ]
