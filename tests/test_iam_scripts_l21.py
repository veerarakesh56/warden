"""Audit A-B-L21: the IAM scripts change nothing without --apply, and the probe recovers from a killed run."""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import apply_operator_policy  # after the sys.path line above
import prove_boundary


class FakeIam:
    def __init__(self, docs: dict[str, dict], default: str):
        self.docs, self.default, self.calls = dict(docs), default, []

    def list_policy_versions(self, PolicyArn):
        return {"Versions": [{"VersionId": v, "IsDefaultVersion": v == self.default,
                              "CreateDate": dt.datetime(2026, 1, int(v[1:]), tzinfo=dt.UTC)} for v in self.docs]}

    def get_policy_version(self, PolicyArn, VersionId):
        return {"PolicyVersion": {"Document": self.docs[VersionId]}}

    def set_default_policy_version(self, PolicyArn, VersionId):
        self.calls.append(("set_default", VersionId))
        self.default = VersionId

    def delete_policy_version(self, PolicyArn, VersionId):
        self.calls.append(("delete", VersionId))
        assert VersionId != self.default, "the default version cannot be deleted"
        del self.docs[VersionId]

    def create_policy_version(self, **kw):
        self.calls.append(("create", kw.get("SetAsDefault")))
        self.docs["v9"] = json.loads(kw["PolicyDocument"])
        if kw.get("SetAsDefault"):
            self.default = "v9"
        return {"PolicyVersion": {"VersionId": "v9"}}


REPO_DOC = {"Statement": [{"Sid": "Read", "Effect": "Allow", "Action": "logs:Get*", "Resource": "*"}]}
PROBE_DOC = {"Statement": [*REPO_DOC["Statement"], {"Sid": prove_boundary.PROBE_SID, "Effect": "Allow",
                                                     "Action": "sqs:ListQueues", "Resource": "*"}]}


def test_a_probe_grant_a_killed_run_left_is_removed_first():
    iam = FakeIam({"v1": REPO_DOC, "v2": PROBE_DOC}, default="v2")
    assert prove_boundary.recover(iam, "arn") == ["v2"]
    assert iam.default == "v1" and list(iam.docs) == ["v1"]
    assert prove_boundary.recover(iam, "arn") == []


def test_the_probe_grant_is_created_not_default_and_made_default_inside_the_restoring_block():
    source = (ROOT / "scripts" / "prove_boundary.py").read_text(encoding="utf-8")
    created = source.index("temp = iam.create_policy_version(")
    assert "SetAsDefault=False" in source[created:created + 200]
    assert source.index("    try:\n        iam.set_default_policy_version(PolicyArn=op, VersionId=temp)") > created


def test_without_apply_the_policy_is_compared_not_pushed(monkeypatch, tmp_path, capsys):
    iam = FakeIam({"v1": REPO_DOC}, default="v1")
    doc = tmp_path / "policy.json"
    doc.write_text(json.dumps(REPO_DOC), encoding="utf-8")
    session = types.SimpleNamespace(client=lambda name: iam if name == "iam" else types.SimpleNamespace(
        get_caller_identity=lambda: {"Account": "0" * 12}))
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(Session=lambda **_: session))
    assert apply_operator_policy.main([str(doc)]) == 0
    assert not any(c[0] == "create" for c in iam.calls)
    assert "identical" in capsys.readouterr().out
    assert apply_operator_policy.main([str(doc), "--apply"]) == 0
    assert ("create", True) in iam.calls
