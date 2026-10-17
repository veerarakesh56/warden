"""Audit A-B-L21: the IAM scripts change nothing without --apply, and the probe recovers from a killed run."""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys
import types

import pytest

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


DENIED = {"Error": {"Code": "AccessDenied", "Message": "no"}}


class ProbeIam(FakeIam):
    """The operator policy (versions v1..), the boundary and the roles, as the probe meets them."""

    def __init__(self, *, unbounded_role_allowed=False):
        super().__init__({"v1": REPO_DOC}, default="v1")
        self.roles, self.unbounded_role_allowed = set(), unbounded_role_allowed

    def create_policy_version(self, **kw):
        if kw["PolicyArn"].endswith("Boundary"):
            raise prove_boundary.ClientError(DENIED, "CreatePolicyVersion")
        return super().create_policy_version(**kw)

    def put_user_permissions_boundary(self, **kw):
        raise prove_boundary.ClientError(DENIED, "PutUserPermissionsBoundary")

    def create_role(self, RoleName, PermissionsBoundary=None, **kw):
        if PermissionsBoundary is None and not self.unbounded_role_allowed:
            raise prove_boundary.ClientError(DENIED, "CreateRole")
        self.calls.append(("create_role", RoleName))
        self.roles.add(RoleName)

    def delete_role(self, RoleName):
        self.calls.append(("delete_role", RoleName))
        self.roles.discard(RoleName)

    def get_role(self, RoleName):
        if RoleName not in self.roles:
            raise prove_boundary.ClientError({"Error": {"Code": "NoSuchEntity", "Message": "x"}}, "GetRole")
        return {}


def _probe(monkeypatch, tmp_path, iam, *, control_after: int | None = 2):
    (tmp_path / "operator-policy.json").write_text(json.dumps(REPO_DOC), encoding="utf-8")
    (tmp_path / "operator-policy-boundary.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(prove_boundary, "REPO", tmp_path)
    monkeypatch.setattr(prove_boundary.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(stdout='{"Project": "warden"}'))
    monkeypatch.setattr(prove_boundary.time, "sleep", lambda s: None)
    monkeypatch.setenv("AWS_REGION", "ap-south-2")
    asked = {"n": 0}

    def list_queues():
        if iam.default == "v1":
            raise prove_boundary.ClientError(DENIED, "ListQueues")
        asked["n"] += 1
        if control_after is None or asked["n"] < control_after:
            raise prove_boundary.ClientError(DENIED, "ListQueues")
        return {}

    clients = {"iam": iam, "sqs": types.SimpleNamespace(list_queues=list_queues),
               "sts": types.SimpleNamespace(get_caller_identity=lambda: {"Account": "0" * 12})}
    session = types.SimpleNamespace(client=clients.__getitem__)
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(Session=lambda **_: session))


RESTORED = ("6. restore\n"
            "  default back to v1; temporary v9 deleted; versions now ['v1']; live identical to repo: True\n"
            "  warden-pg-probe-nobound: gone (NoSuchEntity)\n"
            "  warden-pg-probe-bounded: gone (NoSuchEntity)\n")


def test_the_whole_probe_prints_each_step_and_passes_when_the_boundary_holds(monkeypatch, tmp_path, capsys):
    """Characterisation (before the cognitive-complexity split of main): every step's line, in order."""
    iam = ProbeIam()
    _probe(monkeypatch, tmp_path, iam)
    assert prove_boundary.main() == 0
    assert capsys.readouterr().out == (
        "0. recovering what a killed run may have left\n"
        "  nothing left behind\n"
        "1. control before the grant\n"
        "  PASS  sqs:ListQueues with the normal policy: DENIED (expected DENIED)\n"
        "2. temporary self-grant\n"
        "  temporary version v9 is default (previous v1)\n"
        "3. waiting for the grant to take effect (the control must now SUCCEED)\n"
        "  control allowed - the temporary grant is live\n"
        "4. escalation probes\n"
        "  PASS  write a new version of the boundary: DENIED (expected DENIED)\n"
        "  PASS  re-set my own permissions boundary: DENIED (expected DENIED)\n"
        "  PASS  create a warden-pg-* role WITHOUT the boundary: DENIED (expected DENIED)\n"
        "5. the legitimate path\n"
        "  PASS  create a warden-pg-* role WITH the boundary: ALLOWED (expected ALLOWED)\n"
        + RESTORED + "\n5/5 checks passed\n")
    assert iam.calls == [("create", False), ("set_default", "v9"), ("create_role", "warden-pg-probe-bounded"),
                         ("delete_role", "warden-pg-probe-bounded"), ("set_default", "v1"), ("delete", "v9")]


def test_an_escalation_that_works_fails_the_probe_and_is_undone(monkeypatch, tmp_path, capsys):
    iam = ProbeIam(unbounded_role_allowed=True)
    _probe(monkeypatch, tmp_path, iam)
    assert prove_boundary.main() == 1
    out = capsys.readouterr().out
    assert "  FAIL  create a warden-pg-* role WITHOUT the boundary: ALLOWED (expected DENIED)\n" in out
    assert out.endswith(RESTORED + "\n4/5 checks passed\n")
    assert ("delete_role", "warden-pg-probe-nobound") in iam.calls


def test_a_grant_that_never_takes_effect_stops_and_still_restores(monkeypatch, tmp_path, capsys):
    iam = ProbeIam()
    _probe(monkeypatch, tmp_path, iam, control_after=None)
    with pytest.raises(SystemExit, match="control never succeeded"):
        prove_boundary.main()
    out = capsys.readouterr().out
    assert out.endswith("3. waiting for the grant to take effect (the control must now SUCCEED)\n" + RESTORED)
    assert iam.default == "v1"
    assert list(iam.docs) == ["v1"]


def test_a_full_version_list_makes_room_by_deleting_the_oldest_non_default(monkeypatch, tmp_path, capsys):
    iam = ProbeIam()
    iam.docs.update({f"v{i}": REPO_DOC for i in range(2, 6)})
    iam.default = "v3"
    _probe(monkeypatch, tmp_path, iam)
    assert prove_boundary.main() == 0
    assert iam.calls[0] == ("delete", "v1")
    assert iam.default == "v3"
    assert "  default back to v3; temporary v9 deleted; versions now ['v2', 'v3', 'v4', 'v5']; " in capsys.readouterr().out
