"""The operator identity after W0-now: a role the laptop reaches through IAM Roles Anywhere with a
TPM-held key, replacing the IAM user and its long-lived access key (audit A-I-4, owner rule "no
long-lived keys").

What must hold: the role can read and check, and nothing else. Its one write-shaped action is
assuming the read-only sweep role. No database login, no IAM change, no self-edit. Only the laptop's
certificate, through the one trust anchor, can assume it.
"""

from __future__ import annotations

import fnmatch
import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "iam" / "operator" / "policy.json").read_text(encoding="utf-8"))
TRUST = json.loads((ROOT / "iam" / "operator" / "trust.json").read_text(encoding="utf-8"))

_spec = importlib.util.spec_from_file_location("roles_anywhere_cert", ROOT / "scripts" / "roles_anywhere_cert.py")
rac = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rac)

READ_VERBS = ("Get", "List", "Describe", "Validate", "Check", "Simulate")
REGIONAL = ("bedrock:", "servicequotas:", "rolesanywhere:")
ANCHOR = "arn:aws:rolesanywhere:ap-south-2:111122223333:trust-anchor/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"


def _list(x):
    return [x] if isinstance(x, str) else list(x)


def _allow_statements():
    return [st for st in POLICY["Statement"] if st["Effect"] == "Allow"]


def test_every_allowed_action_only_reads_except_assuming_the_sweep_role():
    for st in _allow_statements():
        assert "NotAction" not in st and "NotResource" not in st, st["Sid"]
        for action in _list(st["Action"]):
            name = action.split(":")[1]
            assert "*" not in action, action
            if action == "sts:AssumeRole":
                assert _list(st["Resource"]) == ["arn:aws:iam::*:role/warden-pg-sweep"]
            else:
                assert name.startswith(READ_VERBS), action


@pytest.mark.parametrize("forbidden", ["rds-db:", "iam:Create", "iam:Put", "iam:Attach", "iam:Update",
                                       "iam:Delete", "iam:Set", "bedrock:Invoke", "secretsmanager:Put",
                                       "secretsmanager:Create", "kms:"])
def test_no_database_login_no_iam_change_no_model_call(forbidden):
    actions = [a for st in _allow_statements() for a in _list(st["Action"])]
    assert not [a for a in actions if a.startswith(forbidden)]


def test_secrets_are_only_the_ops_ones():
    for st in _allow_statements():
        if any(a.startswith("secretsmanager:") for a in _list(st["Action"])):
            assert _list(st["Resource"]) == ["arn:aws:secretsmanager:ap-south-2:*:secret:warden/ops/*"]


def test_regional_reads_are_locked_to_the_home_region():
    for st in _allow_statements():
        if any(a.startswith(REGIONAL) for a in _list(st["Action"])):
            assert st["Condition"] == {"StringEquals": {"aws:RequestedRegion": "ap-south-2"}}, st["Sid"]


def test_fits_the_managed_policy_limit():
    assert len(json.dumps(POLICY, separators=(",", ":"))) <= 6144


def test_only_roles_anywhere_with_the_laptop_certificate_through_one_anchor_may_assume():
    (st,) = TRUST["Statement"]
    assert st["Effect"] == "Allow"
    assert st["Principal"] == {"Service": "rolesanywhere.amazonaws.com"}
    assert sorted(st["Action"]) == ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]
    assert st["Condition"]["ArnEquals"]["aws:SourceArn"].endswith(":trust-anchor/<TRUST_ANCHOR_ID>")
    assert st["Condition"]["StringEquals"] == {"aws:PrincipalTag/x509Subject/CN": rac.SUBJECT_CN,
                                               "aws:PrincipalTag/x509Subject/O": rac.ORG}


def test_the_local_trust_names_the_exact_anchor_and_leaves_no_placeholder():
    doc = rac.render_trust(ANCHOR)
    assert "<" not in doc
    assert json.loads(doc)["Statement"][0]["Condition"]["ArnEquals"]["aws:SourceArn"] == ANCHOR


@pytest.mark.parametrize("bad", ["", "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/x",
                                 ANCHOR.replace("trust-anchor", "profile"), ANCHOR + "/extra"])
def test_anything_but_a_home_region_anchor_arn_is_refused(bad):
    with pytest.raises(ValueError):
        rac.render_trust(bad)


def test_the_filled_in_trust_is_never_committed():
    patterns = [ln.strip() for ln in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()]
    assert any(fnmatch.fnmatch("iam/operator/trust.local.json", p) for p in patterns if p)
