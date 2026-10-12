"""Audit A-P-5: the approver's identity is carried into the actor session. The session that makes a change names
who approved it (a session tag CloudTrail records on every call), the incident (SourceIdentity, which the actor
role's trust requires), the plan, and allows only the plan's actions on its exact resources for 900 s."""

from __future__ import annotations

import json

import pytest

from warden import identity

CREDS = {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "s", "SessionToken": "t"}}
ACCT = "0" * 12  # a placeholder account, built from parts
ROLE = f"arn:aws:iam::{ACCT}:role/warden-dev-actor"
FN = f"arn:aws:lambda:test-region-1:{ACCT}:function:warden-dev-checkout"


class _Sts:
    def __init__(self):
        self.calls = []

    def assume_role(self, **kw):
        self.calls.append(kw)
        return CREDS


def _mint(sts, **over):
    kw = {"role_arn": ROLE, "incident": "inc-42", "plan_hash": "ab" * 32, "approvers": ["owner"],
          "actions": ["lambda:UpdateAlias"], "resources": [FN]} | over
    return identity.actor_session(sts, **kw)


def test_the_actor_session_names_the_approvers_the_incident_and_the_plan():
    sts = _Sts()
    creds = _mint(sts, approvers=["second", "owner"])
    [call] = sts.calls
    assert call["SourceIdentity"] == "inc-42" and call["RoleSessionName"] == "inc-42"
    assert {t["Key"]: t["Value"] for t in call["Tags"]} == {"approver": "owner+second", "incident": "inc-42",
                                                           "plan": "ab" * 8}
    assert call["DurationSeconds"] == 900 and call["RoleArn"] == ROLE
    assert creds == {"aws_access_key_id": "a", "aws_secret_access_key": "s", "aws_session_token": "t"}


def test_an_incident_the_audit_names_without_the_prefix_still_gets_the_name_the_actors_trust_requires():
    """The first live apply (2026-10-12) was refused by STS: the audit's incident id is the alarm's fingerprint and
    time, the actor role trusts SourceIdentity `inc-*` only, and the tests all said `inc-42`."""
    import fnmatch
    import pathlib

    live = "50ac32d0fe243384-20261012T081959Z"
    sts = _Sts()
    _mint(sts, incident=live)
    [call] = sts.calls
    assert call["SourceIdentity"] == call["RoleSessionName"] == f"inc-{live}"
    assert {t["Key"]: t["Value"] for t in call["Tags"]}["incident"] == live  # the audit's id, as actor_use reads it
    templates = pathlib.Path(__file__).resolve().parents[1] / "iam" / "templates"
    for name in ("actor-trust.json", "platform-reader-trust.json"):
        trusts = [s["Condition"]["StringLike"]["sts:SourceIdentity"]
                  for s in json.loads((templates / name).read_text(encoding="utf-8"))["Statement"]
                  if "sts:SourceIdentity" in s.get("Condition", {}).get("StringLike", {})]
        assert trusts, name
        for patterns in trusts:
            patterns = [patterns] if isinstance(patterns, str) else patterns
            assert any(fnmatch.fnmatchcase(identity.correlation(live), p) for p in patterns), (name, patterns)
            assert not any(fnmatch.fnmatchcase(live, p) for p in patterns)  # the bare id is what STS refused
    assert identity.correlation("inc-42") == "inc-42" and len(identity.correlation("x" * 80)) == 64


def test_the_session_allows_only_the_plans_actions_on_its_exact_resources():
    sts = _Sts()
    _mint(sts)
    doc = json.loads(sts.calls[0]["Policy"])
    assert doc["Statement"] == [{"Effect": "Allow", "Action": ["lambda:UpdateAlias"], "Resource": [FN]}]
    with pytest.raises(identity.IdentityError, match="exact ARNs"):
        _mint(_Sts(), resources=["arn:aws:lambda:*:*:function:*"])
    with pytest.raises(identity.IdentityError, match="2048"):
        _mint(_Sts(), resources=[f"{FN}-{i}" for i in range(40)])


def test_no_session_without_an_approver_or_with_a_value_sts_would_refuse():
    for bad in ({"approvers": []}, {"incident": "inc 42; rm"}, {"incident": "x"}, {"approvers": ["a<b>"]}):
        sts = _Sts()
        with pytest.raises(identity.IdentityError):
            _mint(sts, **bad)
        assert sts.calls == []  # refused before STS is asked


def test_the_reader_session_carries_the_incident_and_no_approval():
    sts = _Sts()
    identity.reader_session(sts, role_arn=ROLE.replace("actor", "reader"), incident="inc-42")
    [call] = sts.calls
    assert call["SourceIdentity"] == "inc-42" and "Tags" not in call and "Policy" not in call


def test_a_wildcard_resource_only_with_an_exact_condition():
    """An event source mapping is named to IAM through its function's ARN (lambda:FunctionArn), as the harness role
    proved live in Wave 4: `*` with that exact condition, never `*` alone or with a pattern."""
    cond = {"ArnEquals": {"lambda:FunctionArn": FN}}
    sts = _Sts()
    _mint(sts, actions=["lambda:UpdateEventSourceMapping"], resources=["*"], condition=cond)
    assert json.loads(sts.calls[0]["Policy"])["Statement"][0]["Condition"] == cond
    for resources, condition in ((["*"], None), (["*"], {"ArnLike": {"lambda:FunctionArn": FN[:-8] + "*"}}),
                                 ([FN, "*"], cond)):
        with pytest.raises(identity.IdentityError):
            _mint(_Sts(), resources=resources, condition=condition)
