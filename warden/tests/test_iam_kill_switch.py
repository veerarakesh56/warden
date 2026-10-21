"""B18: the second kill switch - an IAM deny on the actor role that only a person turns (infra/scripts/iam_kill_switch.py)."""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("iam_kill_switch", ROOT / "infra" / "scripts" / "iam_kill_switch.py")
ks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ks)

ENVS = ks.EnvironmentPolicies.load().known_environments


def _load(env, kind):
    return json.loads((ROOT / "infra" / "iam" / env / f"{kind}.json").read_text(encoding="utf-8"))


def _denied(env, tags):
    """Does the kill-switch policy deny an action by a session of the actor role carrying these role tags?"""
    st = next(s for s in _load(env, "kill-switch")["Statement"] if s["Sid"] == "NothingUnlessAPersonTurnedTheSwitchOff")
    assert st["Effect"] == "Deny"
    assert st["Action"] == "*"
    assert st["Resource"] == "*"
    ((op, cond),) = st["Condition"].items()
    ((key, want),) = cond.items()
    # IfExists: true when the role has no such tag - fail closed by the operator's definition, not only by IAM's rule
    # that a negated operator matches a missing key (CodeRabbit, PR 89).
    assert op == "StringNotEqualsIfExists"
    assert key == f"aws:PrincipalTag/{ks.TAG}"
    have = tags.get(ks.TAG)
    return have is None or have != want  # ...IfExists: true when the key is absent


@pytest.mark.parametrize("env", ENVS)
def test_every_action_is_denied_unless_the_tag_says_exactly_off(env):
    assert not _denied(env, {ks.TAG: "off"})
    for tags in ({}, {ks.TAG: "on"}, {ks.TAG: "Off"}, {ks.TAG: ""}, {"other": "off"}):
        assert _denied(env, tags), tags


@pytest.mark.parametrize("env", ENVS)
def test_the_role_cannot_turn_its_own_switch_and_no_session_can_override_it(env):
    st = next(s for s in _load(env, "kill-switch")["Statement"] if s["Sid"] == "TheRoleNeverTurnsItsOwnSwitch")
    assert st["Effect"] == "Deny"
    assert sorted(st["Action"]) == ["iam:TagRole", "iam:UntagRole"]
    assert st["Resource"] == f"arn:aws:iam::*:role/{ks.role_name(env)}"
    # A session tag of the same key would override the role's tag in aws:PrincipalTag: the actor's trust lets a
    # session carry only these keys.
    tagging = [s for s in _load(env, "actor-trust")["Statement"] if "sts:TagSession" in json.dumps(s["Action"])]
    assert tagging, "the actor trust lets no session carry tags: check this test"
    assert all(ks.TAG not in s["Condition"]["ForAllValues:StringEquals"]["aws:TagKeys"] for s in tagging)
    # And the deploy role may not tag the actor (it is hand-made).
    guard = next(s for s in _load(env, "deploy-guard")["Statement"] if s["Sid"] == "NeverTouchTheHandMadeRoles")
    assert {"iam:TagRole", "iam:UntagRole"} <= set(guard["Action"])
    assert f"arn:aws:iam::*:role/{ks.role_name(env)}" in guard["Resource"]


def test_the_live_check_compares_the_kill_switch_policy_too():
    spec_live = importlib.util.spec_from_file_location("check_live_iam", ROOT / "infra" / "scripts" / "check_live_iam.py")
    live = importlib.util.module_from_spec(spec_live)
    spec_live.loader.exec_module(live)
    assert ("WardenKillSwitch-{env}", "kill-switch") in live.POLICIES
    assert ks.policy_name("dev") == "WardenKillSwitch-dev"


class _Iam:
    def __init__(self, tags=None, attached=True):
        self.tags = dict(tags or {})
        self.attached = attached
        self.calls = []

    def get_role(self, **kw):
        self.calls.append(("get_role", kw["RoleName"]))
        return {"Role": {"RoleName": kw["RoleName"], "Tags": [{"Key": k, "Value": v} for k, v in self.tags.items()]}}

    def list_attached_role_policies(self, **kw):
        assert kw["RoleName"] == "warden-dev-actor"
        names = ["WardenActor-dev"] + (["WardenKillSwitch-dev"] if self.attached else [])
        return {"AttachedPolicies": [{"PolicyName": n} for n in names]}

    def tag_role(self, **kw):
        self.calls.append(("tag_role", kw["RoleName"]))
        self.tags.update({t["Key"]: t["Value"] for t in kw["Tags"]})


def test_on_off_and_status(capsys):
    iam = _Iam({ks.TAG: "off"})
    assert ks.main(["status", "--env", "dev"], iam=iam) == 0
    assert "off - fixes allowed" in capsys.readouterr().out
    assert ks.main(["on", "--env", "dev"], iam=iam) == 0
    assert iam.tags[ks.TAG] == "on"
    assert ("tag_role", "warden-dev-actor") in iam.calls
    assert "ON - AWS refuses every fix" in capsys.readouterr().out
    assert ks.main(["off", "--env", "dev", "--confirm"], iam=iam) == 0
    assert iam.tags[ks.TAG] == "off"


def test_turning_it_off_needs_confirm_and_a_missing_tag_is_on(capsys):
    iam = _Iam({})
    with pytest.raises(SystemExit):
        ks.main(["off", "--env", "dev"], iam=iam)
    assert ("tag_role", "warden-dev-actor") not in iam.calls
    assert ks.main(["status", "--env", "dev"], iam=iam) == 0
    assert "ON" in capsys.readouterr().out


def test_an_unattached_policy_is_reported_and_fails(capsys):
    assert ks.main(["status", "--env", "dev"], iam=_Iam({ks.TAG: "on"}, attached=False)) == 1
    assert "is not attached - AWS refuses nothing" in capsys.readouterr().out
