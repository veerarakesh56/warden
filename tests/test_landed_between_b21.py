"""B21: before WARDEN undoes its own fix, it reads what else landed on the target since the fix - a CloudTrail write by
anyone but this incident's own actor session, another WARDEN run's fix, a deploy or a merge on GitHub - and if anything
did, or a configured source cannot be read, the fix is not undone: a person decides."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta

import pytest

from test_apply_reverifies import _acts, _approve
from test_remediation_workflow import REQ
from warden import bounds, landed
from warden.activities import FixRequest

APPLIED = datetime(2026, 10, 20, 6, 0, tzinfo=UTC)
NOW = APPLIED + timedelta(minutes=6)


class _Log:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def entries(self, *a, kinds=(), since=None):
        return [r for r in self.rows if r["kind"] in kinds and (since is None or r["at"] >= since)]


def _since(changes=None, log=None, opener=None, **kw):
    args = {"entry": "k8s_restart", "params": {"namespace": "shop", "deployment": "orders"},
            "target": "dev/k8s:shop/orders", "incident": "inc-42", "workflow_id": "rem-1", "environment": "dev",
            "applied_at": APPLIED, "now": NOW, "log": log or _Log(), "changes": changes}
    args.update(kw)
    return landed.since_fix(**args, **({"opener": opener} if opener else {}))


def _trail(*events):
    return lambda since, until: list(events)


def test_a_write_on_the_target_by_anyone_else_after_the_fix_is_found():
    deploy = {"at": APPLIED + timedelta(minutes=2), "source": "cloudtrail", "what": "UpdateService on orders",
              "who": "deploy-pipeline"}
    found, unread = _since(_trail(deploy))
    assert found == [deploy]
    assert unread == []
    line = landed.said(found, unread)
    assert line.startswith("not rolled back: cloudtrail UpdateService on orders by deploy-pipeline landed on the target")


@pytest.mark.parametrize("event", [
    {"at": APPLIED + timedelta(minutes=1), "source": "cloudtrail", "what": "UpdateService on orders", "who": "inc-42"},
    {"at": APPLIED + timedelta(minutes=1), "source": "cloudtrail", "what": "UpdateService on payments", "who": "x"},
    {"at": APPLIED - timedelta(minutes=1), "source": "cloudtrail", "what": "UpdateService on orders", "who": "x"},
], ids=["this-incidents-own-session", "another-resource", "before-the-fix"])
def test_the_fix_itself_another_resource_or_an_earlier_write_is_not_counted(event):
    assert _since(_trail(event)) == ([], [])


def test_another_wardens_fix_of_the_same_target_is_found_but_not_this_runs():
    rows = [{"kind": bounds.APPLIED, "at": APPLIED, "body": {"service": "dev/k8s:shop/orders", "workflow_id": "rem-1"}},
            {"kind": bounds.APPLIED, "at": APPLIED + timedelta(minutes=3),
             "body": {"service": "dev/k8s:shop/orders", "workflow_id": "rem-9", "action_class": "k8s_scale"}},
            {"kind": bounds.APPLIED, "at": APPLIED + timedelta(minutes=3),
             "body": {"service": "dev/k8s:shop/other", "workflow_id": "rem-8"}}]
    found, _ = _since(log=_Log(rows))
    assert [c["what"] for c in found] == ["k8s_scale by fix run rem-9"]


def test_an_unreadable_trail_is_unknown_and_unknown_is_not_undone():
    def down(since, until):
        raise RuntimeError("AccessDenied")

    found, unread = _since(down)
    assert found == []
    assert unread == ["CloudTrail (RuntimeError)"]
    assert "could not be read" in landed.said(found, unread)


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_github_deploys_and_merges_in_the_window_are_found_where_the_token_is(monkeypatch):
    monkeypatch.setenv("WARDEN_CHANGE_REPO", "owner/repo")
    monkeypatch.setenv("WARDEN_GITHUB_TOKEN", "t" * 8)
    asked = []

    def opener(req, timeout):
        asked.append(req.full_url)
        if "/deployments" in req.full_url:
            return _Resp(json.dumps([{"created_at": (APPLIED + timedelta(minutes=4)).isoformat(), "sha": "a1b2c3d4e5f6",
                                      "ref": "dev", "creator": {"login": "ci"}}]).encode())
        return _Resp(json.dumps([{"number": 7, "merged_at": (APPLIED + timedelta(minutes=1)).isoformat(),
                                  "merged_by": {"login": "dev1"}},
                                 {"number": 6, "merged_at": (APPLIED - timedelta(hours=1)).isoformat()},
                                 {"number": 5, "merged_at": None}]).encode())

    found, unread = _since(opener=opener)
    assert unread == []
    assert [c["what"] for c in found] == ["pull request #7 into dev", "a1b2c3d4e5f6 (dev)"]
    assert any("base=dev" in u for u in asked)

    def offline(req, timeout):
        raise OSError("unreachable")

    assert _since(opener=offline) == ([], ["GitHub deployments", "GitHub merges"])


def _applied(acts, owner):
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert _approve(acts, owner, plan, "rem-1").enough
    assert acts.precheck(plan) == []
    acts.apply(plan, REQ["service"])
    return plan


def test_a_rollback_after_something_landed_is_not_sent_and_the_reads_are_recorded():
    acts, platform, owner = _acts()
    plan = _applied(acts, owner)
    platform.changes_reader = lambda entry, environment: _trail(
        {"at": datetime.now(UTC) + timedelta(seconds=1), "source": "cloudtrail", "what": "PatchDeployment on orders",
         "who": "argocd"})
    detail = acts.rollback(plan)
    assert detail.startswith("not rolled back: cloudtrail PatchDeployment on orders by argocd")
    assert platform.rolled_back == []
    [read] = acts.audit.entries(REQ["incident_id"], kinds=("remediation.landed",))
    assert read["body"]["landed"][0]["who"] == "argocd"
    assert read["body"]["unread"] == []
    assert bounds.killswitch(acts.audit) is None  # a known state: nothing was half-made


def test_a_rollback_with_nothing_landed_is_sent():
    acts, platform, owner = _acts()
    plan = _applied(acts, owner)
    platform.changes_reader = lambda entry, environment: _trail()
    assert not acts.rollback(plan).startswith("not rolled back")
    assert len(platform.rolled_back) == 1
    [read] = acts.audit.entries(REQ["incident_id"], kinds=("remediation.landed",))
    assert read["body"]["landed"] == []
    assert read["body"]["unread"] == []


def test_a_rollback_whose_trail_cannot_be_read_is_not_sent():
    acts, platform, owner = _acts()
    plan = _applied(acts, owner)

    def down(since, until):
        raise RuntimeError("AccessDenied")

    platform.changes_reader = lambda entry, environment: down
    assert acts.rollback(plan).startswith("not rolled back: CloudTrail (RuntimeError) could not be read")
    assert platform.rolled_back == []


def test_the_routed_platform_reads_the_trail_of_the_platform_that_carries_the_entry():
    from test_aws_platform_g6 import FN, Fake
    from warden.platforms import RoutedPlatform
    from warden.platforms.aws import AwsPlatform

    f = Fake()
    f.trail = [{"EventTime": APPLIED + timedelta(minutes=2), "EventName": "UpdateFunctionCode20150331v2",
                "Username": "ci-deployer", "Resources": [{"ResourceName": FN}]}]
    routed = RoutedPlatform(**{"lambda": AwsPlatform(reader=lambda s: f, actor=f.actor)})
    read = routed.changes_reader("lambda_move_alias", "dev")
    found, unread = _since(read, entry="lambda_move_alias", params={"function": FN, "alias": "live", "to_version": "3"},
                           target=f"dev/lambda:{FN}")
    assert unread == [] and [(c["what"], c["who"]) for c in found] == [(f"UpdateFunctionCode20150331v2 on {FN}",
                                                                       "ci-deployer")]
    assert routed.changes_reader("k8s_restart", "dev") is None  # no Kubernetes platform connected
