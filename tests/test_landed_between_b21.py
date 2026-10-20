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


@pytest.fixture(autouse=True)
def _no_github(monkeypatch):
    """No test reads the developer's own GitHub settings (CodeRabbit, PR 84)."""
    monkeypatch.delenv("WARDEN_CHANGE_REPO", raising=False)
    monkeypatch.delenv("WARDEN_GITHUB_TOKEN", raising=False)


def _since(writes=None, log=None, opener=None, **kw):
    """(landed, unread) - and the third value, the sources this target has none of, is checked where it matters."""
    args = {"entry": "k8s_restart", "params": {"namespace": "shop", "deployment": "orders"},
            "target": "dev/k8s:shop/orders", "incident": "inc-42", "workflow_id": "rem-1", "environment": "dev",
            "applied_at": APPLIED, "now": NOW, "log": log or _Log(), "writes": writes}
    args.update(kw)
    found, unread, _ = landed.since_fix(**args, **({"opener": opener} if opener else {}))
    return found, unread


def _trail(*events):
    """CloudTrail looked up by the target's names: the events naming one of them, in the window."""
    def writes(names, since, until):
        return [e for e in events if e["what"].rpartition(" on ")[2] in names
                and (e.get("at") is None or since <= e["at"])]
    return writes


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
    def down(names, since, until):
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
                                  "updated_at": (APPLIED + timedelta(minutes=1)).isoformat(),
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
    platform.writes_reader = lambda entry, environment: _trail(
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
    platform.writes_reader = lambda entry, environment: _trail()
    assert not acts.rollback(plan).startswith("not rolled back")
    assert len(platform.rolled_back) == 1
    [read] = acts.audit.entries(REQ["incident_id"], kinds=("remediation.landed",))
    assert read["body"]["landed"] == []
    assert read["body"]["unread"] == []


def test_a_rollback_whose_trail_cannot_be_read_is_not_sent():
    acts, platform, owner = _acts()
    plan = _applied(acts, owner)

    def down(names, since, until):
        raise RuntimeError("AccessDenied")

    platform.writes_reader = lambda entry, environment: down
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
    read = routed.writes_reader("lambda_move_alias", "dev")
    found, unread = _since(read, entry="lambda_move_alias", params={"function": FN, "alias": "live", "to_version": "3"},
                           target=f"dev/lambda:{FN}")
    assert unread == []
    assert [(c["what"], c["who"]) for c in found] == [(f"UpdateFunctionCode20150331v2 on {FN}", "ci-deployer")]
    assert routed.writes_reader("k8s_restart", "dev") is None  # no Kubernetes platform connected


def test_a_write_with_no_time_or_in_the_fixs_own_second_counts():
    undated = {"at": None, "source": "cloudtrail", "what": "UpdateService on orders", "who": "ci"}
    same_second = {"at": APPLIED - timedelta(milliseconds=600), "source": "cloudtrail",
                   "what": "UpdateService on orders", "who": "ci"}
    found, _ = _since(_trail(undated, same_second))
    assert len(found) == 2


def test_a_github_list_is_read_page_by_page_and_one_longer_than_read_is_unknown(monkeypatch):
    monkeypatch.setenv("WARDEN_CHANGE_REPO", "owner/repo")
    monkeypatch.setenv("WARDEN_GITHUB_TOKEN", "t" * 8)
    later = (APPLIED + timedelta(minutes=1)).isoformat()

    def full(n):
        return [{"number": i, "created_at": later, "updated_at": later} for i in range(n)]

    pages = {"deployments": [full(100), [{"created_at": later, "sha": "f00d", "ref": "dev"}]], "pulls": [full(100)] * 9}

    def opener(req, timeout):
        kind = "deployments" if "/deployments" in req.full_url else "pulls"
        page = int(req.full_url.rsplit("page=", 1)[1])
        return _Resp(json.dumps(pages[kind][page - 1]).encode())

    found, unread = _since(opener=opener)
    assert sum(c["source"] == "deploy" for c in found) == 101  # both pages of deployments
    assert unread == ["GitHub merges"]  # five full pages of pull requests, all since the fix: not all read


def test_what_landed_is_kept_and_said_redacted():
    account = "0" * 12  # built from parts: no account id in the repository
    actor = f"arn:aws:sts::{account}:assumed-role/deployer/ci"
    event = {"at": APPLIED + timedelta(minutes=1), "source": "cloudtrail", "what": "UpdateService on orders",
             "who": actor}
    found, unread = _since(_trail(event))
    assert account not in json.dumps(landed.shown(found))
    assert account not in landed.said(found, unread)


def test_a_target_whose_platform_reads_no_trail_says_so():
    _, _, unchecked = landed.since_fix(entry="k8s_restart", params={"namespace": "shop", "deployment": "orders"},
                                       target="dev/k8s:shop/orders", incident="inc-42", workflow_id="rem-1",
                                       environment="dev", applied_at=APPLIED, now=NOW, log=_Log(), writes=None)
    assert unchecked == ["CloudTrail (this target's platform has no change reader)"]


class _Trail:
    """CloudTrail's LookupEvents, by resource name, in pages of `per` events."""

    def __init__(self, events, per=2):
        self.events, self.per, self.asked = events, per, []

    def lookup_events(self, LookupAttributes, StartTime, EndTime, MaxResults, NextToken=None):
        name = LookupAttributes[0]["AttributeValue"]
        self.asked.append((LookupAttributes[0]["AttributeKey"], name))
        mine = [e for e in self.events if any(r["ResourceName"] == name for r in e["Resources"])]
        start = int(NextToken or 0)
        page = mine[start:start + self.per]
        return {"Events": page, **({"NextToken": str(start + self.per)} if start + self.per < len(mine) else {})}


def _event(i, names, read_only="false"):
    return {"EventId": f"e{i}", "EventTime": APPLIED + timedelta(seconds=i), "EventName": "UpdateService",
            "Username": "ci", "ReadOnly": read_only, "Resources": [{"ResourceName": n} for n in names]}


def test_the_trail_is_read_by_every_name_of_the_target_every_page_once_each():
    from warden.platforms.aws import AwsPlatform

    trail = _Trail([_event(1, ["c1", "orders"]), _event(2, ["orders"]), _event(3, ["orders"], read_only="true"),
                    _event(4, ["orders"]), _event(5, ["other"])])
    p = AwsPlatform(reader=lambda s: trail, actor=None)
    got = p.writes_on(["c1", "orders"], APPLIED, NOW)
    assert sorted(c["event"] for c in got) == ["e1", "e2", "e4"]  # each once; read-only and others left out
    assert ("ResourceName", "orders") in trail.asked


def test_a_trail_longer_than_read_is_unknown():
    from warden.platforms import aws

    trail = _Trail([_event(i, ["orders"]) for i in range(aws.WRITES_PAGES * 2 + 1)])
    p = aws.AwsPlatform(reader=lambda s: trail, actor=None)
    with pytest.raises(aws.AwsPlatformError, match="more than"):
        p.writes_on(["orders"], APPLIED, NOW)
    found, unread = _since(p.writes_on)
    assert found == []
    assert unread == ["CloudTrail (AwsPlatformError)"]
