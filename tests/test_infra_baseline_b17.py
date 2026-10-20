"""B17: infra_restore_baseline is a real executor - through WARDEN's own Helios-checked infra workflow. It applies
exactly ONE kept plan, made at the environment branch's head and passed by Helios; the approval binds the plan's run
and sha256; nothing is sent without a token that may run workflows; it is never undone automatically."""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from warden import catalog
from warden.platforms.infra import (
    ENTRY,
    GitHub,
    InfraPlatform,
    InfraPlatformError,
    InfraPlatformRefused,
    s3_plan_meta,
)

HEAD = "a" * 40
OLD = "b" * 40
SHA = "c" * 64
WHO = {"incident": "inc-7", "plan_hash": "d" * 64, "approvers": ["owner"]}
APPLIED = "2026-10-20T19:00:00+00:00"


class FakeGitHub:
    def __init__(self):
        self.head = HEAD
        self.runs = [{"id": 902, "head_sha": HEAD, "conclusion": "success", "created_at": "2026-10-20T18:00:00Z",
                      "html_url": "https://github.example/run/902"},
                     {"id": 901, "head_sha": OLD, "conclusion": "success", "created_at": "2026-10-19T18:00:00Z"}]
        self.dispatched, self.status, self.fail = [], 204, None

    def get(self, path, token=""):
        if self.fail:
            raise self.fail
        if path.startswith("/branches/"):
            return {"commit": {"sha": self.head}}
        return {"workflow_runs": list(self.runs)}

    def dispatch(self, workflow, ref, inputs, token):
        self.dispatched.append((workflow, ref, inputs, token))
        return self.status


def _meta(plans):
    return lambda stack, run: plans.get((stack, run))


@pytest.fixture
def world():
    gh = FakeGitHub()
    plans = {("fullstack", "902"): {"commit": HEAD, "sha256": SHA, "stack": "fullstack", "environment": "dev"}}
    token = {"value": "t" * 8}
    p = InfraPlatform(environment="dev", github=gh, plan_meta=_meta(plans), token=lambda: token["value"],
                      read_token=lambda: "")
    return gh, plans, token, p


def _plan(p):
    live = p.live(ENTRY, {"stack": "fullstack"})
    return live, {"stack": "fullstack", "plan_run": "902", "plan_sha256": SHA}


def test_the_newest_kept_plan_at_the_branch_head_passed_by_helios_is_allowed(world):
    _, _, _, p = world
    live, params = _plan(p)
    assert live["refused"] == ""
    assert live["plan_run"] == {"902"}
    assert live["plan_sha256"] == {SHA}
    assert live["environment"] == "dev"
    assert catalog.validate(ENTRY, params, live) == []


@pytest.mark.parametrize(("change", "why"), [
    ("older-plan", "not at dev's head"),
    ("run-at-other-commit", "another commit"),
    ("no-plan", "no kept plan"),
    ("bad-sha", "not well formed"),
], ids=["plan-of-older-code", "run-commit-differs", "no-kept-plan", "malformed"])
def test_a_plan_that_is_not_the_heads_helios_passed_one_is_refused(world, change, why):
    gh, plans, _, p = world
    if change == "older-plan":
        gh.head = "e" * 40
    elif change == "run-at-other-commit":
        gh.runs[0]["head_sha"] = OLD
    elif change == "no-plan":
        plans.clear()
    else:
        plans[("fullstack", "902")]["sha256"] = "not-a-sha"
    live, params = _plan(p)
    assert why in live["refused"]
    assert live["plan_run"] == set()
    assert catalog.validate(ENTRY, params, live)


def test_an_unreadable_github_allows_nothing(world):
    gh, _, _, p = world
    gh.fail = urllib.error.URLError("unreachable")
    assert p.live(ENTRY, {"stack": "fullstack"}) == {}
    assert p.live(ENTRY, {"stack": "anything-else"}) == {}


def test_apply_dispatches_exactly_the_approved_plan(world):
    gh, _, _, p = world
    live, params = _plan(p)
    out = p.apply(ENTRY, params, snapshot=live["state"], who=WHO)
    [(workflow, ref, inputs, token)] = gh.dispatched
    assert (workflow, ref) == ("deploy-dev.yml", "dev")
    assert inputs == {"part": "infra", "infra_action": "apply-plan", "infra_stack": "fullstack", "plan_run_id": "902",
                      "plan_sha256": SHA}
    assert token == "t" * 8
    assert "run 902's plan" in out


def test_no_token_or_no_approvers_sends_nothing(world):
    gh, _, token, p = world
    live, params = _plan(p)
    with pytest.raises(InfraPlatformRefused, match="approvers"):
        p.apply(ENTRY, params, snapshot=live["state"], who=None)
    token["value"] = ""
    with pytest.raises(InfraPlatformRefused, match="github-actions-token"):
        p.apply(ENTRY, params, snapshot=live["state"], who=WHO)
    assert gh.dispatched == []


def test_a_branch_that_moved_after_the_approval_sends_nothing(world):
    gh, _, _, p = world
    live, params = _plan(p)
    gh.head = "f" * 40  # a merge landed: the approved plan is no longer of the head
    with pytest.raises(InfraPlatformRefused, match="moved since the plan was approved"):
        p.apply(ENTRY, params, snapshot=live["state"], who=WHO)
    assert gh.dispatched == []


def test_github_refusing_the_dispatch_changed_nothing_and_an_odd_answer_is_unknown(world):
    gh, _, _, p = world
    live, params = _plan(p)

    def refuse(*a):
        raise urllib.error.HTTPError("u", 403, "forbidden", {}, None)

    gh.dispatch = refuse
    with pytest.raises(InfraPlatformRefused, match="403") as err:
        p.apply(ENTRY, params, snapshot=live["state"], who=WHO)
    assert err.value.nothing_changed is True
    gh.dispatch = lambda *a: 500
    with pytest.raises(InfraPlatformError, match="unknown") as err:
        p.apply(ENTRY, params, snapshot=live["state"], who=WHO)
    assert not getattr(err.value, "nothing_changed", False)


@pytest.mark.parametrize(("status", "conclusion", "healthy"), [
    ("completed", "success", True), ("in_progress", None, False), ("completed", "failure", False)])
def test_healthy_is_the_apply_run_after_the_fix_finishing_well(world, status, conclusion, healthy):
    gh, _, _, p = world
    gh.runs = [{"id": 903, "status": status, "conclusion": conclusion, "created_at": "2026-10-20T19:00:05+00:00"},
               *gh.runs]
    assert p.healthy("fullstack", entry=ENTRY, params={catalog.APPLIED_AT: APPLIED}) is healthy


def test_no_run_after_the_fix_is_not_healthy(world):
    _, _, _, p = world
    assert p.healthy("fullstack", entry=ENTRY, params={catalog.APPLIED_AT: APPLIED}) is False


def test_it_is_never_undone_automatically(world):
    gh, _, _, p = world
    assert p.rollback(ENTRY, {}, {}).startswith("nothing to roll back")
    assert gh.dispatched == []


def test_the_approver_reads_the_exact_plan():
    [said] = catalog.change_of(ENTRY, {"stack": "fullstack", "plan_run": "902", "plan_sha256": SHA},
                               {"environment": "dev", "commit": HEAD})
    assert f"plan kept by run 902 (sha256 {SHA})" in said
    assert "not undone automatically" in said
    assert catalog.CATALOG[ENTRY].tier == "T3"


class _S3Error(Exception):
    """botocore's ClientError, as far as the reader looks: a response with an error code."""

    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _S3:
    def __init__(self, fail=None):
        self.fail, self.asked = fail, []

    def get_object(self, Bucket, Key):
        self.asked.append((Bucket, Key))
        if self.fail:
            raise self.fail
        return {"Body": io.BytesIO(json.dumps({"commit": HEAD, "sha256": SHA}).encode())}


def test_the_kept_plan_is_read_from_the_state_bucket_and_only_a_missing_one_is_none():
    s3 = _S3()
    assert s3_plan_meta(lambda: s3, "tf-state")("fullstack", "902")["sha256"] == SHA
    assert s3.asked == [("tf-state", "fullstack/plans/902.json")]
    assert s3_plan_meta(lambda: s3, "tf-state")("other", "902") is None
    assert s3_plan_meta(lambda: s3, "tf-state")("fullstack", "../x") is None
    assert s3_plan_meta(lambda: _S3(_S3Error("NoSuchKey")), "tf-state")("fullstack", "902") is None
    with pytest.raises(InfraPlatformError):
        s3_plan_meta(lambda: _S3(_S3Error("AccessDenied")), "tf-state")("fullstack", "902")


def test_the_repository_is_a_plain_name():
    with pytest.raises(InfraPlatformError):
        GitHub("owner/repo/../../x")
    assert GitHub("owner/repo").repo == "owner/repo"


def test_each_environment_reads_its_own_state_bucket_and_one_without_reads_nothing():
    from warden.platforms.infra import PerEnvironment

    asked = []

    def reader(env):
        asked.append(env)
        return lambda service: _S3()

    per = PerEnvironment(reader, repo="owner/repo", buckets="dev=tf-dev, prod=tf-prod")
    dev = per.for_environment("dev")
    assert isinstance(dev, InfraPlatform)
    assert dev.workflow == "deploy-dev.yml"
    assert per.for_environment("dev") is dev
    assert asked == ["dev"]
    lonely = per.for_environment("stage")
    assert lonely.live(ENTRY, {"stack": "fullstack"}) == {}
    with pytest.raises(InfraPlatformRefused):
        lonely.apply(ENTRY, {}, who=WHO)
    assert PerEnvironment(reader, repo="", buckets="dev=tf-dev").for_environment("dev").live(ENTRY, {}) == {}
