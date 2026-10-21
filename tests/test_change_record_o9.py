"""Register O9: every change WARDEN applied leaves a record where a team looks for changes - a GitHub issue naming
the change, the plan hash, the approvers and the audit head - and only changes that were applied do."""

from __future__ import annotations

import io
import json
import re

from fakes import AWS_ACCESS_KEY_ID
from test_remediation_workflow import _approve_with, _no_approval, _run, owner, world  # noqa: F401
from warden import changes


class _Recorder:
    def __init__(self, fail=False):
        self.opened, self.fail = [], fail

    def open(self, title, body):
        self.opened.append((title, body))
        return (None, "HTTP 503") if self.fail else ("https://github.example.test/o/r/issues/1", "opened")


def test_an_applied_change_opens_one_record_citing_its_plan_and_audit(world, owner):  # noqa: F811
    world["changes"] = rec = _Recorder()
    assert _run(world, _approve_with(owner)).status == "recovered"
    assert len(rec.opened) == 1
    title, body = rec.opened[0]
    plan = world["log"].entries("inc-42", kinds=("remediation.plan",))[-1]["body"]
    assert plan["entry"] in title
    assert "recovered" in title
    assert plan["plan_hash"] in body
    assert "owner" in body
    assert "a single approver" in body
    # Where a reader checks the head: the incident's Full record page (the command it named could not be run).
    assert "the same as on the incident's Full record page, signatures checked" in body
    assert "audit show" not in body
    assert re.search(r"Ended:\*\* recovered at \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z", body), body
    row = world["log"].entries("inc-42", kinds=("change.recorded",))[-1]["body"]
    assert row["url"].endswith("/issues/1")
    assert row["detail"] == "opened"


def test_nothing_applied_means_no_record(world):  # noqa: F811
    world["changes"] = rec = _Recorder()
    assert _run(world, _no_approval, approval_ttl_minutes=1).status == "expired"
    assert rec.opened == []
    assert world["log"].entries("inc-42", kinds=("change.recorded",)) == []


def test_a_record_that_could_not_be_written_is_itself_recorded(world, owner):  # noqa: F811
    world["changes"] = _Recorder(fail=True)
    assert _run(world, _approve_with(owner)).status == "recovered"
    row = world["log"].entries("inc-42", kinds=("change.recorded",))[-1]["body"]
    assert row["url"] is None
    assert row["detail"] == "HTTP 503"


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_the_issue_goes_to_the_one_repository_with_the_token_and_through_the_gate(monkeypatch):
    sent = []

    def urlopen(req, timeout):
        sent.append(req)
        return _Resp(json.dumps({"html_url": "https://github.com/o/r/issues/7"}).encode())

    monkeypatch.setattr(changes.web, "urlopen", urlopen)
    token = "github" + "_pat_" + "0" * 12
    url, detail = changes.GitHubIssues("o/r", token).open("WARDEN change: x", "body text")
    req = sent[0]
    assert url.endswith("/issues/7")
    assert detail == "opened"
    assert req.full_url == "https://api.github.com/repos/o/r/issues"
    assert req.get_method() == "POST"
    assert req.get_header("Authorization") == f"Bearer {token}"
    assert json.loads(req.data)["labels"] == ["warden-change"]
    assert token not in req.data.decode()
    leak = AWS_ACCESS_KEY_ID
    url, detail = changes.GitHubIssues("o/r", token).open("WARDEN change", f"key {leak}")
    assert len(sent) == 1
    assert url is None
    assert detail.startswith("withheld")


def test_records_are_on_only_with_a_repository_and_a_token(monkeypatch):
    from warden import settings

    monkeypatch.delenv("WARDEN_CHANGE_REPO", raising=False)
    monkeypatch.setenv("WARDEN_GITHUB_TOKEN", "t")
    assert changes.from_environment() is None
    monkeypatch.setenv("WARDEN_CHANGE_REPO", "o/r")
    assert changes.from_environment().repo == "o/r"
    assert "WARDEN_GITHUB_TOKEN" in settings.SECRETS
    assert settings.RESTRICTED["WARDEN_GITHUB_TOKEN"] == {"worker"}
