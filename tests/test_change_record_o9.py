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
        self.opened, self.links, self.fail = [], [], fail

    def open(self, title, body, *, links=(), incident=""):
        self.opened.append((title, body))
        self.links.append((links, incident))
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
    # It is the head at the end row: the page's head moves on with later rows (CodeRabbit, PR 114), so it says so.
    for said in ("Audit head at this end:** `", "the head it shows moves on"):
        assert said in body, said
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


# Owner B10: the change record links the incident's record page - WARDEN's own link, added after the gate.
RP = "approve.example"


def _sent_body(monkeypatch, links, incident="inc-42"):
    sent = []

    def urlopen(req, timeout):
        sent.append(json.loads(req.data))
        return _Resp(json.dumps({"html_url": "https://github.com/o/r/issues/8"}).encode())

    monkeypatch.setattr(changes.web, "urlopen", urlopen)
    url, detail = changes.GitHubIssues("o/r", "t").open("WARDEN change: x", "body text", links=links,
                                                         incident=incident)
    assert url.endswith("/issues/8")
    assert detail == "opened"
    return sent[0]["body"]


def test_the_record_links_the_incidents_record_page(monkeypatch):
    from warden.activities import IncidentActivities

    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", RP)
    body = _sent_body(monkeypatch, IncidentActivities._record_link("inc-42"))
    assert body.endswith(f"\n\n[Full record of the incident](https://{RP}/r/inc-42)"), body
    assert f"https://{RP}/r)" not in body  # the record page of this incident, not the list of all of them


def test_only_wardens_own_record_link_is_added(monkeypatch):
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", RP)
    approval = f"https://{RP}/a/" + "A" * 43
    for links in ((("Full record", "https://evil.example/r/inc-42"),),
                  (("Full record", f"https://{RP}/r/inc-42/../../x?y=z"),),
                  (("Open the plan to approve or deny", approval),),
                  (("Something else", f"https://{RP}/r/inc-42"),)):
        body = _sent_body(monkeypatch, links)
        assert body == "body text", links
    # Another incident's record page, or no incident named: the link is not this change's (CodeRabbit, PR 114).
    assert _sent_body(monkeypatch, (("Full record", f"https://{RP}/r/inc-7"),)) == "body text"
    assert _sent_body(monkeypatch, (("Full record", f"https://{RP}/r/inc-42"),), incident="") == "body text"
    assert _sent_body(monkeypatch, (("Full record", f"https://{RP}/r/xinc-42"),)) == "body text"
    # No approval domain configured: there is no record page to link.
    monkeypatch.delenv("WARDEN_APPROVAL_RP_ID")
    assert _sent_body(monkeypatch, (("Full record", f"https://{RP}/r/inc-42"),)) == "body text"


def test_an_incident_id_of_any_length_an_alert_may_have_keeps_its_record_link(monkeypatch):
    """CodeRabbit, PR 114: an alert id may be 128 characters (models.Alert), the record link allowed 120 - a longer id's
    change record lost its link. 128 links; 129, which no alert id can be, does not."""
    from warden.activities import IncidentActivities

    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", RP)
    longest, too_long = "i" * 128, "i" * 129
    body = _sent_body(monkeypatch, IncidentActivities._record_link(longest), incident=longest)
    assert body.endswith(f"[Full record of the incident](https://{RP}/r/{longest})")
    assert _sent_body(monkeypatch, IncidentActivities._record_link(too_long), incident=too_long) == "body text"


def test_the_record_page_opens_for_an_id_of_the_longest_alert_id():
    from warden import approval_page

    assert approval_page._INCIDENT_ID.fullmatch("i" * 128)
    assert not approval_page._INCIDENT_ID.fullmatch("i" * 129)


def test_an_applied_change_passes_its_record_link(world, owner, monkeypatch):  # noqa: F811 - pytest fixtures
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", RP)
    world["changes"] = rec = _Recorder()
    assert _run(world, _approve_with(owner)).status == "recovered"
    links, incident = rec.links[0]
    assert ("Full record", f"https://{RP}/r/inc-42") in links
    assert incident == "inc-42"



def test_the_record_names_the_head_of_the_end_row_not_a_later_page_resolve(world, monkeypatch):  # noqa: F811 - pytest fixtures
    """CodeRabbit, PR 114: a resolved page appends page.resolved after the signed end row; the head named is the end's.

    The activity is called directly (no worker, so its run id is ""), with this run's plan and applied rows."""
    from types import SimpleNamespace

    from warden import audit, bounds, chatops
    from warden.activities import FixOutcome, RemediationActivities

    monkeypatch.setattr(chatops, "page_resolve", lambda incident: SimpleNamespace(delivered=True, detail="resolved"))
    log, rec = world["log"], _Recorder()
    acts = RemediationActivities(audit=log, policy=world["policy"], platform=world["platform"], changes=rec)
    log.append("inc-7", "remediation.plan", {"workflow_id": "rem-7", "run_id": "", "tier": "T1", "plan_hash": "h",
                                             "entry": "k8s_rollout_undo", "target": "orders"})
    log.append("inc-7", bounds.APPLIED, {"workflow_id": "rem-7", "run_id": "", "plan_hash": "h"})
    acts.finish("inc-7", "rem-7", FixOutcome(status="recovered", checklist={}, plan_hash="h"))
    end = log.entries("inc-7", kinds=("workflow.end",))[-1]
    assert log.entries("inc-7", kinds=("page.resolved",))[-1]["seq"] > end["seq"]
    assert f"Audit head at this end:** `{audit.short(end['hash'])}`" in rec.opened[0][1]
