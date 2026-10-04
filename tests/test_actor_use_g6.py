"""G6: every actor session is held to the audit. CloudTrail records each AssumeRole of a `warden-<env>-actor` role; the
`actor-use` Lambda gets it from EventBridge (through the witness trail) and pages - via the `UnapprovedActorUse`
metric's alarm - unless the incident holds accepted approvals of that plan from everyone the session names, as many as
the tier required. A session the check cannot read the audit for pages too."""

from __future__ import annotations

import pathlib

import pytest

from warden import actor_use, lambdas, settings

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "terraform" / "modules" / "warden-runtime"
ACCOUNT = "0" * 12
ROLE = f"arn:aws:iam::{ACCOUNT}:role/warden-dev-actor"
PLAN = "ab" * 32


def _detail(tags=None, *, role=ROLE, source="inc-7", error=None, event="AssumeRole"):
    """CloudTrail's AssumeRole record as EventBridge delivers it (requestParameters.tags as key/value pairs)."""
    tags = {"approver": "alice", "incident": "inc-7", "plan": PLAN[:16]} if tags is None else tags
    d = {"eventSource": "sts.amazonaws.com", "eventName": event, "eventID": "e-1", "eventTime": "2026-10-04T10:00:00Z",
         "userIdentity": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/warden-ops-worker/task"},
         "requestParameters": {"roleArn": role, "roleSessionName": source, "sourceIdentity": source,
                               "durationSeconds": 900, "tags": [{"key": k, "value": v} for k, v in tags.items()]}}
    if error:
        d["errorCode"] = error
    return d


class Audit:
    def __init__(self, rows=()):
        self.rows, self.appended = list(rows), []

    def entries(self, correlation_id=None, *, kinds=(), since=None):
        return [r for r in self.rows if r["correlation_id"] == correlation_id and (not kinds or r["kind"] in kinds)]

    def append(self, correlation_id, kind, body):
        self.appended.append((correlation_id, kind, body))
        return "h"


def _accepted(approver="alice", plan=PLAN, required=1, incident="inc-7"):
    return {"correlation_id": incident, "kind": "approval.accepted",
            "body": {"approver": approver, "plan_hash": plan, "required": required}}


def test_a_session_the_audit_shows_approved_has_no_problem():
    assert actor_use.check(_detail(), Audit([_accepted()])) == []
    two = _detail({"approver": "alice+bob", "incident": "inc-7", "plan": PLAN[:16]})
    assert actor_use.check(two, Audit([_accepted("alice", required=2), _accepted("bob", required=2)])) == []


@pytest.mark.parametrize("detail, rows, needle", [
    (_detail({}), [_accepted()], "without the incident, plan and approver tags"),
    (_detail({"incident": "inc-7", "plan": PLAN[:16]}), [_accepted()], "without the incident, plan and approver tags"),
    (_detail(), [], "holds no accepted approval"),
    (_detail(), [_accepted(plan="cd" * 32)], "holds no accepted approval"),          # another plan's approval
    (_detail(), [_accepted(incident="inc-8")], "holds no accepted approval"),        # another incident's
    (_detail({"approver": "mallory", "incident": "inc-7", "plan": PLAN[:16]}), [_accepted()], "who did not approve"),
    (_detail(), [_accepted(required=2)], "needed 2 approvers and has 1"),
    (_detail(source="inc-9"), [_accepted()], "source identity"),
])
def test_a_session_without_its_approval_is_a_problem(detail, rows, needle):
    problems = actor_use.check(detail, Audit(rows))
    assert any(needle in p for p in problems), problems


def test_only_successful_actor_sessions_are_checked():
    nothing = Audit()
    assert actor_use.check(_detail(role=f"arn:aws:iam::{ACCOUNT}:role/warden-dev-platform-reader"), nothing) == []
    assert actor_use.check(_detail(error="AccessDenied"), nothing) == []  # a refused call minted nothing
    assert actor_use.check(_detail(event="GetCallerIdentity"), nothing) == []


@pytest.fixture
def cloudwatch(monkeypatch):
    import boto3

    sent = []

    class Cw:
        def put_metric_data(self, **kw):
            sent.append(kw)

    monkeypatch.setattr(lambdas, "_configure", lambda name: None)
    monkeypatch.setattr(boto3, "client", lambda service, **kw: Cw())
    monkeypatch.setattr("warden.environments.region", lambda: "test-region-1")
    monkeypatch.setenv("WARDEN_ENV", "ops")
    return sent


def test_the_lambda_pages_an_unapproved_session_and_records_it(cloudwatch, monkeypatch):
    log = Audit()
    monkeypatch.setattr("warden.runtime.open_audit", lambda: log)
    out = lambdas.actor_use({"detail": _detail()})
    assert out["approved"] is False and "holds no accepted approval" in out["problems"][0]
    assert cloudwatch == [{"Namespace": "WARDEN/ops", "MetricData": [
        {"MetricName": lambdas.UNAPPROVED_METRIC, "Value": 1, "Unit": "Count"}]}]
    ((incident, kind, body),) = log.appended
    assert (incident, kind, body["role"], body["event_id"]) == ("inc-7", "actor.unapproved", ROLE, "e-1")


def test_the_lambda_lets_an_approved_session_pass_and_pages_when_it_cannot_check(cloudwatch, monkeypatch):
    monkeypatch.setattr("warden.runtime.open_audit", lambda: Audit([_accepted()]))
    assert lambdas.actor_use({"detail": _detail()}) == {"approved": True} and cloudwatch == []

    def down():
        raise ConnectionError("audit database unreachable")
    monkeypatch.setattr("warden.runtime.open_audit", down)
    out = lambdas.actor_use({"detail": _detail()})
    assert out["approved"] is False and "could not be read" in out["problems"][0] and len(cloudwatch) == 1
    assert lambdas.actor_use({"detail": _detail(error="AccessDenied")})["ignored"] and len(cloudwatch) == 1


def test_the_lambda_loads_only_the_audit_it_reads():
    names = settings.loadable_for("lambda-actor-use")
    assert "WARDEN_AUDIT_DSN" in names
    assert not names & {"WARDEN_TEMPORAL_API_KEY", "WARDEN_ALERTMANAGER_TOKEN", "WARDEN_PAGERDUTY_ROUTING_KEY"}


def test_the_rule_the_trail_and_the_page_are_wired():
    tf = (MODULE / "witness.tf").read_text(encoding="utf-8")
    rule = tf[tf.index('resource "aws_cloudwatch_event_rule" "actor_use"'):tf.index('resource "aws_cloudwatch_event_target"')]
    assert 'state = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"' in rule
    assert 'source        = ["aws.sts"]' in rule and 'eventName         = ["AssumeRole"]' in rule
    assert '{ suffix = ":role/warden-${e}-actor" }' in rule  # every watched environment's actor, nothing else
    assert 'arn  = aws_lambda_function.front_door["actor-use"].arn' in tf and "arn = aws_sqs_queue.alarm_dlq.arn" in tf
    assert 'actor-use    = { handler = "warden.lambdas.actor_use"' in (MODULE / "frontdoor.tf").read_text(encoding="utf-8")
    alarm = tf[tf.index('"unapproved_actor"'):]
    assert f'metric_name         = "{lambdas.UNAPPROVED_METRIC}"' in alarm
    assert 'namespace           = "WARDEN/${var.environment}"' in alarm  # where the Lambda puts it (WARDEN_ENV)
    assert "alarm_actions       = [var.page_topic_arn]" in alarm and 'treat_missing_data  = "notBreaching"' in alarm
    trail = tf[tf.index('resource "aws_cloudtrail" "witness"'):]
    assert "enable_log_file_validation    = true" in trail and "s3_bucket_name                = aws_s3_bucket.witness.id" in trail
    assert 'mode = "COMPLIANCE"' in tf and "object_lock_enabled = true" in tf
    assert tf.count(':trail/${local.witness_trail}"') == 2  # CloudTrail writes for this trail only
    assert 'witness_trail = "warden-${var.environment}-witness"' in tf
