"""G10 v2 (2026-10-10): a queue's timing and size settings, and a stream's retention, back to what AWS Config recorded
just before ONE recorded change (held-out int-sqs-visibility-shorter-than-timeout and int-kinesis-retention-cut).
Field names from AWS's Config resource schemas (awslabs/aws-config-resource-schema, read 2026-10-10):
AWS::SQS::Queue configuration.VisibilityTimeout and the other integer settings, AWS::Kinesis::Stream
configuration.RetentionPeriodHours."""

from __future__ import annotations

import pytest

from test_aws_platform_g6 import ACCT, WHO
from test_revert_config_history_g10d3 import ALARM, Fake, _ci, _p, _trail
from warden import resolver
from warden.models import ActionKind, Alert, RemediationProposal, Severity
from warden.platforms.aws import AwsPlatformRefused

Q = "warden-dev-invoices"
Q_URL = f"https://sqs.test-region-1.amazonaws.com/{ACCT}/{Q}"
Q_ARN = f"arn:aws:sqs:test-region-1:{ACCT}:{Q}"
S = "warden-dev-clicks"
S_ARN = f"arn:aws:kinesis:test-region-1:{ACCT}:stream/{S}"


class Queue(Fake):
    """A queue whose visibility timeout one person's SetQueueAttributes cut from 300 s to 30 s."""

    def __init__(self, attributes=None, before=None):
        super().__init__()
        self.attrs = {"QueueArn": Q_ARN, "VisibilityTimeout": "30", "MessageRetentionPeriod": "345600",
                      "DelaySeconds": "0", "Policy": "{}"}
        self.events = [_trail("SetQueueAttributes", {"queueUrl": Q_URL, "attributes": attributes or {
            "VisibilityTimeout": "30"}}, eid="q-1", source="sqs.amazonaws.com")]
        self.history["AWS::SQS::Queue"] = [
            _ci(600, before or {"VisibilityTimeout": 300, "MessageRetentionPeriod": 345600}),
            _ci(59, {"VisibilityTimeout": 30, "MessageRetentionPeriod": 345600}, related=["q-1"])]

    def get_queue_url(self, QueueName):
        return {"QueueUrl": Q_URL}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        return {"Attributes": dict(self.attrs)}

    def list_queue_tags(self, QueueUrl):
        return {"Tags": {"Environment": "dev"}}

    def list_discovered_resources(self, resourceType, resourceName):
        rid = {"AWS::SQS::Queue": Q_URL, "AWS::Kinesis::Stream": S}.get(resourceType)
        if rid is None:
            return super().list_discovered_resources(resourceType, resourceName)
        return {"resourceIdentifiers": [{"resourceType": resourceType, "resourceId": rid, "resourceName": resourceName}]}


class Stream(Queue):
    """A stream whose retention was cut from 168 h to 24 h while a backfill read it 30 h behind."""

    def __init__(self, before=168):
        super().__init__()
        self.hours = 24
        self.events = [_trail("DecreaseStreamRetentionPeriod", {"streamName": S, "retentionPeriodHours": 24},
                              eid="k-1", source="kinesis.amazonaws.com")]
        self.history["AWS::Kinesis::Stream"] = [_ci(600, {"RetentionPeriodHours": before}),
                                                _ci(59, {"RetentionPeriodHours": 24}, related=["k-1"])]

    def describe_stream_summary(self, StreamName):
        return {"StreamDescriptionSummary": {"StreamName": S, "StreamARN": S_ARN, "RetentionPeriodHours": self.hours,
                                             "StreamStatus": "ACTIVE"}}

    def list_tags_for_stream(self, StreamName):
        return {"Tags": [{"Key": "Environment", "Value": "dev"}]}


QP = {"alarm": ALARM, "queue": Q}
SP = {"alarm": ALARM, "stream": S}


def test_a_visibility_timeout_cut_is_set_back_and_its_rollback_sets_what_the_change_set():
    f = Queue()
    p = _p(f)
    live = p.live("sqs_restore_attributes", QP)
    assert live["event"] == {"q-1"} and live["attributes"] == {"VisibilityTimeout=300"}, live.get("refused")
    params = {**QP, "event": "q-1", "attributes": "VisibilityTimeout=300"}
    p.apply("sqs_restore_attributes", params, snapshot=live["state"], who=WHO)
    assert f.sessions[-1] == {"actions": ["sqs:SetQueueAttributes"], "resources": [Q_ARN]}
    assert f.writes[-1] == ("set_queue_attributes", {"QueueUrl": Q_URL, "Attributes": {"VisibilityTimeout": "300"}})
    f.attrs["VisibilityTimeout"], f.alarm_state = "300", "OK"
    assert p.healthy(Q, entry="sqs_restore_attributes", params=params) is True
    p.rollback("sqs_restore_attributes", params, live["state"], who=WHO)
    assert f.writes[-1] == ("set_queue_attributes", {"QueueUrl": Q_URL, "Attributes": {"VisibilityTimeout": "30"}})


@pytest.mark.parametrize("fake, why", [
    (Queue(attributes={"VisibilityTimeout": "30", "Policy": "{}"}), "also set Policy"),
    (Queue(attributes={"RedrivePolicy": "{}"}), "also set RedrivePolicy"),
    (Queue(attributes={"KmsMasterKeyId": "alias/x"}), "also set KmsMasterKeyId"),
    (Queue(before={"VisibilityTimeout": 99999}), "outside what SQS allows"),
    (Queue(before={"DelaySeconds": 0}), "no value before"),
])
def test_a_queue_change_wardens_restore_may_not_undo_is_refused(fake, why):
    live = _p(fake).live("sqs_restore_attributes", QP)
    assert live["attributes"] == set() and why in live["refused"], live.get("refused")


def test_a_queue_whose_setting_moved_is_refused_before_and_after_the_plan():
    f = Queue()
    f.attrs["VisibilityTimeout"] = "60"
    assert "moved since" in _p(f).live("sqs_restore_attributes", QP)["refused"]
    g = Queue()
    p = _p(g)
    snap = p.live("sqs_restore_attributes", QP)["state"]
    g.attrs["VisibilityTimeout"] = "60"
    with pytest.raises(AwsPlatformRefused):
        p.apply("sqs_restore_attributes", {**QP, "event": "q-1", "attributes": "VisibilityTimeout=300"},
                snapshot=snap, who=WHO)
    assert g.writes == []


def test_a_retention_cut_is_raised_back_and_its_rollback_lowers_it_again():
    f = Stream()
    p = _p(f)
    live = p.live("kinesis_restore_retention", SP)
    assert live["event"] == {"k-1"} and live["hours"] == {"168"}, live.get("refused")
    params = {**SP, "event": "k-1", "hours": "168"}
    p.apply("kinesis_restore_retention", params, snapshot=live["state"], who=WHO)
    assert f.sessions[-1] == {"actions": ["kinesis:IncreaseStreamRetentionPeriod"], "resources": [S_ARN]}
    assert f.writes[-1] == ("increase_stream_retention_period", {"StreamName": S, "RetentionPeriodHours": 168})
    f.hours, f.alarm_state = 168, "OK"
    assert p.healthy(S, entry="kinesis_restore_retention", params=params) is True
    p.rollback("kinesis_restore_retention", params, live["state"], who=WHO)
    assert f.sessions[-1]["actions"] == ["kinesis:DecreaseStreamRetentionPeriod"]
    assert f.writes[-1] == ("decrease_stream_retention_period", {"StreamName": S, "RetentionPeriodHours": 24})


def test_a_stream_without_a_longer_retention_before_or_that_moved_is_refused():
    assert "no longer retention" in _p(Stream(before=24)).live("kinesis_restore_retention", SP)["refused"]
    f = Stream()
    f.hours = 48
    assert "moved since" in _p(f).live("kinesis_restore_retention", SP)["refused"]


def test_the_resolver_plans_a_queue_and_a_stream_revert_from_their_labels():
    proposal = RemediationProposal(action=ActionKind.revert_change, target=Q, reasoning="r", expected_effect="e",
                                   blast_radius="single_service", reversible=True)
    for fake, labels, target, entry in ((Queue(), {"alarm": ALARM, "sqs": Q}, Q, "sqs_restore_attributes"),
                                        (Stream(), {"alarm": ALARM, "kinesis_stream": S}, S,
                                         "kinesis_restore_retention")):
        alert = Alert(alert_id="a1", name="n", service=target, environment="dev", severity=Severity.high, summary="",
                      started_at="2026-10-10T00:00:00+00:00", labels=labels)
        req, why = resolver.request_for(alert, proposal.model_copy(update={"target": target}),
                                        lambda e, params, fake=fake: _p(fake).live(e, params))
        assert why == "" and req["entry"] == entry, why
