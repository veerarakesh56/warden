"""The small decisions platforms/aws.py makes in its own helpers, each pinned directly: when a deployment counts as
the alarm's cause, what a refusal says, and the bounds a restore is held to."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from warden.platforms import aws
from warden.platforms.aws import AwsPlatform

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
FIRED = NOW - timedelta(minutes=30)
IN_ALARM = {"StateValue": "ALARM"}


def test_a_deployment_that_started_before_the_alarm_is_its_possible_cause():
    assert aws._started_before_alarm(IN_ALARM, FIRED, FIRED - timedelta(hours=1)) is True


def test_a_deployment_that_started_after_the_alarm_is_not_its_cause():
    assert aws._started_before_alarm(IN_ALARM, FIRED, FIRED + timedelta(minutes=1)) is False


def test_a_deployment_days_before_the_alarm_is_not_its_cause():
    assert aws._started_before_alarm(IN_ALARM, FIRED, FIRED - timedelta(hours=7)) is False


def test_no_onset_means_the_alarm_is_not_in_alarm():
    assert aws._change_refusal({"at": FIRED}, None) == "the alarm is not in ALARM"


def test_several_writes_are_not_chosen_between():
    assert aws._not_chosen([{}, {}]) == " (WARDEN does not choose one)"


def test_no_write_needs_no_choosing():
    assert aws._not_chosen([]) == ""


def test_a_resource_config_does_not_record_is_refused_without_reading_its_history():
    p = AwsPlatform(reader=lambda service: None, actor=lambda *a: None, clock=lambda: NOW, sleep=lambda s: None)
    got = p._config_values("AWS::SQS::Queue", lambda: "", {"at": FIRED}, lambda i: i, "", FIRED, "no record")
    assert got == (None, None, "no record")


def test_a_reservation_the_account_has_no_room_for_is_not_restored():
    # 500 back from 100 needs 400 more; 450 unreserved less the 100 AWS keeps leaves 350.
    assert aws._concurrency_refusal(500, 100, 100, 450) == "the account has no room to reserve that much again"


def test_a_reservation_the_account_has_room_for_is_restored():
    assert aws._concurrency_refusal(300, 100, 100, 450) == ""


def test_a_retention_under_a_day_is_outside_what_kinesis_allows():
    assert aws._retention_refusal(12, 6, 6) == "the retention before the change is outside what Kinesis allows"


def test_a_deregistered_target_without_a_port_is_still_registered_again():
    assert aws._deregistered({"targets": [{"id": "i-1"}]}) == [["i-1", None]]
