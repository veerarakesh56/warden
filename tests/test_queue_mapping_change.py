"""Scenario fs-07, live: the queue's consumer was switched off by an UpdateEventSourceMapping20150331 that CloudTrail
files with no resource name - only the mapping's id - so a lookup by the queue's name never found it and the report
named nobody. The queue's own mappings (by its ARN) say which ids are its, and the write is read as a change to it."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from test_alarm_reader_g9 import _alarm, _alert, _backend, _Fake

WHEN = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)


def _esm_write(uuid, *, enabled=False):
    detail = {"userIdentity": {"type": "AssumedRole", "sessionContext": {"sessionIssuer": {"userName": "warden-dev-harness"}}},
              "requestParameters": {"uUID": uuid, "enabled": enabled}}
    return {"EventId": f"e-{uuid}", "EventTime": WHEN, "EventSource": "lambda.amazonaws.com",
            "EventName": "UpdateEventSourceMapping20150331", "ReadOnly": "false", "CloudTrailEvent": json.dumps(detail)}


def _reader(mappings=("u-1",)):
    b, _, _ = _backend(_alarm())

    def lookup(**kw):
        attr = kw["LookupAttributes"][0]
        if attr == {"AttributeKey": "EventName", "AttributeValue": "UpdateEventSourceMapping20150331"}:
            return {"Events": [_esm_write("u-1"), _esm_write("u-other")]}
        return {"Events": []}
    b._ct = _Fake(lookup_events=lookup)
    b._sqs = _Fake(get_queue_url={"QueueUrl": "https://sqs/warden-dev-jobs"},
                   get_queue_attributes={"Attributes": {"QueueArn": "arn:aws:sqs:r:a:warden-dev-jobs"}})
    b._lambda = _Fake(list_event_source_mappings={"EventSourceMappings": [{"UUID": u} for u in mappings]})
    return b


def test_the_queues_own_mapping_switched_off_is_a_change_to_the_queue_by_whoever_did_it():
    lines = [ln for ln in _reader()._read_all(_alert()).lines if ln.startswith("CHANGE ")]
    mine = [ln for ln in lines if "UpdateEventSourceMapping20150331 on warden-dev-jobs by role/warden-dev-harness" in ln]
    assert len(mine) == 1, lines  # the queue's mapping, not another queue's (u-other)


def test_a_queue_with_no_mapping_of_its_own_reads_no_such_change():
    lines = [ln for ln in _reader(mappings=())._read_all(_alert()).lines if ln.startswith("CHANGE ")]
    assert not any("EventSourceMapping" in ln for ln in lines)
