"""fs-07, live, 2026-10-15: "Impact: no errors and no failing component" over a queue whose only consumer was switched
off and 95 orders waiting. A queue's consumers switched off, and messages waiting with none being processed, are
counted states - impact."""

from __future__ import annotations

from warden.models import ContextBundle
from warden.verifier import symptoms


def test_a_queue_nobody_consumes_is_impact():
    seen = symptoms(ContextBundle(metrics={"sqs_visible": 95.0, "sqs_in_flight": 0.0, "sqs_consumers_enabled": 0.0}))
    assert "95 message(s) waiting in the queue, none being processed" in seen
    assert "queue consumers enabled: 0" in seen


def test_a_queue_being_worked_through_is_not():
    assert symptoms(ContextBundle(metrics={"sqs_visible": 95.0, "sqs_in_flight": 10.0,
                                           "sqs_consumers_enabled": 1.0})) == []
    per = symptoms(ContextBundle(metrics={"sqs_visible__orders": 3.0, "sqs_in_flight__orders": 0.0}))
    assert per == ["3 message(s) waiting in the queue (orders), none being processed"]
