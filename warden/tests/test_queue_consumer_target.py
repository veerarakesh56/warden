"""fs-07, live, 2026-10-15: a queue's age alarm, its consumer switched off. The diagnosis was right and named the
consumer's function, which the alarm does not name, so no plan was opened. The plan is still on what the alarm names
- the queue, whose one switched-off mapping the live read finds by the queue's ARN - and only when that mapping's
function is the one the diagnosis named."""

from __future__ import annotations

from warden import resolver
from warden.models import ActionKind, Alert, RemediationProposal, Severity

ALERT = Alert(alert_id="cd4a-20261015T163532Z", name="warden-dev-orders-age", service="warden-dev-orders",
              environment="dev", severity=Severity.high, summary="", started_at="2026-10-15T16:35:32+00:00",
              labels={"alarm": "warden-dev-orders-age", "sqs": "warden-dev-orders", "via": "cloudwatch"})


def _prop(action=ActionKind.resume_flow, target="warden-dev-order-processor"):
    return RemediationProposal(action=action, target=target, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)


def _live(function="warden-dev-order-processor"):
    asked = []

    def live(entry, params):
        asked.append((entry, dict(params)))
        return {"function": {function}, "mapping": {"esm-1"}, "environment": "dev",
                "state": {"function": function, "mapping": "esm-1", "enabled": False}}
    return live, asked


def test_the_consumer_named_by_its_function_is_planned_on_the_alarms_queue():
    live, asked = _live()
    req, why = resolver.request_for(ALERT, _prop(), live)
    assert why == ""
    assert req["entry"] == "lambda_enable_esm"
    assert req["params"]["function"] == "warden-dev-order-processor"
    assert req["params"]["mapping"] == "esm-1"
    assert asked[0] == ("lambda_enable_esm", {"queue": "warden-dev-orders"})  # read by the queue the alarm names


def test_another_function_another_action_or_no_queue_opens_no_plan():
    live, _ = _live(function="warden-dev-something-else")
    assert "its one switched-off consumer is not warden-dev-order-processor" in resolver.request_for(
        ALERT, _prop(), live)[1]
    live, _ = _live()
    assert resolver.request_for(ALERT, _prop(action=ActionKind.restart_pods), live)[0] is None
    bare = ALERT.model_copy(update={"labels": {"alarm": "warden-dev-orders-age"}})
    assert resolver.request_for(bare, _prop(), live)[1] == "the proposal's target is not a resource the alert's labels name"
