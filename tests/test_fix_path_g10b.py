"""G10-B: a fix WARDEN has no way to carry out is advice for a person, never a plan put to the approver.

Held-out G9-F (2026-10-10): scale_up on a NAT gateway reached a person as approved_for_human although no catalogue
entry acts on a NAT gateway - the one wrong answer the gate let through. P30 escalates a mutating proposal whose
target is a resource the alarm's labels name, when none of that resource's kinds has an entry for the action."""

from __future__ import annotations

import pytest

from warden import resolver
from warden.models import (
    ActionKind,
    Alert,
    Citation,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Severity,
)
from warden.verifier import verify


def _alert(**labels):
    return Alert(alert_id="a1", name="n", service="checkout", environment="dev", severity=Severity.high,
                 summary="", started_at="2026-10-10T00:00:00+00:00", labels=labels)


def _prop(action, target):
    return RemediationProposal(action=action, target=target, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)


@pytest.mark.parametrize("labels, action, target", [
    ({"nat_gateway": "nat-0a1b"}, ActionKind.scale_up, "nat-0a1b"),
    ({"efs": "fs-0a1b"}, ActionKind.scale_up, "fs-0a1b"),
    ({"quota_service": "Lambda"}, ActionKind.raise_limit, "Lambda"),
    ({"s3_bucket": "media"}, ActionKind.revert_config, "media"),  # revert_config acts on AppConfig only
    ({"sqs": "q"}, ActionKind.freeze_changes, "q"),  # a freeze is reached from a function or a service
    ({"state_machine": "saga"}, ActionKind.rollback_deploy, "saga"),
])
def test_a_named_resource_with_no_entry_for_the_action_has_no_fix_path(labels, action, target):
    assert resolver.no_fix_path(_alert(**labels), _prop(action, target))


@pytest.mark.parametrize("labels, action, target", [
    ({"dynamodb_table": "carts"}, ActionKind.scale_up, "carts"),
    ({"lambda": "fn"}, ActionKind.scale_up, "lambda:fn"),
    ({"lambda": "fn"}, ActionKind.raise_limit, "lambda:fn"),
    ({"aurora_cluster": "shop"}, ActionKind.terminate_connections, "shop"),
    ({"ecs_cluster": "c", "ecs_service": "api"}, ActionKind.freeze_changes, "api"),
    ({"eventbridge_rule": "poll"}, ActionKind.resume_flow, "poll"),
    ({"lambda": "fn"}, ActionKind.revert_config, "app/env"),  # an AppConfig target is found through the alarm
    ({"cluster": "checkout"}, ActionKind.rollback_deploy, "checkout"),  # a qualifier names no kind
    ({"deployment": "x"}, ActionKind.rollback_deploy, "checkout"),  # nothing labelled: unknown is not "none"
    ({"nat_gateway": "nat-0a1b"}, ActionKind.escalate_to_human, "nat-0a1b"),
])
def test_an_action_some_entry_can_carry_out_or_an_unknown_target_is_left_to_the_planner(labels, action, target):
    assert resolver.no_fix_path(_alert(**labels), _prop(action, target)) == ""


def _gated(**labels):
    context = ContextBundle(logs=[f"LOG ecs/x 2026-10-10T00:00:0{i}Z WARN ThrottlingException write throttled"
                                  for i in range(5)],
                            metrics={"write_throttle_events": 412.0, "write_capacity_used_pct": 99.0,
                                     "error_rate": 0.2, "p99_latency_ms": 900.0})
    rc = RootCause(hypothesis="writes throttled at provisioned capacity", confidence=0.9, evidence=["throttle"],
                   citations=[Citation(id="M1", quote="write_throttle_events=412")])
    return verify(_alert(**labels), context, rc, _prop(ActionKind.scale_up, "orders"))


def test_the_gate_escalates_a_fix_nothing_can_carry_out_rather_than_putting_it_to_the_approver():
    """The same evidence and proposal: put to the approver for a table (an entry scales it), escalated for a stream."""
    table = _gated(dynamodb_table="orders")
    assert table.status.value == "approved_for_human", table
    stream = _gated(kinesis_stream="orders")
    assert stream.status.value == "escalated" and stream.policy_ids == ["P30-NO-FIX-PATH"], stream


def test_a_kind_prefixed_target_is_planned_as_the_label_it_names():
    """`lambda:fn` for the label `fn` (9 of 48 held-out targets) was never planned; an ARN is never cut up."""
    alert = _alert(**{"lambda": "fn"})
    assert resolver._platform(alert, "lambda:fn") == ("lambda", {"function": "fn"})
    assert resolver._platform(alert, "arn:aws:lambda:region:acct:function:fn") is None
    assert resolver._platform(alert, "lambda:other") is None


def _db_live(server, names=frozenset({"shop"})):
    return lambda entry, params: {"database": set(names), "environment": "dev",
                                  "state": {"server": server, "database": "shop"}}


@pytest.mark.parametrize("server", [
    "warden-dev-shop-aurora.cluster-abc.ap-south-2.rds.amazonaws.com:5432",
    "host=warden-dev-shop-aurora.cluster-abc.ap-south-2.rds.amazonaws.com port=5432",
])
def test_closing_idle_sessions_is_planned_on_the_labelled_server_the_platform_is_connected_to(server):
    req, why = resolver.request_for(_alert(aurora_cluster="warden-dev-shop-aurora"),
                                    _prop(ActionKind.terminate_connections, "warden-dev-shop-aurora"),
                                    _db_live(server))
    assert why == "" and req["entry"] == "db_terminate_idle_in_tx"
    assert req["params"] == {"database": "shop", "min_idle_seconds": 300, "max_sessions": 20}


@pytest.mark.parametrize("server, names", [
    ("other-db.cluster-abc.ap-south-2.rds.amazonaws.com:5432", {"shop"}),  # connected elsewhere
    ("xwarden-dev-shop-aurora.cluster-abc.rds.amazonaws.com", {"shop"}),  # a longer name is not the server
    ("host=warden-dev-shop-aurora.cluster-abc.rds.amazonaws.com hostaddr=10.0.0.9", {"shop"}),  # address decided
    ("warden-dev-shop-aurora.cluster-abc.rds.amazonaws.com", set()),  # no logins named: nothing may be closed
])
def test_closing_sessions_is_refused_unless_the_connection_is_that_server(server, names):
    req, why = resolver.request_for(_alert(aurora_cluster="warden-dev-shop-aurora"),
                                    _prop(ActionKind.terminate_connections, "warden-dev-shop-aurora"),
                                    _db_live(server, names))
    assert req is None and why
