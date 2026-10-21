"""Characterisation of aws_stack's last_known_good, _principal, parse_tracebacks and _policy_allows_topic, written BEFORE
their cognitive-complexity refactor (Sonar python:S3776) and passing on the code as it was: the same answers, the same
records and their order."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from warden import aws_stack

T0 = datetime(2026, 10, 16, 8, 0, tzinfo=UTC)
P = timedelta(seconds=aws_stack.SERVED_PERIOD)


def _row(rid, starts, n, value=10.0, skip=()):
    stamps = [starts + i * P for i in range(n) if i not in skip]
    return {"Id": rid, "Timestamps": stamps, "Values": [value] * len(stamps)}


# --------------------------------------------------------------------------- last_known_good


def test_lkg_the_stretch_that_ended_latest_wins():
    results = [_row("v0", T0, 6), _row("v1", T0 + 10 * P, 6), _row("e1", T0 + 10 * P, 6, value=0.0)]
    assert aws_stack.last_known_good(results, ["3", "4"]) == "4"


def test_lkg_an_erring_period_breaks_a_stretch_and_a_gap_too():
    errs = _row("e0", T0 + 3 * P, 1, value=2.0)
    assert aws_stack.last_known_good([_row("v0", T0, 7), errs], ["3"]) == ""        # 3 + 3 clean periods: too short
    assert aws_stack.last_known_good([_row("v0", T0, 9), errs], ["3"]) == ""        # 3 + 5 clean: 25 minutes
    assert aws_stack.last_known_good([_row("v0", T0, 10), errs], ["3"]) == "3"      # 3 + 6 clean: 30 minutes
    assert aws_stack.last_known_good([_row("v0", T0, 7, skip=(3,))], ["3"]) == ""   # a gap splits it the same way
    assert aws_stack.last_known_good([_row("v0", T0, 6)], ["3"]) == "3"             # exactly 30 minutes counts


def test_lkg_ties_on_the_end_go_to_the_higher_version_and_ids_out_of_range_are_ignored():
    results = [_row("v0", T0, 6), _row("v1", T0, 6), _row("v2", T0, 60), _row("x0", T0, 60), _row("vx", T0, 60)]
    assert aws_stack.last_known_good(results, ["10", "9"]) == "10"


def test_lkg_unreadable_stamps_and_zero_calls_count_for_nothing():
    row = _row("v0", T0, 6)
    row["Timestamps"][2] = "not a time"
    assert aws_stack.last_known_good([row], ["3"]) == ""
    assert aws_stack.last_known_good([_row("v0", T0, 6, value=0.0)], ["3"]) == ""
    iso = {"Id": "v0", "Timestamps": [(T0 + i * P).isoformat() for i in range(6)], "Values": [1.0] * 6}
    assert aws_stack.last_known_good([iso], ["3"]) == "3"
    assert aws_stack.last_known_good([], ["3"]) == ""


# --------------------------------------------------------------------------- _principal


def _ev(identity):
    return {"CloudTrailEvent": json.dumps({"userIdentity": identity})}


@pytest.mark.parametrize(("event", "who"), [
    (_ev({"type": "AssumedRole", "sessionContext": {"sessionIssuer": {"userName": "deployer"}}}), "role/deployer"),
    (_ev({"type": "AssumedRole", "sessionContext": {"sessionIssuer": {
        "userName": "AWSReservedSSO_Admin_0123456789abcdef"}}}), "role/AWSReservedSSO_Admin"),
    (_ev({"type": "AssumedRole", "sessionContext": {"sessionIssuer": {
        "userName": "AWSReservedSSO_Admin_0123456789ABCDEF"}}}), "role/AWSReservedSSO_Admin_0123456789ABCDEF"),
    (_ev({"type": "AssumedRole", "sessionContext": None}), "role"),
    (_ev({"type": "AssumedRole", "sessionContext": {"sessionIssuer": {"userName": "my role"}}}), "role/my_role"),
    (_ev({"type": "IAMUser", "userName": "bob"}), "user/bob"),
    (_ev({"type": "IAMUser"}), "user"),
    (_ev({"type": "AWSService", "invokedBy": "lambda.amazonaws.com"}), "service/lambda.amazonaws.com"),
    (_ev({"type": "AWSService"}), "service"),
    (_ev({"type": "Root"}), "Root"),
    (_ev({"type": "Federated User"}), "Federated_User"),
    (_ev({}), "unknown"),
    ({"CloudTrailEvent": "{not json"}, "unknown"),
    ({}, "unknown"),
])
def test_principal(event, who):
    assert aws_stack._principal(event) == who


# --------------------------------------------------------------------------- parse_tracebacks


def test_tracebacks_the_innermost_package_frame_with_the_exception_after_it():
    lines = [("START", "3"),
             ("Traceback (most recent call last):", "3"),
             ('  File "/var/runtime/bootstrap.py", line 60, in main', "3"),
             ('  File "/var/task/app.py", line 12, in handler', "3"),
             ("    return charge(x)", "3"),
             ('  File "/var/task/lib/pay.py", line 40, in charge', "3"),
             ("", "3"),
             ('  File "/opt/python/requests/api.py", line 9, in post', "3"),
             ("KeyError: 'amount'", "3"),
             ("END", "3")]
    assert aws_stack.parse_tracebacks(lines) == [
        {"path": "lib/pay.py", "line": 40, "func": "charge", "exception": "KeyError: 'amount'", "version": "3"}]


def test_tracebacks_the_lambda_runtime_shape_takes_the_error_line_before():
    lines = [("[ERROR] ValueError: bad input", "$LATEST"),
             ("Traceback (most recent call last):", "$LATEST"),
             ('  File "/var/task/app.py", line 7, in handler', "$LATEST"),
             ("START next", "$LATEST")]
    assert aws_stack.parse_tracebacks(lines) == [
        {"path": "app.py", "line": 7, "func": "handler", "exception": "ValueError: bad input", "version": "$LATEST"}]
    inline = [("[ERROR] TypeError: x Traceback (most recent call last):", "5"),
              ('  File "/var/task/a.py", line 1, in f', "5")]
    assert aws_stack.parse_tracebacks(inline) == [
        {"path": "a.py", "line": 1, "func": "f", "exception": "TypeError: x", "version": "5"}]


def test_tracebacks_without_a_package_frame_or_exception():
    lines = [("Traceback (most recent call last):", "1"),
             ('  File "/var/runtime/x.py", line 1, in f', "1"),
             ("RuntimeError: boom", "1"),
             ("Traceback (most recent call last):", "2"),
             ('  File "/var/task/b.py", line 3, in g', "2"),
             ("not an exception line!", "2"),
             ("Traceback (most recent call last):", "2")]
    assert aws_stack.parse_tracebacks(lines) == [
        {"path": "b.py", "line": 3, "func": "g", "exception": "?", "version": "2"}]
    assert aws_stack.parse_tracebacks([]) == []
    assert aws_stack.parse_tracebacks([("Traceback (most recent call last):", "1")]) == []


def test_tracebacks_two_in_a_row_and_an_error_prefixed_exception_line():
    lines = [("Traceback (most recent call last):", "1"),
             ('  File "/var/task/a.py", line 1, in f', "1"),
             ("[ERROR] OSError: disk", "1"),
             ("Traceback (most recent call last):", "1"),
             ('  File "/var/task/b.py", line 2, in g', "1"),
             ("pkg.mod.CustomError", "1")]
    assert aws_stack.parse_tracebacks(lines) == [
        {"path": "a.py", "line": 1, "func": "f", "exception": "OSError: disk", "version": "1"},
        {"path": "b.py", "line": 2, "func": "g", "exception": "pkg.mod.CustomError", "version": "1"}]


# --------------------------------------------------------------------------- _policy_allows_topic

ACCT = "0" * 12  # built, never a literal account id
TOPIC = f"arn:aws:sns:eu-west-1:{ACCT}:orders"


def _policy(*statements):
    return json.dumps({"Statement": list(statements)})


def _st(effect="Allow", action="sqs:SendMessage", principal=None, condition=None):
    st = {"Effect": effect, "Action": action, "Principal": principal or {"Service": "sns.amazonaws.com"}}
    if condition is not None:
        st["Condition"] = condition
    return st


@pytest.mark.parametrize(("policy", "allowed"), [
    (None, False), ("", False),
    (_policy(_st()), True),
    (json.dumps({"Statement": _st()}), True),                                   # one statement, not a list
    (_policy(_st(action=["sqs:ReceiveMessage"])), False),                       # the wrong action
    (_policy(_st(action="*")), True), (_policy(_st(action=["sqs:*"])), True),
    (_policy(_st(principal="*")), True),
    (_policy(_st(principal={"AWS": "arn:aws:iam::1:root"})), False),            # not SNS
    (_policy(_st(principal={"AWS": ["*"]})), True),
    (_policy(_st(principal={"Service": []})), False),
    (_policy(_st(condition={"ArnEquals": {"aws:SourceArn": TOPIC}})), True),
    (_policy(_st(condition={"ArnLike": {"AWS:SourceArn": ["arn:aws:sns:*:*:ord*"]}})), True),
    (_policy(_st(condition={"ArnEquals": {"aws:SourceArn": "arn:aws:sns:x:1:other"}})), False),
    (_policy(_st(condition={"ArnNotEquals": {"aws:SourceArn": TOPIC}})), False),
    (_policy(_st(condition={"StringNotLikeIfExists": {"aws:SourceArn": "nope"}})), True),
    (_policy(_st(condition={"Null": {"aws:SourceArn": "false"}})), True),
    (_policy(_st(condition={"Null": {"aws:SourceArn": "true"}})), False),
    (_policy(_st(condition={"ForAnyValue:ArnLike": {"aws:SourceArn": TOPIC}})), True),
    (_policy(_st(condition={"IpAddress": {"aws:SourceArn": TOPIC}})), False),   # not understood: no Allow proven
    (_policy(_st(condition={"StringEquals": {"aws:SourceAccount": "1"}})), True),   # another key: not read
    (_policy(_st(), _st(effect="Deny")), False),
    (_policy(_st(), _st(effect="Deny", condition={"IpAddress": {"aws:SourceArn": TOPIC}})), False),  # unknown Deny
    (_policy(_st(), _st(effect="Deny", condition={"ArnNotEquals": {"aws:SourceArn": TOPIC}})), True),
    (_policy(_st(), _st(effect="Deny", action="sqs:DeleteQueue")), True),
    (_policy(_st(effect="Audit")), False),
    (json.dumps({}), False),
])
def test_policy_allows_topic(policy, allowed):
    assert aws_stack._policy_allows_topic(policy, TOPIC) is allowed
