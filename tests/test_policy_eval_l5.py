"""Audit A-B-L5: the queue-policy reader reads each condition operator by its meaning; the SG line names every source."""

from __future__ import annotations

import json

import pytest

from warden.aws_stack import _policy_allows_topic

TOPIC = "arn:aws:sns:ap-south-2:1:warden-dev-order-events"
OTHER = "arn:aws:sns:ap-south-2:1:other"


def _policy(*statements):
    return json.dumps({"Statement": list(statements)})


def _st(effect, condition=None):
    return {"Effect": effect, "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
            **({"Condition": condition} if condition else {})}


@pytest.mark.parametrize("statements, allowed", [
    ([_st("Allow", {"ArnEquals": {"aws:SourceArn": TOPIC}})], True),
    ([_st("Allow", {"ArnEquals": {"aws:SourceArn": OTHER}})], False),
    ([_st("Allow", {"ArnNotEquals": {"aws:SourceArn": OTHER}})], True),     # every topic but another one
    ([_st("Allow", {"ArnNotEquals": {"aws:SourceArn": TOPIC}})], False),    # every topic but this one
    ([_st("Allow"), _st("Deny", {"ArnNotLike": {"aws:SourceArn": TOPIC}})], True),   # deny all others
    ([_st("Allow"), _st("Deny", {"ArnNotLike": {"aws:SourceArn": OTHER}})], False),  # deny all but another
    ([_st("Allow", {"StringLikeIfExists": {"aws:sourcearn": "arn:aws:sns:*:*:warden-dev-*"}})], True),
    ([_st("Allow", {"Null": {"aws:SourceArn": "false"}})], True),
    ([_st("Allow", {"Null": {"aws:SourceArn": "true"}})], False),
    ([_st("Allow", {"ArnSomethingNew": {"aws:SourceArn": TOPIC}})], False),          # not understood: no proof
    ([_st("Allow"), _st("Deny", {"ArnSomethingNew": {"aws:SourceArn": OTHER}})], False),  # a Deny is taken to apply
])
def test_each_condition_operator_is_read_by_its_meaning(statements, allowed):
    assert _policy_allows_topic(_policy(*statements), TOPIC) is allowed
