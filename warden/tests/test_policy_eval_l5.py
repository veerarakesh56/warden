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


# PR 122 review: a statement's conditions all have to hold (they are ANDed). One that is not understood used to end the
# reading at once, so its answer depended on which condition the policy happened to list first: a Deny that names an
# unreadable condition and, after it, another topic was taken to apply - and a policy that lets this topic send read as
# one that does not.
UNKNOWN_THEN_MISMATCH = {"ArnSomethingNew": {"aws:SourceArn": OTHER}, "ArnEquals": {"aws:SourceArn": OTHER}}
MISMATCH_THEN_UNKNOWN = {"ArnEquals": {"aws:SourceArn": OTHER}, "ArnSomethingNew": {"aws:SourceArn": OTHER}}


@pytest.mark.parametrize("condition", [UNKNOWN_THEN_MISMATCH, MISMATCH_THEN_UNKNOWN])
def test_a_deny_whose_other_condition_does_not_hold_does_not_apply_whatever_the_order(condition):
    assert _policy_allows_topic(_policy(_st("Allow"), _st("Deny", condition)), TOPIC) is True


@pytest.mark.parametrize("condition", [
    {"ArnSomethingNew": {"aws:SourceArn": OTHER}, "ArnEquals": {"aws:SourceArn": TOPIC}},
    {"ArnEquals": {"aws:SourceArn": TOPIC}, "ArnSomethingNew": {"aws:SourceArn": OTHER}},
])
def test_an_unreadable_condition_still_decides_when_every_other_one_holds(condition):
    assert _policy_allows_topic(_policy(_st("Allow"), _st("Deny", condition)), TOPIC) is False  # a Deny: taken to apply
    assert _policy_allows_topic(_policy(_st("Allow", condition)), TOPIC) is False                # an Allow: no proof


@pytest.mark.parametrize("condition", [UNKNOWN_THEN_MISMATCH, MISMATCH_THEN_UNKNOWN])
def test_an_allow_whose_other_condition_does_not_hold_never_allows(condition):
    assert _policy_allows_topic(_policy(_st("Allow", condition)), TOPIC) is False
