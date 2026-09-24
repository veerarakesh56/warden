"""Security-group descriptions must satisfy EC2's character set, checked here rather than at apply.

⛔ WHY THIS EXISTS. `terraform validate` passes a description EC2 will reject: the restriction lives
in the provider's API-side validation, which only runs against a real account at plan time. Wave 3's
security-group rule said "the operator's own address", the apostrophe is not allowed, and the first
live apply of the database wave would have failed on it - found only because a plan was run to test
something else entirely. This moves that failure from "a billed apply" to "the test suite".
"""

from __future__ import annotations

import pathlib
import re

import pytest

TERRAFORM = pathlib.Path(__file__).resolve().parents[1] / "terraform" / "proving-ground"

# EC2's own rule, quoted from the error it returns:
#   "ingress.0.description" doesn't comply with restrictions ("^[0-9A-Za-z_ .:/()#,@\[\]+=&;{}!$*-]*$")
EC2_DESCRIPTION = re.compile(r"^[0-9A-Za-z_ .:/()#,@\[\]+=&;{}!$*-]*$")
EC2_MAX = 255

# The blocks whose `description` EC2 validates. An `output` or `variable` description is
# Terraform's own and never reaches AWS, so it may say whatever it likes.
VALIDATED = ("aws_security_group", "aws_security_group_rule", "ingress", "egress")


def _descriptions() -> list[tuple[str, int, str, str]]:
    found = []
    for tf in sorted(TERRAFORM.glob("*.tf")):
        stack: list[str] = []
        for number, line in enumerate(tf.read_text(encoding="utf-8").splitlines(), 1):
            text = line.strip()
            opened = re.match(r'(?:resource\s+"(\w+)"|(ingress|egress)\s*\{)', text)
            if opened:
                stack.append(opened.group(1) or opened.group(2))
            described = re.match(r'description\s*=\s*"(.*)"\s*$', text)
            if described and stack and stack[-1] in VALIDATED:
                found.append((tf.name, number, stack[-1], described.group(1)))
    return found


def test_there_are_descriptions_to_check():
    """⛔ The positive control. A parser that found nothing would pass every assertion below."""
    blocks = {block for _, _, block, _ in _descriptions()}
    assert "aws_security_group" in blocks and "ingress" in blocks


@pytest.mark.parametrize("where,block,text", [
    (f"{name}:{number}", block, text) for name, number, block, text in _descriptions()
])
def test_every_security_group_description_is_one_ec2_will_accept(where, block, text):
    illegal = sorted({c for c in text if not EC2_DESCRIPTION.match(c)})
    assert not illegal, f"{where} [{block}]: EC2 rejects {illegal} in {text!r}"
    assert len(text) <= EC2_MAX, f"{where} [{block}]: {len(text)} chars, EC2 allows {EC2_MAX}"


def test_the_character_set_is_the_one_that_caught_the_real_bug():
    """Pins the regex to the failure it was lifted from, so a 'tidy-up' cannot loosen it."""
    assert not EC2_DESCRIPTION.match("PostgreSQL from the operator's own address")
    assert EC2_DESCRIPTION.match("PostgreSQL from the operator address only, and nowhere else.")
