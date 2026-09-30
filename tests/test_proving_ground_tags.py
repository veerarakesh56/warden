"""The harness's guards follow the tags Terraform actually applies to the proving ground.

Second review (2026-09-30): the stack's tags moved to Project=warden + Environment (owner rule R53) and
every guard kept checking Project=warden-proving-ground. Every fault injection would have refused, and
the teardown sweep's tag filter would have found nothing - while CI stayed green, because every fake
used the old tag too. This reads terraform/proving-ground/main.tf itself.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import teardown_sweep
from scenarios import ops, ops_db, runner


def _terraform_tags() -> dict[str, str]:
    main = (ROOT / "terraform" / "proving-ground" / "main.tf").read_text(encoding="utf-8")
    block = main[main.index("  tags = {"):]
    block = block[:block.index("\n  }")]
    tags = dict(re.findall(r'^\s+(\w+)\s+=\s+"([^"]+)"', block, re.MULTILINE))
    tags["Environment"] = re.search(r'variable "environment" \{[^}]*?default\s+=\s+"([^"]+)"',
                                    (ROOT / "terraform" / "proving-ground" / "variables.tf").read_text(encoding="utf-8"),
                                    re.DOTALL).group(1)
    return tags


def test_every_guard_checks_the_tag_terraform_applies():
    tags = _terraform_tags()
    stack = ("Stack", tags["Stack"])
    assert ops.STACK_TAG == stack and ops_db.STACK_TAG == stack and teardown_sweep.STACK == stack
    assert runner._FakeAws().describe_clusters()["clusters"][0]["tags"] == [{"key": "Stack", "value": tags["Stack"]}]


def test_what_the_harness_creates_carries_what_terraform_puts_on_its_own():
    tags = _terraform_tags()
    for key in ("Project", "Environment", "Stack"):
        assert ops.CREATE_TAGS[key] == tags[key], key
    probe = (ROOT / "scripts" / "prove_boundary.py").read_text(encoding="utf-8")
    for key in ("Project", "Environment", "Stack"):
        assert f'{{"Key": "{key}", "Value": "{tags[key]}"}}' in probe, key


def test_the_proof_script_looks_for_leftovers_by_the_tag_terraform_applies():
    """Review 3 (2026-09-30): scripts/aws_proof.sh still filtered Key=Project,Values=warden-proving-ground
    after the tags changed, so its post-destroy check always found 0 leftovers - a false "clean"."""
    stack = _terraform_tags()["Stack"]
    proof = (ROOT / "scripts" / "aws_proof.sh").read_text(encoding="utf-8")
    filters = re.findall(r"--tag-filters (Key=\w+,Values=[\w-]+)", proof)
    assert filters and set(filters) == {f"Key=Stack,Values={stack}"}, filters
