"""The operator IAM policies, checked for the mistakes that only show up in the AWS console.

⚠ WHAT THIS CANNOT DO. It cannot tell you an action name is real — only AWS knows the full list, and
it changes. `budgets:DescribeBudget` looked perfectly plausible and does not exist; it was caught by
the IAM console's own validator when the policy was pasted in, which is the authoritative check and
must still be run.

What it DOES catch is the class of bug that the console will happily accept and that then fails at
`terraform apply` with a confusing AccessDenied:

  - a GLOBAL service's actions sitting under an `aws:RequestedRegion` condition, which does not
    narrow the grant, it silently voids it. This was written wrong twice, in two files.
  - a statement carrying keys IAM does not accept, e.g. a `_comment` field.
  - a region drifting out of sync with `variables.tf`, which denies every call for a reason the
    error message does not mention.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TF_DIR = ROOT / "terraform" / "proving-ground"
POLICIES = sorted(TF_DIR.glob("operator-policy*.json"))

# Services with a single global endpoint. An `aws:RequestedRegion` condition on one of these does
# not restrict the grant to a region — it fails to match and the statement never applies.
GLOBAL_SERVICES = ("iam", "sts", "organizations", "account", "budgets", "cloudfront", "route53")

# The only keys IAM accepts inside a Statement. Anything else is a MalformedPolicyDocument.
STATEMENT_KEYS = {"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource",
                  "Principal", "NotPrincipal", "Condition"}

pytestmark = pytest.mark.skipif(not POLICIES, reason="no operator policy files in this checkout")


def _statements(path: pathlib.Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["Statement"]


def _actions(statement: dict) -> list[str]:
    action = statement.get("Action") or statement.get("NotAction") or []
    return [action] if isinstance(action, str) else list(action)


@pytest.mark.parametrize("path", POLICIES, ids=lambda p: p.name)
def test_the_policy_is_valid_json_with_the_right_shape(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["Version"] == "2012-10-17"
    assert isinstance(doc["Statement"], list) and doc["Statement"]


@pytest.mark.parametrize("path", POLICIES, ids=lambda p: p.name)
def test_no_statement_carries_a_key_iam_does_not_accept(path):
    """⛔ IAM rejects the whole document for an unknown key. A `_comment` field explaining why a
    statement exists is exactly the sort of thing that seems harmless and is not — the explanation
    belongs in the docs or the Sid."""
    offenders = [
        f"{s.get('Sid', '?')}: {sorted(set(s) - STATEMENT_KEYS)}"
        for s in _statements(path) if set(s) - STATEMENT_KEYS
    ]
    assert not offenders, "IAM will reject these statements outright:\n  " + "\n  ".join(offenders)


@pytest.mark.parametrize("path", POLICIES, ids=lambda p: p.name)
def test_no_global_service_action_sits_under_a_region_condition(path):
    """⛔ The bug this file exists for, written wrong twice.

    `iam:`, `sts:`, `budgets:` and friends do not go to a regional endpoint. An
    `aws:RequestedRegion` condition on them never matches, so the statement grants nothing — and the
    failure arrives much later, as an AccessDenied on an action the policy visibly contains.
    """
    offenders: list[str] = []
    for statement in _statements(path):
        condition = json.dumps(statement.get("Condition") or {})
        if "aws:RequestedRegion" not in condition:
            continue
        for action in _actions(statement):
            if action.split(":")[0] in GLOBAL_SERVICES:
                offenders.append(f"{statement.get('Sid', '?')}: {action}")
    assert not offenders, (
        "these are global-service actions under a region condition, so they grant NOTHING:\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("path", POLICIES, ids=lambda p: p.name)
def test_the_region_matches_the_terraform_default(path):
    """A policy pinned to one region and a Terraform default of another denies every call, and the
    error does not say the word 'region'."""
    tf_default = re.search(
        r'variable "region".*?default\s*=\s*"([^"]+)"',
        (TF_DIR / "variables.tf").read_text(encoding="utf-8"),
        re.DOTALL,
    )
    assert tf_default, "could not find the region default in variables.tf"
    pinned = set(re.findall(r'"aws:RequestedRegion":\s*"([^"]+)"',
                            path.read_text(encoding="utf-8")))
    assert pinned <= {tf_default.group(1)}, (
        f"{path.name} pins {sorted(pinned)} but variables.tf defaults to {tf_default.group(1)!r}"
    )


def test_every_action_the_fault_injector_calls_is_granted():
    """The injector's ops are useless if the operator cannot make the call. Checked against the
    boto3 method names in scenarios/ops.py rather than against a list somebody maintains by hand."""
    ops_src = (ROOT / "scenarios" / "ops.py").read_text(encoding="utf-8")
    called = set(re.findall(r"clients\.(ecs|logs|ec2|iam)\.(\w+)\(", ops_src))

    granted: set[str] = set()
    for path in POLICIES:
        for statement in _statements(path):
            if statement.get("Effect") != "Allow":
                continue
            granted.update(a.lower() for a in _actions(statement))

    # boto3's snake_case method -> the IAM action it maps to, e.g. update_service -> ecs:UpdateService
    missing: list[str] = []
    for service, method in sorted(called):
        action = f"{service}:{''.join(part.title() for part in method.split('_'))}".lower()
        wildcard = f"{service}:{method.split('_')[0].title()}*".lower()
        if action not in granted and wildcard not in granted:
            missing.append(action)
    assert not missing, (
        "scenarios/ops.py makes these calls and no operator policy grants them:\n  "
        + "\n  ".join(missing)
    )
