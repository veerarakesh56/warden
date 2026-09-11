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
        if path.name == "operator-policy-boundary.json":
            continue  # a ceiling, not a grant - it must never make a missing grant look present
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


# --------------------------------------------------------------------------- the permissions boundary
#
# ⛔ The operator may edit its own policy, so that it can grant itself what a new wave needs without
# a human pasting JSON each time. A principal that can edit its own permissions is an administrator
# UNLESS something it cannot edit caps what those permissions can reach. That something is
# operator-policy-boundary.json, and these tests are the reason to believe it holds.
#
# ⚠ These check the policy DOCUMENTS, action by action. They are not a full IAM evaluation - AWS's
# policy simulator is the authority, and a real attempt to exceed the ceiling is the proof.

BOUNDARY = TF_DIR / "operator-policy-boundary.json"
OPERATOR = TF_DIR / "operator-policy.json"
BOUNDARY_ARN = "arn:aws:iam::*:policy/WardenProvingGroundBoundary"
OPERATOR_ARN = "arn:aws:iam::*:policy/WardenProvingGroundOperator"


def _matches(pattern: str, action: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def _denies(action: str, resource: str) -> bool:
    """Does the boundary deny this action on this resource, unconditionally?"""
    import fnmatch

    for st in _statements(BOUNDARY):
        if st["Effect"] != "Deny" or "Condition" in st:
            continue
        if not any(_matches(p, action) for p in _actions(st)):
            continue
        resources = st.get("Resource")
        resources = [resources] if isinstance(resources, str) else (resources or [])
        if any(fnmatch.fnmatchcase(resource, r) for r in resources):
            return True
    return False


def test_the_operator_can_edit_only_its_own_policy():
    """Self-edit on ANY other policy would let it rewrite the permissions of principals it does not
    own - including whatever the account owner is attached to."""
    for path in (OPERATOR, BOUNDARY):
        for st in _statements(path):
            if st["Effect"] != "Allow":
                continue
            if any(_matches(a, "iam:CreatePolicyVersion") for a in _actions(st)):
                assert st["Resource"] == OPERATOR_ARN, f"{path.name}::{st['Sid']} -> {st['Resource']}"


def test_the_boundary_cannot_be_edited_by_the_principal_it_bounds():
    """⛔ Load-bearing. If the operator could edit the ceiling, the ceiling would be a suggestion."""
    for action in ("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
                   "iam:DeletePolicyVersion", "iam:DeletePolicy"):
        assert _denies(action, BOUNDARY_ARN), f"{action} on the boundary is not denied"


def test_the_boundary_cannot_be_detached_or_replaced():
    """⛔ Removing the boundary from itself is the one-step way out of it."""
    for action in ("iam:DeleteUserPermissionsBoundary", "iam:PutUserPermissionsBoundary",
                   "iam:DeleteRolePermissionsBoundary"):
        assert _denies(action, "arn:aws:iam::111122223333:user/warden-operator"), action


def test_every_new_role_must_carry_the_boundary():
    """⛔ Closes the indirect route out: create a role with broad permissions, pass it to an ECS
    task, and run code as that role. A role carrying the same boundary cannot exceed it either.

    The condition relies on documented IAM behaviour: a negated operator (ArnNotLike) evaluates TRUE
    when the key is absent - so a CreateRole with no boundary at all is denied, not waved through."""
    st = next(s for s in _statements(BOUNDARY) if s["Sid"] == "DenyAnyRoleThatDoesNotCarryThisBoundary")
    assert st["Effect"] == "Deny"
    assert "iam:CreateRole" in _actions(st)
    assert st["Condition"] == {"ArnNotLike": {"iam:PermissionsBoundary": BOUNDARY_ARN}}


def test_the_boundary_never_allows_identity_or_group_escalation():
    """Attaching a policy to a group the operator is in, or to itself, sidesteps a user boundary."""
    for action in ("iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AttachGroupPolicy",
                   "iam:PutGroupPolicy", "iam:AddUserToGroup", "iam:CreateAccessKey",
                   "iam:CreateUser", "iam:CreatePolicy"):
        assert _denies(action, "*"), f"{action} is not denied by the boundary"


def test_roles_can_only_be_assumed_or_passed_within_the_proving_ground():
    """With self-edit, the operator could grant itself sts:AssumeRole on ANY role - including an
    existing admin role that trusts the account. The ceiling has to stop that."""
    for st in _statements(BOUNDARY):
        if st["Effect"] == "Allow" and any(a in ("sts:AssumeRole", "iam:PassRole") for a in _actions(st)):
            assert st["Resource"] == "arn:aws:iam::*:role/warden-pg-*", st["Sid"]


def test_the_operator_policy_fits_inside_the_boundary():
    """Every action the operator grants must be allowed by the ceiling and not flatly denied by it.
    A grant the boundary silently cancels is a permission that looks present and is not."""
    ceiling = [a for st in _statements(BOUNDARY) if st["Effect"] == "Allow" for a in _actions(st)]
    outside = []
    for st in _statements(OPERATOR):
        if st["Effect"] != "Allow":
            continue
        for action in _actions(st):
            if not any(_matches(p, action) for p in ceiling):
                outside.append(f"{st['Sid']}: {action} (not in the ceiling)")
            elif _denies(action, "*"):
                outside.append(f"{st['Sid']}: {action} (flatly denied by the boundary)")
    assert not outside, "granted by the operator policy but cancelled by the boundary:\n  " + \
        "\n  ".join(outside)


def test_budgets_are_scoped_to_the_proving_ground():
    """It was `Resource: "*"` - which let this user modify or delete ANY budget, including the
    account-level alarm its owner relies on. Found while writing the boundary."""
    for path in (OPERATOR, BOUNDARY):
        for st in _statements(path):
            if st["Effect"] == "Allow" and any(a.startswith("budgets:") for a in _actions(st)):
                assert st["Resource"] == "arn:aws:budgets::*:budget/warden-pg-*", f"{path.name}::{st['Sid']}"


@pytest.mark.parametrize("path", POLICIES, ids=lambda p: p.name)
def test_no_two_statements_share_a_sid(path):
    """IAM rejects a policy with a repeated Sid. A merge that duplicated one did exactly that, and
    it would only have surfaced on the paste."""
    sids = [st.get("Sid") for st in _statements(path) if st.get("Sid")]
    assert len(sids) == len(set(sids)), f"duplicate Sid in {path.name}"


@pytest.mark.parametrize("path", POLICIES, ids=lambda p: p.name)
def test_no_account_id_is_written_into_a_policy(path):
    """The ARNs wildcard the account (`arn:aws:iam::*:...`). A literal account id here would be one
    more place it leaks from, and the policies are meant to be pasted anywhere."""
    import re

    assert not re.search(r"\b\d{12}\b", path.read_text(encoding="utf-8"))
