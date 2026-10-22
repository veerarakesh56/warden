"""Live, 2026-10-16: the public Actions log of "Deploy · dev · on merge" printed
`role-to-assume: arn:aws:iam::<the account id>:role/warden-dev-deploy` - AWS_ROLE_ARN was a GitHub variable, and a
variable is printed unmasked in a step's inputs before any masking runs (aws-actions' mask-aws-account-id starts only
after that step). RUNTIME_ECR_REPOSITORY did the same in Runtime · ops. Every value that holds the account id is an
environment secret, which GitHub masks everywhere."""

from __future__ import annotations

import pathlib
import re

WORKFLOWS = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"
HOLD_THE_ACCOUNT = ("AWS_ROLE_ARN", "RUNTIME_ECR_REPOSITORY", "EKS_OPERATOR_ROLE_ARNS", "EKS_ADMIN_ROLE_ARNS")


def test_no_workflow_reads_an_account_holding_value_as_a_variable():
    found = [(p.name, m.group(0)) for p in sorted(WORKFLOWS.glob("*.yml"))
             for m in re.finditer(r"vars\.(" + "|".join(HOLD_THE_ACCOUNT) + r")\b", p.read_text(encoding="utf-8"))]
    assert found == []


def test_the_deploys_read_them_as_secrets():
    text = {p.name: p.read_text(encoding="utf-8") for p in WORKFLOWS.glob("*.yml")}
    assert "role-to-assume: ${{ secrets.AWS_ROLE_ARN }}" in text["_infra-deploy.yml"]
    assert "role-to-assume: ${{ secrets.AWS_ROLE_ARN }}" in text["_apps-deploy.yml"]
    assert text["runtime.yml"].count("role-to-assume: ${{ secrets.AWS_ROLE_ARN }}") == 3
    assert "REPOSITORY: ${{ secrets.RUNTIME_ECR_REPOSITORY }}" in text["runtime.yml"]


def test_every_caller_passes_them_and_the_deploys_require_the_role():
    """The secret is an empty string in a reusable workflow unless its caller passes it - with no error (GitHub docs,
    read 2026-10-16; the first dev plan after the switch could not assume the role)."""
    text = {p.name: p.read_text(encoding="utf-8") for p in WORKFLOWS.glob("*.yml")}
    # deploy-<env>.yml and on-merge-<env>.yml for dev and prod (2026-10-16: the four other environments went).
    callers = [n for n in text if n.startswith(("deploy-", "on-merge-"))]
    assert len(callers) == 4
    for name in callers:
        for called in ("_infra-deploy.yml", "_apps-deploy.yml"):
            after = text[name].split(f"uses: $/.github/workflows/{called}", 1)[1]
            assert after.lstrip().startswith("secrets:\n      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}"), (name, called)
    for called in ("_infra-deploy.yml", "_apps-deploy.yml"):
        assert "    secrets:\n      AWS_ROLE_ARN:\n        required: true\n" in text[called], called


def test_the_operator_role_arns_have_their_new_name_and_the_old_one_reads_for_one_release():
    """B24 (2026-10-20): "admin" out of every name - EKS_ADMIN_ROLE_ARNS is EKS_OPERATOR_ROLE_ARNS. The old secret is
    still passed and read for one release, only when the new one is unset, with a warning that names the new one."""
    text = {p.name: p.read_text(encoding="utf-8") for p in WORKFLOWS.glob("*.yml")}
    deploy = text["_infra-deploy.yml"]
    for name in ("EKS_OPERATOR_ROLE_ARNS", "EKS_ADMIN_ROLE_ARNS"):
        assert f"      {name}:\n        required: false\n" in deploy, name
    assert "OPERATOR_ROLE_ARNS: ${{ secrets.EKS_OPERATOR_ROLE_ARNS }}" in deploy
    assert "OLD_ROLE_ARNS: ${{ secrets.EKS_ADMIN_ROLE_ARNS }}" in deploy
    assert 'if [ -z "$OPERATOR_ROLE_ARNS" ] && [ -n "$OLD_ROLE_ARNS" ]; then' in deploy
    assert "::warning::EKS_ADMIN_ROLE_ARNS is deprecated: set EKS_OPERATOR_ROLE_ARNS" in deploy
    assert 'echo "TF_VAR_eks_operator_principal_arns=$OPERATOR_ROLE_ARNS"' in deploy
    assert "TF_VAR_eks_admin_principal_arns" not in deploy
    callers = [n for n in text if n.startswith(("deploy-", "on-merge-"))]
    for name in callers:
        assert "EKS_OPERATOR_ROLE_ARNS: ${{ secrets.EKS_OPERATOR_ROLE_ARNS }}" in text[name], name
    # The old name appears only where it is still read: the secret's declaration, its read and the warning in the
    # deploy, and each caller's line passing it on (`EKS_ADMIN_ROLE_ARNS: ${{ secrets.EKS_ADMIN_ROLE_ARNS }}`).
    assert sum(t.count("EKS_ADMIN_ROLE_ARNS") for t in text.values()) == 3 + 2 * len(callers)

