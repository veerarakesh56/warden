"""The docs must not overclaim (owner: "honesty, not polish").

Each phrase below was a false claim found by the 2026-09-28 audit and corrected. If one comes back,
this fails. Add a phrase here whenever a doc claim is found to contradict the code.
"""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]

# (file, phrase that must not appear, why it is false)
FALSE_CLAIMS = [
    ("README.md", "Nothing here executes against infrastructure",
     "the RemediationWorkflow applies changes after a signed approval"),
    ("README.md", "Twelve policies", "there are sixteen (P1-P16)"),
    ("README.md", "| 12 policies", "there are sixteen (P1-P16)"),
    ("README.md", "an entropy backstop would erase", "redaction.py has a HIGHENTROPY backstop"),
    ("README.md", "is designed and built, not yet run", "Wave 4 fs-00..fs-05 ran on 2026-09-26"),
    ("README.md", "any Kubernetes — EKS, GKE, AKS, k3d", "only ECS and EKS were measured; k3d is CI only"),
    ("CHANGELOG.md", "v2 re-architecture, Phase 1.5 and Phase 2.\n", "Phase 2 was not done"),
    ("CHANGELOG.md", "with a boundary that denies every other", "rds-db:connect escapes the tag denies"),
    # the 26 infra doc-vs-code contradictions (audit A-I-DOC)
    ("terraform/fullstack/README.md", "Everything is named `warden-dev-*`", "names are warden-<env>-*"),
    ("terraform/fullstack/README.md", "The ALB listens on 0.0.0.0/0:80", "the ALB is internal"),
    ("terraform/fullstack/README.md", "Public IPv4 addresses (2 ECS tasks", "only the NAT is public"),
    ("terraform/fullstack/README.md", "from your gitignored terraform.tfvars", "budget_email comes from SSM"),
    ("terraform/fullstack/README.md", "the OIDC role `warden-dev-ci`", "the role is warden-<env>-deploy"),
    ("terraform/fullstack/README.md", "not yet seen on this", "the alarms were verified live on 2026-09-26"),
    ("terraform/fullstack/README.md", "--tag-filters Key=Project,Values=warden", "a sweep must not trust tags"),
    ("terraform/fullstack/main.tf", "ECS tasks with public IPs", "ECS and EKS are in private subnets"),
    ("terraform/fullstack/main.tf", "budgets scope (budget/warden-pg-*)", "the budget is warden-<env>-guard"),
    ("terraform/fullstack/ecs.tf", "Image layers come through the free S3 gateway endpoint",
     "there are no ECR endpoints; pulls go through the NAT"),
    ("terraform/fullstack/eks.tf", "- no node-wide\n# grant", "IMDS hop limit 2 exposes node credentials"),
    ("terraform/README.md", "with a validation rule that rejects an empty list. WARDEN",
     "subnet_ids is unused, so nothing enforces private subnets"),
    ("k8s/remediation-rbac.yaml", "deployments and NOTHING else", "patch deployments rewrites the pod template"),
    ("docs/OWNER-CONSOLE-STEPS.md", "it can never touch another environment's resources",
     "tag-based isolation has gaps"),
    ("docs/OWNER-CONSOLE-STEPS.md", "It also runs a negative check", "no negative OIDC check exists yet"),
    ("docs/AWS-SETUP.md", "your buckets' contents, or your existing databases", "see audit A-I-4"),
    ("docs/PRODUCTION-ARCHITECTURE.md", "boundary-capped", "the proving-ground boundary has no env dimension"),
    ("docs/SYSTEM-COMPONENTS.md", "| **IAM Identity Center** | replaces", "Identity Center needs Organizations"),
    (".github/dependabot.yml", "Every PR still runs the full CI, security job included",
     "paths-ignore skips the security job for infra/apps-only PRs"),
    ("tests/test_fullstack_infra.py", "retired in Phase 1.5 part 5", "the policy is still attached"),
]


def test_no_known_false_claim_is_back():
    found = []
    for rel, phrase, why in FALSE_CLAIMS:
        if phrase in (ROOT / rel).read_text(encoding="utf-8"):
            found.append(f"{rel}: {phrase!r} is false: {why}")
    assert not found, "\n".join(found)


def test_the_readme_does_not_pitch_adoption():
    text = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    assert "What this is, and is not." in text
    assert "not offered as a product to adopt as-is" in text


def test_the_v0_10_0_correction_stays_visible():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    head = text[: text.index("## [0.9.0]")]
    assert "Correction" in head and "That was false" in head
