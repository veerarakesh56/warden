"""The docs must not overclaim (owner: "honesty, not polish").

Each phrase below was a false claim found by the 2026-09-28 audit and corrected. If one comes back,
this fails. Add a phrase here whenever a doc claim is found to contradict the code.
"""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]

# (file, phrase that must not appear, why it is false)
FALSE_CLAIMS = [
    # audit A-C-23 second round: the check covers what a pattern FOUND, by the _sweep rule
    ("README.md", "Redaction that is verified, not assumed", "only found values are re-checked"),
    ("README.md", "a surviving value\n  raises", "only found values are re-checked"),
    ("docs/ai-boundary.md", "raises if any original value\nsurvived", "found values only, by the _sweep rule"),
    ("docs/DESIGN-DECISIONS.md", "raises `RedactionLeak` if any original value survived",
     "found values only, by the _sweep rule"),
    ("src/warden/redaction.py", "GUARANTEES none of the found values", "the sweep follows _sweep's rule"),
    # second review (2026-09-30): the in-redact re-scan could never fire and was removed
    ("README.md", "a re-scan raises if one survived", "the independent check is the gate's G5"),
    ("docs/ai-boundary.md", "raises if a value it found survived", "the independent check is the gate's G5"),
    ("docs/DESIGN-DECISIONS.md", "raises `RedactionLeak` if a value it found survived", "removed; G5 is the check"),
    ("src/warden/mcp_server.py", "Fails if a value it found survived", "the re-scan was removed"),
    ("README.md", "156 recorded incident prompts: no false alarm", "7-8 of 36 benign alert texts were flagged"),
    ("tests/test_redaction.py", "can no longer produce a leak", "the sweep follows _sweep's rule"),
    ("docs/SYSTEM-COMPONENTS.md", "verifier P1–P15", "there are sixteen (P1-P16)"),
    # audit A-C-18: each vendor host reads its own key variable
    ("README.md", "OPENAI_API_KEY=$GROQ_API_KEY", "Groq reads GROQ_API_KEY; the OpenAI key never goes there"),
    # audit A-C-23: the re-scan checks only values a pattern found; it cannot prove none was missed
    ("src/warden/redaction.py", "Redaction that is verified, not assumed", "only the substitution is verified"),
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
    # second review (2026-09-30): the owner steps named a flag helper 1.8.5 does not have, and
    # told the owner to delete a file the proving ground still reads
    ("docs/OWNER-CONSOLE-STEPS.md", "--reuse-latest-expiring-certificate", "the flag is --use-latest-expiring-certificate"),
    ("README.md", "approval-gate case was silently skipped and is being fixed", "fixed; 35/35 caught 2026-09-30"),
    ("docs/ROADMAP.md", "SYSTEM-COMPONENTS cost table still owed", "delivered in 40f5f0e"),
    ("docs/FAILURE-MODES.md", "The model CLI gets no credential (environment allowlist)",
     "its own login token passes since 6504f71"),
    ("docs/SYSTEM-COMPONENTS.md", "Temporal is covered\n  by the trial's credits.", "only until about 2026-12-27"),
    ("docs/OWNER-CONSOLE-STEPS.md", "and `terraform\\proving-ground\\terraform.tfvars` (your", "the proving ground still reads its tfvars"),
    ("docs/AWS-SETUP.md", "your buckets' contents, or your existing databases", "see audit A-I-4"),
    ("docs/PRODUCTION-ARCHITECTURE.md", "boundary-capped", "the proving-ground boundary has no env dimension"),
    ("docs/SYSTEM-COMPONENTS.md", "| **IAM Identity Center** | replaces", "Identity Center needs Organizations"),
    (".github/dependabot.yml", "Every PR still runs the full CI, security job included",
     "paths-ignore skips the security job for infra/apps-only PRs"),
    ("tests/test_fullstack_infra.py", "retired in Phase 1.5 part 5", "the policy is still attached"),
    # third review (2026-09-30): false records and owner steps
    ("docs/OWNER-CONSOLE-STEPS.md", "exists) and `WardenFullstackOperator`, each only if",
     "A-I-18 is undecided; keep WardenFullstackOperator"),
    ("docs/OWNER-CONSOLE-STEPS.md", "Delete the `{}` and paste", "the box holds more than {}; Ctrl+A"),
    ("docs/OWNER-CONSOLE-STEPS.md", "Step B1 is the real test.", "the real test is the first sign-in after B4"),
    ("docs/ROADMAP.md", "~1 hour of the owner's time", "the steps say about 25 minutes"),
    ("CHANGELOG.md", "Each time the cause was a push made before CI on the previous one was green.",
     "ab900cd and bdb8a13 were pushed after green"),
    ("CHANGELOG.md", "Every tool error recorded in past runs keeps its", "old runs read failed (unclassified)"),
    ("CHANGELOG.md", "The rendered prompt is scanned as well", "only outside text is scanned"),
    ("docs/REQUIREMENTS-TRACE.md", "recorded per window in OWNER-CONSOLE-STEPS", "it was not; step E5"),
    ("docs/AUDIT-2026-09-28.md", "W0-now step A detaches the policy", "step A leaves WardenFullstackOperator"),
    ("src/warden/data/environments.yaml", "secrets under /warden/ops/", "the secret is in Secrets Manager"),
    ("README.md", "redaction with a re-scan", "the re-scan was removed; G5 is the check"),
    ("README.md", "the re-scan can only look for values", "the re-scan was removed"),
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


def test_the_readme_test_count_is_a_lower_bound(request):
    """Fourth review (2026-09-30, D #2): the README said 2,840 tests when there were 2,969. It now states a
    lower bound, and this keeps it one. A partial run (one file, -k) counts the whole suite itself."""
    import re
    import subprocess
    import sys

    m = re.search(r"Over ([\d,]+) tests", (ROOT / "README.md").read_text(encoding="utf-8"))
    assert m, "the README no longer states its test count as a lower bound"
    claimed = int(m.group(1).replace(",", ""))
    # The README counts the unit tests; the opt-in live-infrastructure tests and the evals are listed apart
    # ("plus 23 ... 26 evals"), so they are not counted here (fifth review, 2026-10-01).
    count = len([i for i in request.session.items
                 if i.nodeid.startswith("tests/") and not i.nodeid.startswith("tests/integration/")])
    if count < claimed:
        out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
                              "tests", "--ignore=tests/integration"],
                             capture_output=True, text=True, cwd=ROOT, check=False).stdout
        found = re.search(r"(\d+) tests? collected", out)
        count = int(found.group(1)) if found else 0
    assert count >= claimed, f"the README claims over {claimed} tests; {count} are collected"
