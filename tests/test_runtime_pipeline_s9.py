"""Register S9 (supply chain) and G6: WARDEN's own runtime pipeline, .github/workflows/runtime.yml. The image is built
before the job holds a credential, pushed by the commit's SHA, signed by digest with cosign (keyless, this workflow's
own identity) and given build provenance; the deploy verifies both - signed by this workflow on main - before it
plans, and applies only the plan it made, with that digest. terraform/runtime takes every per-install value from SSM."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
FLOW = (ROOT / ".github" / "workflows" / "runtime.yml").read_text(encoding="utf-8")
IMAGE_JOB = FLOW[FLOW.index("\n  image:"):FLOW.index("\n  deploy:")]
DEPLOY_JOB = FLOW[FLOW.index("\n  deploy:"):FLOW.index("\n  restart:")]


def test_the_image_is_built_before_any_credential_and_pushed_by_the_commit():
    assert IMAGE_JOB.index("Runtime deploys run from main only") < IMAGE_JOB.index("configure-aws-credentials")
    assert IMAGE_JOB.index("docker build") < IMAGE_JOB.index("configure-aws-credentials")
    assert "-f Dockerfile.runtime" in IMAGE_JOB and 'docker push "$REPOSITORY:$GITHUB_SHA"' in IMAGE_JOB
    assert 'echo "image=$REPOSITORY@$digest"' in IMAGE_JOB  # everything after works on the digest, never a tag
    # Only the digest crosses jobs: an output holding the repository's address (the masked account id) is dropped by
    # GitHub, and the deploy job verified an empty image (2026-10-09).
    assert "digest: ${{ steps.push.outputs.digest }}" in IMAGE_JOB and "needs.image.outputs.image" not in FLOW
    assert "IMAGE: ${{ vars.RUNTIME_ECR_REPOSITORY }}@${{ needs.image.outputs.digest }}" in DEPLOY_JOB
    # Tags are immutable: a commit already pushed keeps its image and signature, and is neither re-signed nor re-attested
    # here (2026-10-09: the apply after a plan of the same commit failed on the push). The deploy verifies it regardless.
    assert '--image-ids imageTag="$GITHUB_SHA"' in IMAGE_JOB and 'echo "existing=true"' in IMAGE_JOB
    assert IMAGE_JOB.count("if: steps.push.outputs.existing != 'true'") == 2
    assert "if:" not in DEPLOY_JOB[DEPLOY_JOB.index("Verify the signature"):DEPLOY_JOB.index("cosign verify")]


def test_the_digest_is_signed_and_given_provenance():
    assert re.search(r'cosign sign --yes "\$IMAGE"', IMAGE_JOB) and "IMAGE: ${{ steps.push.outputs.image }}" in IMAGE_JOB
    assert "actions/attest-build-provenance@" in IMAGE_JOB and "subject-digest: ${{ steps.push.outputs.digest }}" in IMAGE_JOB
    assert "push-to-registry: true" in IMAGE_JOB
    assert "attestations: write" in IMAGE_JOB and "attestations: write" not in DEPLOY_JOB


def test_nothing_is_deployed_that_this_workflow_did_not_sign_and_attest():
    verify = DEPLOY_JOB.index("cosign verify")
    assert verify < DEPLOY_JOB.index("terraform -chdir=terraform/runtime init") < DEPLOY_JOB.index("plan -input=false")
    assert '--certificate-identity "$SIGNER"' in DEPLOY_JOB
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in DEPLOY_JOB
    assert "/.github/workflows/runtime.yml@refs/heads/main" in DEPLOY_JOB  # this workflow, on main
    assert 'gh attestation verify "oci://$IMAGE" --repo "$REPO"' in DEPLOY_JOB
    assert '-var "runtime_image=$IMAGE"' in DEPLOY_JOB and 'apply -input=false -no-color "$RUNNER_TEMP/tfplan"' in DEPLOY_JOB
    assert "-auto-approve" not in DEPLOY_JOB
    # After an apply, the audit's schema and writer login, from inside the VPC; a failure fails the deploy.
    assert DEPLOY_JOB.index("apply -input=false") < DEPLOY_JOB.index("jq -r .migrate_function")
    assert '!= "None" ]; then' in DEPLOY_JOB
    # Paused there is no way out of the VPC: the migrate step is skipped, and only then (2026-10-10).
    assert '--name /warden/ops/tf/paused' in DEPLOY_JOB and DEPLOY_JOB.index("tf/paused") < DEPLOY_JOB.index("jq -r .migrate_function")
    assert DEPLOY_JOB.index("Runtime deploys run from main only") < DEPLOY_JOB.index("configure-aws-credentials")


def test_the_pipeline_is_by_hand_into_ops_only():
    on = FLOW[FLOW.index("\non:"):FLOW.index("\npermissions:")]
    assert "workflow_dispatch" in on and "push" not in on and "pull_request" not in on
    assert FLOW.count("environment: ops") == 3


def test_restart_redeploys_the_zone_services_without_an_image_or_a_plan():
    """After a secret is set or rotated the workers must start again (they read secrets at start; 2026-10-09 every
    service had stopped retrying before its secrets were set). restart builds nothing and plans nothing."""
    restart = FLOW[FLOW.index("\n  restart:"):]
    assert "if: inputs.action == 'restart'" in restart
    assert "if: inputs.action != 'restart'" in IMAGE_JOB
    assert "if: inputs.action != 'image' && inputs.action != 'restart'" in DEPLOY_JOB
    assert "--force-new-deployment" in restart and "aws ecs wait services-stable" in restart
    assert restart.index("Runtime deploys run from main only") < restart.index("configure-aws-credentials")
    assert "terraform" not in restart and "docker" not in restart


def test_the_runtime_root_reads_every_per_install_value_from_ssm():
    tf = (ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8")
    assert 'source                    = "../modules/warden-runtime"' in tf
    assert 'path = "/warden/${local.env}/tf"' in tf and re.search(r"\n  env\s+= terraform\.workspace\n", tf)
    assert re.search(r"condition\s+= local\.env == local\.runtime\n", tf)  # WARDEN's own environment, nothing else
    assert re.search(r"\n  runtime\s+= local\.config\.runtime\n", tf)
    assert "WardenEnvBoundary-${local.env}" in tf
    assert not re.search(r"\b\d{12}\b", tf)  # no account id
    assert not re.search(r"\b(?:ap|us|eu|ca|sa|me|af|il)-[a-z]+-\d\b", tf)  # no region
    module = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "terraform" / "modules" / "warden-runtime").glob("*.tf"))
    assert module.count("permissions_boundary = var.permissions_boundary_arn") == 5  # every role the module makes
