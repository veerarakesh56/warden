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
DEPLOY_JOB = FLOW[FLOW.index("\n  deploy:"):]


def test_the_image_is_built_before_any_credential_and_pushed_by_the_commit():
    assert IMAGE_JOB.index("Runtime deploys run from main only") < IMAGE_JOB.index("configure-aws-credentials")
    assert IMAGE_JOB.index("docker build") < IMAGE_JOB.index("configure-aws-credentials")
    assert "-f Dockerfile.runtime" in IMAGE_JOB and 'docker push "$REPOSITORY:$GITHUB_SHA"' in IMAGE_JOB
    assert 'echo "image=$REPOSITORY@$digest"' in IMAGE_JOB  # everything after works on the digest, never a tag


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
    assert DEPLOY_JOB.index("Runtime deploys run from main only") < DEPLOY_JOB.index("configure-aws-credentials")


def test_the_pipeline_is_by_hand_into_ops_only():
    on = FLOW[FLOW.index("\non:"):FLOW.index("\npermissions:")]
    assert "workflow_dispatch" in on and "push" not in on and "pull_request" not in on
    assert FLOW.count("environment: ops") == 2


def test_the_runtime_root_reads_every_per_install_value_from_ssm():
    tf = (ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8")
    assert 'source                   = "../modules/warden-runtime"' in tf
    assert 'path = "/warden/${local.env}/tf"' in tf and "env          = terraform.workspace" in tf
    assert "contains(local.environments, local.env)" in tf
    assert "WardenEnvBoundary-${local.env}" in tf
    assert not re.search(r"\b\d{12}\b", tf)  # no account id
    assert not re.search(r"\b(?:ap|us|eu|ca|sa|me|af|il)-[a-z]+-\d\b", tf)  # no region
    module = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "terraform" / "modules" / "warden-runtime").glob("*.tf"))
    assert module.count("permissions_boundary = var.permissions_boundary_arn") == 4  # every role the module makes
