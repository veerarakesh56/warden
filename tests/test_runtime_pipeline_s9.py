"""Register S9 (supply chain) and G6: WARDEN's own runtime pipeline, .github/workflows/runtime.yml. The image is built
before the job holds a credential, pushed by the commit's SHA, signed by digest with cosign (keyless, this workflow's
own identity) and given build provenance; the deploy verifies both - signed by this workflow on the runtime branch -
before it plans, and applies only the plan it made, with that digest. terraform/runtime takes every per-install value
from SSM. The pipeline runs from environments.yaml `github.runtime_branch` only (owner, 2026-10-16: dev, until prod
exists), at a commit promoted onto it from its upstream branch."""

from __future__ import annotations

import os
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FLOW = (ROOT / ".github" / "workflows" / "runtime.yml").read_text(encoding="utf-8")
IMAGE_JOB = FLOW[FLOW.index("\n  image:"):FLOW.index("\n  deploy:")]
DEPLOY_JOB = FLOW[FLOW.index("\n  deploy:"):FLOW.index("\n  restart:")]
GUARD = "Runtime deploys run from the runtime branch only"


def _runtime_branch() -> str:
    from warden.environments import EnvironmentPolicies

    return EnvironmentPolicies.load().github["runtime_branch"]


def test_the_runtime_runs_only_from_its_branch_at_a_promoted_commit_and_signs_as_it():
    """Owner, 2026-10-16: main deploys nothing; the runtime runs from environments.yaml `github.runtime_branch` (dev,
    until prod exists). Every job refuses any other ref first; the image job checks that the commit was promoted onto
    the branch, as the deploys do, before it holds the Hugging Face token or an AWS credential; and the signing
    identity both jobs check is this workflow on that branch."""
    import yaml

    branch = _runtime_branch()
    doc = yaml.safe_load(FLOW)
    for job_id, job in doc["jobs"].items():
        first = job["steps"][0]
        assert first["name"] == GUARD and first["if"] == f"github.ref != 'refs/heads/{branch}'", job_id
        assert "exit 1" in first["run"], job_id
    signer = f"${{{{ github.server_url }}}}/${{{{ github.repository }}}}/.github/workflows/runtime.yml@refs/heads/{branch}"
    signers = [s["env"]["SIGNER"] for s in doc["jobs"]["image"]["steps"] if "SIGNER" in s.get("env", {})]
    assert signers == [signer] and doc["jobs"]["deploy"]["env"]["SIGNER"] == signer
    assert FLOW.count("runtime.yml@refs/heads/") == 2
    steps = doc["jobs"]["image"]["steps"]
    at = {s.get("name") or s.get("uses", "").split("@")[0]: i for i, s in enumerate(steps)}
    check = at["The commit was promoted from its upstream branch"]
    assert steps[at["actions/checkout"]]["with"]["fetch-depth"] == 0
    assert at["actions/checkout"] < check < at["Build the runtime image"] < at["aws-actions/configure-aws-credentials"]
    assert all(i > check for i, s in enumerate(steps) if "secrets." in str(s.get("with", "")) + str(s.get("env", "")))
    # Its upstream is the one the runtime branch's own deploys are promoted from.
    deploy = yaml.safe_load((ROOT / ".github" / "workflows" / f"deploy-{branch}.yml").read_text(encoding="utf-8"))
    assert steps[check]["env"]["UPSTREAM"] == deploy["jobs"]["infra"]["with"]["upstream"]


def test_the_image_is_built_before_any_credential_and_pushed_by_the_commit():
    assert IMAGE_JOB.index(GUARD) < IMAGE_JOB.index("configure-aws-credentials")
    assert IMAGE_JOB.index("docker build") < IMAGE_JOB.index("configure-aws-credentials")
    assert "-f Dockerfile.runtime" in IMAGE_JOB and 'docker push "$REPOSITORY:$GITHUB_SHA"' in IMAGE_JOB
    assert 'echo "image=$REPOSITORY@$digest"' in IMAGE_JOB  # everything after works on the digest, never a tag
    # Only the digest crosses jobs: an output holding the repository's address (the masked account id) is dropped by
    # GitHub, and the deploy job verified an empty image (2026-10-09).
    assert "digest: ${{ steps.push.outputs.digest }}" in IMAGE_JOB and "needs.image.outputs.image" not in FLOW
    assert "IMAGE: ${{ secrets.RUNTIME_ECR_REPOSITORY }}@${{ needs.image.outputs.digest }}" in DEPLOY_JOB
    # Tags are immutable: a commit already pushed keeps its image and signature, and is neither re-signed nor re-attested
    # here (2026-10-09: the apply after a plan of the same commit failed on the push). The deploy verifies it regardless.
    assert '--image-ids imageTag="$GITHUB_SHA"' in IMAGE_JOB and 'echo "existing=true"' in IMAGE_JOB
    # ...unless the run that pushed it died before signing (2026-10-12: the signing tool's download failed after the
    # push, and the commit could never be deployed): an image found without a valid signature and provenance is signed
    # and attested by this run, and the tool is installed before anything is pushed.
    assert IMAGE_JOB.count("if: steps.push.outputs.existing != 'true' || steps.check.outputs.signed != 'true'") == 2
    assert "if: steps.push.outputs.existing == 'true'" in IMAGE_JOB and 'echo "signed=true"' in IMAGE_JOB
    assert IMAGE_JOB.index("sigstore/cosign-installer@") < IMAGE_JOB.index('docker push "$REPOSITORY:$GITHUB_SHA"')
    assert IMAGE_JOB.count("sigstore/cosign-installer@") == 1
    check = IMAGE_JOB[IMAGE_JOB.index("id: check"):IMAGE_JOB.index("Sign the digest")]
    assert 'cosign verify "$IMAGE" --certificate-identity "$SIGNER"' in check and "gh attestation verify" in check
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
    assert f"/.github/workflows/runtime.yml@refs/heads/{_runtime_branch()}" in DEPLOY_JOB  # this workflow, its branch
    assert 'gh attestation verify "oci://$IMAGE" --repo "$REPO"' in DEPLOY_JOB
    assert '-var "runtime_image=$IMAGE"' in DEPLOY_JOB and 'apply -input=false -no-color "$RUNNER_TEMP/tfplan"' in DEPLOY_JOB
    assert "-auto-approve" not in DEPLOY_JOB
    # After an apply, the audit's schema and writer login, from inside the VPC; a failure fails the deploy.
    assert DEPLOY_JOB.index("apply -input=false") < DEPLOY_JOB.index("jq -r .migrate_function")
    assert '!= "None" ]; then' in DEPLOY_JOB
    # Paused there is no way out of the VPC: the migrate step is skipped, and only then (2026-10-10).
    assert '--name "/warden/$RUNTIME_ENV/tf/paused"' in DEPLOY_JOB and DEPLOY_JOB.index("tf/paused") < DEPLOY_JOB.index("jq -r .migrate_function")
    assert DEPLOY_JOB.index(GUARD) < DEPLOY_JOB.index("configure-aws-credentials")


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
    assert restart.index(GUARD) < restart.index("configure-aws-credentials")
    assert "terraform" not in restart and "docker" not in restart


def test_the_runtime_root_reads_every_per_install_value_from_ssm():
    tf = (ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8")
    assert re.search(r'\n  source\s+= "\.\./modules/warden-runtime"\n', tf)
    assert 'path = "/warden/${local.env}/tf"' in tf and re.search(r"\n  env\s+= terraform\.workspace\n", tf)
    assert re.search(r"condition\s+= local\.env == local\.runtime\n", tf)  # WARDEN's own environment, nothing else
    assert re.search(r"\n  runtime\s+= local\.config\.runtime\n", tf)
    assert "WardenEnvBoundary-${local.env}" in tf
    assert not re.search(r"\b\d{12}\b", tf)  # no account id
    assert not re.search(r"\b(?:ap|us|eu|ca|sa|me|af|il)-[a-z]+-\d\b", tf)  # no region
    module = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "terraform" / "modules" / "warden-runtime").glob("*.tf"))
    # Every role the module makes carries the boundary - counted against the roles themselves.
    assert module.count("permissions_boundary = var.permissions_boundary_arn") == module.count(
        'resource "aws_iam_role" "') == 5  # the EC2 instance role went with Fargate (2026-10-14)


EIP_ERROR = "Error: disassociating EC2 EIP (eipassoc-0abc): operation error EC2: DisassociateAddress, UnauthorizedOperation"


@pytest.mark.parametrize("first, second, exit_code, calls", [
    ("ok", "", 0, ["apply"]),
    (EIP_ERROR, "ok", 0, ["apply", "plan", "apply"]),
    (EIP_ERROR, "Error: still failing", 1, ["apply", "plan", "apply"]),  # once, never a loop
    ("Error: creating ECS Service (warden-ops-core): AccessDenied", "ok", 1, ["apply"]),
    (EIP_ERROR + "|Error: waiting for ECS Service delete: timeout", "ok", 1, ["apply"]),  # not the ONE error
    ("Error: disassociating EC2 EIP|" + EIP_ERROR, "ok", 1, ["apply"]),
])
def test_a_pause_retries_only_the_one_known_address_error_and_only_once(tmp_path, first, second, exit_code, calls):
    """2026-10-11: a pause removed everything in order and still ended red - EC2 answered the release of the NAT
    gateway's address with UnauthorizedOperation while it still listed the address as associated. The apply step runs
    here as written, against a stand-in terraform: it applies what is left once, only for that one error."""
    import shutil
    import subprocess

    import yaml

    bash = shutil.which("bash")
    assert bash, "the workflow's step is a bash script: bash must be on PATH to test it"
    steps = yaml.safe_load(FLOW)["jobs"]["deploy"]["steps"]
    script = next(s["run"] for s in steps if s.get("name") == "apply the plan just made")
    answers = tmp_path / "answers"
    answers.write_text(first + "\n" + second + "\n", encoding="utf-8", newline="\n")
    fake = tmp_path / "terraform"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'here="$(dirname "$0")"\n'
        'verb="$2"\n'
        'echo "$verb" >> "$here/calls"\n'
        '[ "$verb" = plan ] && exit 0\n'
        'n=$(grep -c apply "$here/calls")\n'
        'answer="$(sed -n "${n}p" "$here/answers")"\n'
        '[ "$answer" = ok ] && { echo "Apply complete!"; exit 0; }\n'
        'echo "$answer" | tr "|" "\\n" >&2\n'  # stderr, as Terraform writes its errors
        "exit 1\n", encoding="utf-8", newline="\n")
    fake.chmod(0o755)
    env = {**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], "RUNNER_TEMP": str(tmp_path),
           "IMAGE": "registry.example/warden@sha256:0"}
    done = subprocess.run([bash, "-e", "-c", script], env=env, capture_output=True, text=True, cwd=tmp_path,
                          check=False)
    assert (done.returncode != 0) == (exit_code != 0), done.stdout + done.stderr
    assert (tmp_path / "calls").read_text(encoding="utf-8").split() == calls


def test_the_pipeline_names_its_environment_once_as_the_configuration_does_and_no_workflow_names_a_resource():
    """Owner, 2026-10-12: nothing in the repository is hardcoded. The runtime's environment is environments.yaml
    `runtime`; this workflow names it once (RUNTIME_ENV, and the `environment:` keys GitHub needs written out), and no
    workflow line names a resource of one environment (`warden-ops-runtime`)."""
    import yaml

    from warden.environments import EnvironmentPolicies

    cfg = EnvironmentPolicies.load()
    doc = yaml.safe_load(FLOW)
    assert doc["env"]["RUNTIME_ENV"] == cfg.runtime_environment
    assert {job["environment"] for job in doc["jobs"].values()} == {cfg.runtime_environment}
    shell = "\n".join(step.get("run", "") for job in doc["jobs"].values() for step in job["steps"])
    assert 'cluster="warden-$RUNTIME_ENV-runtime"' in shell and '"/warden/$RUNTIME_ENV/tf/paused"' in shell
    named = re.compile("warden-(?:" + "|".join(map(re.escape, (*cfg.known_environments, cfg.runtime_environment)))
                       + ")-[a-z0-9]|/warden/(?:" + "|".join(map(re.escape, cfg.known_environments)) + "|"
                       + re.escape(cfg.runtime_environment) + ")/")
    offenders = [f"{p.name}:{i}" for p in sorted((ROOT / ".github" / "workflows").glob("*.yml"))
                 for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
                 if named.search(line.split("#", 1)[0])]
    assert not offenders, offenders


def test_a_deploy_fails_unless_every_zone_runs_the_new_image():
    """2026-10-15: the apply succeeded, ECS could not start the new tasks (the account's Fargate vCPU limit), rolled
    every zone back - and the workflow said success. The deploy now ends only when each service has one deployment,
    COMPLETED, on the image just built."""
    deploy = FLOW[FLOW.index("\n  deploy:"):FLOW.index("\n  restart:")]
    step = deploy[deploy.index("- name: Every zone runs the image just built"):]
    assert deploy.index("apply the plan just made") < deploy.index("Every zone runs the image just built")
    for must in ("seq 1 50", "length(deployments)", "rolloutState", '"$image" != "$IMAGE"',
                 'exit "$bad"'):
        assert must in step, must


def test_a_deploy_never_starts_an_extra_task():
    tf = (ROOT / "terraform" / "modules" / "warden-runtime" / "compute.tf").read_text(encoding="utf-8")
    assert "deployment_minimum_healthy_percent = var.worker_instances > 1 ? 50 : 0" in tf
    assert "deployment_maximum_percent         = var.worker_instances > 1 ? 150 : 100" in tf
    # ECS refuses a maximum of 100% while Availability Zone rebalancing is on (2026-10-15).
    assert 'availability_zone_rebalancing      = var.worker_instances > 1 ? "ENABLED" : "DISABLED"' in tf


def test_apply_deploys_and_restarts_in_one_run():
    """Owner B34: apply -> deploy -> restart in one run, no restart dispatch after it. Every safety step stays: the zone
    check on the new image comes first, and a restart is waited for until stable."""
    deploy = FLOW[FLOW.index("\n  deploy:"):FLOW.index("\n  restart:")]
    started, apply = deploy.index("APPLY_STARTED=$(date -u +%s)"), deploy.index("name: apply the plan just made")
    zones = deploy.index("name: Every zone runs the image just built")
    restart = deploy.index("name: Every zone started after this apply")
    assert started < apply < zones < restart
    step = deploy[restart:]
    assert "if: env.ACTION == 'apply' || env.ACTION == 'resume'" in step.split("\n")[1]
    assert '[ "$began_s" -lt "$APPLY_STARTED" ]' in step  # only a zone this apply left as it was is restarted
    assert "--force-new-deployment" in step
    assert "for _ in $(seq 1 50)" in step  # 25 minutes, as the zone check: a 10-minute waiter gave up on one
    assert 'echo "::error::not stable after 25 minutes:$restarted"' in step
    # Fail closed on a start time that cannot be read: never "rolled out by this apply" by accident.
    fail_closed = step.index('if ! began_s=$(date -u -d "$began" +%s 2>/dev/null) || ! [[ "$began_s" =~ ^[0-9]+$ ]]; then')
    assert "cannot be read\"\n              exit 1" in step[fail_closed:]
    assert fail_closed < step.index('[ "$began_s" -lt "$APPLY_STARTED" ]')
    assert "--task-definition" not in step  # the same task definition: the image the zone check verified
    assert 'test -n "$APPLY_STARTED"' in step
    # The restart action stays for a secret rotated when nothing else is deployed.
    assert "if: inputs.action == 'restart'" in FLOW

