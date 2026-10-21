"""G6: WARDEN's own runtime IAM - iam/<runtime>/, rendered from iam/templates/runtime-*.json. The deploy role is the one
.github/workflows/runtime.yml assumes, and the boundary bounds it AND every role terraform/runtime makes (worker, front
door, task execution, ECS instance). The deploy policies fitting the boundary, the size limit and the folder's presence
are held by tests/test_env_iam.py; this file holds what is the runtime's own."""

from __future__ import annotations

import fnmatch
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import render_env_iam as r  # after the sys.path line above

RUNTIME = r.runtime_environment()
MODULE = ROOT / "terraform" / "modules" / "warden-runtime"


def _load(kind):
    return json.loads((ROOT / "iam" / RUNTIME / f"{kind}.json").read_text(encoding="utf-8"))


def _list(x):
    return [x] if isinstance(x, str) else list(x or [])


def _sid(doc, sid):
    return next(st for st in doc["Statement"] if st.get("Sid") == sid)


def _matches(action, patterns):
    return any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in patterns)


def test_the_committed_files_are_exactly_the_render():
    for kind, text in r.render_runtime(RUNTIME).items():
        committed = (ROOT / "iam" / RUNTIME / f"{kind}.json").read_text(encoding="utf-8")
        assert committed == text, f"iam/{RUNTIME}/{kind}.json drifted: run scripts/render_env_iam.py"


def test_only_the_runtime_pipeline_on_its_branch_may_assume_the_deploy_role():
    """Owner, 2026-10-16: the runtime pipeline runs from environments.yaml `github.runtime_branch` (dev until prod
    exists), never from main."""
    from warden.environments import EnvironmentPolicies

    branch = EnvironmentPolicies.load().github["runtime_branch"]
    assert branch != "main"
    (st,) = _load("trust")["Statement"]
    assert st["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert st["Principal"]["Federated"].endswith(":oidc-provider/token.actions.githubusercontent.com")
    assert st["Condition"] == {"StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": f"repo:veerarakesh56@171412850/warden@1341685493:environment:{RUNTIME}",
        "token.actions.githubusercontent.com:ref": f"refs/heads/{branch}",
        "token.actions.githubusercontent.com:job_workflow_ref":
            f"veerarakesh56/warden/.github/workflows/runtime.yml@refs/heads/{branch}"}}


def test_every_action_the_runtimes_own_roles_hold_fits_the_boundary():
    """The module's inline role policies (iam.tf): each action within the ceiling and not flatly denied - a boundary
    that denied GetSecretValue or kms:Sign would leave the worker unable to read its secrets or sign the audit."""
    boundary = _load("boundary")
    ceiling = [a for st in boundary["Statement"] if st["Effect"] == "Allow" for a in _list(st["Action"])]
    flat = [a for st in boundary["Statement"] if st["Effect"] == "Deny" and "Condition" not in st
            and st.get("Resource") == "*" for a in _list(st["Action"])]
    iam_tf = "\n".join((MODULE / f).read_text(encoding="utf-8") for f in ("iam.tf", "migrate.tf"))
    actions = {a for block in re.findall(r"Action\s*=\s*\[([^\]]*)\]", iam_tf) for a in re.findall(r'"([^"]+)"', block)}
    assert {"secretsmanager:GetSecretValue", "kms:Sign", "sts:AssumeRole", "rds-db:connect"} <= actions
    assert not [a for a in actions if a.startswith("bedrock:")]
    assert "bedrock:" not in json.dumps(boundary)  # no Bedrock
    assert [a for a in sorted(actions) if not _matches(a, ceiling)] == []
    assert [a for a in sorted(actions) if _matches(a, flat)] == []


def test_the_worker_reaches_other_environments_only_through_their_reader_and_actor():
    boundary = _load("boundary")
    assert _sid(boundary, "CeilingWatched")["Resource"] == [
        "arn:aws:iam::*:role/warden-*-platform-reader", "arn:aws:iam::*:role/warden-*-actor"]
    other = _sid(boundary, "DenyOtherEnvResources")
    assert other["NotAction"] == "sts:*"
    assert "Action" not in other  # every other service stays out
    assert other["Condition"]["StringNotEquals"] == {"aws:ResourceTag/Environment": RUNTIME}
    for kind, zones in (("actor-trust", ("act",)), ("platform-reader-trust", ("read", "notify", "act"))):
        principals = {p for st in json.loads((ROOT / "iam" / "templates" / f"{kind}.json").read_text(encoding="utf-8"))
                      ["Statement"] for p in _list(st["Principal"]["AWS"])}  # and those roles trust only its zones
        assert principals == {f"arn:aws:iam::${{account}}:role/warden-${{runtime}}-{z}" for z in zones}
        rendered = json.loads((ROOT / "iam" / "dev" / f"{kind}.json").read_text(encoding="utf-8"))
        assert {p for st in rendered["Statement"] for p in _list(st["Principal"]["AWS"])} == {
            f"arn:aws:iam::<ACCOUNT_ID>:role/warden-{RUNTIME}-{z}" for z in zones}  # and rendered: the runtime's own


def test_instances_launch_only_from_a_template_with_imdsv2():
    boundary = _load("boundary")
    assert _sid(boundary, "DenyNoTemplate")["Condition"] == {"Null": {"ec2:LaunchTemplate": "true"}}
    assert _sid(boundary, "DenyNoImdsv2")["Condition"] == {"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}}
    assert "ec2:RunInstances" not in _sid(boundary, "DenyAlways")["Action"]
    assert _sid(_load("deploy-ec2"), "LaunchFromATemplate")["Condition"] == {
        "ArnLike": {"ec2:LaunchTemplate": f"arn:aws:ec2:{r.names(RUNTIME).region}:*:launch-template/*"}}
    # The runtime runs no instance since 2026-10-14 (Fargate); the grant stays template-and-IMDSv2-only until it goes.


def test_the_deploy_role_never_reads_or_writes_a_secret_value_or_signs():
    deploy = [a for kind in ("deploy", "deploy-ec2") for st in _load(kind)["Statement"] for a in _list(st["Action"])]
    for action in ("secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "kms:Sign", "sts:AssumeRole"):
        assert not _matches(action, deploy), action
    assert {"secretsmanager:PutSecretValue", "ecr:SetRepositoryPolicy"} <= set(_sid(_load("boundary"), "DenyAlways")["Action"])


def test_the_ecs_cluster_is_one_the_boundary_lets_its_services_into():
    compute = (MODULE / "compute.tf").read_text(encoding="utf-8")
    assert 'name = "warden-${var.environment}-runtime"' in compute
    cluster = _sid(_load("boundary"), "DenyOtherClusters")["Condition"]["ArnNotLike"]["ecs:cluster"]
    assert fnmatch.fnmatchcase(f"arn:aws:ecs:r:0:cluster/warden-{RUNTIME}-runtime", cluster)


def test_an_address_comes_off_its_aws_managed_interface_and_nothing_more():
    """A NAT gateway's network interface is AWS-managed and untagged, so the tag-conditioned DisassociateAddress was
    refused and pausing the runtime stopped half-way (2026-10-10). The interface side is allowed for that action only."""
    st = _sid(_load("deploy-ec2"), "AnAddressOffItsAwsManagedInterface")
    assert st["Action"] == "ec2:DisassociateAddress"
    assert "Condition" not in st
    assert st["Resource"] == f"arn:aws:ec2:{r.names(RUNTIME).region}:*:network-interface/*"


def test_the_runtime_deploy_role_attaches_only_the_managed_policies_its_module_uses():
    """B22 (2026-10-20): the attach list still named the ECS task-execution and EC2 container-instance policies after
    the module stopped using them (its own minimal execution policy; Fargate since 2026-10-14). The list is exactly
    the AWS-managed policies terraform/runtime and its module attach."""
    allowed = set(_sid(_load("deploy"), "AttachOnlyTheManagedPoliciesUsed")["Condition"]["ArnEquals"]["iam:PolicyARN"])
    tf = "\n".join(p.read_text(encoding="utf-8") for d in (MODULE, ROOT / "terraform" / "runtime") for p in d.glob("*.tf"))
    used = set(re.findall(r'"(arn:aws:iam::aws:policy/[\w/-]+[\w-])"', tf))
    assert allowed == used, (sorted(allowed - used), sorted(used - allowed))


def test_the_task_execution_role_has_only_its_own_minimal_policy():
    """B22: no AWS-managed policy on the execution role - it pulls the runtime image from its one repository and writes
    the worker's log stream, nothing else."""
    compute = (MODULE / "compute.tf").read_text(encoding="utf-8")
    assert "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy" not in compute
    assert 'resource "aws_iam_role_policy_attachment" "execution"' not in compute
    block = compute[compute.index('resource "aws_iam_role_policy" "execution"'):]
    block = block[:block.index("\n}\n")]
    assert '"ecr:GetAuthorizationToken", Resource = "*"' in block
    assert 'Resource = "arn:aws:ecr:${local.region}:${local.account}:repository/${local.runtime_repository}"' in block
    assert 'Resource = "${aws_cloudwatch_log_group.worker.arn}:log-stream:*"' in block
    assert re.findall(r'"((?:ecr|logs):\w+)"', block) == [
        "ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer", "logs:CreateLogStream", "logs:PutLogEvents"]


def test_the_runtime_deploy_role_has_exact_api_gateway_verbs_on_its_own_paths():
    """B22: `apigateway:*` on every resource was granted for the front door. API Gateway authorises by HTTP verb on a
    path (AWS Service Reference); the module creates, reads, updates and deletes an HTTP API, its stage, routes,
    integrations, its request authorizer (main's webhook authorizer: /apis/<id>/authorizers[/<id>], AWS Service
    Reference read 2026-10-21 - inside /apis/*), a custom domain name with its API mapping, and their tags - nothing
    else (no PUT import, no REST API, no API keys, no account settings)."""
    grants = [(st.get("Sid"), a, _list(st["Resource"])) for kind in ("deploy", "deploy-ec2")
              for st in _load(kind)["Statement"] if st["Effect"] == "Allow"
              for a in _list(st["Action"]) if a.startswith("apigateway:")]
    assert {a for _, a, _ in grants} == {"apigateway:GET", "apigateway:POST", "apigateway:PATCH", "apigateway:DELETE"}
    assert {sid for sid, _, _ in grants} == {"TheFrontDoorApi"}
    region = r.names(RUNTIME).region
    assert _sid(_load("deploy"), "TheFrontDoorApi")["Resource"] == [
        f"arn:aws:apigateway:{region}::/{p}" for p in ("apis", "apis/*", "domainnames", "domainnames/*", "tags/*")]
    tf = "\n".join(p.read_text(encoding="utf-8") for p in MODULE.glob("*.tf"))
    assert set(re.findall(r'^resource "(aws_api\w+)"', tf, re.MULTILINE)) == {
        "aws_apigatewayv2_api", "aws_apigatewayv2_stage", "aws_apigatewayv2_integration", "aws_apigatewayv2_route",
        "aws_apigatewayv2_domain_name", "aws_apigatewayv2_api_mapping", "aws_apigatewayv2_authorizer",
    }, "a new API Gateway resource: check its paths"


def test_the_environment_tag_never_comes_off_an_api():
    """B22 review (CodeRabbit, PR 85): the boundary denies touching a resource tagged as another environment's, but an
    untag goes to /tags/<arn>, which carries no resource tag - removing another environment's Environment tag would
    have made its API untagged, and then changeable. The guard refuses removing that key on any API Gateway resource;
    adding another environment's value is already refused (boundary DenyOtherEnvTags)."""
    st = _sid(_load("deploy-guard"), "TheEnvironmentTagNeverComesOffAnApi")
    assert st["Effect"] == "Deny"
    assert st["Action"] == "apigateway:DELETE"
    assert st["Resource"] == "arn:aws:apigateway:*::/tags/*"
    assert st["Condition"] == {"ForAnyValue:StringEquals": {"aws:TagKeys": "Environment"}}
    tags = _sid(_load("boundary"), "DenyOtherEnvTags")["Condition"]
    assert tags["StringNotEquals"] == {"aws:RequestTag/Environment": RUNTIME}

