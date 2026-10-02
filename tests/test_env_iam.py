"""Per-environment IAM (v2 Phase 1.5): one boundary, deploy policy and trust policy per environment,
rendered from iam/templates/ by scripts/render_env_iam.py and committed.

What must hold for every environment: the committed files are exactly the templates' render; each
fits IAM's limit; no file names another environment; parameters and buckets are only its own; the
deploy policy fits inside its boundary; new roles must carry its boundary; and only GitHub's
environment of the same name may assume the deploy role. (iam/operator/ is the operator identity,
not an environment; tests/test_operator_role.py covers it.)
"""

from __future__ import annotations

import fnmatch
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import render_env_iam as r  # after the sys.path line above

ENVS = r.environments()
LIMIT = 6144


def _load(env, kind):
    return json.loads((ROOT / "iam" / env / f"{kind}.json").read_text(encoding="utf-8"))


def _list(x):
    return [x] if isinstance(x, str) else list(x or [])


# The deploy role's two managed policies: what it may do is their union.
DEPLOY = ("deploy", "deploy-ec2")


def _deploy(env):
    return {"Statement": [st for kind in DEPLOY for st in _load(env, kind)["Statement"]]}


def _allows(doc):
    return [a for st in doc["Statement"] if st["Effect"] == "Allow" for a in _list(st["Action"])]


def test_every_environment_has_its_files_and_nothing_else_exists():
    dirs = {p.name for p in (ROOT / "iam").iterdir() if p.is_dir()} - {"templates", "operator"}
    assert dirs == set(ENVS)
    assert len(ENVS) == 6


@pytest.mark.parametrize("env", ENVS)
def test_committed_files_are_exactly_the_render(env):
    for kind, text in r.render(env).items():
        committed = (ROOT / "iam" / env / f"{kind}.json").read_text(encoding="utf-8")
        assert committed == text, f"iam/{env}/{kind}.json drifted: run scripts/render_env_iam.py"


@pytest.mark.parametrize("env", ENVS)
def test_each_file_fits_iams_limit(env):
    for kind in r.KINDS:
        size = len("".join(json.dumps(_load(env, kind), separators=(",", ":")).split()))
        assert size <= LIMIT, f"{env}/{kind}: {size} > {LIMIT}"


@pytest.mark.parametrize("env", ENVS)
def test_no_file_names_another_environment(env):
    for kind in r.KINDS:
        text = json.dumps(_load(env, kind))
        for other in ENVS:
            if other != env:
                assert f"warden-{other}-" not in text and f"/warden/{other}/" not in text and \
                    f"WardenEnvBoundary-{other}\"" not in text, f"{env}/{kind} names {other}"


@pytest.mark.parametrize("env", ENVS)
def test_parameters_and_buckets_are_only_its_own(env):
    for kind in ("boundary", *DEPLOY):
        for st in _load(env, kind)["Statement"]:
            for res in _list(st.get("Resource")):
                if ":ssm:" in res:
                    # Only what Terraform reads: the Slack webhook and other runtime values live beside it
                    # (audit A-I-17).
                    assert res.endswith(f":parameter/warden/{env}/tf/*"), (kind, res)
                if res.startswith("arn:aws:s3:::"):
                    assert res.startswith(f"arn:aws:s3:::warden-{env}-"), (kind, res)
    ceiling = _load(env, "boundary")["Statement"][0]
    assert not any(a.startswith(("ssm:", "s3:", "secretsmanager:Get")) for a in _list(ceiling["Action"])), \
        "the region-wide ceiling must not grant parameters, buckets or secrets of every environment"


@pytest.mark.parametrize("env", ENVS)
def test_the_deploy_policy_fits_inside_its_boundary(env):
    boundary, deploy = _load(env, "boundary"), _deploy(env)
    ceiling = _allows(boundary)
    flat_denies = [a for st in boundary["Statement"] if st["Effect"] == "Deny" and "Condition" not in st
                   and st.get("Resource") == "*" for a in _list(st["Action"])]
    for action in _allows(deploy):
        assert any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in ceiling), f"{env}: {action} outside the ceiling"
        assert not any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in flat_denies), \
            f"{env}: {action} granted but flatly denied"


@pytest.mark.parametrize("env", ENVS)
def test_the_boundary_holds_every_environment_to_itself(env):
    st = {s["Sid"]: s for s in _load(env, "boundary")["Statement"]}
    assert st["DenyRoleWithoutThisBoundary"]["Condition"]["ArnNotLike"]["iam:PermissionsBoundary"] == \
        f"arn:aws:iam::*:policy/WardenEnvBoundary-{env}"
    assert st["DenySelfEdit"]["Resource"] == f"arn:aws:iam::*:role/warden-{env}-deploy"
    # Data that is not this environment's is never destroyed, even untagged: rds:* is region-wide
    # in the ceiling (RDS is addressed by id), so this deny is what protects a foreign database.
    destroy = st["DenyDestroyingOthers"]
    assert {"rds:DeleteDBCluster", "dynamodb:DeleteTable", "secretsmanager:DeleteSecret"} <= set(destroy["Action"])
    assert all(f"warden-{env}-" in r for r in destroy["NotResource"])
    for sid, key in (("DenyOtherEnvResources", "aws:ResourceTag/Environment"),
                     ("DenyOtherEnvTags", "aws:RequestTag/Environment")):
        cond = st[sid]["Condition"]
        assert st[sid]["Effect"] == "Deny" and st[sid]["Action"] == "*"
        assert cond["StringNotEquals"] == {key: env}
        # Only when the tag EXISTS: an IfExists form would deny every untagged resource.
        assert cond["Null"] == {key: "false"} and "StringNotEqualsIfExists" not in cond


@pytest.mark.parametrize("env", ENVS)
def test_only_the_same_named_github_environment_may_assume(env):
    doc = _load(env, "trust")
    [gh] = doc["Statement"]  # deploys run only in GitHub Actions: nothing and nobody else is trusted
    cond = gh["Condition"]
    assert list(cond) == ["StringEquals"], "exact match only - no StringLike, no wildcards"
    # aud and sub here; ref and job_workflow_ref in test_only_main_and_the_two_deploy_workflows_may_assume.
    assert {k: v for k, v in cond["StringEquals"].items() if k.endswith((":aud", ":sub"))} == {
                                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                    "token.actions.githubusercontent.com:sub":
                                        f"repo:veerarakesh56/warden:environment:{env}"}
    assert gh["Principal"]["Federated"].endswith(":oidc-provider/token.actions.githubusercontent.com")
    assert "*" not in json.dumps(doc), "no wildcard anywhere in a trust policy"


def test_templates_use_only_the_known_placeholders():
    """env, env_sql (the environment as a database user name has it: `_` for `-`) and account."""
    import re

    for kind in r.KINDS:
        text = (r.TEMPLATES / f"{kind}.json").read_text(encoding="utf-8")
        assert set(re.findall(r"\$\{(\w+)\}", text)) <= {"env", "env_sql", "account"}, kind


@pytest.mark.parametrize("env", ENVS)
def test_no_role_trust_can_be_rewritten(env):
    """Audit A-I-21: UpdateAssumeRolePolicy let the deploy role make one of its roles trust any principal after
    creation, past the checks on CreateRole. A trust change is a replacement of the role."""
    for kind in ("boundary", *DEPLOY):
        assert "iam:UpdateAssumeRolePolicy" not in _allows(_load(env, kind)), kind


@pytest.mark.parametrize("env", ENVS)
def test_a_tag_cannot_make_another_resource_its_own(env):
    """Audit A-I-7: ec2:CreateTags on any resource let the role tag an untagged resource Environment=<env> and
    then delete it. It may tag only while creating, its own environment's resources, and its own EKS cluster's
    security group (created and tagged by EKS)."""
    grants = [st for st in _deploy(env)["Statement"] if st["Effect"] == "Allow"
              and any(fnmatch.fnmatchcase("ec2:CreateTags", a) for a in _list(st["Action"]))]
    assert len(grants) == 3, [st.get("Sid") for st in grants]
    for st in grants:
        cond = st.get("Condition", {})
        on_create = cond.get("StringLike", {}).get("ec2:CreateAction")
        own = cond.get("StringEquals", {}).get("aws:ResourceTag/Environment") == env
        eks = cond.get("StringLike", {}).get("aws:ResourceTag/aws:eks:cluster-name") == f"warden-{env}-*"
        assert on_create or own or eks, st.get("Sid")
        if on_create:
            assert all(a.startswith(("Create", "AllocateAddress", "AuthorizeSecurityGroup")) for a in on_create)
        if eks:
            assert st["Resource"] == "arn:aws:ec2:*:*:security-group/*"


@pytest.mark.parametrize("env", ENVS)
def test_only_the_managed_policies_terraform_uses_can_be_attached(env):
    """Audit A-I-3: AttachRolePolicy with no condition let the deploy role give one of its roles any managed
    policy. It may attach exactly the AWS-managed policies Terraform attaches."""
    import re

    grants = [st for st in _deploy(env)["Statement"] if st["Effect"] == "Allow"
              and any(fnmatch.fnmatchcase("iam:AttachRolePolicy", a) for a in _list(st["Action"]))]
    assert len(grants) == 1, [st.get("Sid") for st in grants]
    allowed = set(grants[0]["Condition"]["ArnEquals"]["iam:PolicyARN"])
    tf = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "terraform" / "fullstack").glob("*.tf"))
    used = set(re.findall(r'"(arn:aws:iam::aws:policy/[\w/-]+[\w-])"', tf))
    used |= {f"arn:aws:iam::aws:policy/service-role/{n}" for n in re.findall(r'"(AWSLambda\w+ExecutionRole)"', tf)}
    assert allowed == used, (sorted(allowed - used), sorted(used - allowed))


@pytest.mark.parametrize("env", ENVS)
def test_the_boundary_carries_every_guardrail_its_roles_could_break(env):
    """Audit A-I-3/A-I-20: the guardrails were attached to the deploy role only, so a role it created - bound
    only by the boundary - could make a bucket, snapshot or function public. Every guardrail action the
    boundary's ceiling grants is denied in the boundary too, under the same condition."""
    guard = json.loads((ROOT / "terraform" / "proving-ground" / "operator-guardrails.json").read_text(encoding="utf-8"))
    boundary = _load(env, "boundary")
    ceiling = _allows(boundary)
    denied = [(a, st.get("Condition")) for st in boundary["Statement"] if st["Effect"] == "Deny"
              and st.get("Resource") == "*" for a in _list(st["Action"])]
    # IAM wildcards in the boundary's denies (`s3:Put*PublicAccessBlock`) cover the guardrail's exact actions.
    missing = [a for st in guard["Statement"] for a in _list(st["Action"])
               if any(fnmatch.fnmatchcase(a.lower(), p.lower()) for p in ceiling)
               and not any(fnmatch.fnmatchcase(a.lower(), d.lower()) and c == st.get("Condition") for d, c in denied)]
    # Stricter than the guardrail is allowed: AddPermission is denied for any principal that is not an AWS service -
    # "*" included, and another account by id, which Access Analyzer does not see on an alias (eighth review).
    stricter = {"StringNotEquals": {"lambda:Principal": ["events.amazonaws.com", "apigateway.amazonaws.com"]}}
    missing = [a for a in missing if not (a == "lambda:AddPermission" and ("lambda:AddPermission", stricter) in denied)]
    assert not missing, missing
    # `s3:DeleteBucketPublicAccessBlock` is no IAM action: deleting the block is authorised as the Put (ninth review).
    for action in ("s3:PutBucketPublicAccessBlock", "s3:PutBucketPolicy"):
        assert any(fnmatch.fnmatchcase(action.lower(), d.lower()) and c is None for d, c in denied), action


@pytest.mark.parametrize("env", ENVS)
def test_a_role_connects_only_as_its_own_environments_database_users(env):
    """Audit A-I-1/A-I-2: rds-db:connect was in the region-wide ceiling - any database user, the master
    `postgres` included, in any environment's cluster. Now only warden_<env>_* users, and never postgres."""
    boundary = _load(env, "boundary")
    grants = [st for st in boundary["Statement"] if st["Effect"] == "Allow"
              and any(fnmatch.fnmatchcase("rds-db:connect", a) for a in _list(st["Action"]))]
    # Its statement may hold other services' own-name ARNs; an action applies only to its own service's ARNs.
    users = [r for st in grants for r in _list(st["Resource"]) if r.startswith("arn:aws:rds-db") or r == "*"]
    assert users == [f"arn:aws:rds-db:{_region()}:*:dbuser:*/warden_{env.replace('-', '_')}_*"], grants
    master = [st for st in boundary["Statement"] if st["Effect"] == "Deny" and "rds-db:connect" in _list(st["Action"])]
    assert master and "arn:aws:rds-db:*:*:dbuser:*/postgres" in _list(master[0]["Resource"])


def _region():
    ceiling = next(st for st in _load(ENVS[0], "boundary")["Statement"] if st.get("Sid") == "CeilingRegional")
    return ceiling["Condition"]["StringEquals"]["aws:RequestedRegion"]


@pytest.mark.parametrize("env", ENVS)
def test_the_deploy_role_can_do_what_the_first_real_deploy_needed(env):
    """Audit A-I-5/A-I-6: Aurora express authorises CreateDBCluster against the `default` subnet group and needs
    EnableInternetAccessGateway; default_tags tag every event source mapping. The operator got these after the
    first real deploy; the per-environment deploy role did not, so CI's apply would fail the same way."""
    grants = [(a, r) for st in _deploy(env)["Statement"] if st["Effect"] == "Allow"
              for a in _list(st["Action"]) for r in _list(st["Resource"])]

    def allowed(action, resource):
        return any(fnmatch.fnmatchcase(action, a) and fnmatch.fnmatchcase(resource, r) for a, r in grants)

    subgrp = "arn:aws:rds:region:111122223333:subgrp:default"
    for action in ("rds:CreateDBCluster", "rds:CreateDBInstance", "rds:EnableInternetAccessGateway"):
        assert allowed(action, subgrp), action
    esm = "arn:aws:lambda:region:111122223333:event-source-mapping:0a1b2c3d-aaaa-bbbb-cccc-ddddeeeeffff"
    for action in ("lambda:TagResource", "lambda:UntagResource", "lambda:ListTags"):
        assert allowed(action, esm), action


@pytest.mark.parametrize("env", ENVS)
def test_only_main_and_the_two_deploy_workflows_may_assume(env):
    """Audit A-I-10: any workflow run in the repository's `<env>` environment - from any branch - could assume the
    deploy role. The trust now also requires `ref` = main and a `job_workflow_ref` of one of the two reusable
    deploy workflows on main (IAM condition keys for GitHub's tokens, read 2026-10-01)."""
    cond = _load(env, "trust")["Statement"][0]["Condition"]
    assert cond["StringEquals"]["token.actions.githubusercontent.com:ref"] == "refs/heads/main"
    refs = cond["StringEquals"]["token.actions.githubusercontent.com:job_workflow_ref"]
    assert all(r.endswith("@refs/heads/main") for r in refs), refs
    assert sorted(r.split("@")[0].rsplit("/", 1)[-1] for r in refs) == ["_apps-deploy.yml", "_infra-deploy.yml"]


@pytest.mark.parametrize("env", ENVS)
def test_mappings_and_task_definitions_are_the_environments_own(env):
    """Audit A-I-8: event-source-mapping and task-definition grants were Resource "*" with a region condition only.
    The mappings are bound to this environment's functions (lambda:FunctionArn), task definitions to its families;
    DeregisterTaskDefinition has no resource and no condition key (AWS Service Reference, read 2026-10-01)."""
    by_sid = {st["Sid"]: st for st in _deploy(env)["Statement"]}
    esm = by_sid["EsmsOfOwnFunctions"]
    assert esm["Condition"]["ArnLike"]["lambda:FunctionArn"] == f"arn:aws:lambda:*:*:function:warden-{env}-*"
    assert by_sid["OwnTaskDefinitions"]["Resource"] == f"arn:aws:ecs:*:*:task-definition/warden-{env}-*"
    unbound = [a for st in _deploy(env)["Statement"] if st["Effect"] == "Allow" and st.get("Resource") == "*"
               and "ArnLike" not in st.get("Condition", {}) for a in _list(st["Action"])
               if "EventSourceMapping" in a or "TaskDefinition" in a]
    assert unbound == ["ecs:DeregisterTaskDefinition"], unbound


@pytest.mark.parametrize("env", ENVS)
def test_ecs_writes_stay_in_the_environments_own_clusters(env):
    """Seventh review (2026-10-01, HIGH): an ECS service's ARN is service/<cluster>/<name>, so `*/warden-dev-*`
    matched a dev-named service in prod's cluster, and CreateService authorizes the new, untagged service - the tag
    deny never fired; RunTask authorizes only the task definition. The boundary - binding every role the deploy
    role creates too - denies ECS writes into any cluster but the environment's own, on `ecs:cluster`, which every
    action these patterns match carries (Service Reference, 2026-10-01)."""
    st = {s["Sid"]: s for s in _load(env, "boundary")["Statement"]}
    deny = st["DenyOtherClusters"]
    assert deny["Effect"] == "Deny" and deny["Resource"] == "*"
    for action in ("ecs:CreateService", "ecs:UpdateService", "ecs:DeleteService", "ecs:RunTask", "ecs:StartTask",
                   "ecs:StopTask", "ecs:CreateTaskSet", "ecs:UpdateTaskSet"):
        assert any(fnmatch.fnmatchcase(action, p) for p in _list(deny["Action"])), action
    for read in ("ecs:DescribeServices", "ecs:ListServices", "ecs:DescribeTasks"):
        assert not any(fnmatch.fnmatchcase(read, p) for p in _list(deny["Action"])), read
    [(op, cond)] = deny["Condition"].items()
    [pattern] = cond.values()
    assert op == "ArnNotLike" and list(cond) == ["ecs:cluster"]
    other = next(e for e in ENVS if e != env)
    assert fnmatch.fnmatchcase(f"arn:aws:ecs:x:1:cluster/warden-{env}-ecs", pattern)
    assert not fnmatch.fnmatchcase(f"arn:aws:ecs:x:1:cluster/warden-{other}-ecs", pattern)  # denied: not its own
    # The folded IAM ceiling grants no new kind of IAM write: never a role's trust.
    ceiling = _allows(_load(env, "boundary"))
    assert not any(fnmatch.fnmatchcase("iam:UpdateAssumeRolePolicy", p) for p in ceiling)


@pytest.mark.parametrize("env", ENVS)
def test_the_deploy_role_turns_on_api_access_logs_without_writing_a_logs_resource_policy(env):
    """Audit A-I-13 (owner's choice, 2026-10-01): API Gateway's access logs use vended log delivery. The owner creates
    the account's delivery policy for /aws/vendedlogs/warden-* once; the deploy role creates its own group and the
    delivery, and may never write a CloudWatch Logs resource policy - one can share logs with another account."""
    grants = [(a, r) for st in _deploy(env)["Statement"] if st["Effect"] == "Allow"
              for a in _list(st["Action"]) for r in _list(st["Resource"])]

    def allowed(action, resource):
        return any(fnmatch.fnmatchcase(action, a) and fnmatch.fnmatchcase(resource, r) for a, r in grants)

    group = f"arn:aws:logs:x:1:log-group:/aws/vendedlogs/warden-{env}-api-access"
    assert allowed("logs:CreateLogGroup", group) and allowed("logs:PutRetentionPolicy", group)
    for action in ("logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery",
                   "logs:ListLogDeliveries", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"):
        assert allowed(action, "*"), action
    other = next(e for e in ENVS if e != env)
    assert not allowed("logs:CreateLogGroup", f"arn:aws:logs:x:1:log-group:/aws/vendedlogs/warden-{other}-api-access")
    assert not allowed("logs:PutResourcePolicy", "*")
    denied = [a for st in _load(env, "boundary")["Statement"] if st["Effect"] == "Deny" and "Condition" not in st
              for a in _list(st["Action"])]
    assert any(fnmatch.fnmatchcase("logs:PutResourcePolicy", d) for d in denied)


@pytest.mark.parametrize("env", ENVS)
def test_no_role_shares_an_event_bus_or_the_image_registry_outside(env):
    """Seventh review (2026-10-01): roles inside the boundary could share outside the account through resource
    policies. IAM Access Analyzer's external-access analyzer (the owner's, since 2026-09-27) reports role trusts,
    Lambda, SQS, SNS, ECR repositories and DynamoDB; it does not analyze an EventBridge bus's permissions or the ECR
    registry's policy and replication (AWS docs, read 2026-10-01) - so those are denied outright."""
    denied = [a for st in _load(env, "boundary")["Statement"] if st["Effect"] == "Deny" and "Condition" not in st
              and st.get("Resource") == "*" for a in _list(st["Action"])]
    for action in ("events:PutPermission", "ecr:PutRegistryPolicy", "ecr:PutReplicationConfiguration",
                   "logs:PutResourcePolicy"):
        assert any(fnmatch.fnmatchcase(action, p) for p in denied), action
    assert not any(fnmatch.fnmatchcase(a, p) for a in ("ecr:PutImage", "ecr:PutLifecyclePolicy") for p in denied)


@pytest.mark.parametrize("env", ENVS)
def test_no_task_runs_outside_a_service_and_nothing_shares_logs_buses_or_functions(env):
    """Eighth review (2026-10-01): RunTask and StartTask carry no subnet key, and ECS's own role makes the task's
    network interface - a dev role could run a task with prod's subnets and security groups (HIGH). Nothing in the
    stack runs one, so both are denied. Also: daemons in another cluster, EventBridge's bus policy API, account-wide
    log policies, and a function permission for another account (by id, or on an alias Access Analyzer misses)."""
    statements = _load(env, "boundary")["Statement"]
    flat = [a for st in statements if st["Effect"] == "Deny" and "Condition" not in st and st.get("Resource") == "*"
            for a in _list(st["Action"])]
    for action in ("ecs:RunTask", "ecs:StartTask", "ec2:RunInstances", "ec2:PurchaseHostReservation",
                   "events:PutResourcePolicy", "logs:PutAccountPolicy"):
        assert any(fnmatch.fnmatchcase(action, p) for p in flat), action
    for kept in ("ecs:CreateService", "ec2:CreateTags", "logs:PutRetentionPolicy", "events:PutRule"):
        assert not any(fnmatch.fnmatchcase(kept, p) for p in flat), kept
    clusters = next(st for st in statements if st["Sid"] == "DenyOtherClusters")
    assert any(fnmatch.fnmatchcase("ecs:CreateDaemon", p) for p in _list(clusters["Action"]))
    # Only the two service principals the stack grants, exactly: "ends in .amazonaws.com" let through a role ARN
    # ending so and any service without a source ARN (ninth review).
    invoke = next(st for st in statements if st["Sid"] == "DenyInvokeByAll")
    granted = invoke["Condition"]["StringNotEquals"]["lambda:Principal"]
    assert set(invoke["Condition"]) == {"StringNotEquals"} and sorted(granted) == ["apigateway.amazonaws.com",
                                                                                     "events.amazonaws.com"]
    tf = (ROOT / "terraform" / "fullstack" / "lambda.tf").read_text(encoding="utf-8")
    assert set(re.findall(r'principal\s*=\s*"([^"]+)"', tf)) == set(granted)


def test_no_environment_name_is_another_ones_prefix():
    """Eighth review (2026-10-01): every IAM pattern is `warden-<env>-*`, so an environment `qa` beside `qa-prod` would
    match the other's resources - the hazard R7-D5 fixed in the Aurora script, latent in IAM."""
    for a in ENVS:
        for b in ENVS:
            assert a == b or not b.startswith(f"{a}-"), (a, b)


def _denied_untagged(boundary: dict, action: str, resource: str, tags: dict) -> bool:
    """A deny whose only condition is that the resource carries no Environment tag."""
    for st in boundary["Statement"]:
        null = st.get("Condition", {}).get("Null", {}).get("aws:ResourceTag/Environment")
        if st["Effect"] == "Deny" and null == "true" and set(st["Condition"]) == {"Null"} \
                and any(fnmatch.fnmatchcase(action, a) for a in _list(st["Action"])) \
                and any(fnmatch.fnmatchcase(resource, r) for r in _list(st["Resource"])) and "Environment" not in tags:
            return True
    return False


@pytest.mark.parametrize("env", ENVS)
def test_no_role_changes_a_vpcs_untagged_defaults(env):
    """Ninth review (2026-10-01, HIGH, pre-existing): a VPC's default network ACL, default security group and main
    route table are made by AWS untagged, so the other-environment deny never applied - any environment's role
    could rewrite prod's default NACL. Scoped to the ACL, group and table themselves: a security-group RULE is
    untagged when it is made, and the stack's own rules must still go through; reads are never denied."""
    boundary = _load(env, "boundary")
    acl, sg, rtb = (f"arn:aws:ec2:{_region()}:111122223333:{kind}" for kind in
                    ("network-acl/acl-0abc", "security-group/sg-0abc", "route-table/rtb-0abc"))
    for action, resource in [("ec2:CreateNetworkAclEntry", acl), ("ec2:ReplaceNetworkAclEntry", acl),
                             ("ec2:DeleteNetworkAclEntry", acl), ("ec2:AuthorizeSecurityGroupIngress", sg),
                             ("ec2:AuthorizeSecurityGroupEgress", sg), ("ec2:RevokeSecurityGroupIngress", sg),
                             ("ec2:RevokeSecurityGroupEgress", sg), ("ec2:ModifySecurityGroupRules", sg),
                             ("ec2:CreateRoute", rtb), ("ec2:ReplaceRoute", rtb), ("ec2:DeleteRoute", rtb)]:
        assert _denied_untagged(boundary, action, resource, {}), (action, resource)
        assert not _denied_untagged(boundary, action, resource, {"Environment": env}), (action, resource)
    rule = f"arn:aws:ec2:{_region()}:111122223333:security-group-rule/sgr-0abc"
    assert not _denied_untagged(boundary, "ec2:AuthorizeSecurityGroupIngress", rule, {})
    for read, resource in [("ec2:DescribeNetworkAcls", "*"), ("ec2:DescribeSecurityGroups", "*"),
                           ("ec2:DescribeSecurityGroupRules", "*"), ("ec2:DescribeRouteTables", "*")]:
        assert not _denied_untagged(boundary, read, acl, {}) and not _denied_untagged(boundary, read, resource, {})


@pytest.mark.parametrize("env", ENVS)
def test_no_role_changes_account_settings_opens_a_way_out_or_buys_capacity(env):
    """Ninth review (2026-10-01): an environment's role could change account- and region-wide settings every
    environment lives under (EBS encryption by default, instance metadata defaults, block public access for images,
    snapshots and the VPC, ECS account defaults, account log policies), open a way out (another account's access to
    a queue, topic or layer; peering; accepting an attachment) or commit money (reservations, purchases). Nothing in
    the stack does any of these. IAM matches actions case-insensitively, so the check does too."""
    flat = [a.lower() for st in _load(env, "boundary")["Statement"] if st["Effect"] == "Deny"
            and "Condition" not in st and st.get("Resource") == "*" for a in _list(st["Action"])]
    for action in ("ec2:DisableEbsEncryptionByDefault", "ec2:ModifyEbsDefaultKmsKeyId", "ec2:ModifyInstanceMetadataDefaults",
                   "ec2:DisableImageBlockPublicAccess", "ec2:DisableSnapshotBlockPublicAccess",
                   "ec2:ModifyVpcBlockPublicAccessOptions", "ecs:PutAccountSettingDefault", "logs:DeleteAccountPolicy",
                   "logs:DeleteResourcePolicy", "ecr:CreateRepositoryCreationTemplate", "sqs:AddPermission",
                   "sns:AddPermission", "lambda:AddLayerVersionPermission", "ec2:CreateVpcPeeringConnection",
                   "ec2:AcceptVpcPeeringConnection", "ec2:AcceptTransitGatewayVpcAttachment",
                   "ec2:ModifyVpcEndpointServicePermissions", "rds:PurchaseReservedDBInstancesOffering",
                   "elasticache:PurchaseReservedCacheNodesOffering", "ec2:CreateCapacityReservation",
                   "eks:CreateEksAnywhereSubscription", "events:PutPermission", "s3:PutObjectAcl"):
        assert any(fnmatch.fnmatchcase(action.lower(), p) for p in flat), action
    for kept in ("events:PutRule", "events:PutTargets", "events:PutEvents", "logs:PutRetentionPolicy",
                 "logs:DeleteRetentionPolicy", "logs:CreateLogDelivery", "sqs:SetQueueAttributes", "ec2:CreateVpc",
                 "ec2:ModifyVpcAttribute", "ec2:ModifySubnetAttribute", "ecs:CreateCluster", "ecr:PutLifecyclePolicy",
                 "s3:PutBucketTagging", "lambda:AddPermission"):
        assert not any(fnmatch.fnmatchcase(kept.lower(), p) for p in flat), kept


@pytest.mark.parametrize("env", ENVS)
def test_every_deploy_grant_lies_inside_the_boundary_on_resources_too(env):
    """Audit A-I-VT: the fit test compared action names only - a grant on a resource the boundary never allows (another
    environment's bucket) passed, and would silently do nothing in AWS. Each (action, resource) the deploy policy
    grants must be allowed by one boundary statement covering both. An action is paired only with ARNs of its own
    service, and a region wildcard is read as the boundary's region (the boundary narrows it by design)."""
    region = _region()
    allows = [s for s in _load(env, "boundary")["Statement"] if s["Effect"] == "Allow"]
    outside = []
    for st in _deploy(env)["Statement"]:
        if st["Effect"] != "Allow" or "NotResource" in st:
            continue
        for action in _list(st["Action"]):
            service = action.split(":")[0].lower()
            for resource in _list(st.get("Resource", "*")):
                arn = re.match(r"arn:aws:([^:]+):", resource)
                if arn and arn.group(1) != service:
                    continue
                resource = re.sub(r"^(arn:aws:[^:]+:)\*:", rf"\g<1>{region}:", resource)
                if not any(any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in _list(b["Action"]))
                           and any(fnmatch.fnmatchcase(resource, r) for r in _list(b.get("Resource", "*")))
                           for b in allows):
                    outside.append((st.get("Sid"), action, resource))
    assert not outside, outside[:10]


def test_the_harness_policy_is_devs_only_and_names_its_own_cluster(tmp_path, monkeypatch):
    """Audit A-I-18 (owner, 2026-10-02): the operator runs the Wave 4 harness from the laptop, in dev only. Its policy
    writes only dev's named or tagged resources, and logs in to Aurora - as the master user, which the faults need -
    only on dev's cluster, named by its resource id: `dbuser:*` would reach every environment's database."""
    assert [e for e in ENVS if (ROOT / "iam" / e / "harness.json").exists()] == list(r.HARNESS_ENVS) == ["dev"]
    policy = json.loads((ROOT / "iam" / "dev" / "harness.json").read_text(encoding="utf-8"))
    for st in policy["Statement"]:
        resources = _list(st["Resource"])
        if st["Sid"] in ("ReadTheStack", "TaskDefinitionsTakeNoName", "EventSourceMappingsOfThisEnvironmentsFunctions",
                         "SecurityGroupRulesOfThisEnvironmentOnly"):
            assert "Condition" in st, st["Sid"]  # region, function ARN or the environment's tags
            continue
        for res in resources:
            assert "warden-dev-" in res or res.endswith(("/postgres", "/warden_dev_ro")), (st["Sid"], res)
        if any(a.startswith("rds-db:") for a in _list(st["Action"])):
            assert all(":dbuser:<CLUSTER_RESOURCE_ID>/" in res for res in resources), resources
    sg = next(s for s in policy["Statement"] if s["Sid"] == "SecurityGroupRulesOfThisEnvironmentOnly")
    assert sg["Condition"]["StringEquals"]["aws:ResourceTag/Environment"] == "dev"

    monkeypatch.setattr(r, "ROOT", tmp_path)
    monkeypatch.setattr(r, "environments", lambda: ("dev",))
    with pytest.raises(SystemExit):
        r.main(["--cluster-resource-id", "*"])
    assert r.main(["--cluster-resource-id", "cluster-ABCDEFGHIJ1234"]) == 0
    local = (tmp_path / "iam" / "dev" / "harness.local.json").read_text(encoding="utf-8")
    assert "dbuser:cluster-ABCDEFGHIJ1234/postgres" in local and "<CLUSTER_RESOURCE_ID>" not in local


def test_only_the_operator_role_of_this_account_may_assume_the_harness_role():
    """Register R18 (owner, 2026-10-02): the harness is its own identity, warden-dev-harness - not permissions added to
    the read-only operator role. Only that role may assume it, in this account, keeping its source identity."""
    trust = json.loads((ROOT / "iam" / "dev" / "harness-trust.json").read_text(encoding="utf-8"))
    [st] = trust["Statement"]
    assert st["Effect"] == "Allow" and st["Principal"] == {"AWS": "arn:aws:iam::<ACCOUNT_ID>:role/warden-ops-operator"}
    assert sorted(_list(st["Action"])) == ["sts:AssumeRole", "sts:SetSourceIdentity"]
    assert not (ROOT / "iam" / "staging" / "harness-trust.json").exists()
