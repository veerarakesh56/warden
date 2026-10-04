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


def test_only_the_runtime_pipeline_on_main_may_assume_the_deploy_role():
    (st,) = _load("trust")["Statement"]
    assert st["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert st["Principal"]["Federated"].endswith(":oidc-provider/token.actions.githubusercontent.com")
    assert st["Condition"] == {"StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": f"repo:veerarakesh56/warden:environment:{RUNTIME}",
        "token.actions.githubusercontent.com:ref": "refs/heads/main",
        "token.actions.githubusercontent.com:job_workflow_ref":
            "veerarakesh56/warden/.github/workflows/runtime.yml@refs/heads/main"}}


def test_every_action_the_runtimes_own_roles_hold_fits_the_boundary():
    """The module's inline role policies (iam.tf): each action within the ceiling and not flatly denied - a boundary
    that denied GetSecretValue or kms:Sign would leave the worker unable to read its secrets or sign the audit."""
    boundary = _load("boundary")
    ceiling = [a for st in boundary["Statement"] if st["Effect"] == "Allow" for a in _list(st["Action"])]
    flat = [a for st in boundary["Statement"] if st["Effect"] == "Deny" and "Condition" not in st
            and st.get("Resource") == "*" for a in _list(st["Action"])]
    iam_tf = (MODULE / "iam.tf").read_text(encoding="utf-8")
    actions = {a for block in re.findall(r"Action\s*=\s*\[([^\]]*)\]", iam_tf) for a in re.findall(r'"([^"]+)"', block)}
    assert {"secretsmanager:GetSecretValue", "kms:Sign", "sts:AssumeRole", "bedrock:InvokeModel"} <= actions
    assert [a for a in sorted(actions) if not _matches(a, ceiling)] == []
    assert [a for a in sorted(actions) if _matches(a, flat)] == []


def test_the_worker_reaches_other_environments_only_through_their_reader_and_actor():
    boundary = _load("boundary")
    assert _sid(boundary, "CeilingWatchedRoles")["Resource"] == [
        "arn:aws:iam::*:role/warden-*-platform-reader", "arn:aws:iam::*:role/warden-*-actor"]
    other = _sid(boundary, "DenyOtherEnvResources")
    assert other["NotAction"] == "sts:*" and "Action" not in other  # every other service stays out
    assert other["Condition"]["StringNotEquals"] == {"aws:ResourceTag/Environment": RUNTIME}
    for kind, zones in (("actor-trust", ("act",)), ("platform-reader-trust", ("read", "notify", "act"))):
        principals = {p for st in json.loads((ROOT / "iam" / "templates" / f"{kind}.json").read_text(encoding="utf-8"))
                      ["Statement"] for p in _list(st["Principal"]["AWS"])}  # and those roles trust only its zones
        assert principals == {f"arn:aws:iam::${{account}}:role/warden-{RUNTIME}-{z}" for z in zones}


def test_instances_launch_only_from_a_template_with_imdsv2():
    boundary = _load("boundary")
    assert _sid(boundary, "DenyNoTemplate")["Condition"] == {"Null": {"ec2:LaunchTemplate": "true"}}
    assert _sid(boundary, "DenyNoImdsv2")["Condition"] == {"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}}
    assert "ec2:RunInstances" not in _sid(boundary, "DenyAlways")["Action"]
    assert _sid(_load("deploy-ec2"), "LaunchFromATemplate")["Condition"] == {
        "ArnLike": {"ec2:LaunchTemplate": f"arn:aws:ec2:{r.names(RUNTIME).region}:*:launch-template/*"}}
    assert 'http_tokens                 = "required"' in (MODULE / "compute.tf").read_text(encoding="utf-8")


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
