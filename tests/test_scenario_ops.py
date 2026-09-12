"""The fault-injection layer, against stubbed AWS clients.

Two very different things are tested here and only one of them is ordinary.

The ordinary half: the operations do what they say — a variant is derived from the baseline, a
revert restores exactly what was saved, an unknown op is refused.

⛔ The half that matters: **the injector cannot reach anything outside the proving ground, and it
shares nothing with the tool under test.** Those two properties are what make the published
benchmark believable, so they are tested adversarially — each guard is given a case it MUST refuse,
because a guard that has only ever been shown valid input has not been tested at all.
"""

from __future__ import annotations

import ast
import copy
import inspect
import json
import pathlib

import pytest
from scenarios import ops
from scenarios.ops import Clients, OpError, Target, run_steps

ACCOUNT = "111122223333"
TAGS_OK = [{"key": "Project", "value": "warden-proving-ground"}]
EC2_TAGS_OK = [{"Key": "Project", "Value": "warden-proving-ground"}]


# --------------------------------------------------------------------------- fakes


class FakeEcs:
    def __init__(self, *, cluster_tags=None):
        self.calls: list[tuple[str, dict]] = []
        self.cluster_tags = TAGS_OK if cluster_tags is None else cluster_tags
        self.registered: list[dict] = []
        self.task_arns = ["arn:aws:ecs:r:1:task/abc"]

    def describe_clusters(self, **kw):
        self.calls.append(("describe_clusters", kw))
        return {"clusters": [{"clusterName": "pg", "tags": self.cluster_tags}]}

    def describe_task_definition(self, **kw):
        self.calls.append(("describe_task_definition", kw))
        return {"taskDefinition": {
            "family": "checkout",
            "cpu": "256", "memory": "512",
            "networkMode": "awsvpc",
            "requiresCompatibilities": ["FARGATE"],
            "executionRoleArn": f"arn:aws:iam::{ACCOUNT}:role/exec",
            "taskRoleArn": f"arn:aws:iam::{ACCOUNT}:role/warden-pg-task",
            "containerDefinitions": [{
                "name": "checkout",
                "image": "public.ecr.aws/docker/library/python:3.12-alpine",
                "essential": True,
                "command": ["python", "-u", "-c", "baseline"],
                "logConfiguration": {"logDriver": "awslogs", "options": {}},
            }],
        }}

    def register_task_definition(self, **kw):
        self.calls.append(("register_task_definition", kw))
        self.registered.append(kw)
        rev = len(self.registered) + 1
        return {"taskDefinition": {"taskDefinitionArn": f"arn:aws:ecs:r:1:task-definition/checkout:{rev}"}}

    def update_service(self, **kw):
        self.calls.append(("update_service", kw))
        return {}

    def list_tasks(self, **kw):
        self.calls.append(("list_tasks", kw))
        return {"taskArns": self.task_arns}

    def stop_task(self, **kw):
        self.calls.append(("stop_task", kw))
        return {}


class FakeLogs:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def delete_log_group(self, **kw):
        self.calls.append(("delete_log_group", kw))

    def create_log_group(self, **kw):
        self.calls.append(("create_log_group", kw))

    def put_retention_policy(self, **kw):
        self.calls.append(("put_retention_policy", kw))


class FakeEc2:
    def __init__(self, *, sg_tags=None, rt_tags=None):
        self.calls: list[tuple[str, dict]] = []
        self.sg_tags = EC2_TAGS_OK if sg_tags is None else sg_tags
        self.rt_tags = EC2_TAGS_OK if rt_tags is None else rt_tags
        self.egress = [{
            "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "https"}],
        }]

    def describe_security_groups(self, **kw):
        self.calls.append(("describe_security_groups", kw))
        return {"SecurityGroups": [{"IpPermissionsEgress": self.egress, "Tags": self.sg_tags}]}

    def revoke_security_group_egress(self, **kw):
        self.calls.append(("revoke_security_group_egress", kw))

    def authorize_security_group_egress(self, **kw):
        self.calls.append(("authorize_security_group_egress", kw))

    def describe_route_tables(self, **kw):
        self.calls.append(("describe_route_tables", kw))
        return {"RouteTables": [{
            "Tags": self.rt_tags,
            "Routes": [
                {"DestinationCidrBlock": "10.42.0.0/16", "GatewayId": "local"},
                {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123"},
            ],
        }]}

    def delete_route(self, **kw):
        self.calls.append(("delete_route", kw))

    def create_route(self, **kw):
        self.calls.append(("create_route", kw))


class FakeIam:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.document = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:FilterLogEvents", "ecs:DescribeServices", "cloudwatch:GetMetricData"],
            "Resource": "*",
        }]}

    def list_role_policies(self, **kw):
        self.calls.append(("list_role_policies", kw))
        return {"PolicyNames": ["warden-readonly"]}

    def get_role_policy(self, **kw):
        self.calls.append(("get_role_policy", kw))
        return {"PolicyDocument": copy.deepcopy(self.document)}

    def put_role_policy(self, **kw):
        self.calls.append(("put_role_policy", kw))


@pytest.fixture
def clients():
    return Clients(ecs=FakeEcs(), logs=FakeLogs(), ec2=FakeEc2(), iam=FakeIam())


@pytest.fixture
def target():
    return Target(
        region="ap-south-1", cluster="warden-pg-a1b2", service="checkout",
        log_group="/ecs/checkout",
        baseline_task_definition="arn:aws:ecs:r:1:task-definition/checkout:2",
        security_group_id="sg-123", route_table_id="rtb-123",
        warden_role_name="warden-pg-a1b2-reader",
    )


# --------------------------------------------------------------------------- the boundary


def test_the_injector_does_not_import_the_tool_under_test():
    """⛔ The load-bearing separation. If the thing that breaks AWS could import the thing that
    diagnoses AWS, a reader would be right to suspect they agree with each other behind the scenes.
    Making it structurally impossible is the only convincing answer."""
    src = pathlib.Path(inspect.getsourcefile(ops)).read_text(encoding="utf-8")
    offenders: list[str] = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            offenders += [a.name for a in node.names if a.name.split(".")[0] == "warden"]
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "warden":
            offenders.append(node.module or "")
    assert not offenders, f"scenarios/ops.py must not import warden; found {offenders}"


def test_an_untagged_cluster_is_refused(target):
    """The guard that stops this harness from ever touching real infrastructure."""
    bad = Clients(ecs=FakeEcs(cluster_tags=[]), logs=FakeLogs(), ec2=FakeEc2(), iam=FakeIam())
    with pytest.raises(OpError, match="not tagged"):
        ops.op_ecs_force_new_deployment(bad, target)


def test_a_cluster_tagged_for_a_different_project_is_refused(target):
    bad = Clients(
        ecs=FakeEcs(cluster_tags=[{"key": "Project", "value": "production"}]),
        logs=FakeLogs(), ec2=FakeEc2(), iam=FakeIam(),
    )
    with pytest.raises(OpError, match="not tagged"):
        ops.op_ecs_deploy_baseline(bad, target)


def test_a_missing_cluster_is_refused_rather_than_assumed(target):
    class Empty(FakeEcs):
        def describe_clusters(self, **kw):
            return {"clusters": []}

    bad = Clients(ecs=Empty(), logs=FakeLogs(), ec2=FakeEc2(), iam=FakeIam())
    with pytest.raises(OpError, match="not found"):
        ops.op_ecs_force_new_deployment(bad, target)


def test_only_proving_ground_log_groups_may_be_deleted(clients, target):
    with pytest.raises(OpError, match="refusing"):
        ops.op_logs_delete_group(clients, target, log_group="/aws/lambda/production-billing")
    assert clients.logs.calls == [], "nothing may be called before the guard passes"


def test_only_a_warden_prefixed_role_may_be_shrunk(clients, target):
    target.warden_role_name = "OrganizationAccountAccessRole"
    with pytest.raises(OpError, match="refusing"):
        ops.op_iam_shrink_role_policy(
            clients, target, role_kind="warden_reader", remove_actions=["s3:*"],
        )


def test_only_wardens_own_reader_role_may_be_modified(clients, target):
    """The execution role starts the workload. Shrinking it would break the proving ground itself
    rather than constrain the tool under test."""
    with pytest.raises(OpError, match="only WARDEN's own reader role"):
        ops.op_iam_shrink_role_policy(
            clients, target, role_kind="execution", remove_actions=["logs:CreateLogStream"],
        )


def test_an_untagged_security_group_is_refused(target):
    bad = Clients(ecs=FakeEcs(), logs=FakeLogs(), ec2=FakeEc2(sg_tags=[]), iam=FakeIam())
    with pytest.raises(OpError, match="not tagged"):
        ops.op_sg_revoke_all_egress(bad, target)


def test_an_untagged_route_table_is_refused(target):
    bad = Clients(ecs=FakeEcs(), logs=FakeLogs(), ec2=FakeEc2(rt_tags=[]), iam=FakeIam())
    with pytest.raises(OpError, match="not tagged"):
        ops.op_route_delete_default(bad, target)


# --------------------------------------------------------------------------- variants


def test_a_variant_differs_from_the_baseline_only_in_the_declared_way(clients, target):
    """Deriving from the baseline is what stops something incidental explaining a result."""
    ops.op_ecs_deploy_variant(clients, target, variant="oom", account=ACCOUNT)
    registered = clients.ecs.registered[0]
    container = registered["containerDefinitions"][0]

    assert registered["family"] == "checkout"
    assert registered["memory"] == "512", "unchanged from the baseline"
    assert registered["executionRoleArn"].endswith("role/exec"), "unchanged"
    assert container["image"].endswith(":3.12.7-alpine"), "the image tag is the declared change"
    assert "900*1024*1024" in container["command"][-1], "and so is the command"
    assert container["logConfiguration"]["logDriver"] == "awslogs", "logging must survive"


def test_the_same_image_variant_really_keeps_the_baseline_image(clients, target):
    """⭐ Load-bearing for scenario ecs-10. If this variant changed the image, WARDEN would report a
    deploy and the pair with ecs-03 would prove nothing."""
    ops.op_ecs_deploy_variant(clients, target, variant="oom_same_image", account=ACCOUNT)
    image = clients.ecs.registered[0]["containerDefinitions"][0]["image"]
    assert image == "public.ecr.aws/docker/library/python:3.12-alpine"


def test_the_bad_image_variant_points_at_a_tag_that_cannot_resolve(clients, target):
    ops.op_ecs_deploy_variant(clients, target, variant="bad_image", account=ACCOUNT)
    image = clients.ecs.registered[0]["containerDefinitions"][0]["image"]
    assert image.endswith(":this-tag-does-not-exist-9x8y7z")


def test_the_bad_secret_variant_interpolates_the_real_account_and_region(clients, target):
    ops.op_ecs_deploy_variant(clients, target, variant="bad_secret", account=ACCOUNT)
    secrets = clients.ecs.registered[0]["containerDefinitions"][0]["secrets"]
    assert secrets[0]["valueFrom"].startswith(f"arn:aws:secretsmanager:ap-south-1:{ACCOUNT}:")


def test_an_unknown_variant_is_refused_loudly(clients, target):
    with pytest.raises(OpError, match="unknown variant"):
        ops.op_ecs_deploy_variant(clients, target, variant="nope", account=ACCOUNT)


def test_every_variant_registers_without_error(clients, target):
    """A variant that only fails at inject time wastes a whole live AWS run to discover a typo."""
    for variant in ops._VARIANTS:
        ops.op_ecs_deploy_variant(clients, target, variant=variant, account=ACCOUNT)
    assert len(clients.ecs.registered) == len(ops._VARIANTS)


def test_every_variant_command_is_a_known_command(clients, target):
    unknown = [
        name for name, spec in ops._VARIANTS.items() if spec["command_key"] not in ops._COMMANDS
    ]
    assert not unknown, f"variants referencing a command that does not exist: {unknown}"


# --------------------------------------------------------------------------- revert fidelity


def test_egress_is_restored_verbatim_not_reconstructed(clients, target):
    """⭐ Reconstructing 'the usual rule' would leave the environment subtly different from how it
    started, and every later scenario would then run against something nobody described."""
    original = copy.deepcopy(clients.ec2.egress)
    ops.op_sg_revoke_all_egress(clients, target)
    ops.op_sg_restore_egress(clients, target)

    authorized = [kw for name, kw in clients.ec2.calls if name == "authorize_security_group_egress"]
    assert authorized[0]["IpPermissions"] == original
    assert authorized[0]["IpPermissions"][0]["IpRanges"][0]["Description"] == "https"


def test_the_default_route_is_restored_to_the_same_gateway(clients, target):
    ops.op_route_delete_default(clients, target)
    ops.op_route_restore_default(clients, target)
    created = [kw for name, kw in clients.ec2.calls if name == "create_route"]
    assert created[0]["GatewayId"] == "igw-123"


def test_restoring_a_route_without_having_deleted_one_is_an_error(clients, target):
    """Silently doing nothing would leave a scenario believing it had cleaned up."""
    with pytest.raises(OpError, match="no saved gateway"):
        ops.op_route_restore_default(clients, target)


def test_the_role_policy_is_restored_to_its_exact_original_document(clients, target):
    original = copy.deepcopy(clients.iam.document)
    ops.op_iam_shrink_role_policy(
        clients, target, role_kind="warden_reader", remove_actions=["logs:FilterLogEvents"],
    )
    put = next(kw for n, kw in clients.iam.calls if n == "put_role_policy")
    shrunk = json.loads(put["PolicyDocument"])
    assert "logs:FilterLogEvents" not in shrunk["Statement"][0]["Action"]
    assert "ecs:DescribeServices" in shrunk["Statement"][0]["Action"], "only the named action goes"

    ops.op_iam_restore_role_policy(clients, target)
    restored = json.loads([kw for n, kw in clients.iam.calls if n == "put_role_policy"][-1]["PolicyDocument"])
    assert restored == original


def test_restoring_a_policy_that_was_never_saved_is_an_error(clients, target):
    with pytest.raises(OpError, match="no saved role policy"):
        ops.op_iam_restore_role_policy(clients, target)


def test_stopping_a_task_when_none_are_running_is_an_error_not_a_pass(clients, target):
    """If the service was already broken, the scenario did not inject its fault and must not be
    scored as though it had."""
    clients.ecs.task_arns = []
    with pytest.raises(OpError, match="no running task"):
        ops.op_ecs_stop_one_task(clients, target)


# --------------------------------------------------------------------------- dispatch


def test_run_steps_executes_in_order_and_records_what_it_did(clients, target):
    performed = run_steps(
        clients, target,
        [{"op": "sg_revoke_all_egress"}, {"op": "ecs_force_new_deployment"}],
        account=ACCOUNT,
    )
    assert [p["op"] for p in performed] == ["sg_revoke_all_egress", "ecs_force_new_deployment"]
    assert performed[0]["result"]["revoked_rules"] == 1


def test_an_unknown_op_is_refused_before_anything_is_touched(clients, target):
    with pytest.raises(OpError, match="unknown op"):
        run_steps(clients, target, [{"op": "delete_everything"}], account=ACCOUNT)
    assert clients.ecs.calls == []


# Which injector module owns a catalog, keyed by the `service:` the catalog declares.
#
# ⛔ RESOLVED PER WAVE, NOT "ANYWHERE". Checking a name against both registries at once would let an
# ECS scenario reference `k8s_scale` and still pass - the check would confirm the string exists
# somewhere rather than that the wave can actually run it. Each catalog is validated against the
# registry that will really dispatch it, so a typo in either wave still surfaces here rather than
# halfway through a live run.
def _registry_for(service: str):
    from scenarios import ops_k8s

    return {"ecs": (ops.OPS, ops._VARIANTS), "k8s": (ops_k8s.OPS, ops_k8s._VARIANTS)}.get(service)


def _catalogs():
    import yaml

    root = pathlib.Path(__file__).resolve().parents[1]
    catalog = root / "scenarios" / "catalog"
    if not catalog.exists():
        pytest.skip("no catalog in this checkout")
    for path in sorted(catalog.glob("*.yaml")):
        yield path, yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def test_every_catalog_declares_a_service_with_an_injector():
    """A catalog whose `service:` nothing owns would silently skip both checks below."""
    orphans = [
        f"{path.name}: service={doc.get('service')!r}"
        for path, doc in _catalogs() if _registry_for(str(doc.get("service") or "")) is None
    ]
    assert not orphans, f"catalogs with no injector module: {orphans}"


def test_every_op_named_in_the_catalog_exists():
    """A typo in a scenario's YAML would otherwise surface halfway through a live run."""
    missing: list[str] = []
    for path, doc in _catalogs():
        registry = _registry_for(str(doc.get("service") or ""))
        if registry is None:
            continue  # reported by the test above
        for scenario in doc.get("scenarios") or []:
            for step in (scenario.get("inject") or []) + (scenario.get("revert") or []):
                if step.get("op") not in registry[0]:
                    missing.append(f"{path.name}/{scenario['id']}: {step.get('op')}")
    assert not missing, f"scenarios referencing ops their wave cannot run: {missing}"


def test_every_variant_named_in_the_catalog_exists():
    missing: list[str] = []
    for path, doc in _catalogs():
        registry = _registry_for(str(doc.get("service") or ""))
        if registry is None:
            continue
        for scenario in doc.get("scenarios") or []:
            for step in (scenario.get("inject") or []) + (scenario.get("revert") or []):
                variant = step.get("variant")
                if variant is not None and variant not in registry[1]:
                    missing.append(f"{path.name}/{scenario['id']}: {variant}")
    assert not missing, f"scenarios referencing variants their wave does not define: {missing}"


# --------------------------------------------------------------------------- leaving nothing behind
#
# ⛔ Everything the injector creates must carry the project tag. Terraform does not know about these
# resources, and until 2026-09-11 nothing tagged them - so the teardown sweep, which reports "0 tagged
# resources remaining", could not see them and would have declared the account clean with one
# task-definition revision per scenario per wave still in it.


def test_a_registered_variant_is_tagged_so_teardown_can_find_it(clients, target):
    ops.op_ecs_deploy_variant(clients, target, variant="oom", account=ACCOUNT)
    tags = clients.ecs.registered[-1].get("tags") or []
    assert {"key": "Project", "value": "warden-proving-ground"} in tags


def test_the_recreated_log_group_is_tagged_so_teardown_can_find_it(clients, target):
    ops.op_logs_create_group(clients, target, log_group="/ecs/checkout")
    created = [kw for name, kw in clients.logs.calls if name == "create_log_group"]
    assert created and created[-1].get("tags") == {"Project": "warden-proving-ground"}
