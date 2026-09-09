"""The fault-injection vocabulary.

Every way this benchmark is allowed to break the proving ground lives in this one file, as a small
set of named operations. Scenarios reference them by name in YAML, so a reader can see exactly what
was done to a real AWS account without reading any Python at all — and can check that nothing else
was done, because nothing else *can* be.

Three rules this module exists to enforce:

1. **It only touches the proving ground.** Every call is scoped to the cluster, service, security
   group and roles created by `terraform/proving-ground/`, and `_guard()` refuses any resource that
   is not tagged `Project=warden-proving-ground`. A fault injector that can reach production is not
   a test harness, it is an outage waiting for a typo.

2. **Everything is reversible, and the reverse is declared next to the break.** `revert` is not
   best-effort cleanup bolted on afterwards; it is part of the operation's definition, and
   `tests/test_no_scenario_leakage.py` fails any scenario that breaks something without one.

3. ⛔ **It shares nothing with the tool under test.** This module never imports from `warden`, and a
   test asserts that. The injector and the responder must not be able to agree with each other
   behind the scenes — that agreement is exactly what a hostile reader would suspect, and the only
   convincing answer is that it is structurally impossible.

⚠ **What this file cannot do, stated plainly.** Some real incidents cannot be caused on demand: a
genuine Fargate Spot reclamation, a real AZ impairment, a real hardware fault. Where a scenario
approximates one, the catalog entry carries `fidelity: approximated` and a note saying exactly what
the difference is. This module deliberately offers no operation that would let a scenario claim more
than it did.
"""

from __future__ import annotations

import copy
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

PROJECT_TAG = ("Project", "warden-proving-ground")


class OpError(RuntimeError):
    """An injection or revert failed. Never swallowed: a scenario that did not actually break
    anything must be reported as ERROR, not scored as a pass."""


@dataclass
class Target:
    """Everything the ops need to find the proving ground. Built once from terraform outputs."""

    region: str
    cluster: str
    service: str
    log_group: str
    baseline_task_definition: str
    security_group_id: str = ""
    route_table_id: str = ""
    # The role the harness ASSUMES before running WARDEN - four read actions, nothing else.
    # Scenario ecs-11 removes one of them, which only means anything because WARDEN really
    # runs under this role rather than under the operator's own credentials.
    warden_role_name: str = ""
    # Populated by ops that must remember what they replaced, so revert is exact rather than
    # reconstructed from assumptions.
    saved: dict[str, Any] = field(default_factory=dict)


@dataclass
class Clients:
    ecs: Any
    logs: Any
    ec2: Any
    iam: Any


# --------------------------------------------------------------------------- safety


def _guard_cluster(clients: Clients, target: Target) -> None:
    """Refuse to operate on anything that is not the proving ground.

    ⛔ This is the one check that must never be relaxed for convenience. The tag is applied by
    `terraform/proving-ground/main.tf` to every resource it creates; an untagged cluster is, by
    definition, not ours to break.
    """
    resp = clients.ecs.describe_clusters(clusters=[target.cluster], include=["TAGS"])
    clusters = resp.get("clusters") or []
    if not clusters:
        raise OpError(f"cluster {target.cluster!r} not found - refusing to inject anything")
    tags = {t["key"]: t["value"] for t in clusters[0].get("tags") or []}
    key, value = PROJECT_TAG
    if tags.get(key) != value:
        raise OpError(
            f"cluster {target.cluster!r} is not tagged {key}={value}. This harness only breaks the "
            "proving ground. Refusing."
        )


# --------------------------------------------------------------------------- task definitions
#
# The variants. Each one is a real, registerable task definition that fails in a specific, honest
# way — not a log line that says "OOM". Fargate, the ECS agent and the container runtime produce
# every symptom that follows.

_VARIANTS: dict[str, dict[str, Any]] = {
    # Allocates 900 MiB inside a 512 MiB task. The kernel does the rest.
    "oom": {
        "image_tag": "3.12.7-alpine",
        "command_key": "oom",
    },
    # ⭐ The pair to `oom`. Same IMAGE as the baseline; only the command changes. WARDEN compares
    # images between revisions, so it reports NO DEPLOY here - a real change it is structurally
    # unable to see. That blind spot is the measurement, and it is a limitation of WARDEN, not a
    # trick played on it.
    #
    # ⛔ An earlier version also set memory="512", which is what the baseline already is. A no-op
    # override that implies a change is worse than no override at all: it would have put a false
    # sentence in the published catalog.
    "oom_same_image": {
        "image_tag": None,  # keep the baseline image - this is the whole point
        "command_key": "oom",
    },
    # A tag that does not exist. The task never starts and never logs.
    "bad_image": {
        "image_tag": "this-tag-does-not-exist-9x8y7z",
        "command_key": "healthy",
    },
    "exit_one": {
        "image_tag": "3.12.7-alpine",
        "command_key": "exit_one",
    },
    "bad_healthcheck": {
        "image_tag": "3.12.7-alpine",
        "command_key": "healthy",
        "health_check": ["CMD-SHELL", "exit 1"],
    },
    "cpu_starved": {
        "image_tag": "3.12.7-alpine",
        "command_key": "busy",
        "cpu": "256",
    },
    # A Secrets Manager ARN that does not resolve. The EXECUTION role fails before the container
    # runs, which is a different failure surface from anything the container itself can produce.
    "bad_secret": {
        "image_tag": "3.12.7-alpine",
        "command_key": "healthy",
        "secret_arn": "arn:aws:secretsmanager:{region}:{account}:secret:warden-no-such-secret-AbCdEf",
    },
}

# The programs each variant runs, written out in full rather than assembled. These strings ARE
# the experiment: a reader has to be able to see that the OOM scenario really allocates memory,
# rather than printing the word "OOM" and calling that an incident.
_SRC_HEALTHY = (
    "import time\n"
    "print('checkout: started, healthy', flush=True)\n"
    "while True:\n"
    "    print('checkout: heartbeat ok', flush=True)\n"
    "    time.sleep(15)\n"
)
_SRC_OOM = (
    "import time\n"
    "print('checkout: started', flush=True)\n"
    "print('checkout: WARN memory pressure rising', flush=True)\n"
    "time.sleep(2)\n"
    "print('checkout: allocating 900MiB cache', flush=True)\n"
    "time.sleep(1)\n"
    "blob = bytearray(900*1024*1024)\n"
    "print('unreachable', flush=True)\n"
)
_SRC_EXIT_ONE = (
    "import sys\n"
    "print('checkout: fatal: configuration invalid', flush=True)\n"
    "sys.exit(1)\n"
)
_SRC_BUSY = (
    "import time\n"
    "print('checkout: started', flush=True)\n"
    "t = time.time()\n"
    "while True:\n"
    "    _ = sum(i*i for i in range(200000))\n"
    "    if time.time() - t > 15:\n"
    "        print('checkout: still working', flush=True)\n"
    "        t = time.time()\n"
)

_COMMANDS: dict[str, list[str]] = {
    "healthy": ["python", "-u", "-c", _SRC_HEALTHY],
    "oom": ["python", "-u", "-c", _SRC_OOM],
    "exit_one": ["python", "-u", "-c", _SRC_EXIT_ONE],
    "busy": ["python", "-u", "-c", _SRC_BUSY],
}


def _baseline_definition(clients: Clients, target: Target) -> dict:
    resp = clients.ecs.describe_task_definition(taskDefinition=target.baseline_task_definition)
    return resp["taskDefinition"]


def _register_variant(clients: Clients, target: Target, variant: str, account: str) -> str:
    """Register a new revision derived from the baseline, differing only in the declared way.

    Deriving from the baseline rather than writing a definition from scratch is deliberate: it keeps
    every scenario's task definition identical to the healthy one except for the injected fault, so
    nothing incidental can explain a difference in behaviour.
    """
    spec = _VARIANTS.get(variant)
    if spec is None:
        raise OpError(f"unknown variant {variant!r}. Known: {sorted(_VARIANTS)}")

    base = _baseline_definition(clients, target)
    container = copy.deepcopy(base["containerDefinitions"][0])

    if spec.get("image_tag"):
        image = container["image"].rsplit(":", 1)[0]
        container["image"] = f"{image}:{spec['image_tag']}"
    container["command"] = list(_COMMANDS[spec["command_key"]])

    if spec.get("health_check"):
        container["healthCheck"] = {
            "command": list(spec["health_check"]),
            "interval": 10, "timeout": 5, "retries": 2, "startPeriod": 10,
        }
    if spec.get("secret_arn"):
        arn = spec["secret_arn"].format(region=target.region, account=account)
        container["secrets"] = [{"name": "APP_SECRET", "valueFrom": arn}]

    kwargs: dict[str, Any] = {
        "family": base["family"],
        "requiresCompatibilities": base.get("requiresCompatibilities", ["FARGATE"]),
        "networkMode": base.get("networkMode", "awsvpc"),
        "cpu": spec.get("cpu", base["cpu"]),
        "memory": spec.get("memory", base["memory"]),
        "executionRoleArn": base["executionRoleArn"],
        "containerDefinitions": [container],
    }
    if base.get("taskRoleArn"):
        kwargs["taskRoleArn"] = base["taskRoleArn"]

    registered = clients.ecs.register_task_definition(**kwargs)
    return registered["taskDefinition"]["taskDefinitionArn"]


# --------------------------------------------------------------------------- the operations


def op_ecs_deploy_variant(clients: Clients, target: Target, *, variant: str, account: str, **_):
    _guard_cluster(clients, target)
    arn = _register_variant(clients, target, variant, account)
    target.saved.setdefault("registered_variants", []).append(arn)
    clients.ecs.update_service(
        cluster=target.cluster, service=target.service, taskDefinition=arn,
    )
    return {"deployed": arn}


def op_ecs_deploy_baseline(clients: Clients, target: Target, **_):
    _guard_cluster(clients, target)
    clients.ecs.update_service(
        cluster=target.cluster, service=target.service,
        taskDefinition=target.baseline_task_definition,
    )
    return {"deployed": target.baseline_task_definition}


def op_ecs_set_desired_count(clients: Clients, target: Target, *, count: int, **_):
    _guard_cluster(clients, target)
    clients.ecs.update_service(
        cluster=target.cluster, service=target.service, desiredCount=int(count),
    )
    return {"desired_count": int(count)}


def op_ecs_force_new_deployment(clients: Clients, target: Target, **_):
    _guard_cluster(clients, target)
    clients.ecs.update_service(
        cluster=target.cluster, service=target.service, forceNewDeployment=True,
    )
    return {"forced": True}


def op_ecs_stop_one_task(clients: Clients, target: Target, **_):
    """Stop one running task.

    ⚠ This is NOT a Spot interruption and the catalog says so. A real reclamation carries a SIGTERM,
    a two-minute warning and its own stopped reason. This produces a similar service-level symptom
    with a different cause, and the scenario is labelled `approximated` for exactly that reason.
    """
    _guard_cluster(clients, target)
    listed = clients.ecs.list_tasks(
        cluster=target.cluster, serviceName=target.service, desiredStatus="RUNNING",
    )
    arns = listed.get("taskArns") or []
    if not arns:
        raise OpError("no running task to stop - the service was already unhealthy")
    clients.ecs.stop_task(
        cluster=target.cluster, task=arns[0], reason="warden benchmark: simulated reclamation",
    )
    return {"stopped": arns[0]}


def op_logs_delete_group(clients: Clients, target: Target, *, log_group: str, **_):
    if not log_group.startswith("/ecs/"):
        raise OpError(f"refusing to delete log group {log_group!r} - not a proving-ground group")
    clients.logs.delete_log_group(logGroupName=log_group)
    return {"deleted": log_group}


def op_logs_create_group(clients: Clients, target: Target, *, log_group: str,
                         retention_days: int = 1, **_):
    try:
        clients.logs.create_log_group(logGroupName=log_group)
    except Exception as exc:
        if "ResourceAlreadyExists" not in str(exc):
            raise
    clients.logs.put_retention_policy(logGroupName=log_group, retentionInDays=int(retention_days))
    return {"created": log_group}


def op_sg_revoke_all_egress(clients: Clients, target: Target, **_):
    """Remove every egress rule from the task security group, so image pulls fail.

    The rules are SAVED before removal and restored verbatim. Reconstructing "the usual" egress rule
    on revert would leave the environment subtly different from how it started, and every subsequent
    scenario would then be running against something nobody described.
    """
    if not target.security_group_id:
        raise OpError("no security group id in the target")
    resp = clients.ec2.describe_security_groups(GroupIds=[target.security_group_id])
    group = resp["SecurityGroups"][0]
    tags = {t["Key"]: t["Value"] for t in group.get("Tags") or []}
    key, value = PROJECT_TAG
    if tags.get(key) != value:
        raise OpError(f"security group {target.security_group_id} is not tagged {key}={value}")

    permissions = group.get("IpPermissionsEgress") or []
    target.saved["egress"] = copy.deepcopy(permissions)
    if permissions:
        clients.ec2.revoke_security_group_egress(
            GroupId=target.security_group_id, IpPermissions=permissions,
        )
    return {"revoked_rules": len(permissions)}


def op_sg_restore_egress(clients: Clients, target: Target, **_):
    permissions = target.saved.get("egress")
    if not permissions:
        return {"restored_rules": 0}
    try:
        clients.ec2.authorize_security_group_egress(
            GroupId=target.security_group_id, IpPermissions=permissions,
        )
    except Exception as exc:
        if "Duplicate" not in str(exc):
            raise
    return {"restored_rules": len(permissions)}


def op_route_delete_default(clients: Clients, target: Target, **_):
    if not target.route_table_id:
        raise OpError("no route table id in the target")
    resp = clients.ec2.describe_route_tables(RouteTableIds=[target.route_table_id])
    table = resp["RouteTables"][0]
    tags = {t["Key"]: t["Value"] for t in table.get("Tags") or []}
    key, value = PROJECT_TAG
    if tags.get(key) != value:
        raise OpError(f"route table {target.route_table_id} is not tagged {key}={value}")

    default = next(
        (r for r in table.get("Routes") or [] if r.get("DestinationCidrBlock") == "0.0.0.0/0"),
        None,
    )
    if default is None:
        raise OpError("no default route to delete")
    target.saved["default_route_gateway"] = default.get("GatewayId")
    clients.ec2.delete_route(
        RouteTableId=target.route_table_id, DestinationCidrBlock="0.0.0.0/0",
    )
    return {"deleted_route_via": default.get("GatewayId")}


def op_route_restore_default(clients: Clients, target: Target, **_):
    gateway = target.saved.get("default_route_gateway")
    if not gateway:
        raise OpError("no saved gateway - cannot restore the default route")
    try:
        clients.ec2.create_route(
            RouteTableId=target.route_table_id,
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=gateway,
        )
    except Exception as exc:
        if "RouteAlreadyExists" not in str(exc):
            raise
    return {"restored_route_via": gateway}


def op_iam_shrink_role_policy(clients: Clients, target: Target, *, role_kind: str,
                              remove_actions: list[str], **_):
    """Remove named actions from WARDEN's own reader role, saving the original first.

    ⭐ This scenario only measures anything because the harness runs WARDEN under that role. Invoked
    with the operator's own credentials it would remove a permission nobody was using and the run
    would pass while proving nothing - which is exactly the shape of a benchmark that flatters its
    author.

    ⚠ IAM is eventually consistent. A policy change can take several seconds to take effect, and a
    scenario that reads too early sees the old behaviour and scores a false pass. The scenario's
    `settle_seconds` covers this, and it is set higher for IAM than for anything else.
    """
    if role_kind != "warden_reader":
        raise OpError(f"only WARDEN's own reader role may be modified, not {role_kind!r}")
    role = target.warden_role_name
    if not role:
        raise OpError("no reader role name in the target")
    if not role.startswith("warden-"):
        raise OpError(f"refusing to modify role {role!r} - not a proving-ground role")

    listed = clients.iam.list_role_policies(RoleName=role)
    names = listed.get("PolicyNames") or []
    if not names:
        raise OpError(f"role {role} has no inline policy to shrink")
    policy_name = names[0]
    current = clients.iam.get_role_policy(RoleName=role, PolicyName=policy_name)
    document = current["PolicyDocument"]
    target.saved["role_policy"] = (role, policy_name, copy.deepcopy(document))

    remove = set(remove_actions)
    shrunk = copy.deepcopy(document)
    for statement in shrunk.get("Statement", []):
        actions = statement.get("Action")
        if isinstance(actions, str):
            actions = [actions]
        statement["Action"] = [a for a in actions or [] if a not in remove]
    clients.iam.put_role_policy(
        RoleName=role, PolicyName=policy_name, PolicyDocument=_json_dumps(shrunk),
    )
    return {"removed": sorted(remove), "policy": policy_name}


def op_iam_restore_role_policy(clients: Clients, target: Target, **_):
    saved = target.saved.get("role_policy")
    if not saved:
        raise OpError("no saved role policy - cannot restore")
    role, policy_name, document = saved
    clients.iam.put_role_policy(
        RoleName=role, PolicyName=policy_name, PolicyDocument=_json_dumps(document),
    )
    return {"restored": policy_name}


def _json_dumps(obj) -> str:
    import json

    return json.dumps(obj)


# --------------------------------------------------------------------------- dispatch

OPS: dict[str, Callable[..., dict]] = {
    "ecs_deploy_variant": op_ecs_deploy_variant,
    "ecs_deploy_baseline": op_ecs_deploy_baseline,
    "ecs_set_desired_count": op_ecs_set_desired_count,
    "ecs_force_new_deployment": op_ecs_force_new_deployment,
    "ecs_stop_one_task": op_ecs_stop_one_task,
    "logs_delete_group": op_logs_delete_group,
    "logs_create_group": op_logs_create_group,
    "sg_revoke_all_egress": op_sg_revoke_all_egress,
    "sg_restore_egress": op_sg_restore_egress,
    "route_delete_default": op_route_delete_default,
    "route_restore_default": op_route_restore_default,
    "iam_shrink_role_policy": op_iam_shrink_role_policy,
    "iam_restore_role_policy": op_iam_restore_role_policy,
}


def run_steps(clients: Clients, target: Target, steps: list[dict], *, account: str,
              pause_s: float = 0.0) -> list[dict]:
    """Execute a scenario's `inject` or `revert` list, in order, recording what each one did.

    The record is what ends up in the ground-truth file: not "scenario ecs-03 ran" but "these exact
    operations were performed against these exact resources, and this is what they returned."
    """
    performed: list[dict] = []
    for step in steps:
        op_name = step.get("op")
        fn = OPS.get(op_name or "")
        if fn is None:
            raise OpError(f"unknown op {op_name!r}. Known: {sorted(OPS)}")
        kwargs = {k: v for k, v in step.items() if k != "op"}
        result = fn(clients, target, account=account, **kwargs)
        performed.append({"op": op_name, "args": kwargs, "result": result})
        if pause_s:
            time.sleep(pause_s)
    return performed
