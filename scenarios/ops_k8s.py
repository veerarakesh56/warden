"""Fault injection for the KUBERNETES proving ground - Wave 2.

The same rules as `ops.py`, restated because they are the rules, not preferences:

  1. ⛔ NOTHING OUTSIDE THE PROVING GROUND. Every op guards on the namespace carrying
     `project=warden-proving-ground` before it touches anything. `default` in somebody's cluster is
     one typo away from a scenario id, and a benchmark that breaks a real workload is an incident.
  2. ⛔ EVERY INJECT HAS A REVERT, and the revert restores what was SAVED rather than what the code
     assumes was there. `tests/test_no_scenario_leakage.py` fails a catalog entry that breaks
     something without saying how to put it back.
  3. ⛔ THE FAULT MUST BE REAL. These ops change an image, a command, a probe, a replica count or an
     RBAC rule, and then the kubelet, the scheduler and the kernel produce the symptoms. Nothing
     here writes a log line that says "OOMKilled" - the OOM is a real kernel kill of a real process
     that really allocated the memory.
  4. ⛔ THIS MODULE MUST NOT IMPORT `warden`. The tool under test and the thing that breaks it stay
     separate, so a scenario can never be tuned against the tool's internals.

⚠ WHAT WAVE 2 CAN AND CANNOT MEASURE, decided by what `k8s_backend.py` actually reads (pods, pod
logs, namespaced events, the Deployment and its ReplicaSets):

  measurable  OOM kills, CrashLoopBackOff, ImagePullBackOff, failing probes, restart counts,
              replicas scaled to zero, a pod deleted out from under the Deployment, and an
              image-visible rollout
  NOT         CPU starvation - the backend reads `memory_limit_mib` and no CPU figure at all, so a
              throttled container is invisible to it; and anything network-policy shaped, which it
              never reads. Writing scenarios for those would be writing questions the evidence
              cannot answer, and they are left out rather than scored as model failures.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .ops import OpError

# Kubernetes labels are lowercase/DNS-shaped, so the ECS tag ("Project") becomes this. Same meaning,
# same job: the one check that must never be relaxed for convenience.
PROJECT_LABEL = ("project", "warden-proving-ground")


@dataclass
class Target:
    """Everything the Kubernetes ops need to find the proving ground.

    Deliberately a different type from `ops.Target`: a namespace is not a cluster, a Deployment is
    not a service, and one dataclass carrying both would invite an ECS op to run against a k8s
    target with half its fields empty.
    """

    context: str                 # kubeconfig context - which cluster this is
    namespace: str
    deployment: str
    container: str
    baseline_image: str
    # The ServiceAccount WARDEN reads as, and the ClusterRole that grants it exactly five reads.
    # One scenario removes a verb from that role, which only measures anything because WARDEN really
    # runs as this identity rather than as the operator's kubeconfig.
    service_account: str = "warden"
    cluster_role: str = "warden-readonly"
    # Populated by ops that must remember what they replaced, so revert is exact rather than
    # reconstructed from assumptions.
    saved: dict[str, Any] = field(default_factory=dict)


@dataclass
class Clients:
    core: Any    # kubernetes.client.CoreV1Api
    apps: Any    # kubernetes.client.AppsV1Api
    rbac: Any    # kubernetes.client.RbacAuthorizationV1Api


# --------------------------------------------------------------------------- safety


def _guard_namespace(clients: Clients, target: Target) -> None:
    """Refuse to operate on any namespace that is not the proving ground.

    ⛔ Never relax this. The label is applied by the proving-ground manifest; an unlabelled
    namespace is, by definition, not ours to break - and unlike an ECS cluster name, `default` is a
    namespace that exists in every cluster on earth.
    """
    try:
        ns = clients.core.read_namespace(name=target.namespace)
    except Exception as exc:  # any failure here means "do not touch it"
        raise OpError(f"cannot read namespace {target.namespace!r}: {type(exc).__name__}") from exc
    # ⛔ Through _to_dict, because a namespace arrives as a model OR as a plain dict depending on the
    # client call. An earlier version read `ns.metadata.labels` by attribute, which is None for a
    # dict - so the guard refused EVERY namespace, including the proving ground. It looked like the
    # safest possible bug and it was still a bug: a guard that refuses everything is a guard nobody
    # has actually tested, and its test passed while the label check did nothing.
    labels = dict((_to_dict(ns).get("metadata") or {}).get("labels") or {})
    key, value = PROJECT_LABEL
    if labels.get(key) != value:
        raise OpError(
            f"namespace {target.namespace!r} is not labelled {key}={value}. This harness only "
            "breaks the proving ground. Refusing."
        )


# --------------------------------------------------------------------------- the fault variants
#
# Each variant is a real container spec that fails in one specific, honest way. The programs are
# written out in full rather than assembled, so a reader can see that the OOM scenario really
# allocates memory instead of printing the word "OOM".

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
    "blob = bytearray(900*1024*1024)\n"
    "print('unreachable', flush=True)\n"
)
_SRC_EXIT_ONE = (
    "import sys\n"
    "print('checkout: fatal: configuration invalid', flush=True)\n"
    "sys.exit(1)\n"
)

_COMMANDS: dict[str, list[str]] = {
    "healthy": ["python", "-u", "-c", _SRC_HEALTHY],
    "oom": ["python", "-u", "-c", _SRC_OOM],
    "exit_one": ["python", "-u", "-c", _SRC_EXIT_ONE],
}

# (image tag override or None to keep the baseline image, command key, extra container patch)
_VARIANTS: dict[str, dict[str, Any]] = {
    # Allocates 900 MiB against a 48 MiB limit. The kernel does the rest, and the kubelet records
    # lastState.terminated.reason=OOMKilled, which is exactly what the backend reads.
    "oom": {
        "image_tag": "3.12.7-alpine",
        "command_key": "oom",
    },
    # ⭐ The pair to `oom`, and the reason both exist. Same IMAGE as the baseline; only the command
    # changes. `k8s_backend.deploys()` compares IMAGES between ReplicaSets, so it reports NO DEPLOY
    # for a rollout that really happened - the same blind spot the ECS backend has, on a second
    # backend. That is the measurement, not a trick played on the tool.
    "oom_same_image": {
        "image_tag": None,
        "command_key": "oom",
    },
    # A tag that does not exist: ImagePullBackOff. The pod never starts and never logs, so the only
    # evidence is events and the ready/total pod counts.
    "bad_image": {
        "image_tag": "this-tag-does-not-exist-9x8y7z",
        "command_key": "healthy",
    },
    # Exits non-zero immediately: CrashLoopBackOff, which the backend surfaces as
    # `crashloop_containers` plus a BackOff event.
    "exit_one": {
        "image_tag": "3.12.7-alpine",
        "command_key": "exit_one",
    },
    # The container is healthy; its liveness probe is not. The kubelet kills and restarts it, so the
    # symptom is a rising restart_count and Unhealthy events - with the process itself blameless.
    "bad_probe": {
        "image_tag": "3.12.7-alpine",
        "command_key": "healthy",
        "liveness_probe": {
            "exec": {"command": ["sh", "-c", "exit 1"]},
            "initialDelaySeconds": 5,
            "periodSeconds": 5,
            "failureThreshold": 1,
        },
    },
}


def _container_index(spec: Any, name: str) -> int:
    containers = spec["template"]["spec"]["containers"]
    for i, c in enumerate(containers):
        if c.get("name") == name:
            return i
    raise OpError(f"container {name!r} not found in deployment spec")


def _read_deployment(clients: Clients, target: Target) -> dict:
    try:
        dep = clients.apps.read_namespaced_deployment(
            name=target.deployment, namespace=target.namespace, _preload_content=False,
        )
    except TypeError:  # a fake client in tests, or an older client signature
        dep = clients.apps.read_namespaced_deployment(
            name=target.deployment, namespace=target.namespace,
        )
    return dep if isinstance(dep, dict) else _to_dict(dep)


def _to_dict(obj: Any) -> dict:
    """Kubernetes models carry `to_dict()`; a raw response carries `.data`. Both appear in practice,
    and so does a plain dict - from `_preload_content=False` and from the test fakes."""
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    data = getattr(obj, "data", None)
    if data is not None:
        import json

        return json.loads(data)
    raise OpError(f"cannot read a deployment out of {type(obj).__name__}")


# --------------------------------------------------------------------------- the ops


def op_k8s_patch_variant(clients: Clients, target: Target, *, variant: str, account: str = "",
                         **_: Any) -> dict:
    """Patch the deployment's container into one of the variants above.

    The baseline container spec is SAVED on first use, so the revert restores what was actually
    there rather than what this module believes the baseline to be.
    """
    spec = _VARIANTS.get(variant)
    if spec is None:
        raise OpError(f"unknown variant {variant!r}. Known: {sorted(_VARIANTS)}")
    _guard_namespace(clients, target)

    dep = _read_deployment(clients, target)
    containers = dep["spec"]["template"]["spec"]["containers"]
    index = _container_index(dep["spec"], target.container)
    if "container" not in target.saved:
        target.saved["container"] = copy.deepcopy(containers[index])

    container = copy.deepcopy(target.saved["container"])
    if spec.get("image_tag"):
        container["image"] = f"{target.baseline_image.rsplit(':', 1)[0]}:{spec['image_tag']}"
    container["command"] = list(_COMMANDS[spec["command_key"]])
    # Explicitly cleared, not left behind: a probe from a previous variant would attribute the next
    # scenario's restarts to the wrong fault.
    container.pop("livenessProbe", None)
    if spec.get("liveness_probe"):
        container["livenessProbe"] = copy.deepcopy(spec["liveness_probe"])

    patch = {"spec": {"template": {"spec": {"containers": [container]}}}}
    clients.apps.patch_namespaced_deployment(
        name=target.deployment, namespace=target.namespace, body=patch,
    )
    return {"variant": variant, "image": container["image"],
            "command": container["command"][:3] + ["<program>"]}


def op_k8s_restore_baseline(clients: Clients, target: Target, *, account: str = "",
                            **_: Any) -> dict:
    """Put the container back exactly as it was saved. Refuses if nothing was saved."""
    _guard_namespace(clients, target)
    saved = target.saved.get("container")
    if saved is None:
        raise OpError("no saved container spec - refusing to guess what the baseline was")
    patch = {"spec": {"template": {"spec": {"containers": [copy.deepcopy(saved)]}}}}
    clients.apps.patch_namespaced_deployment(
        name=target.deployment, namespace=target.namespace, body=patch,
    )
    return {"restored": saved.get("image")}


def op_k8s_scale(clients: Clients, target: Target, *, replicas: int, account: str = "",
                 **_: Any) -> dict:
    """Set the replica count. `replicas: 0` is the scaled-to-zero scenario."""
    _guard_namespace(clients, target)
    clients.apps.patch_namespaced_deployment_scale(
        name=target.deployment, namespace=target.namespace,
        body={"spec": {"replicas": int(replicas)}},
    )
    return {"replicas": int(replicas)}


def op_k8s_delete_one_pod(clients: Clients, target: Target, *, account: str = "", **_: Any) -> dict:
    """Delete one running pod out from under the Deployment - the eviction/reclaim analogue.

    Kubernetes replaces it by itself, which is why the correct answer to this scenario is to do
    nothing. No revert is needed, and the catalog says so.
    """
    _guard_namespace(clients, target)
    selector = f"app={target.deployment}"
    # ⛔ Through _to_dict, never `getattr(pods, "items", ...)`. On a DICT that getattr returns the
    # built-in `dict.items` METHOD, which is truthy - so the pod list was never read, the "no pods"
    # check below could never fire, and the op failed on a type error instead of refusing cleanly.
    pods = _to_dict(clients.core.list_namespaced_pod(
        namespace=target.namespace, label_selector=selector,
    ))
    names = [
        name for name in (
            (_to_dict(p).get("metadata") or {}).get("name") for p in (pods.get("items") or [])
        ) if name
    ]
    if not names:
        raise OpError(f"no pods match {selector!r} - nothing to stop, so nothing to measure")
    victim = min(names)
    clients.core.delete_namespaced_pod(name=victim, namespace=target.namespace)
    return {"deleted_pod": victim, "of": len(names)}


def op_k8s_rollout_restart(clients: Clients, target: Target, *, account: str = "",
                           **_: Any) -> dict:
    """Force new pods with no spec change - the k8s `rollout restart`.

    ⚠ Deliberately NOT a deploy as far as WARDEN is concerned: the images are identical, so
    `deploys()` reports nothing. Used where a scenario needs new pods without handing the tool a
    rollback to reach for.
    """
    _guard_namespace(clients, target)
    stamp = {"spec": {"template": {"metadata": {"annotations": {
        "warden-bench/restartedAt": _now(),
    }}}}}
    clients.apps.patch_namespaced_deployment(
        name=target.deployment, namespace=target.namespace, body=stamp,
    )
    return {"restarted": target.deployment}


def op_k8s_revoke_log_access(clients: Clients, target: Target, *, account: str = "",
                             **_: Any) -> dict:
    """Remove `pods/log` from the ClusterRole WARDEN reads as.

    ⭐ The scenario that bites the tool itself: WARDEN keeps its pod and event access, so it can
    still see that something is wrong, and loses the container logs that would say what. The right
    answer is to escalate, and the wrong one is to answer confidently from half the evidence.
    """
    _guard_namespace(clients, target)
    role = clients.rbac.read_cluster_role(name=target.cluster_role)
    rules = _to_dict(role).get("rules") or []
    if "rules" not in target.saved:
        target.saved["rules"] = copy.deepcopy(rules)
    kept = [
        r for r in rules
        if "pods/log" not in (r.get("resources") or [])
    ]
    if len(kept) == len(rules):
        raise OpError(
            f"ClusterRole {target.cluster_role!r} does not grant pods/log, so removing it would "
            "measure nothing - refusing rather than reporting a fault that was never injected"
        )
    clients.rbac.patch_cluster_role(name=target.cluster_role, body={"rules": kept})
    return {"removed": "pods/log", "rules_before": len(rules), "rules_after": len(kept)}


def op_k8s_restore_log_access(clients: Clients, target: Target, *, account: str = "",
                              **_: Any) -> dict:
    _guard_namespace(clients, target)
    saved = target.saved.get("rules")
    if saved is None:
        raise OpError("no saved ClusterRole rules - refusing to guess what they were")
    clients.rbac.patch_cluster_role(name=target.cluster_role, body={"rules": copy.deepcopy(saved)})
    return {"restored_rules": len(saved)}


def _now() -> str:
    import datetime as dt

    return dt.datetime.now(dt.UTC).isoformat()


# ⛔ The registry a catalog's `op:` names are looked up in. `ops.run_steps(..., registry=OPS)`
# dispatches through it, so the performed-record and the unknown-op error stay in one place.
OPS: dict[str, Callable[..., dict]] = {
    "k8s_patch_variant": op_k8s_patch_variant,
    "k8s_restore_baseline": op_k8s_restore_baseline,
    "k8s_scale": op_k8s_scale,
    "k8s_delete_one_pod": op_k8s_delete_one_pod,
    "k8s_rollout_restart": op_k8s_rollout_restart,
    "k8s_revoke_log_access": op_k8s_revoke_log_access,
    "k8s_restore_log_access": op_k8s_restore_log_access,
}
