"""The Kubernetes harness: the gate, the identity, and which registry dispatches.

⛔ The one that matters most is `test_warden_is_given_a_kubeconfig_and_no_aws_credentials`. Wave 2's
whole claim is that WARDEN read a cluster as a ServiceAccount with five verbs. If an AWS credential
leaked into its environment, scenario k8s-09 would revoke a permission nobody was using and pass
while proving nothing - the identical trap Wave 1's IAM scenario documents.
"""

from __future__ import annotations

import pytest
from scenarios import ops, ops_k8s, runner

BASELINE_IMAGE = "public.ecr.aws/docker/library/python:3.12-alpine"
FULL_RULES = [
    {"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]},
    {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]},
    {"apiGroups": [""], "resources": ["events"], "verbs": ["list"]},
]


class FakeK8s:
    """One fake standing in for core, apps and rbac, as the dry harness does."""

    def __init__(self, *, deployment=None, rules=None, raises=None):
        self._deployment = deployment if deployment is not None else _deployment()
        self._rules = FULL_RULES if rules is None else rules
        self._raises = raises

    def read_namespace(self, **_kw):
        return {"metadata": {"labels": {"project": "warden-proving-ground"}}}

    def read_namespaced_deployment(self, **_kw):
        if self._raises:
            raise self._raises
        return self._deployment

    def read_cluster_role(self, **_kw):
        return {"rules": [dict(r) for r in self._rules]}


def _deployment(*, replicas=2, ready=2, updated=2, unavailable=0, image=BASELINE_IMAGE,
                probe=None, name="checkout"):
    container = {"name": name, "image": image, "command": ["python", "-u", "-c", "x"]}
    if probe:
        container["livenessProbe"] = probe
    return {
        "spec": {"replicas": replicas,
                 "template": {"spec": {"containers": [container]}}},
        "status": {"readyReplicas": ready, "updatedReplicas": updated,
                   "unavailableReplicas": unavailable},
    }


def _target(**kw):
    base = dict(context="k3d-x", namespace="warden-pg", deployment="checkout",
                container="checkout", baseline_image=BASELINE_IMAGE)
    base.update(kw)
    return ops_k8s.Target(**base)


def _clients(fake):
    return ops_k8s.Clients(core=fake, apps=fake, rbac=fake)


# --------------------------------------------------------------------------- the baseline gate


def test_a_healthy_deployment_has_no_baseline_problems():
    assert runner.check_baseline_k8s(_clients(FakeK8s()), _target()) == []


def test_the_dry_harness_runs_the_real_gate_rather_than_skipping_it():
    """⭐ Unlike the ECS dry harness, this one exercises check_baseline_k8s - new code that decides
    whether a scenario may start. Skipping it here would leave it first tried on a billed cluster."""
    assert runner._k8s_dry_harness().baseline() == []


@pytest.mark.parametrize("deployment,expected", [
    (_deployment(replicas=1), "replicas is 1"),
    (_deployment(ready=1), "ready replicas is 1"),
    (_deployment(updated=1), "updated replicas is 1"),
    (_deployment(unavailable=1), "rollout in flight"),
    (_deployment(image="repo/checkout:variant-9"), "baseline is"),
    (_deployment(probe={"exec": {"command": ["false"]}}), "livenessProbe is still set"),
    (_deployment(name="something-else"), "is missing from the pod template"),
])
def test_the_gate_catches_a_cluster_that_is_not_back_at_baseline(deployment, expected):
    """Each of these would otherwise let the next scenario measure state nobody injected - the exact
    failure the ECS gate was written for after a scenario read its predecessor's rollout."""
    problems = runner.check_baseline_k8s(_clients(FakeK8s(deployment=deployment)), _target())
    assert any(expected in p for p in problems), problems


def test_a_revoked_rbac_rule_stops_the_next_scenario():
    """k8s-09 strips pods/log. If the revert failed, every later scenario would look like the tool
    had gone blind on its own."""
    rules = [r for r in FULL_RULES if "pods/log" not in r["resources"]]
    problems = runner.check_baseline_k8s(_clients(FakeK8s(rules=rules)), _target())
    assert any("no longer grants pods/log" in p for p in problems), problems


def test_an_unreadable_deployment_stops_the_wave_rather_than_passing():
    problems = runner.check_baseline_k8s(
        _clients(FakeK8s(raises=RuntimeError("connection refused"))), _target())
    assert problems and "cannot read deployment" in problems[0]


# --------------------------------------------------------------------------- the identity


def test_warden_is_given_a_kubeconfig_and_no_aws_credentials():
    """⛔ Load-bearing for every Wave 2 number. WARDEN must read the cluster as the constrained
    ServiceAccount, not as whoever ran the benchmark."""
    env = runner.k8s_warden_env({"KUBECONFIG": "/tmp/kubeconfig"}, _target(), {})

    assert env["KUBECONFIG"] == "/tmp/kubeconfig"
    assert env["WARDEN_BACKEND"] == "k8s"
    assert env["WARDEN_K8S_NAMESPACE"] == "warden-pg"
    leaked = sorted(k for k in env if k.startswith("AWS_"))
    assert not leaked, f"AWS credentials must not reach a Kubernetes wave: {leaked}"


def test_the_arm_can_still_set_the_model_but_not_smuggle_a_backend():
    env = runner.k8s_warden_env({"KUBECONFIG": "/x"}, _target(), {"WARDEN_MODEL": "sonnet"})
    assert env["WARDEN_MODEL"] == "sonnet"
    assert env["WARDEN_BACKEND"] == "k8s"


# --------------------------------------------------------------------------- which backend is this


def test_describe_target_names_the_backend_and_its_environment():
    """One definition, used by BOTH the manifest and the resume guard - they previously read
    `target.cluster`, an ECS field, so a Kubernetes wave crashed writing its manifest and a
    Kubernetes resume would have skipped the same-environment check entirely."""
    k8s = runner.describe_target(_target())
    assert k8s == {"target_kind": "k8s", "context": "k3d-x", "namespace": "warden-pg",
                   "deployment": "checkout"}

    ecs = runner.describe_target(ops.Target(
        region="ap-south-2", cluster="warden-pg-1", service="checkout",
        log_group="/ecs/checkout", baseline_task_definition="arn:...:checkout:2"))
    assert ecs["target_kind"] == "ecs" and ecs["cluster"] == "warden-pg-1"


# --------------------------------------------------------------------------- which ops dispatch


def test_a_kubernetes_harness_dispatches_kubernetes_ops():
    """The wave loop must not import one backend's registry directly: it did, and every Wave 2
    scenario failed with "unknown op 'k8s_restore_baseline'" against the ECS table."""
    assert runner._k8s_dry_harness().registry is ops_k8s.OPS


def test_the_default_registry_is_still_the_ecs_one():
    """Wave 1 must be unaffected by Wave 2 existing."""
    assert runner._dry_harness().registry is ops.OPS
