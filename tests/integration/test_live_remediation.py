"""The LIVE remediation backend against a REAL cluster. Skipped unless opted in; fails (not skips)
if opted in and no cluster is reachable.

    WARDEN_K8S_INTEGRATION=1 pytest tests/integration/test_live_remediation.py -q

It is self-contained: it creates its own throwaway Deployment, so it cannot disturb the read-path
integration tests (which operate on `checkout`). It proves the one thing the unit tests cannot — that
`patch_namespaced_deployment` against a real API server actually changes the running Deployment:
a scale_up raises the replica count, and a restart stamps the rollout annotation. Cleans up after.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("WARDEN_K8S_INTEGRATION") != "1",
    reason="set WARDEN_K8S_INTEGRATION=1 with a reachable cluster",
)

kubernetes = pytest.importorskip("kubernetes", reason="pip install -e '.[k8s]'")

from warden.models import ActionKind
from warden.remediation import RemediationError
from warden.remediation_k8s import KubernetesRemediationBackend

NS = "default"
NAME = "warden-rem-target"


def _admin():
    from kubernetes import client, config

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.AppsV1Api()


@pytest.fixture(scope="module")
def apps():
    try:
        return _admin()
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"WARDEN_K8S_INTEGRATION=1 but no cluster is reachable: {exc}")


@pytest.fixture(scope="module")
def target(apps):
    """A 1-replica throwaway Deployment (the `pause` image needs no network). Deleted at teardown."""
    body = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": NAME, "labels": {"app": NAME}},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": NAME}},
            "template": {
                "metadata": {"labels": {"app": NAME}},
                "spec": {"containers": [{
                    "name": "pause",
                    "image": "registry.k8s.io/pause:3.9",
                }]},
            },
        },
    }
    try:
        apps.create_namespaced_deployment(NS, body)
    except kubernetes.client.ApiException as exc:
        if exc.status != 409:  # already exists from a prior run
            raise
    yield NAME
    try:
        apps.delete_namespaced_deployment(NAME, NS)
    except kubernetes.client.ApiException:
        pass


def test_scale_up_actually_raises_replicas_on_the_real_deployment(apps, target):
    before = apps.read_namespaced_deployment(NAME, NS).spec.replicas or 1
    backend = KubernetesRemediationBackend(apps=apps, namespace=NS)
    msg = backend.apply(ActionKind.scale_up, NAME, "staging")
    after = apps.read_namespaced_deployment(NAME, NS).spec.replicas
    assert after == before + 1, f"scale_up did not change the cluster: {msg}"


def test_restart_actually_stamps_the_rollout_annotation(apps, target):
    backend = KubernetesRemediationBackend(apps=apps, namespace=NS)
    backend.apply(ActionKind.restart_pods, NAME, "staging")
    dep = apps.read_namespaced_deployment(NAME, NS)
    anns = dep.spec.template.metadata.annotations or {}
    assert "kubectl.kubernetes.io/restartedAt" in anns, "restart did not stamp the template"


def test_it_refuses_a_rollback_against_a_real_cluster_too(apps, target):
    backend = KubernetesRemediationBackend(apps=apps, namespace=NS)
    with pytest.raises(RemediationError):
        backend.apply(ActionKind.rollback_deploy, NAME, "staging")
