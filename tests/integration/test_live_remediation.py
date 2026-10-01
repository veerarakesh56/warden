"""The Kubernetes platform behind the RemediationWorkflow (decision D16) against a REAL cluster. Skipped
unless opted in; fails (not skips) if opted in and no cluster is reachable.

    WARDEN_K8S_INTEGRATION=1 pytest tests/integration/test_live_remediation.py -q

It is self-contained: it creates its own throwaway Deployment, so it cannot disturb the read-path
integration tests (which operate on `checkout`). It proves what the unit tests cannot - that against a
real API server the conditional JSON Patch is accepted and changes the running Deployment, that a count
that moved is refused with nothing changed, that a restart stamps the rollout annotation, and that a
rollback returns the count. Cleans up after.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("WARDEN_K8S_INTEGRATION") != "1",
    reason="set WARDEN_K8S_INTEGRATION=1 with a reachable cluster",
)

kubernetes = pytest.importorskip("kubernetes", reason="pip install -e '.[k8s]'")

from warden.platforms.k8s import RESTARTED_AT, KubernetesPlatform, KubernetesPlatformError

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


def _params(**kw):
    return {"namespace": NS, "deployment": NAME, **kw}


def test_live_reads_the_real_deployment(apps, target):
    live = KubernetesPlatform(apps=apps, namespace=NS).live("k8s_scale", _params())
    assert NAME in live["deployment"] and live["namespace"] == {NS}
    assert live["state"]["replicas"] == live["current_replicas"] >= 1


def test_an_approved_scale_changes_the_real_deployment_and_rollback_returns_it(apps, target):
    p = KubernetesPlatform(apps=apps, namespace=NS)
    before = apps.read_namespaced_deployment(NAME, NS).spec.replicas or 1
    msg = p.apply("k8s_scale", _params(replicas=before + 1))
    assert apps.read_namespaced_deployment(NAME, NS).spec.replicas == before + 1, msg
    p.rollback("k8s_scale", _params(replicas=before + 1), {"replicas": before})
    assert apps.read_namespaced_deployment(NAME, NS).spec.replicas == before


def test_a_count_that_moved_is_refused_by_the_real_api_server(apps, target):
    """The JSON Patch `test` op, as a real API server evaluates it: expecting a count the Deployment no
    longer has changes nothing."""
    p = KubernetesPlatform(apps=apps, namespace=NS)
    now = apps.read_namespaced_deployment(NAME, NS).spec.replicas or 1
    with pytest.raises(KubernetesPlatformError, match="nothing was changed"):
        p._write_replicas(NAME, expect=now + 5, to=now + 1)
    assert apps.read_namespaced_deployment(NAME, NS).spec.replicas == now


def test_a_restart_stamps_the_rollout_annotation(apps, target):
    KubernetesPlatform(apps=apps, namespace=NS).apply("k8s_restart", _params())
    anns = apps.read_namespaced_deployment(NAME, NS).spec.template.metadata.annotations or {}
    assert RESTARTED_AT in anns, "restart did not stamp the template"


def test_a_rollout_undo_is_refused_against_a_real_cluster_too(apps, target):
    p = KubernetesPlatform(apps=apps, namespace=NS)
    assert p.live("k8s_rollout_undo", _params()) == {}
    with pytest.raises(KubernetesPlatformError):
        p.apply("k8s_rollout_undo", _params(to_revision="1"))


def test_the_platform_works_as_the_least_privilege_service_account(apps, target):
    """Everything above runs with the runner's admin kubeconfig, which can do anything - so a platform
    that needed more than the write ServiceAccount grants would pass there and fail in a real cluster.
    This impersonates `warden-remediator` (k8s/remediation-rbac.yaml: get and patch deployments, not
    even list; CI applies it before this step): reading, scaling and rolling back must all work as it."""
    from kubernetes import client

    api = client.ApiClient()
    api.set_default_header("Impersonate-User", "system:serviceaccount:warden:warden-remediator")
    p = KubernetesPlatform(apps=client.AppsV1Api(api), namespace=NS)
    live = p.live("k8s_scale", _params())
    assert live, "the remediator could not read the Deployment it is meant to change (is remediation-rbac.yaml applied?)"
    before = live["current_replicas"]
    p.apply("k8s_scale", _params(replicas=before + 1))
    assert apps.read_namespaced_deployment(NAME, NS).spec.replicas == before + 1
    p.rollback("k8s_scale", _params(replicas=before + 1), {"replicas": before})
    assert apps.read_namespaced_deployment(NAME, NS).spec.replicas == before
