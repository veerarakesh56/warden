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
        "metadata": {"name": NAME, "labels": {"app": NAME, "environment": "dev"}},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": NAME}},
            "template": {
                "metadata": {"labels": {"app": NAME}},
                # No token: the throwaway pod reads nothing from the API (seventh review, A-I-26).
                "spec": {"automountServiceAccountToken": False, "containers": [{
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
    # The API's own default strategy, read as the C10 check reads it: RollingUpdate, maxUnavailable "25%", rounded down.
    assert live["at_once"] == live["current_replicas"] * 25 // 100 and live["rollout"] in ("complete", "progressing")
    assert live["environment"] == "dev"  # the Deployment's own label, read for P18 (register S6)


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
    with pytest.raises(KubernetesPlatformError, match="something else scaled it; nothing was changed"):
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


def _as_remediator():
    from kubernetes import client

    api = client.ApiClient()
    api.set_default_header("Impersonate-User", "system:serviceaccount:warden:warden-remediator")
    return client.AppsV1Api(api)


def test_the_admission_policy_refuses_a_pod_spec_change_by_the_remediator(apps, target):
    """Audit A-I-11: `patch deployments` could rewrite the pod template - an image, a command, a service account.
    The ValidatingAdmissionPolicy in k8s/remediation-rbac.yaml refuses that for the remediator, on the real API
    server."""
    from kubernetes.client.exceptions import ApiException

    before = apps.read_namespaced_deployment(NAME, NS).spec.template.spec.containers[0].image
    patch = {"spec": {"template": {"spec": {"containers": [{"name": "pause", "image": "busybox:1.36"}]}}}}
    with pytest.raises(ApiException) as refused:
        _as_remediator().patch_namespaced_deployment(NAME, NS, patch)
    assert refused.value.status in (403, 422), refused.value
    assert apps.read_namespaced_deployment(NAME, NS).spec.template.spec.containers[0].image == before
    with pytest.raises(ApiException):
        _as_remediator().patch_namespaced_deployment(NAME, NS, {"spec": {"replicas": 9}})


def test_the_remediator_can_still_restart_through_the_policy(apps, target):
    p = KubernetesPlatform(apps=_as_remediator(), namespace=NS)
    p.apply("k8s_restart", _params())
    ann = apps.read_namespaced_deployment(NAME, NS).spec.template.metadata.annotations or {}
    assert RESTARTED_AT in ann


@pytest.mark.parametrize("patch", [
    # A dangling owner: the garbage collector would delete the Deployment and its pods.
    {"metadata": {"ownerReferences": [{"apiVersion": "v1", "kind": "ConfigMap", "name": "gone",
                                       "uid": "00000000-0000-0000-0000-00000000dead"}]}},
    {"metadata": {"finalizers": ["example.com/hold"]}},
    {"metadata": {"labels": {"app": "not-this-one"}}},
    {"spec": {"revisionHistoryLimit": 0}},  # the rollback history, gone
    {"spec": {"minReadySeconds": 86400}},
    {"spec": {"template": {"metadata": {"finalizers": ["example.com/hold"]}}}},
], ids=["owner", "finalizer", "label", "history", "min-ready", "pod-finalizer"])
def test_the_admission_policy_holds_the_deployments_metadata_and_rollout_fields(apps, target, patch):
    """Seventh review (2026-10-01, HIGH): the policy never read metadata, so one allowed patch could have the
    garbage collector delete the Deployment, or wipe its rollback history. Refused on the real API server."""
    from kubernetes.client.exceptions import ApiException

    before = apps.read_namespaced_deployment(NAME, NS).to_dict()
    with pytest.raises(ApiException) as refused:
        _as_remediator().patch_namespaced_deployment(NAME, NS, patch)
    assert refused.value.status in (403, 422), refused.value
    after = apps.read_namespaced_deployment(NAME, NS).to_dict()
    assert after["metadata"]["owner_references"] == before["metadata"]["owner_references"]
    assert after["spec"] == before["spec"]


def test_the_admission_policy_caps_the_replica_count(apps, target):
    """The ceiling is per request too: two at a time, never past ten (the platform's default ceiling)."""
    from kubernetes.client.exceptions import ApiException

    remediator = _as_remediator()
    try:
        for n in (3, 5, 7, 9):
            remediator.patch_namespaced_deployment(NAME, NS, {"spec": {"replicas": n}})
        with pytest.raises(ApiException):
            remediator.patch_namespaced_deployment(NAME, NS, {"spec": {"replicas": 11}})
        assert apps.read_namespaced_deployment(NAME, NS).spec.replicas == 9
    finally:
        apps.patch_namespaced_deployment(NAME, NS, {"spec": {"replicas": 1}})


def test_a_write_the_policy_refuses_is_reported_as_the_policy_s(apps, target):
    """Eighth review: the real API server's wording for a policy refusal is what the platform reads - not a moved
    count."""
    p = KubernetesPlatform(apps=_as_remediator(), namespace=NS)
    now = apps.read_namespaced_deployment(NAME, NS).spec.replicas or 1
    with pytest.raises(KubernetesPlatformError, match="admission policy"):
        p._write_replicas(NAME, expect=now, to=now + 5)
    assert apps.read_namespaced_deployment(NAME, NS).spec.replicas == now


@pytest.mark.parametrize("patch", [
    {"spec": {"template": {"metadata": {"annotations": {"example.com/kept": None}}}}},  # remove a template annotation
    {"spec": {"paused": True}},
], ids=["remove-annotation", "pause"])
def test_the_policy_refuses_removing_a_template_annotation_or_pausing(apps, target, patch):
    """Eighth review: no live case for these; a policy that let them through passed CI."""
    from kubernetes.client.exceptions import ApiException

    apps.patch_namespaced_deployment(NAME, NS, {"spec": {"template": {"metadata": {"annotations": {
        "example.com/kept": "yes"}}}}})
    before = apps.read_namespaced_deployment(NAME, NS).to_dict()["spec"]
    with pytest.raises(ApiException) as refused:
        _as_remediator().patch_namespaced_deployment(NAME, NS, patch)
    assert refused.value.status in (403, 422), refused.value
    assert apps.read_namespaced_deployment(NAME, NS).to_dict()["spec"] == before


def test_the_policy_refuses_a_big_step_down(apps, target):
    """Eighth review: one patch from ten to one passed the unit test and the live tests."""
    from kubernetes.client.exceptions import ApiException

    try:
        apps.patch_namespaced_deployment(NAME, NS, {"spec": {"replicas": 5}})
        with pytest.raises(ApiException):
            _as_remediator().patch_namespaced_deployment(NAME, NS, {"spec": {"replicas": 1}})
        assert apps.read_namespaced_deployment(NAME, NS).spec.replicas == 5
    finally:
        apps.patch_namespaced_deployment(NAME, NS, {"spec": {"replicas": 1}})


def test_a_restart_of_a_deployment_above_the_ceiling_is_allowed(apps, target):
    """Eighth review: the 1..10 ceiling applied to every update, so a restart of a Deployment at 12 was refused."""
    try:
        apps.patch_namespaced_deployment(NAME, NS, {"spec": {"replicas": 12}})
        KubernetesPlatform(apps=_as_remediator(), namespace=NS).apply("k8s_restart", _params())
        ann = apps.read_namespaced_deployment(NAME, NS).spec.template.metadata.annotations or {}
        assert RESTARTED_AT in ann
    finally:
        apps.patch_namespaced_deployment(NAME, NS, {"spec": {"replicas": 1}})
