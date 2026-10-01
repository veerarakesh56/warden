"""The Kubernetes platform behind the RemediationWorkflow (decision D16) - a fake API server, no cluster.

It keeps what the removed in-process backend guaranteed: two entries only, a scale bounded and conditioned
on the count it just read, a restart through the rollout annotation, a fault reported - and adds what an
approved plan needs: a count that moved since the approval is refused, never stepped from."""

from __future__ import annotations

import types

import pytest

from test_remediation_workflow import _approve_with, _run, owner, world  # noqa: F401 - fixtures
from warden.platforms import RoutedPlatform
from warden.platforms.k8s import RESTARTED_AT, KubernetesPlatform, KubernetesPlatformError

NS = "shop"


class _Conflict(Exception):
    status = 422


class _Apps:
    def __init__(self, replicas=2, names=("orders", "payments"), fail=False):
        self.replicas = {n: replicas for n in names}
        self.fail = fail
        self.patches: list[tuple[str, object]] = []
        self.moved_to: int | None = None   # someone else scales before our write lands

    def _dep(self, name):
        n = self.replicas[name]
        status = types.SimpleNamespace(available_replicas=n, updated_replicas=n, unavailable_replicas=0)
        return types.SimpleNamespace(metadata=types.SimpleNamespace(name=name, generation=7),
                                     spec=types.SimpleNamespace(replicas=n), status=status)

    def list_namespaced_deployment(self, ns, **kw):
        if self.fail:
            raise RuntimeError("boom: API unreachable")
        return types.SimpleNamespace(items=[self._dep(n) for n in self.replicas] if ns == NS else [])

    def read_namespaced_deployment(self, name, ns, **kw):
        if self.fail or ns != NS or name not in self.replicas:
            raise RuntimeError("404 not found")
        return self._dep(name)

    def patch_namespaced_deployment(self, name, ns, body, **kw):
        if self.fail:
            raise RuntimeError("403 forbidden")
        self.patches.append((name, body))
        if isinstance(body, list):
            if self.moved_to is not None:
                self.replicas[name] = self.moved_to
            test, replace = body
            if test["value"] != self.replicas[name]:
                raise _Conflict("the test op did not hold")
            self.replicas[name] = replace["value"]


def _platform(apps, **kw):
    return KubernetesPlatform(apps=apps, namespace=NS, **kw)


def test_live_reads_the_named_deployment_with_one_get_and_lists_nothing():
    """The write ServiceAccount may get and patch Deployments, not list them (k8s/remediation-rbac.yaml)."""
    apps = _Apps()
    apps.list_namespaced_deployment = None  # a call would raise: the RBAC does not grant list
    live = _platform(apps).live("k8s_scale", {"deployment": "orders"})
    assert live["namespace"] == {NS} and live["deployment"] == {"orders"}
    assert live["current_replicas"] == 2 and live["state"] == {"deployment": "orders", "replicas": 2,
                                                                "generation": 7}


def test_nothing_read_allows_nothing():
    assert _platform(_Apps(fail=True)).live("k8s_scale", {"deployment": "orders"}) == {}
    assert _platform(_Apps()).live("k8s_scale", {"deployment": "absent"}) == {}
    assert _platform(_Apps()).live("k8s_scale", {}) == {}
    assert _platform(_Apps()).live("k8s_rollout_undo", {"deployment": "orders"}) == {}, \
        "rollout undo waits for an admission policy: it reads no revisions, so the catalogue refuses it"


def test_a_scale_is_bounded_and_conditioned_on_the_count_just_read():
    apps = _Apps(replicas=2)
    out = _platform(apps).apply("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 4})
    assert "from 2 to 4" in out and apps.replicas["orders"] == 4
    assert apps.patches[-1][1] == [{"op": "test", "path": "/spec/replicas", "value": 2},
                                   {"op": "replace", "path": "/spec/replicas", "value": 4}]


@pytest.mark.parametrize("replicas", [2, 1, 5, 0, True, "3"])
def test_a_scale_outside_the_bound_is_refused_before_any_write(replicas):
    apps = _Apps(replicas=2)
    with pytest.raises(KubernetesPlatformError, match="outside the bound"):
        _platform(apps).apply("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": replicas})
    assert apps.patches == []


def test_the_ceiling_holds_even_within_two_more():
    apps = _Apps(replicas=9)
    with pytest.raises(KubernetesPlatformError, match="outside the bound"):
        _platform(apps, max_replicas=10).apply("k8s_scale", {"namespace": NS, "deployment": "orders",
                                                            "replicas": 11})


def test_a_count_that_moved_is_refused_and_nothing_changes():
    """The old backend re-read and stepped again; an approved plan must not be carried out against a count
    nobody approved."""
    apps = _Apps(replicas=2)
    apps.moved_to = 3
    with pytest.raises(KubernetesPlatformError, match="something else scaled it; nothing was changed"):
        _platform(apps).apply("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 4})
    assert apps.replicas["orders"] == 3


def test_a_restart_sets_the_rollout_annotation():
    apps = _Apps()
    out = _platform(apps).apply("k8s_restart", {"namespace": NS, "deployment": "orders"})
    name, body = apps.patches[-1]
    assert name == "orders" and RESTARTED_AT in body["spec"]["template"]["metadata"]["annotations"]
    assert "rollout restart of deployment/orders" in out


@pytest.mark.parametrize("entry", ["k8s_rollout_undo", "db_terminate_idle_in_tx", "delete_deployment"])
def test_every_other_entry_is_refused(entry):
    with pytest.raises(KubernetesPlatformError, match="not something the Kubernetes platform does"):
        _platform(_Apps()).apply(entry, {"namespace": NS, "deployment": "orders"})


def test_another_namespace_is_refused():
    with pytest.raises(KubernetesPlatformError, match="not the one this platform serves"):
        _platform(_Apps()).apply("k8s_restart", {"namespace": "kube-system", "deployment": "orders"})


def test_an_api_fault_is_an_error_not_a_silent_success():
    with pytest.raises(KubernetesPlatformError, match="failed"):
        _platform(_Apps(fail=True)).apply("k8s_restart", {"namespace": NS, "deployment": "orders"})


def test_rollback_returns_the_scale_to_the_planned_snapshot_and_a_restart_needs_none():
    apps = _Apps(replicas=4)
    p = _platform(apps)
    out = p.rollback("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 4}, {"replicas": 2})
    assert "from 4 to 2" in out and apps.replicas["orders"] == 2
    assert "nothing to roll back" in p.rollback("k8s_restart", {"namespace": NS, "deployment": "orders"}, {})
    with pytest.raises(KubernetesPlatformError, match="no replica count"):
        p.rollback("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 2}, {})


def test_healthy_needs_every_replica_updated_and_available():
    apps = _Apps(replicas=2)
    p = _platform(apps)
    assert p.healthy("orders") and p.knows("orders")
    assert not p.healthy("nope") and not p.knows("nope")
    sick = apps._dep("orders")
    sick.status.available_replicas = 1
    apps.read_namespaced_deployment = lambda *a, **k: sick
    assert not p.healthy("orders")


def test_the_router_asks_only_platforms_that_know_the_service():
    class _Db:
        def knows(self, service):
            return False

        def healthy(self, service):
            return False

    routed = RoutedPlatform(k8s=_platform(_Apps()), db=_Db())
    assert routed.healthy("orders"), "a database platform must not fail a Deployment's health check"
    assert not RoutedPlatform(db=_Db()).healthy("orders"), "nobody knowing the service is not healthy"
    assert RoutedPlatform(db=_Db()).live("k8s_scale", {}) == {}


def test_an_approved_scale_runs_through_the_workflow_end_to_end(world, owner):  # noqa: F811
    apps = _Apps(replicas=2)
    world["platform"] = RoutedPlatform(k8s=_platform(apps))
    out = _run(world, _approve_with(owner), entry="k8s_scale", service="orders",
               params={"namespace": NS, "deployment": "orders", "replicas": 3})
    assert out.status == "recovered", (out.status, out.reasons)
    assert apps.replicas["orders"] == 3 and len(apps.patches) == 1
