"""The Kubernetes platform behind the RemediationWorkflow (decision D16) - a fake API server, no cluster.

It keeps what the removed in-process backend guaranteed: two entries only, a scale bounded and conditioned
on the count it just read, a restart through the rollout annotation, a fault reported - and adds what an
approved plan needs: a count that moved since the approval is refused, never stepped from."""

from __future__ import annotations

import types

import pytest

from test_remediation_workflow import _approve_with, _run, owner, world  # noqa: F401 - fixtures
from warden.platforms import RoutedPlatform
from warden.platforms.k8s import (
    RESTARTED_AT,
    KubernetesPlatform,
    KubernetesPlatformError,
    KubernetesPlatformRefused,
)

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
        status = types.SimpleNamespace(available_replicas=n, updated_replicas=n, unavailable_replicas=0,
                                       observed_generation=7, conditions=[])
        return types.SimpleNamespace(metadata=types.SimpleNamespace(name=name, generation=7,
                                                                       labels={"environment": "dev"}),
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


class _Hpas:
    """The autoscaling API: HorizontalPodAutoscalers in the namespace, each targeting a Deployment by name."""

    def __init__(self, *targets):
        self.targets = targets

    def list_namespaced_horizontal_pod_autoscaler(self, ns, **kw):
        ref = [types.SimpleNamespace(spec=types.SimpleNamespace(
            scale_target_ref=types.SimpleNamespace(kind="Deployment", name=t))) for t in self.targets]
        return types.SimpleNamespace(items=ref)


def _platform(apps, **kw):
    kw.setdefault("autoscaling", _Hpas())  # none: an autoscaler owns no count here unless a test says so
    return KubernetesPlatform(apps=apps, namespace=NS, **kw)


def test_live_reads_the_named_deployment_with_one_get_and_lists_nothing():
    """The write ServiceAccount may get and patch Deployments, not list them (k8s/remediation-rbac.yaml)."""
    apps = _Apps()
    apps.list_namespaced_deployment = None  # a call would raise: the RBAC does not grant list
    live = _platform(apps).live("k8s_scale", {"deployment": "orders"})
    assert live["namespace"] == {NS} and live["deployment"] == {"orders"}
    assert live["current_replicas"] == 2 and live["state"] == {"deployment": "orders", "replicas": 2,
                                                                "generation": 7, "server": ""}


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


def test_healthy_needs_the_current_spec_seen_and_a_rollout_not_stalled():
    """Sixth review (2026-10-01): counts from before the change (observedGeneration behind) or from a rollout past
    its deadline (Progressing=False) read healthy."""
    apps = _Apps(replicas=2)
    p = _platform(apps)
    behind = apps._dep("orders")
    behind.status.observed_generation = 6
    apps.read_namespaced_deployment = lambda *a, **k: behind
    assert not p.healthy("orders")
    stalled = _Apps(replicas=2)._dep("orders")
    stalled.status.conditions = [types.SimpleNamespace(type="Progressing", status="False",
                                                       reason="ProgressDeadlineExceeded")]
    apps.read_namespaced_deployment = lambda *a, **k: stalled
    assert not p.healthy("orders")


def test_an_admission_policy_narrows_what_the_remediator_may_patch():
    """Audit A-I-11: get+patch on deployments could rewrite the pod template. The policy, applied with the
    ServiceAccount, holds the pod spec, selector, labels, strategy and other annotations to what they were, and the
    replica count to within two (the live test proves it on a real API server)."""
    import pathlib

    import yaml

    text = (pathlib.Path(__file__).resolve().parents[1] / "k8s" / "remediation-rbac.yaml").read_text(encoding="utf-8")
    docs = {d["kind"]: d for d in yaml.safe_load_all(text) if d}
    vap, binding = docs["ValidatingAdmissionPolicy"], docs["ValidatingAdmissionPolicyBinding"]
    assert vap["spec"]["failurePolicy"] == "Fail" and binding["spec"]["validationActions"] == ["Deny"]
    assert binding["spec"]["policyName"] == vap["metadata"]["name"]
    [who] = vap["spec"]["matchConditions"]
    assert who["expression"] == 'request.userInfo.username == "system:serviceaccount:warden:warden-remediator"'
    rules = " ".join(v["expression"] for v in vap["spec"]["validations"])
    for held in ("object.spec.template.spec == oldObject.spec.template.spec", "object.spec.selector ==",
                 "object.spec.replicas <= oldObject.spec.replicas + 2", "object.spec.replicas >= 1"):
        assert held in rules, held
    # Every field the API defines is held, or named here as the remediator's (replicas, the restart annotation) or
    # the server's. A string check let a rule be deleted unseen, and missed metadata entirely (seventh review:
    # a dangling ownerReference has the garbage collector delete the Deployment). A field Kubernetes adds later
    # fails this until it is placed.
    from kubernetes.client import V1DeploymentSpec, V1ObjectMeta

    def held(path):
        return f"object.{path} == oldObject.{path}" in rules or f"has(object.{path}) ? object.{path} :" in rules

    server_owned = {"creationTimestamp", "deletionGracePeriodSeconds", "deletionTimestamp", "generation",
                    "managedFields", "resourceVersion", "selfLink", "uid", "name", "namespace", "generateName"}
    for f in V1ObjectMeta.attribute_map.values():
        assert f in server_owned or held(f"metadata.{f}"), f"metadata.{f} is not held"
    for f in set(V1DeploymentSpec.attribute_map.values()) - {"replicas", "template", "paused"}:
        assert held(f"spec.{f}"), f"spec.{f} is not held"
    for f in ("spec", "metadata.labels", "metadata.finalizers"):
        assert held(f"spec.template.{f}"), f"spec.template.{f} is not held"
    assert "restartedAt" in rules and "paused" in rules
    # The ceiling is the platform's default ceiling.
    k8s_src = (pathlib.Path(__file__).resolve().parents[1] / "src" / "warden" / "platforms" / "k8s.py").read_text()
    assert '"WARDEN_REMEDIATION_MAX_REPLICAS", "10"' in k8s_src and "object.spec.replicas <= 10 " in rules
    # The ceiling only when the count changes: a restart of a Deployment above ten was refused (eighth review).
    assert "object.spec.replicas == oldObject.spec.replicas ||" in rules
    # Matched for updates of Deployments themselves - a CREATE or a misspelt resource would match nothing.
    [rule] = vap["spec"]["matchConstraints"]["resourceRules"]
    assert rule == {"apiGroups": ["apps"], "apiVersions": ["v1"], "operations": ["UPDATE"], "resources": ["deployments"]}


def test_the_plan_names_the_api_server_it_writes_to():
    """Sixth review (2026-10-01): staging's plan and prod's looked the same to the approver."""
    import types

    apps = _Apps(replicas=2)
    apps.api_client = types.SimpleNamespace(configuration=types.SimpleNamespace(host="https://prod-cluster.example:6443"))
    state = _platform(apps).live("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 3})["state"]
    assert state["server"] == "https://prod-cluster.example:6443"


def test_a_count_that_moved_after_the_approval_is_refused_not_stepped_from():
    """Sixth review (2026-10-01): approved on 3, the count moved to 2 before the write; the scale wrote 2 -> 4 and a
    rollback returned to 3. The platform now holds the write to the count the plan was approved on."""
    apps = _Apps(replicas=2)
    p = _platform(apps)
    with pytest.raises(KubernetesPlatformError, match="not the 3 the plan was approved on"):
        p.apply("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 4}, snapshot={"replicas": 3})
    assert apps.patches == []
    p.apply("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 3}, snapshot={"replicas": 2})
    assert apps.patches


def test_a_write_the_api_server_refused_changed_nothing():
    """Seventh review (2026-10-01): an RBAC or admission-policy refusal (403, or a policy's 422) is never persisted,
    but a refused restart ended "apply_failed - may be half-made" and a refused scale said "something else scaled
    it". Both end refused, saying what refused them."""
    class _Denied(Exception):
        def __init__(self, status, reason):
            super().__init__(reason)
            self.status, self.reason = status, reason

    class _Refusing(_Apps):
        def __init__(self, status, reason):
            super().__init__(replicas=2)
            self.denial = (status, reason)

        def patch_namespaced_deployment(self, name, ns, body, **kw):
            raise _Denied(*self.denial)

    for status in (403, 422):
        p = _platform(_Refusing(status, "ValidatingAdmissionPolicy denied request"))
        with pytest.raises(KubernetesPlatformRefused, match="an admission policy.*nothing was changed"):
            p.apply("k8s_restart", {"namespace": NS, "deployment": "orders"})
        with pytest.raises(KubernetesPlatformRefused, match="an admission policy.*nothing was changed"):
            p.apply("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 3})
    p = _platform(_Refusing(500, "etcd unavailable"))
    with pytest.raises(KubernetesPlatformError) as failed:
        p.apply("k8s_restart", {"namespace": NS, "deployment": "orders"})
    assert not isinstance(failed.value, KubernetesPlatformRefused)


def test_in_a_cluster_the_plan_names_the_cluster_it_was_told(monkeypatch):
    """Seventh review: in a cluster the API server is the `kubernetes` Service's IP, the same in staging and prod."""
    import types

    apps = _Apps(replicas=2)
    apps.api_client = types.SimpleNamespace(configuration=types.SimpleNamespace(host="https://10.100.0.1:443"))
    monkeypatch.setenv("WARDEN_CLUSTER_NAME", "prod-eks")
    state = _platform(apps).live("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 3})["state"]
    assert state["server"] == "prod-eks (https://10.100.0.1:443)"


def test_a_policy_refusal_is_not_read_as_a_moved_count_whatever_the_deployment_is_called():
    """Eighth review: `"test" in str(exc)` took the admission policy's 422 for a JSON Patch test failure when the
    Deployment's name held "test" - the signed reason said "something else scaled it"."""
    class _Denied(Exception):
        def __init__(self, status, text):
            super().__init__(text)
            self.status, self.reason = status, text

    class _Refusing(_Apps):
        def __init__(self, exc):
            super().__init__(replicas=2)
            self.exc = exc

        def patch_namespaced_deployment(self, name, ns, body, **kw):
            raise self.exc

    # The API server's text names the Deployment: "test" in the name was "test" in the text.
    for name in ("orders", "latest-api", "contest-scoring"):
        policy = (f'deployments.apps "{name}" is forbidden: ValidatingAdmissionPolicy '
                  "'warden-remediator-narrow-writes' denied request: the remediator may change the replica count ...")
        p = _platform(_Refusing(_Denied(422, policy)))
        with pytest.raises(KubernetesPlatformRefused, match="admission policy"):
            p.apply("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 3})
    moved = 'deployments.apps "latest-api": the server rejected our request: testing value /spec/replicas failed'
    p = _platform(_Refusing(_Denied(422, moved)))
    with pytest.raises(KubernetesPlatformRefused, match="something else scaled it"):
        p.apply("k8s_scale", {"namespace": NS, "deployment": "orders", "replicas": 3})


def test_a_write_that_never_reached_the_api_server_changed_nothing():
    """Eighth review: a refused connection - nothing sent - ended apply_failed and tripped the global kill switch."""
    import urllib3

    class _Down(_Apps):
        def patch_namespaced_deployment(self, name, ns, body, **kw):
            refused = urllib3.exceptions.NewConnectionError(None, "Failed to establish a new connection: refused")
            raise urllib3.exceptions.MaxRetryError(None, "/apis/apps/v1", reason=refused)

    p = _platform(_Down(replicas=2))
    with pytest.raises(KubernetesPlatformRefused, match="could not reach the API server"):
        p.apply("k8s_restart", {"namespace": NS, "deployment": "orders"})

    class _Reset(_Apps):
        def patch_namespaced_deployment(self, name, ns, body, **kw):
            raise urllib3.exceptions.ProtocolError("Connection aborted.", ConnectionResetError())

    with pytest.raises(KubernetesPlatformError) as unknown:  # sent, then lost: nobody knows - not "refused"
        _platform(_Reset(replicas=2)).apply("k8s_restart", {"namespace": NS, "deployment": "orders"})
    assert not isinstance(unknown.value, KubernetesPlatformRefused)
