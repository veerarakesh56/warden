"""Register C4: WARDEN does not fight other automation - GitOps self-heal, or an autoscaler that owns the count."""

from __future__ import annotations

import pathlib

import pytest
import yaml

from test_platform_k8s import _Apps, _Hpas, _platform
from warden import catalog

ROOT = pathlib.Path(__file__).resolve().parents[1]
OK = {"namespace": "shop", "deployment": "orders"}


def _live(entry="k8s_restart", labels=None, annotations=None, **kw):
    apps = _Apps()
    dep = apps._dep

    def marked(name):
        d = dep(name)
        d.metadata.labels = {**d.metadata.labels, **(labels or {})}
        d.metadata.annotations = annotations or {}
        return d

    apps._dep = marked
    return _platform(apps, **kw).live(entry, {"deployment": "orders"})


@pytest.mark.parametrize(("labels", "annotations", "owner"), [
    ({}, {"argocd.argoproj.io/tracking-id": "shop:apps/Deployment:shop/orders"}, "Argo CD"),
    ({"argocd.argoproj.io/instance": "shop"}, {}, "Argo CD"),
    ({"kustomize.toolkit.fluxcd.io/name": "apps"}, {}, "Flux"),
    ({"helm.toolkit.fluxcd.io/name": "orders"}, {}, "Flux"),
    ({"app.kubernetes.io/instance": "orders"}, {}, ""),  # Helm sets it too, and Helm does not self-heal
])
def test_a_gitops_owned_deployment_is_refused_a_direct_change(labels, annotations, owner):
    live = _live(labels=labels, annotations=annotations)
    assert live["gitops"] == owner
    problems = catalog.validate("k8s_restart", OK, {**live, "at_once": 0})
    assert any(p.startswith(f"C4: {owner} manages") for p in problems) is bool(owner), problems


def test_a_scale_an_autoscaler_owns_is_refused_and_a_restart_is_not():
    live = _live("k8s_scale", autoscaling=_Hpas("orders"))
    assert live["autoscaled"] is True
    assert any("an autoscaler (a HorizontalPodAutoscaler" in p for p in catalog.validate("k8s_scale", {**OK, "replicas": 3}, live))
    assert not [p for p in catalog.validate("k8s_restart", OK, {**live, "at_once": 0}) if p.startswith("C4")]
    other = _live("k8s_scale", autoscaling=_Hpas("payments"))  # an HPA for another Deployment
    assert other["autoscaled"] is False and catalog.validate("k8s_scale", {**OK, "replicas": 3}, other) == []


def test_a_scale_is_refused_when_the_autoscalers_cannot_be_read():
    class _Denied:
        def list_namespaced_horizontal_pod_autoscaler(self, ns, **kw):
            raise RuntimeError("403 forbidden")

    live = _live("k8s_scale", autoscaling=_Denied())
    assert live["autoscaled"] is None
    assert any("could not be read" in p for p in catalog.validate("k8s_scale", {**OK, "replicas": 3}, live))


# --------------------------------------------------------------------------- Argo CD and a restart (owner, 2026-10-17)

TRACKED = {"argocd.argoproj.io/tracking-id": "shop:apps/Deployment:shop/orders"}
POINTER = "/spec/template/metadata/annotations/kubectl.kubernetes.io~1restartedAt"


def _application(rules, destination="shop"):
    return {"spec": {"destination": {"namespace": destination}, "ignoreDifferences": rules}}


class _Custom:
    """Argo CD's Applications, as the reader reads them: one by namespace and name, or a refusal."""

    def __init__(self, app=None, fail=False):
        self.app, self.fail, self.asked = app, fail, []

    def get_namespaced_custom_object(self, group, version, namespace, plural, name, **kw):
        self.asked.append((group, version, namespace, plural, name))
        if self.fail or self.app is None:
            raise RuntimeError("403 forbidden" if self.fail else "404 not found")
        return self.app


IGNORED = _application([{"group": "apps", "kind": "Deployment", "jsonPointers": [POINTER]}])


def test_a_restart_argo_cd_provably_ignores_is_allowed_and_nothing_else_is():
    custom = _Custom(IGNORED)
    live = _live(annotations=TRACKED, custom=custom)
    assert live["gitops"] == "Argo CD"
    assert live["gitops_ignores_restart"] is True
    assert custom.asked == [("argoproj.io", "v1alpha1", "argocd", "applications", "shop")]
    assert not [p for p in catalog.validate("k8s_restart", OK, {**live, "at_once": 0}) if p.startswith("C4")]
    # A scale of the same Deployment would fight Git: refused, whatever the Application ignores.
    scale = _live("k8s_scale", annotations=TRACKED, custom=_Custom(IGNORED))
    assert "gitops_ignores_restart" not in scale
    assert any(p.startswith("C4: Argo CD manages") for p in catalog.validate("k8s_scale", {**OK, "replicas": 3}, scale))
    assert any(p.startswith("C4: Argo CD manages") for p in catalog.validate(
        "k8s_scale", {**OK, "replicas": 3}, {**scale, "gitops_ignores_restart": True}))
    # A Flux-managed Deployment is never let through on an Argo CD reading.
    flux = {"gitops": "Flux", "gitops_ignores_restart": True, **{k: v for k, v in live.items() if k not in ("gitops",)}}
    assert any(p.startswith("C4: Flux manages") for p in catalog.validate("k8s_restart", OK, {**flux, "at_once": 0}))


@pytest.mark.parametrize(("annotations", "labels", "custom"), [
    (TRACKED, {}, None),  # no Application client: unknown
    (TRACKED, {}, _Custom(fail=True)),  # the Application cannot be read
    (TRACKED, {}, _Custom()),  # no such Application
    ({}, {"argocd.argoproj.io/instance": "shop"}, _Custom(IGNORED)),  # label tracking names no resource: unproven
    ({"argocd.argoproj.io/tracking-id": "shop:apps/Deployment:shop/payments"}, {}, _Custom(IGNORED)),  # another's id
    (TRACKED, {"kustomize.toolkit.fluxcd.io/name": "apps"}, _Custom(IGNORED)),  # Flux reconciles it as well
    (TRACKED, {}, _Custom(_application([{"group": "apps", "kind": "Deployment", "jsonPointers": ["/spec/replicas"]}]))),
    (TRACKED, {}, _Custom(_application([{"group": "apps", "kind": "Deployment", "name": "payments",
                                         "jsonPointers": [POINTER]}]))),  # a rule for another Deployment
    (TRACKED, {}, _Custom(_application([{"group": "apps", "kind": "Deployment",
                                         "jqPathExpressions": [".spec.template.metadata.annotations"]}]))),
    (TRACKED, {}, _Custom(_application([{"group": "apps", "kind": "Deployment", "jsonPointers": ["/spec/t"]}]))),
    (TRACKED, {}, _Custom(_application([{"group": "apps", "kind": "Deployment", "jsonPointers": [POINTER]}],
                                       destination="other"))),  # an Application deploying elsewhere
], ids=["no-client", "unreadable", "absent", "label-tracking", "other-id", "flux-too", "other-field", "other-name",
        "jq-only", "pointer-prefix", "other-destination"])
def test_a_restart_on_argo_cd_stays_refused_unless_the_ignore_is_proven(annotations, labels, custom):
    kw = {"custom": custom} if custom is not None else {}
    live = _live(annotations=annotations, labels=labels, **kw)
    assert live.get("gitops_ignores_restart") is not True
    assert any(p.startswith("C4:") for p in catalog.validate("k8s_restart", OK, {**live, "at_once": 0}))


@pytest.mark.parametrize("reading", [{}, {"gitops_ignores_restart": None}, {"gitops_ignores_restart": "yes"}])
def test_the_catalogue_lets_a_restart_through_only_on_a_proven_reading(reading):
    """No reading, an unknown one, or anything but True: the catalogue refuses, whatever produced the live state."""
    live = {k: v for k, v in _live(annotations=TRACKED, custom=_Custom(IGNORED)).items() if k != "gitops_ignores_restart"}
    assert any(p.startswith("C4: Argo CD manages") for p in catalog.validate("k8s_restart", OK,
                                                                             {**live, **reading, "at_once": 0}))


@pytest.mark.parametrize("pointer", ["/", "", "/spec/", "/spec/template/", POINTER + "/", "spec/template",
                                     "/spec/templat"])
def test_a_near_miss_pointer_is_no_proof(pointer):
    """Review, PR 48: RFC 6901 compared by whole segments. `/` and `/spec/` name a key "" - not an ancestor of the
    annotation - and a pointer without its leading `/` is not one; none of them makes Argo CD leave a restart."""
    custom = _Custom(_application([{"group": "apps", "kind": "Deployment", "name": "orders", "namespace": "shop",
                                    "jsonPointers": [pointer]}]))
    assert _live(annotations=TRACKED, custom=custom)["gitops_ignores_restart"] is False


@pytest.mark.parametrize("pointer", [POINTER, "/spec/template/metadata/annotations", "/spec/template", "/spec"])
def test_an_ignore_of_the_annotation_or_a_field_holding_it_is_proof(pointer):
    custom = _Custom(_application([{"group": "apps", "kind": "Deployment", "name": "orders", "namespace": "shop",
                                    "jsonPointers": ["/spec/replicas", pointer]}]))
    assert _live(annotations=TRACKED, custom=custom)["gitops_ignores_restart"] is True


def test_the_shop_application_ignores_the_restart_and_the_reader_may_read_it_alone():
    """What the pipeline deploys: the Application's own rule, and the reader's one Argo CD grant."""
    docs = [d for d in yaml.safe_load_all((ROOT / "k8s" / "argocd" / "shop.yaml").read_text(encoding="utf-8")) if d]
    app = next(d for d in docs if d["kind"] == "Application")
    from warden.platforms.k8s import _ignores_restart

    assert any(_ignores_restart(r, "catalog-api", "shop") for r in app["spec"]["ignoreDifferences"])
    role = next(d for d in docs if d["kind"] == "Role")
    assert role["metadata"]["namespace"] == "argocd"
    assert role["rules"] == [
        {"apiGroups": ["argoproj.io"], "resources": ["applications"], "resourceNames": [app["metadata"]["name"]],
         "verbs": ["get"]}]
    binding = next(d for d in docs if d["kind"] == "RoleBinding")
    # (The reader's access entry gives it that group: tests/test_fullstack_infra.py.)
    assert binding["subjects"] == [{"kind": "Group", "name": "warden-readers", "apiGroup": "rbac.authorization.k8s.io"}]


def test_the_remediator_may_list_autoscalers_and_change_none():
    docs = list(yaml.safe_load_all((ROOT / "k8s" / "remediation-rbac.yaml").read_text(encoding="utf-8")))
    rules = next(d for d in docs if d and d.get("kind") == "ClusterRole")["rules"]
    hpa = [r for r in rules if "autoscaling" in r["apiGroups"]]
    assert hpa == [{"apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["list"]}]
