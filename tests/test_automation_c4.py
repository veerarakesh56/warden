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


def test_the_remediator_may_list_autoscalers_and_change_none():
    docs = list(yaml.safe_load_all((ROOT / "k8s" / "remediation-rbac.yaml").read_text(encoding="utf-8")))
    rules = next(d for d in docs if d and d.get("kind") == "ClusterRole")["rules"]
    hpa = [r for r in rules if "autoscaling" in r["apiGroups"]]
    assert hpa == [{"apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["list"]}]
