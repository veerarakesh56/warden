"""The Kubernetes fault injectors, against a stubbed API.

⛔ The one that matters most is `test_an_unlabelled_namespace_is_never_touched`. These ops delete
pods, rewrite container specs and strip RBAC rules. `default` exists in every cluster on earth and
is one typo away from a scenario's namespace, so the guard is the difference between a benchmark
and an incident.
"""

from __future__ import annotations

import pytest
from scenarios.ops import OpError, run_steps
from scenarios.ops_k8s import OPS, Clients, Target

BASELINE_IMAGE = "public.ecr.aws/docker/library/python:3.12-alpine"


class FakeCore:
    def __init__(self, *, labels=None, pods=("checkout-aaa", "checkout-bbb")):
        self._labels = {"project": "warden-proving-ground"} if labels is None else labels
        self._pods = list(pods)
        self.deleted: list[str] = []

    def read_namespace(self, *, name):
        return {"metadata": {"labels": dict(self._labels)}}

    def list_namespaced_pod(self, *, namespace, label_selector=None):
        return {"items": [{"metadata": {"name": n}} for n in self._pods]}

    def delete_namespaced_pod(self, *, name, namespace):
        self.deleted.append(name)
        return {}


class FakeApps:
    def __init__(self):
        self.patches: list[dict] = []
        self.scales: list[int] = []

    def read_namespaced_deployment(self, *, name, namespace, **_kw):
        return {"spec": {"template": {"spec": {"containers": [
            {"name": "checkout", "image": BASELINE_IMAGE,
             "command": ["python", "-u", "-c", "print('healthy')"]},
        ]}}}}

    def patch_namespaced_deployment(self, *, name, namespace, body):
        self.patches.append(body)
        return {}

    def patch_namespaced_deployment_scale(self, *, name, namespace, body):
        self.scales.append(body["spec"]["replicas"])
        return {}


class FakeRbac:
    def __init__(self, *, rules=None):
        self.rules = rules if rules is not None else [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]},
            {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["events"], "verbs": ["list"]},
        ]
        self.patched: list[list[dict]] = []

    def read_cluster_role(self, *, name):
        return {"rules": [dict(r) for r in self.rules]}

    def patch_cluster_role(self, *, name, body):
        self.patched.append(body["rules"])
        return {}


def _clients(**kw):
    return Clients(core=kw.get("core") or FakeCore(), apps=kw.get("apps") or FakeApps(),
                   rbac=kw.get("rbac") or FakeRbac())


def _target(**kw):
    base = dict(context="k3d-warden", namespace="warden-pg", deployment="checkout",
                container="checkout", baseline_image=BASELINE_IMAGE)
    base.update(kw)
    return Target(**base)


# --------------------------------------------------------------------------- the guard


@pytest.mark.parametrize("labels", [{}, {"project": "someone-elses"}, {"env": "prod"}])
def test_an_unlabelled_namespace_is_never_touched(labels):
    """Load-bearing. Every op guards, so one test per op would be noise - but the guard itself must
    be proven to refuse, and to refuse BEFORE anything is written."""
    apps = FakeApps()
    clients = _clients(core=FakeCore(labels=labels), apps=apps)
    with pytest.raises(OpError, match="proving ground"):
        OPS["k8s_patch_variant"](clients, _target(), variant="oom")
    assert apps.patches == [], "it patched anyway"


def test_the_guard_allows_the_proving_ground_itself():
    """⛔ THE POSITIVE CONTROL, and it is not a formality. The first version of the guard read the
    namespace's labels by attribute, which is None for a dict-shaped response, so it refused EVERY
    namespace - and the refusal tests above all passed. A guard that refuses everything is
    indistinguishable from a guard that works, until something has to be allowed through."""
    apps = FakeApps()
    OPS["k8s_patch_variant"](_clients(apps=apps), _target(), variant="oom")
    assert apps.patches, "the labelled proving ground must be allowed through"


def test_a_namespace_that_cannot_be_read_is_refused_not_assumed_safe():
    class Unreadable(FakeCore):
        def read_namespace(self, *, name):
            raise RuntimeError("connection refused")

    with pytest.raises(OpError, match="cannot read namespace"):
        OPS["k8s_scale"](_clients(core=Unreadable()), _target(), replicas=0)


# --------------------------------------------------------------------------- the variants


def test_the_oom_variant_changes_the_image_and_really_allocates_memory():
    apps = FakeApps()
    OPS["k8s_patch_variant"](_clients(apps=apps), _target(), variant="oom")
    container = apps.patches[0]["spec"]["template"]["spec"]["containers"][0]
    assert container["image"].endswith(":3.12.7-alpine"), "a visible image change, so deploys() sees it"
    program = container["command"][-1]
    assert "bytearray(900*1024*1024)" in program, "the fault must be a real allocation, not a log line"


def test_the_same_image_variant_keeps_the_baseline_image_on_purpose():
    """⭐ The pair to `oom`: a real rollout the backend cannot see, because deploys() compares
    images between ReplicaSets and this one changes only the command."""
    apps = FakeApps()
    OPS["k8s_patch_variant"](_clients(apps=apps), _target(), variant="oom_same_image")
    container = apps.patches[0]["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == BASELINE_IMAGE
    assert "bytearray" in container["command"][-1]


def test_a_probe_from_a_previous_variant_is_cleared_not_inherited():
    """Otherwise the next scenario's restarts would be attributed to the wrong fault."""
    apps = FakeApps()
    target, clients = _target(), _clients(apps=apps)
    OPS["k8s_patch_variant"](clients, target, variant="bad_probe")
    assert "livenessProbe" in apps.patches[0]["spec"]["template"]["spec"]["containers"][0]
    OPS["k8s_patch_variant"](clients, target, variant="oom")
    assert "livenessProbe" not in apps.patches[1]["spec"]["template"]["spec"]["containers"][0]


def test_an_unknown_variant_is_refused():
    with pytest.raises(OpError, match="unknown variant"):
        OPS["k8s_patch_variant"](_clients(), _target(), variant="make_it_broken_somehow")


# --------------------------------------------------------------------------- revert


def test_the_revert_restores_what_was_saved_not_what_the_code_assumes():
    apps = FakeApps()
    target, clients = _target(), _clients(apps=apps)
    OPS["k8s_patch_variant"](clients, target, variant="exit_one")
    OPS["k8s_restore_baseline"](clients, target)
    restored = apps.patches[-1]["spec"]["template"]["spec"]["containers"][0]
    assert restored["image"] == BASELINE_IMAGE
    assert restored["command"] == ["python", "-u", "-c", "print('healthy')"]


def test_restoring_without_a_saved_spec_refuses_rather_than_guessing():
    with pytest.raises(OpError, match="refusing to guess"):
        OPS["k8s_restore_baseline"](_clients(), _target())


# --------------------------------------------------------------------------- the other ops


def test_scaling_to_zero_is_recorded_exactly():
    apps = FakeApps()
    result = OPS["k8s_scale"](_clients(apps=apps), _target(), replicas=0)
    assert apps.scales == [0] and result["replicas"] == 0


def test_deleting_a_pod_picks_one_and_reports_which():
    core = FakeCore(pods=("checkout-bbb", "checkout-aaa"))
    result = OPS["k8s_delete_one_pod"](_clients(core=core), _target())
    assert core.deleted == ["checkout-aaa"], "deterministic choice, so the record is reproducible"
    assert result["of"] == 2


def test_deleting_a_pod_when_none_match_is_an_error_not_a_silent_pass():
    """A scenario that injected nothing must be reported as an error, never scored as a result."""
    with pytest.raises(OpError, match="nothing to measure"):
        OPS["k8s_delete_one_pod"](_clients(core=FakeCore(pods=())), _target())


def test_revoking_log_access_removes_only_the_log_rule():
    rbac = FakeRbac()
    result = OPS["k8s_revoke_log_access"](_clients(rbac=rbac), _target())
    kept = {tuple(r["resources"]) for r in rbac.patched[0]}
    assert ("pods/log",) not in kept, "the log rule must be gone"
    assert ("pods",) in kept and ("events",) in kept, "WARDEN must still see that something is wrong"
    assert result["rules_after"] == result["rules_before"] - 1


def test_revoking_log_access_refuses_when_the_role_never_had_it():
    """⛔ Injecting nothing and calling it a fault would score the model against a healthy cluster."""
    rbac = FakeRbac(rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]}])
    with pytest.raises(OpError, match="measure nothing"):
        OPS["k8s_revoke_log_access"](_clients(rbac=rbac), _target())


def test_rbac_is_restored_from_the_saved_rules():
    rbac = FakeRbac()
    target, clients = _target(), _clients(rbac=rbac)
    OPS["k8s_revoke_log_access"](clients, target)
    OPS["k8s_restore_log_access"](clients, target)
    assert {tuple(r["resources"]) for r in rbac.patched[-1]} == {("pods",), ("pods/log",), ("events",)}


# --------------------------------------------------------------------------- dispatch


def test_the_catalog_dispatches_through_the_shared_run_steps():
    """One dispatch loop for both waves: the performed-record and the unknown-op error cannot drift
    apart if there is only one of them."""
    apps = FakeApps()
    performed = run_steps(
        _clients(apps=apps), _target(),
        [{"op": "k8s_patch_variant", "variant": "bad_image"}], account="", registry=OPS,
    )
    assert performed[0]["op"] == "k8s_patch_variant"
    assert performed[0]["args"] == {"variant": "bad_image"}
    assert "this-tag-does-not-exist" in performed[0]["result"]["image"]


def test_an_unknown_op_names_the_kubernetes_registry_not_the_ecs_one():
    with pytest.raises(OpError, match="k8s_patch_variant"):
        run_steps(_clients(), _target(), [{"op": "ecs_deploy_variant"}], account="", registry=OPS)
