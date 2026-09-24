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
    """Applies patches the way the API server does, and keeps the resulting state.

    ⛔ A fake that only RECORDED patches let a real bug through: the revert left a livenessProbe
    on the live cluster, and the test asserted "livenessProbe is not in the patch" - which is the
    bug, not the fix. A strategic-merge patch merges `containers` BY NAME and keeps every field the
    patch does not mention; only an explicit null deletes one. Tests now assert on `container()`,
    the state after the patch, which is what the next scenario actually runs against.
    """

    def __init__(self):
        self.patches: list[dict] = []
        self.scales: list[int] = []
        self.live = {"spec": {"template": {"spec": {"containers": [
            {"name": "checkout", "image": BASELINE_IMAGE,
             "command": ["python", "-u", "-c", "print('healthy')"],
             "imagePullPolicy": "IfNotPresent"},
        ]}}}}

    def read_namespaced_deployment(self, *, name, namespace, **_kw):
        import copy
        return copy.deepcopy(self.live)

    def patch_namespaced_deployment(self, *, name, namespace, body):
        import copy
        self.patches.append(copy.deepcopy(body))
        live = self.live["spec"]["template"]["spec"]["containers"]
        for patch in body["spec"]["template"]["spec"]["containers"]:
            current = next((c for c in live if c["name"] == patch["name"]), None)
            if current is None:
                live.append({k: v for k, v in patch.items() if v is not None})
                continue
            for key, value in patch.items():
                if value is None:
                    current.pop(key, None)
                else:
                    current[key] = copy.deepcopy(value)
        return {}

    def container(self) -> dict:
        return self.live["spec"]["template"]["spec"]["containers"][0]

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
    assert "livenessProbe" in apps.container()
    OPS["k8s_patch_variant"](clients, target, variant="oom")
    assert "livenessProbe" not in apps.container(), "the probe survived into the next variant"


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


def test_the_revert_removes_a_field_the_fault_added():
    """⛔ THE BUG THAT STOPPED THE FIRST LIVE WAVE 2 RUN AT k8s-07. The bad_probe variant ADDS a
    livenessProbe the baseline never had. Re-sending the saved container as a merge patch leaves
    it in place - image and command revert, the probe stays, and every pod keeps being killed.
    The baseline gate caught it; this catches it before a cluster exists."""
    apps = FakeApps()
    target, clients = _target(), _clients(apps=apps)
    before = dict(apps.container())

    OPS["k8s_patch_variant"](clients, target, variant="bad_probe")
    OPS["k8s_restore_baseline"](clients, target)

    assert "livenessProbe" not in apps.container(), "the revert left the fault's probe behind"
    assert apps.container() == before, "the revert must leave the container exactly as it was"


@pytest.mark.parametrize("variant", ["oom", "oom_same_image", "bad_image", "exit_one", "bad_probe"])
def test_every_variant_reverts_to_exactly_the_baseline(variant):
    """Each variant, injected and reverted, must leave the container byte-for-byte as it started.
    Not just the one that failed live: any variant adding a field would fail the same way."""
    apps = FakeApps()
    target, clients = _target(), _clients(apps=apps)
    before = dict(apps.container())

    OPS["k8s_patch_variant"](clients, target, variant=variant)
    assert apps.container() != before, "the variant did not change anything - not a fault"
    OPS["k8s_restore_baseline"](clients, target)

    assert apps.container() == before


def test_restoring_without_a_saved_spec_refuses_rather_than_guessing():
    with pytest.raises(OpError, match="refusing to guess"):
        OPS["k8s_restore_baseline"](_clients(), _target())


class ModelRbac:
    """RBAC the way the REAL client returns it and the REAL server accepts it.

    ⛔ `read_cluster_role` returns a kubernetes client MODEL, not a dict - and a model's
    `to_dict()` uses Python attribute names (`api_groups`). Sent back unchanged, the API server
    ignores those as unknown fields, sees no `apiGroups`, and rejects the ClusterRole with 422 -
    which is exactly how k8s-09 failed on EKS. FakeRbac returns camelCase dicts, so it could never
    show this; this one reproduces both halves.
    """

    def __init__(self):
        from kubernetes import client as k
        self._k = k
        self.rules = [
            k.V1PolicyRule(api_groups=[""], resources=["pods"], verbs=["list"]),
            k.V1PolicyRule(api_groups=[""], resources=["pods/log"], verbs=["get"]),
            k.V1PolicyRule(api_groups=[""], resources=["events"], verbs=["list"]),
            k.V1PolicyRule(api_groups=["apps"], resources=["deployments"], verbs=["get"]),
        ]
        self.patched: list[list[dict]] = []

    def read_cluster_role(self, *, name):
        return self._k.V1ClusterRole(rules=list(self.rules))

    def patch_cluster_role(self, *, name, body):
        for i, rule in enumerate(body["rules"]):
            if not isinstance(rule, dict) or "apiGroups" not in rule:
                raise ValueError(f"422: rules[{i}].apiGroups: Required value (got keys {sorted(rule)})")
        self.patched.append(body["rules"])
        return {}


def test_revoking_log_access_sends_rules_the_api_server_accepts():
    """⛔ THE k8s-09 FAILURE ON EKS: rules read as a client model came back as `api_groups`."""
    rbac = ModelRbac()
    target, clients = _target(), _clients(rbac=rbac)

    OPS["k8s_revoke_log_access"](clients, target)

    sent = rbac.patched[-1]
    assert all("apiGroups" in r for r in sent)
    assert not any("pods/log" in r["resources"] for r in sent), "log access was not removed"
    assert len(sent) == 3


def test_restoring_log_access_puts_back_exactly_the_original_rules():
    rbac = ModelRbac()
    target, clients = _target(), _clients(rbac=rbac)

    OPS["k8s_revoke_log_access"](clients, target)
    OPS["k8s_restore_log_access"](clients, target)

    restored = rbac.patched[-1]
    assert all("apiGroups" in r for r in restored)
    assert [r["resources"] for r in restored] == [["pods"], ["pods/log"], ["events"], ["deployments"]]
    assert restored[3]["apiGroups"] == ["apps"]


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
