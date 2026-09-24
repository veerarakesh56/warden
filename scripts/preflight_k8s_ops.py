"""Before a live Kubernetes wave: send every op's exact request to the REAL API server, dry-run.

    python scripts/preflight_k8s_ops.py [--context CONTEXT]      # default: warden-eks

Every mutating call carries dryRun=All, so the server validates it completely - schema, admission,
RBAC field rules - and persists nothing. Exits non-zero if the server rejects anything.

⛔ WHY THIS EXISTS. Test fakes let two harness bugs reach a billed EKS cluster in one run:
  - a strategic-merge revert that could not DELETE a field the fault had added (k8s-06's probe);
  - ClusterRole rules serialised with Python attribute names (`api_groups`), which the server
    rejected with 422 halfway through k8s-09.
Both passed every unit test, because the fakes accepted what the real server does not. This asks
the real server instead. Watched catch the second bug: with the old serialiser it REJECTS the
revoke, with the fix it accepts all 16 calls.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from kubernetes import client as k
from kubernetes import config
from scenarios import ops_k8s
from scenarios.runner import K8S_CLUSTER_ROLE, K8S_DEPLOYMENT, K8S_NAMESPACE, K8S_SERVICE_ACCOUNT

context = sys.argv[sys.argv.index("--context") + 1] if "--context" in sys.argv else "warden-eks"
config.load_kube_config(context=context)


class DryRun:
    """Wraps a real API object; every mutating call gets dry_run='All'."""
    MUTATING = ("patch_", "delete_", "create_", "replace_")

    def __init__(self, api):
        self._api = api
        self.calls = []

    def __getattr__(self, name):
        attr = getattr(self._api, name)
        if not name.startswith(self.MUTATING):
            return attr

        def call(*a, **kw):
            kw["dry_run"] = "All"
            self.calls.append(name)
            return attr(*a, **kw)
        return call


core, apps, rbac = DryRun(k.CoreV1Api()), DryRun(k.AppsV1Api()), DryRun(k.RbacAuthorizationV1Api())
clients = ops_k8s.Clients(core=core, apps=apps, rbac=rbac)
live = ops_k8s._read_deployment(clients, ops_k8s.Target(
    context=context, namespace=K8S_NAMESPACE, deployment=K8S_DEPLOYMENT, container=K8S_DEPLOYMENT,
    baseline_image="", service_account=K8S_SERVICE_ACCOUNT, cluster_role=K8S_CLUSTER_ROLE))
image = live["spec"]["template"]["spec"]["containers"][0]["image"]


def target():
    return ops_k8s.Target(
        context=context, namespace=K8S_NAMESPACE, deployment=K8S_DEPLOYMENT,
        container=K8S_DEPLOYMENT, baseline_image=image,
        service_account=K8S_SERVICE_ACCOUNT, cluster_role=K8S_CLUSTER_ROLE)


checks = [(f"variant {v} + restore", [("k8s_patch_variant", {"variant": v}), ("k8s_restore_baseline", {})])
          for v in sorted(ops_k8s._VARIANTS)]
checks += [
    ("scale to 0 + back to 2", [("k8s_scale", {"replicas": 0}), ("k8s_scale", {"replicas": 2})]),
    ("delete one pod", [("k8s_delete_one_pod", {})]),
    ("revoke + restore log access", [("k8s_revoke_log_access", {}), ("k8s_restore_log_access", {})]),
    ("rollout restart", [("k8s_rollout_restart", {})]),
]
failed = 0
for label, steps in checks:
    t = target()
    try:
        for op, args in steps:
            ops_k8s.OPS[op](clients, t, **args)
        print(f"ACCEPTED  {label}")
    except Exception as exc:  # noqa: BLE001
        failed += 1
        msg = str(exc).splitlines()
        body = next((line for line in msg if line.startswith("HTTP response body")), msg[0])
        print(f"REJECTED  {label}: {type(exc).__name__}: {body[:300]}")
print(f"\nmutating calls sent with dryRun=All: {len(apps.calls) + len(rbac.calls) + len(core.calls)}")
print("ALL ACCEPTED BY THE REAL API SERVER" if not failed else f"{failed} REJECTED")
sys.exit(1 if failed else 0)
