"""A REAL, gated Kubernetes remediation backend — the opt-in write path.

`KubernetesBackend` (k8s_backend.py) is read-only by construction. This is its deliberate opposite:
the one place AEGIS can actually change a cluster. It is kept small, separate, and hard to reach:

  - it does exactly TWO reversible things — a rollout **restart** and a **scale** (up/down) — and
    refuses every other action loudly. No delete, no rollback, no failover, no cache flush: those are
    either irreversible or high-blast-radius, and this backend does not know how to do them on purpose.
  - it never runs unless `resolve_remediation_backend()` is explicitly armed (`AEGIS_REMEDIATION=live`),
    AND the four-way gate in remediation.py already passed (env auto-remediates × authorised principal
    × approval × an admissible action). Arming it is necessary, never sufficient.
  - its write permission is a SEPARATE ServiceAccount (`k8s/remediation-rbac.yaml`) that can `patch`
    deployments and nothing else — the RBAC, not this code, is the real boundary, exactly as it is for
    the read path. The read-only `aegis` SA is untouched.

Scaling is clamped: never below 1, never above AEGIS_REMEDIATION_MAX_REPLICAS. A restart sets the
standard `kubectl.kubernetes.io/restartedAt` template annotation, which is what `kubectl rollout
restart` itself does — the kube controllers do the rest, and it is fully reversible.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from .models import ActionKind
from .remediation import RemediationError

REQUEST_TIMEOUT = (
    float(os.environ.get("AEGIS_K8S_CONNECT_TIMEOUT", "3.0")),
    float(os.environ.get("AEGIS_K8S_READ_TIMEOUT", "4.0")),
)
SCALE_STEP = int(os.environ.get("AEGIS_REMEDIATION_SCALE_STEP", "1"))
MAX_REPLICAS = int(os.environ.get("AEGIS_REMEDIATION_MAX_REPLICAS", "10"))

# The only actions this backend will carry out. Everything else is refused — see the module docstring.
_SUPPORTED = {ActionKind.restart_pods, ActionKind.scale_up, ActionKind.scale_down}


class KubernetesRemediationBackend:
    """Applies a restart or a scale to one Deployment. `live = True` — it really acts."""

    live = True

    def __init__(self, *, apps=None, namespace: str | None = None, kubeconfig: str | None = None) -> None:
        self._ns = namespace or os.environ.get("AEGIS_K8S_NAMESPACE", "default")
        if apps is None:
            from kubernetes import client, config

            try:
                config.load_incluster_config()
            except config.ConfigException:
                try:
                    config.load_kube_config(config_file=kubeconfig)
                except config.ConfigException as exc:
                    raise RemediationError(
                        "AEGIS_REMEDIATION=live but no cluster credentials were found "
                        f"(not in-cluster, and no usable kubeconfig): {exc}"
                    ) from exc
            apps = client.AppsV1Api()
        self._apps = apps

    def apply(self, action: ActionKind, target: str, environment: str) -> str:
        """Carry out `action` on Deployment `target`. Raises RemediationError on refusal or fault."""
        if action not in _SUPPORTED:
            raise RemediationError(
                f"{action.value} is not something the k8s remediation backend performs "
                f"(it does restart_pods / scale_up / scale_down only)"
            )
        if action is ActionKind.restart_pods:
            return self._restart(target)
        return self._scale(action, target)

    # ------------------------------------------------------------------ actions

    def _restart(self, deployment: str) -> str:
        stamp = datetime.now(UTC).isoformat()
        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {"kubectl.kubernetes.io/restartedAt": stamp}
                    }
                }
            }
        }
        try:
            self._apps.patch_namespaced_deployment(
                deployment, self._ns, body, _request_timeout=REQUEST_TIMEOUT
            )
        except Exception as exc:
            raise RemediationError(f"rollout restart of {deployment} failed: {_one_line(exc)}") from exc
        return f"rollout restart of deployment/{deployment} in {self._ns} (restartedAt={stamp})"

    def _scale(self, action: ActionKind, deployment: str) -> str:
        try:
            dep = self._apps.read_namespaced_deployment(
                deployment, self._ns, _request_timeout=REQUEST_TIMEOUT
            )
        except Exception as exc:
            raise RemediationError(f"could not read deployment/{deployment}: {_one_line(exc)}") from exc

        current = dep.spec.replicas if dep.spec.replicas is not None else 1
        if action is ActionKind.scale_up:
            target = min(current + SCALE_STEP, MAX_REPLICAS)
        else:  # scale_down — never to zero; that is an outage, not a remediation
            target = max(current - SCALE_STEP, 1)

        if target == current:
            return f"deployment/{deployment} already at {current} replica(s); no change (bounds hit)"

        try:
            self._apps.patch_namespaced_deployment(
                deployment, self._ns, {"spec": {"replicas": target}}, _request_timeout=REQUEST_TIMEOUT
            )
        except Exception as exc:
            raise RemediationError(f"scaling deployment/{deployment} failed: {_one_line(exc)}") from exc
        return f"scaled deployment/{deployment} in {self._ns} from {current} to {target} replica(s)"


def resolve_remediation_backend():
    """The backend `decide_remediation` should use. DRY-RUN unless explicitly armed.

    Default (unset / anything but 'live'): a DryRunBackend that changes nothing. Set
    AEGIS_REMEDIATION=live to arm the real Kubernetes backend — necessary, never sufficient: the
    four-way policy gate still has to pass before it is ever called.
    """
    from .remediation import DryRunBackend

    if os.environ.get("AEGIS_REMEDIATION", "").lower() == "live":
        return KubernetesRemediationBackend()
    return DryRunBackend()


def _one_line(value) -> str:
    text = str(value).strip()
    first = text.splitlines()[0] if text else ""
    return first[:200]
