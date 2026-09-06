"""A REAL, gated Kubernetes remediation backend — the opt-in write path.

`KubernetesBackend` (k8s_backend.py) is read-only by construction. This is its deliberate opposite:
the one place WARDEN can actually change a cluster. It is kept small, separate, and hard to reach:

  - it does exactly TWO reversible things — a rollout **restart** and a **scale** (up/down) — and
    refuses every other action loudly. No delete, no rollback, no failover, no cache flush: those are
    either irreversible or high-blast-radius, and this backend does not know how to do them on purpose.
  - it never runs unless `resolve_remediation_backend()` is explicitly armed (`WARDEN_REMEDIATION=live`),
    AND the four-way gate in remediation.py already passed (env auto-remediates × authorised principal
    × approval × an admissible action). Arming it is necessary, never sufficient.
  - its write permission is a SEPARATE ServiceAccount (`k8s/remediation-rbac.yaml`) that can `patch`
    deployments and nothing else — the RBAC, not this code, is the real boundary, exactly as it is for
    the read path. The read-only `warden` SA is untouched.

Scaling is clamped: never below 1, never above WARDEN_REMEDIATION_MAX_REPLICAS. A restart sets the
standard `kubectl.kubernetes.io/restartedAt` template annotation, which is what `kubectl rollout
restart` itself does — the kube controllers do the rest, and it is fully reversible.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from .models import ActionKind
from .remediation import RemediationError

REQUEST_TIMEOUT = (
    float(os.environ.get("WARDEN_K8S_CONNECT_TIMEOUT", "3.0")),
    float(os.environ.get("WARDEN_K8S_READ_TIMEOUT", "4.0")),
)
SCALE_STEP = int(os.environ.get("WARDEN_REMEDIATION_SCALE_STEP", "1"))
MAX_REPLICAS = int(os.environ.get("WARDEN_REMEDIATION_MAX_REPLICAS", "10"))
# A Deployment's resourceVersion churns because its own controller writes `status`, so a
# read-then-write needs bounded retries rather than a whole-object precondition.
SCALE_CONFLICT_RETRIES = int(os.environ.get("WARDEN_REMEDIATION_SCALE_RETRIES", "3"))

# The only actions this backend will carry out. Everything else is refused — see the module docstring.
_SUPPORTED = {ActionKind.restart_pods, ActionKind.scale_up, ActionKind.scale_down}


class KubernetesRemediationBackend:
    """Applies a restart or a scale to one Deployment. `live = True` — it really acts."""

    live = True

    def __init__(self, *, apps=None, namespace: str | None = None, kubeconfig: str | None = None) -> None:
        self._ns = namespace or os.environ.get("WARDEN_K8S_NAMESPACE", "default")
        if apps is None:
            from kubernetes import client, config

            try:
                config.load_incluster_config()
            except config.ConfigException:
                try:
                    config.load_kube_config(config_file=kubeconfig)
                except config.ConfigException as exc:
                    raise RemediationError(
                        "WARDEN_REMEDIATION=live but no cluster credentials were found "
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
        """Step the replica count, conditional on the count we actually read.

        This is a read-then-write, so it needs a concurrency story. Sending
        `metadata.resourceVersion` as a precondition is the obvious one and it is WRONG here: a
        Deployment's resourceVersion is bumped by its own controller writing `status`, constantly
        and especially during an incident, so the precondition fails for reasons that have nothing
        to do with anyone changing `spec`. That was tried, and a real cluster rejected it with
        "the object has been modified" on the first attempt.

        So: re-read and recompute on conflict, bounded. That is the idiomatic Kubernetes pattern and
        it is also the semantically correct one for a *relative* step — if something else scaled the
        Deployment to 5 while we were deciding, stepping from 5 is right and stepping from the stale
        value is not. Nothing is ever clobbered, because the target is always derived from a fresh
        read. Sustained contention raises rather than looping.
        """
        last_conflict: Exception | None = None
        for _ in range(SCALE_CONFLICT_RETRIES):
            try:
                dep = self._apps.read_namespaced_deployment(
                    deployment, self._ns, _request_timeout=REQUEST_TIMEOUT
                )
            except Exception as exc:
                raise RemediationError(
                    f"could not read deployment/{deployment}: {_one_line(exc)}"
                ) from exc

            current = dep.spec.replicas if dep.spec.replicas is not None else 1
            if action is ActionKind.scale_up:
                target = min(current + SCALE_STEP, MAX_REPLICAS)
            else:  # scale_down — never to zero; that is an outage, not a remediation
                target = max(current - SCALE_STEP, 1)

            if target == current:
                return (
                    f"deployment/{deployment} already at {current} replica(s); "
                    f"no change (bounds hit)"
                )

            # Condition the write on the replica count we just read, not on the whole object's
            # version: we care whether `spec.replicas` moved, not whether the controller touched
            # `status`. A JSON Patch `test` op does exactly that, and the API server rejects the
            # whole patch if it does not hold.
            patch = [
                {"op": "test", "path": "/spec/replicas", "value": current},
                {"op": "replace", "path": "/spec/replicas", "value": target},
            ]
            try:
                self._apps.patch_namespaced_deployment(
                    deployment,
                    self._ns,
                    patch,
                    # A list body already selects this, but say it rather than rely on it.
                    _content_type="application/json-patch+json",
                    _request_timeout=REQUEST_TIMEOUT,
                )
            except Exception as exc:
                if getattr(exc, "status", None) in (409, 422):
                    # 409: the object moved. 422: the `test` op did not hold — someone else changed
                    # spec.replicas. Either way, re-read and recompute from the new truth.
                    last_conflict = exc
                    continue
                raise RemediationError(
                    f"scaling deployment/{deployment} failed: {_one_line(exc)}"
                ) from exc
            return (
                f"scaled deployment/{deployment} in {self._ns} "
                f"from {current} to {target} replica(s)"
            )

        raise RemediationError(
            f"deployment/{deployment} kept changing under us while scaling "
            f"({SCALE_CONFLICT_RETRIES} attempts); something else is actively scaling it — "
            f"refusing to fight it: {_one_line(last_conflict)}"
        )


class LiveRemediationRouter:
    """Sends an approved action to the backend that can actually perform it.

    Kubernetes actions (restart/scale) go to `KubernetesRemediationBackend`; `terminate_connections`
    goes to `DatabaseRemediationBackend`. Anything else is refused — a router that silently did
    nothing would be worse than one that says it cannot.

    Both delegates are built LAZILY, on first use of an action they own. A Kubernetes-only deployment
    therefore never needs database credentials, and a database-only one never needs a kubeconfig; a
    missing credential surfaces as a `failed` remediation naming the real reason, at the moment the
    action is actually attempted.
    """

    def __init__(self, *, k8s=None, database=None) -> None:
        self._k8s = k8s
        self._db = database
        # Provisional: overwritten per-apply with what the DELEGATE reports, because a database
        # backend may be running dry (WARDEN_DB_DRY_RUN=1) and the audit must not call that a change.
        self.live = True

    def _backend_for(self, action: ActionKind):
        if action in _SUPPORTED:
            if self._k8s is None:
                self._k8s = KubernetesRemediationBackend()
            return self._k8s
        if action is ActionKind.terminate_connections:
            if self._db is None:
                from .database_remediation import DatabaseRemediationBackend

                self._db = DatabaseRemediationBackend()
            return self._db
        raise RemediationError(
            f"{action.value} has no live remediation backend "
            "(restart_pods / scale_up / scale_down go to Kubernetes; "
            "terminate_connections goes to the database)"
        )

    def apply(self, action: ActionKind, target: str, environment: str) -> str:
        backend = self._backend_for(action)
        # Report the DELEGATE's honesty flag, so a dry-running database backend is recorded as a dry
        # run and a real Kubernetes patch is recorded as a change.
        self.live = bool(getattr(backend, "live", True))
        return backend.apply(action, target, environment)


def resolve_remediation_backend():
    """The backend `decide_remediation` should use. DRY-RUN unless explicitly armed.

    Default (unset / anything but 'live'): a DryRunBackend that changes nothing. Set
    WARDEN_REMEDIATION=live to arm the real backends — necessary, never sufficient: the four-way
    policy gate still has to pass before either of them is ever called.
    """
    from .remediation import DryRunBackend

    if os.environ.get("WARDEN_REMEDIATION", "").lower() == "live":
        return LiveRemediationRouter()
    return DryRunBackend()


def _one_line(value) -> str:
    text = str(value).strip()
    first = text.splitlines()[0] if text else ""
    return first[:200]
