"""Kubernetes behind the RemediationWorkflow: `k8s_restart` and `k8s_scale` (decision D16).

The workflow decides whether to act; this carries out one approved entry on one Deployment and keeps
the safety properties of the old in-process backend (remediation_k8s.py, removed):
- two things only, a rollout restart and a scale; every other entry is refused loudly;
- a scale writes only if the replica count is still the one just read (a JSON Patch `test` op), and
  re-checks its bounds against that read: above the current count, at most two more, never above the
  ceiling, never below 1 - a count that moved since the approval is refused, never stepped from;
- a restart sets the `kubectl.kubernetes.io/restartedAt` template annotation, as `kubectl rollout
  restart` does;
- its credentials are a separate ServiceAccount that can patch Deployments and nothing else
  (`k8s/remediation-rbac.yaml`) - the RBAC, not this code, is the real boundary.
`k8s_rollout_undo` reads no revisions here yet, so the catalogue refuses it: it needs to read
ReplicaSets and write a pod template, which waits for a ValidatingAdmissionPolicy (audit A-I-11).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

REQUEST_TIMEOUT = (float(os.environ.get("WARDEN_K8S_CONNECT_TIMEOUT", "3.0")),
                   float(os.environ.get("WARDEN_K8S_READ_TIMEOUT", "4.0")))
MAX_REPLICAS = int(os.environ.get("WARDEN_REMEDIATION_MAX_REPLICAS", "10"))
RESTARTED_AT = "kubectl.kubernetes.io/restartedAt"
# The Deployment's own label naming its environment (P18, register S6): one without it is in no environment WARDEN
# may change.
ENV_LABEL = os.environ.get("WARDEN_K8S_ENV_LABEL", "environment")
_ENTRIES = {"k8s_restart", "k8s_scale"}
# Register C4: controllers that undo a direct change. A Deployment carrying one of these is reconciled from Git by
# Argo CD or Flux, whose self-heal reverts what WARDEN patched. (`app.kubernetes.io/instance` alone is not counted:
# Helm sets it too, and Helm does not self-heal.)
_GITOPS = {"argocd.argoproj.io/tracking-id": "Argo CD", "argocd.argoproj.io/instance": "Argo CD",
           "kustomize.toolkit.fluxcd.io/name": "Flux", "helm.toolkit.fluxcd.io/name": "Flux"}


class KubernetesPlatformError(RuntimeError):
    pass


class KubernetesPlatformRefused(KubernetesPlatformError):
    """Refused before anything was written: the workflow reports "nothing was changed" (sixth review)."""

    nothing_changed = True


class KubernetesPlatform:
    def __init__(self, *, apps: Any = None, namespace: str | None = None, kubeconfig: str | None = None,
                 max_replicas: int = MAX_REPLICAS, autoscaling: Any = None) -> None:
        self._ns = namespace or os.environ.get("WARDEN_K8S_NAMESPACE", "default")
        self._max = max_replicas
        if apps is None:
            from kubernetes import client, config

            try:
                config.load_incluster_config()
            except config.ConfigException:
                try:
                    config.load_kube_config(config_file=kubeconfig)
                except config.ConfigException as exc:
                    raise KubernetesPlatformError(f"no cluster credentials (not in-cluster, no kubeconfig): "
                                                  f"{_one_line(exc)}") from exc
            apps = client.AppsV1Api()
            autoscaling = autoscaling or client.AutoscalingV2Api()
        self._apps = apps
        self._autoscaling = autoscaling  # None: whether an HPA owns the count is unknown, and a scale is refused

    # ------------------------------------------------------------------ reads

    def _read(self, deployment: str) -> Any:
        return self._apps.read_namespaced_deployment(deployment, self._ns, _request_timeout=REQUEST_TIMEOUT)

    def live(self, entry: str, params: dict[str, Any]) -> dict[str, Any]:
        """The namespace WARDEN serves and - if the named Deployment exists there - that Deployment, its
        replica count and a snapshot that changes with any change to its spec. One `get`: the write
        ServiceAccount may get and patch Deployments and nothing else, not even list. Nothing read means
        nothing allowed."""
        name = params.get("deployment")
        if entry not in _ENTRIES or not isinstance(name, str):
            return {}
        try:
            dep = self._read(name)
        except Exception:  # noqa: BLE001 - absent or unreadable allows nothing; the catalogue refuses
            return {}
        labels = getattr(dep.metadata, "labels", None) or {}
        return {"namespace": {self._ns}, "deployment": {dep.metadata.name}, "current_replicas": _replicas(dep),
                "environment": labels.get(ENV_LABEL), "rollout": _rollout(dep), "at_once": _at_once(dep),
                "gitops": _gitops(dep), "autoscaled": self._autoscaled(dep.metadata.name),
                "state": {"deployment": dep.metadata.name, "replicas": _replicas(dep),
                          "generation": dep.metadata.generation, "server": self._server()}}

    def _autoscaled(self, deployment: str) -> bool | None:
        """Does a HorizontalPodAutoscaler own this Deployment's replica count (register C4)? None when it cannot be
        read: the remediator's role lists HPAs and nothing else of theirs (k8s/remediation-rbac.yaml)."""
        if self._autoscaling is None:
            return None
        try:
            hpas = self._autoscaling.list_namespaced_horizontal_pod_autoscaler(
                self._ns, _request_timeout=REQUEST_TIMEOUT).items or []
        except Exception:  # noqa: BLE001 - unknown, and a scale is refused
            return None
        return any(getattr(getattr(h.spec, "scale_target_ref", None), "kind", "") == "Deployment"
                   and getattr(h.spec.scale_target_ref, "name", "") == deployment for h in hpas)

    def _server(self) -> str:
        """The API server this platform writes to, in the plan the approver signs: staging's plan and prod's no
        longer look the same (sixth review, 2026-10-01). No credential is in it."""
        config = getattr(getattr(self._apps, "api_client", None), "configuration", None)
        host = str(getattr(config, "host", "") or "")
        # In a cluster the address is the `kubernetes` Service's IP - the same in every cluster (seventh review,
        # 2026-10-01): the operator names the cluster.
        name = os.environ.get("WARDEN_CLUSTER_NAME", "").strip()
        return f"{name} ({host})" if name else host

    def knows(self, service: str) -> bool:
        try:
            self._read(service)
        except Exception:  # noqa: BLE001 - not found or unreadable: not this platform's service
            return False
        return True

    def healthy(self, service: str) -> bool:
        """Every desired replica updated and available - a positive signal, never the absence of a bad one."""
        try:
            dep = self._read(service)
        except Exception:  # noqa: BLE001 - unknown is not healthy
            return False
        want, status = _replicas(dep), dep.status
        if not status:
            return False
        # The controller must have seen the current spec, and the rollout must not have stalled: counts from
        # before the change, or from a rollout past its deadline, are not recovery (sixth review, 2026-10-01).
        seen, generation = getattr(status, "observed_generation", None), getattr(dep.metadata, "generation", None)
        if generation is not None and (seen is None or seen < generation):
            return False
        if any(getattr(c, "type", "") == "Progressing" and getattr(c, "status", "") == "False"
               for c in getattr(status, "conditions", None) or []):
            return False
        return want >= 1 and (status.available_replicas or 0) >= want \
            and (status.updated_replicas or 0) >= want and not (status.unavailable_replicas or 0)

    # ------------------------------------------------------------------ writes

    def apply(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any] | None = None) -> str:
        if entry not in _ENTRIES:
            raise KubernetesPlatformRefused(f"{entry} is not something the Kubernetes platform does "
                                          f"(it does {', '.join(sorted(_ENTRIES))} only)")
        self._same_namespace(params)
        if entry == "k8s_restart":
            return self._restart(params["deployment"])
        approved = (snapshot or {}).get("replicas")
        return self._scale(params["deployment"], params["replicas"], approved if isinstance(approved, int) else None)

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any]) -> str:
        self._same_namespace(params)
        if entry == "k8s_restart":
            # A restart changes only the template's restartedAt annotation: the old pods are gone, and a second
            # restart would not bring them back (sixth review: "changes no spec" was wrong).
            return "nothing to roll back: a restart replaced the pods, and the old ones cannot come back"
        if entry == "k8s_scale":
            before = snapshot.get("replicas")
            if not isinstance(before, int) or before < 1:
                raise KubernetesPlatformError("the plan holds no replica count to return to")
            return self._write_replicas(params["deployment"], expect=params["replicas"], to=before)
        raise KubernetesPlatformError(f"{entry} is not something the Kubernetes platform does")

    def _same_namespace(self, params: dict[str, Any]) -> None:
        if params.get("namespace") != self._ns:
            raise KubernetesPlatformRefused(f"namespace {params.get('namespace')!r} is not the one this platform "
                                          f"serves ({self._ns})")

    def _restart(self, deployment: str) -> str:
        stamp = datetime.now(UTC).isoformat()
        body = {"spec": {"template": {"metadata": {"annotations": {RESTARTED_AT: stamp}}}}}
        try:
            self._apps.patch_namespaced_deployment(deployment, self._ns, body, _request_timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            _refused_by_the_server(exc, deployment)
            raise KubernetesPlatformError(f"rollout restart of {deployment} failed: {_one_line(exc)}") from exc
        return f"rollout restart of deployment/{deployment} in {self._ns} (restartedAt={stamp})"

    def _scale(self, deployment: str, replicas: Any, approved: int | None = None) -> str:
        try:
            current = _replicas(self._read(deployment))
        except Exception as exc:
            raise KubernetesPlatformRefused(f"could not read deployment/{deployment}: {_one_line(exc)}") from exc
        # The count the approver saw, not one that moved since: a move between the final precheck and this
        # read was stepped from (2 -> 4 with 3 approved) - sixth review, 2026-10-01.
        if approved is not None and current != approved:
            raise KubernetesPlatformRefused(f"deployment/{deployment} has {current} replica(s), not the {approved} "
                                          f"the plan was approved on; nothing was changed")
        # The catalogue's bound, again, against what was just read: the count may have moved since the
        # approval, and an approved "4" means "one or two above what we saw", not "4 whatever happens".
        if not isinstance(replicas, int) or isinstance(replicas, bool) \
                or not (current < replicas <= min(current + 2, self._max)) or replicas < 1:
            raise KubernetesPlatformRefused(f"scaling deployment/{deployment} to {replicas!r} is outside the bound "
                                          f"(above {current}, at most {min(current + 2, self._max)})")
        return self._write_replicas(deployment, expect=current, to=replicas)

    def _write_replicas(self, deployment: str, *, expect: int, to: int) -> str:
        # Conditioned on spec.replicas, not on the object's version: a Deployment's resourceVersion moves
        # whenever its controller writes status. The API server rejects the whole patch if `test` fails.
        patch = [{"op": "test", "path": "/spec/replicas", "value": expect},
                 {"op": "replace", "path": "/spec/replicas", "value": to}]
        try:
            self._apps.patch_namespaced_deployment(deployment, self._ns, patch,
                                                   _content_type="application/json-patch+json",
                                                   _request_timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            # A 422 is the JSON Patch `test` failing (the count moved) unless the admission policy is what refused it -
            # "test" in a Deployment's name (`latest-api`) read a policy refusal as a moved count (eighth review).
            if getattr(exc, "status", None) == 409 or (getattr(exc, "status", None) == 422 and not _a_policy(exc)):
                raise KubernetesPlatformRefused(f"deployment/{deployment} no longer has {expect} replica(s): "
                                              f"something else scaled it; nothing was changed") from exc
            _refused_by_the_server(exc, deployment)
            raise KubernetesPlatformError(f"scaling deployment/{deployment} failed: {_one_line(exc)}") from exc
        return f"scaled deployment/{deployment} in {self._ns} from {expect} to {to} replica(s)"


def _never_sent(exc: BaseException) -> bool:
    """A connection refused or never established (urllib3's NewConnectionError, inside the client's MaxRetryError):
    the request never left - unlike a timeout or a reset, after which nobody knows."""
    seen, todo = set(), [exc]
    while todo:
        e = todo.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        if isinstance(e, ConnectionRefusedError) or type(e).__name__ in ("NewConnectionError", "NameResolutionError"):
            return True
        todo += [getattr(e, "reason", None) if isinstance(getattr(e, "reason", None), BaseException) else None,
                 e.__cause__, e.__context__]
    return False


def _a_policy(exc: Exception) -> bool:
    """An admission policy's refusal, as the API server words it ("ValidatingAdmissionPolicy ... denied request")."""
    return "denied request" in str(exc) or "AdmissionPolicy" in str(exc)


def _refused_by_the_server(exc: Exception, deployment: str) -> None:
    """A write the API server refused - RBAC (403) or an admission policy (403/422) - was never persisted: nothing
    changed, and the run ends refused, not "may be half-made" (seventh review, 2026-10-01)."""
    if _never_sent(exc):
        # No connection was made, so nothing was written - and an unreachable API server tripped the global kill
        # switch through apply_failed (eighth review, 2026-10-01).
        raise KubernetesPlatformRefused(f"could not reach the API server for deployment/{deployment} "
                                      f"({_one_line(exc)}); nothing was sent") from exc
    if getattr(exc, "status", None) in (403, 422):
        raise KubernetesPlatformRefused(f"the API server refused the write to deployment/{deployment} "
                                      f"(RBAC or an admission policy: {_one_line(getattr(exc, 'reason', '') or exc)}); "
                                      f"nothing was changed") from exc


def _gitops(dep: Any) -> str:
    """The GitOps controller reconciling this Deployment, by its own labels and annotations; "" for none (C4)."""
    meta = dep.metadata
    marks = {**(getattr(meta, "labels", None) or {}), **(getattr(meta, "annotations", None) or {})}
    return next((who for key, who in _GITOPS.items() if key in marks), "")


def _at_once(dep: Any) -> int | None:
    """How many pods a restart may take down together, by the Deployment's own strategy (register C10): every one
    for Recreate; for RollingUpdate maxUnavailable, a percentage rounded down as Kubernetes rounds it. None when the
    strategy cannot be read."""
    import math

    strategy = getattr(dep.spec, "strategy", None)
    kind = getattr(strategy, "type", None)
    if kind == "Recreate":
        return _replicas(dep)
    rolling = getattr(strategy, "rolling_update", None)
    value = getattr(rolling, "max_unavailable", None)
    if kind != "RollingUpdate" or value is None:
        return None
    if isinstance(value, str) and value.endswith("%") and value[:-1].isdigit():
        return math.floor(_replicas(dep) * int(value[:-1]) / 100)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _rollout(dep: Any) -> str:
    """`progressing` while a rollout is under way inside its deadline, `stalled` once it missed it, else `complete` -
    `kubectl rollout status`'s reading. A bad revision crash-looping reads `progressing` until its deadline (600 s by
    default) and `stalled` after: the rollback that fixes it is refused for that long, not for ever (register C5)."""
    st = dep.status
    for c in getattr(st, "conditions", None) or []:
        if getattr(c, "type", "") == "Progressing" and getattr(c, "reason", "") == "ProgressDeadlineExceeded":
            return "stalled"
    want, updated = _replicas(dep), st.updated_replicas or 0
    if ((st.observed_generation or 0) < (dep.metadata.generation or 0) or updated < want
            or (getattr(st, "replicas", None) or updated) > updated or (st.available_replicas or 0) < updated):
        return "progressing"
    return "complete"


def _replicas(dep: Any) -> int:
    return dep.spec.replicas if dep.spec.replicas is not None else 1


def _one_line(value: Any) -> str:
    text = str(value).strip()
    return (text.splitlines()[0] if text else "")[:200]
