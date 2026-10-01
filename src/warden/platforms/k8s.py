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
_ENTRIES = {"k8s_restart", "k8s_scale"}


class KubernetesPlatformError(RuntimeError):
    pass


class KubernetesPlatform:
    def __init__(self, *, apps: Any = None, namespace: str | None = None, kubeconfig: str | None = None,
                 max_replicas: int = MAX_REPLICAS) -> None:
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
        self._apps = apps

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
        return {"namespace": {self._ns}, "deployment": {dep.metadata.name}, "current_replicas": _replicas(dep),
                "state": {"deployment": dep.metadata.name, "replicas": _replicas(dep),
                          "generation": dep.metadata.generation}}

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

    def apply(self, entry: str, params: dict[str, Any]) -> str:
        if entry not in _ENTRIES:
            raise KubernetesPlatformError(f"{entry} is not something the Kubernetes platform does "
                                          f"(it does {', '.join(sorted(_ENTRIES))} only)")
        self._same_namespace(params)
        if entry == "k8s_restart":
            return self._restart(params["deployment"])
        return self._scale(params["deployment"], params["replicas"])

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
            raise KubernetesPlatformError(f"namespace {params.get('namespace')!r} is not the one this platform "
                                          f"serves ({self._ns})")

    def _restart(self, deployment: str) -> str:
        stamp = datetime.now(UTC).isoformat()
        body = {"spec": {"template": {"metadata": {"annotations": {RESTARTED_AT: stamp}}}}}
        try:
            self._apps.patch_namespaced_deployment(deployment, self._ns, body, _request_timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            raise KubernetesPlatformError(f"rollout restart of {deployment} failed: {_one_line(exc)}") from exc
        return f"rollout restart of deployment/{deployment} in {self._ns} (restartedAt={stamp})"

    def _scale(self, deployment: str, replicas: Any) -> str:
        try:
            current = _replicas(self._read(deployment))
        except Exception as exc:
            raise KubernetesPlatformError(f"could not read deployment/{deployment}: {_one_line(exc)}") from exc
        # The catalogue's bound, again, against what was just read: the count may have moved since the
        # approval, and an approved "4" means "one or two above what we saw", not "4 whatever happens".
        if not isinstance(replicas, int) or isinstance(replicas, bool) \
                or not (current < replicas <= min(current + 2, self._max)) or replicas < 1:
            raise KubernetesPlatformError(f"scaling deployment/{deployment} to {replicas!r} is outside the bound "
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
            if getattr(exc, "status", None) in (409, 422):
                raise KubernetesPlatformError(f"deployment/{deployment} no longer has {expect} replica(s): "
                                              f"something else scaled it; nothing was changed") from exc
            raise KubernetesPlatformError(f"scaling deployment/{deployment} failed: {_one_line(exc)}") from exc
        return f"scaled deployment/{deployment} in {self._ns} from {expect} to {to} replica(s)"


def _replicas(dep: Any) -> int:
    return dep.spec.replicas if dep.spec.replicas is not None else 1


def _one_line(value: Any) -> str:
    text = str(value).strip()
    return (text.splitlines()[0] if text else "")[:200]
