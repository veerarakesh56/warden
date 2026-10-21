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
In the cloud runtime (`eks_from_environment`) each watched environment's EKS cluster is reached with no kubeconfig and
no in-cluster identity: reads in the environment's platform-reader role (its access entry: view only), and each write
in an actor session minted for that one approved plan, whose access entry maps it to the remediator group - the same
ClusterRole and admission policy, bound in the served namespace only.
`k8s_rollout_undo` reads no revisions here yet, so the catalogue refuses it: it needs to read
ReplicaSets and write a pod template, which waits for a ValidatingAdmissionPolicy (audit A-I-11).
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

REQUEST_TIMEOUT = (float(os.environ.get("WARDEN_K8S_CONNECT_TIMEOUT", "3.0")),
                   float(os.environ.get("WARDEN_K8S_READ_TIMEOUT", "4.0")))
MAX_REPLICAS = int(os.environ.get("WARDEN_REMEDIATION_MAX_REPLICAS", "10"))
RESTARTED_AT = "kubectl.kubernetes.io/restartedAt"
# Register R7-O3: a scale up records the count it replaced on the Deployment; the admission policy lets the remediator
# step a count down only back to that count, clearing the mark - so no series of patches takes a Deployment below where
# WARDEN found it.
SCALED_FROM = "warden.io/scaled-from"
_MARK = "/metadata/annotations/" + SCALED_FROM.replace("~", "~0").replace("/", "~1")
# The Deployment's own label naming its environment (P18, register S6): one without it is in no environment WARDEN
# may change.
ENV_LABEL = os.environ.get("WARDEN_K8S_ENV_LABEL", "environment")
_ENTRIES = {"k8s_restart", "k8s_scale"}
# Register C4: controllers that undo a direct change. A Deployment carrying one of these is reconciled from Git by
# Argo CD or Flux, whose self-heal reverts what WARDEN patched. (`app.kubernetes.io/instance` alone is not counted:
# Helm sets it too, and Helm does not self-heal.)
ARGO_CD = "Argo CD"
_GITOPS = {"argocd.argoproj.io/tracking-id": ARGO_CD, "argocd.argoproj.io/instance": ARGO_CD,
           "kustomize.toolkit.fluxcd.io/name": "Flux", "helm.toolkit.fluxcd.io/name": "Flux"}
# Where Argo CD keeps its Applications (its chart's default), unless an Application's tracking id names another.
ARGOCD_NAMESPACE = os.environ.get("WARDEN_ARGOCD_NAMESPACE", "argocd")
# The restart annotation as a JSON Pointer, as an Application's ignoreDifferences names it.
RESTART_POINTER = "/spec/template/metadata/annotations/" + RESTARTED_AT.replace("~", "~0").replace("/", "~1")


class KubernetesPlatformError(RuntimeError):
    pass


class KubernetesPlatformRefused(KubernetesPlatformError):
    """Refused before anything was written: the workflow reports "nothing was changed" (sixth review)."""

    nothing_changed = True


class KubernetesPlatform:
    def __init__(self, *, apps: Any = None, namespace: str | None = None, kubeconfig: str | None = None,
                 max_replicas: int = MAX_REPLICAS, autoscaling: Any = None,
                 writer: Callable[[dict[str, Any]], Any] | None = None, cluster_name: str | None = None,
                 custom: Any = None) -> None:
        self._ns = namespace or os.environ.get("WARDEN_K8S_NAMESPACE", "default")
        self._max = max_replicas
        # `writer`: an approved plan's who -> the client its writes go through (an actor session's). Without one,
        # writes go through `apps` - one identity for both, as in a cluster or with a kubeconfig.
        self._writer = writer
        self._cluster_name = cluster_name
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
            custom = custom or client.CustomObjectsApi()
        self._apps = apps
        self._custom = custom  # Argo CD's Applications; None: whether one ignores a restart is unknown, and refused
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
        live = {"namespace": {self._ns}, "deployment": {dep.metadata.name}, "current_replicas": _replicas(dep),
                "environment": labels.get(ENV_LABEL), "rollout": _rollout(dep), "at_once": _at_once(dep),
                "gitops": _gitops(dep), "autoscaled": self._autoscaled(dep.metadata.name),
                "state": {"deployment": dep.metadata.name, "replicas": _replicas(dep),
                          "generation": dep.metadata.generation, "server": self._server()}}
        if live["gitops"] == ARGO_CD and entry == "k8s_restart":
            live["gitops_ignores_restart"] = self._argo_ignores_restart(dep)
        return live

    def _argo_ignores_restart(self, dep: Any) -> bool:
        """Register C4, owner decision 2026-10-17: does the Argo CD Application tracking this Deployment ignore the
        restart annotation, so its self-heal leaves a restart in place? True only when proven, from the live
        Application: the Deployment's own tracking id names it and this exact Deployment, the Application deploys to
        this namespace, and an ignoreDifferences rule for this Deployment holds a JSON Pointer covering the
        annotation, with RespectIgnoreDifferences on. Anything else - no tracking id (label tracking), a Flux marker as
        well, an Application that cannot be read, a rule by jq expression only - is not proof, and the restart stays
        refused."""
        spec = self._tracking_application(dep.metadata)
        if spec is None or (spec.get("destination") or {}).get("namespace") != self._ns:
            return False
        # Without RespectIgnoreDifferences, a sync for any other reason applies Git's template and drops the restart
        # (Argo CD's sync options, review PR 48): the ignore is proof only with it.
        if "RespectIgnoreDifferences=true" not in ((spec.get("syncPolicy") or {}).get("syncOptions") or []):
            return False
        return any(_ignores_restart(rule, dep.metadata.name, self._ns) for rule in spec.get("ignoreDifferences") or [])

    def _tracking_application(self, meta: Any) -> dict[str, Any] | None:
        """The spec of the Argo CD Application whose tracking id names this exact Deployment, read live; None when there
        is none to read (label tracking, a Flux marker as well, no client, another resource's id, unreadable)."""
        marks = {**(getattr(meta, "labels", None) or {}), **(getattr(meta, "annotations", None) or {})}
        if self._custom is None or any(_GITOPS[k] == "Flux" for k in marks if k in _GITOPS):
            return None
        app, _, resource = str(marks.get("argocd.argoproj.io/tracking-id", "")).partition(":")
        if not app or resource != f"apps/Deployment:{self._ns}/{meta.name}":
            return None
        where, _, name = app.rpartition("_")  # `<namespace>_<name>` for an Application outside Argo CD's namespace
        try:
            found = self._custom.get_namespaced_custom_object("argoproj.io", "v1alpha1", where or ARGOCD_NAMESPACE,
                                                              "applications", name, _request_timeout=REQUEST_TIMEOUT)
        except Exception:  # noqa: BLE001  # unread is unproven
            return None
        spec = found.get("spec") if isinstance(found, dict) else None
        return spec if isinstance(spec, dict) else None

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
        name = self._cluster_name or os.environ.get("WARDEN_CLUSTER_NAME", "").strip()
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

    def apply(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any] | None = None,
              who: dict[str, Any] | None = None) -> str:
        if entry not in _ENTRIES:
            raise KubernetesPlatformRefused(f"{entry} is not something the Kubernetes platform does "
                                          f"(it does {', '.join(sorted(_ENTRIES))} only)")
        self._same_namespace(params)
        if entry == "k8s_restart":
            return self._restart(params["deployment"], self._for_write(who, params["deployment"]))
        approved = (snapshot or {}).get("replicas")
        return self._scale(params["deployment"], params["replicas"], approved if isinstance(approved, int) else None,
                           who)

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any],
                 who: dict[str, Any] | None = None) -> str:
        self._same_namespace(params)
        if entry == "k8s_restart":
            # A restart changes only the template's restartedAt annotation: the old pods are gone, and a second
            # restart would not bring them back (sixth review: "changes no spec" was wrong).
            return "nothing to roll back: a restart replaced the pods, and the old ones cannot come back"
        if entry == "k8s_scale":
            before = snapshot.get("replicas")
            if not isinstance(before, int) or before < 1:
                raise KubernetesPlatformError("the plan holds no replica count to return to")
            return self._write_replicas(params["deployment"], expect=params["replicas"], to=before,
                                        apps=self._for_write(who, params["deployment"]))
        raise KubernetesPlatformError(f"{entry} is not something the Kubernetes platform does")

    def _for_write(self, who: dict[str, Any] | None, deployment: str) -> Any:
        """The client this plan's write goes through, able to patch its one Deployment in the served namespace only.
        With a writer (the cloud), an actor session minted for this approved plan - never the reader's."""
        if self._writer is None:
            return _Bound(self._apps, self._ns, deployment)
        if not who or not who.get("approvers"):
            raise KubernetesPlatformRefused("a write needs the approved plan's actor session; nothing was changed")
        try:
            apps = self._writer(who)
        except Exception as exc:
            raise KubernetesPlatformRefused(f"no actor session for deployment/{deployment}: {_one_line(exc)}; "
                                          "nothing was changed") from exc
        return _Bound(apps, self._ns, deployment)

    def _same_namespace(self, params: dict[str, Any]) -> None:
        if params.get("namespace") != self._ns:
            raise KubernetesPlatformRefused(f"namespace {params.get('namespace')!r} is not the one this platform "
                                          f"serves ({self._ns})")

    def _restart(self, deployment: str, apps: Any) -> str:
        stamp = datetime.now(UTC).isoformat()
        body = {"spec": {"template": {"metadata": {"annotations": {RESTARTED_AT: stamp}}}}}
        try:
            apps.patch_namespaced_deployment(deployment, self._ns, body, _request_timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            _refused_by_the_server(exc, deployment)
            raise KubernetesPlatformError(f"rollout restart of {deployment} failed: {_one_line(exc)}") from exc
        return f"rollout restart of deployment/{deployment} in {self._ns} (restartedAt={stamp})"

    def _scale(self, deployment: str, replicas: Any, approved: int | None = None,
               who: dict[str, Any] | None = None) -> str:
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
        return self._write_replicas(deployment, expect=current, to=replicas, apps=self._for_write(who, deployment))

    def _write_replicas(self, deployment: str, *, expect: int, to: int, apps: Any = None) -> str:
        if apps is None:  # no plan's session given: without a writer the one client, held to this target
            apps = self._for_write(None, deployment)
        # Conditioned on spec.replicas, not on the object's version: a Deployment's resourceVersion moves
        # whenever its controller writes status. The API server rejects the whole patch if `test` fails.
        try:
            dep = self._read(deployment)
            marks = getattr(dep.metadata, "annotations", None) or {}
        except Exception as exc:
            raise KubernetesPlatformRefused(f"could not read deployment/{deployment}: {_one_line(exc)}") from exc
        if to > expect:  # the count this replaces, the floor of any later step down (R7-O3)
            note = [{"op": "add", "path": _MARK, "value": str(expect)} if marks else
                    {"op": "add", "path": "/metadata/annotations", "value": {SCALED_FROM: str(expect)}}]
        elif marks.get(SCALED_FROM) != str(to) and _replicas(dep) == expect:
            # (A count that moved is the `test` op's to refuse, as the server words it.)
            raise _own_check(KubernetesPlatformRefused(
                f"deployment/{deployment} was not scaled up from {to} by WARDEN (its {SCALED_FROM} mark is "
                f"{marks.get(SCALED_FROM)!r}); a step down goes only back to that count; nothing was changed"))
        else:
            note = [{"op": "test", "path": _MARK, "value": str(to)}, {"op": "remove", "path": _MARK}]
        patch = [{"op": "test", "path": "/spec/replicas", "value": expect},
                 {"op": "replace", "path": "/spec/replicas", "value": to}, *note]
        try:
            apps.patch_namespaced_deployment(deployment, self._ns, patch,
                                                   _content_type="application/json-patch+json",
                                                   _request_timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            # A 422 is the JSON Patch `test` failing (the count moved) unless the admission policy is what refused it -
            # "test" in a Deployment's name (`latest-api`) read a policy refusal as a moved count (eighth review).
            if getattr(exc, "status", None) == 409 or (getattr(exc, "status", None) == 422 and not _a_policy(exc)):
                raise _own_check(KubernetesPlatformRefused(f"deployment/{deployment} no longer has {expect} replica(s): "
                                                           "something else scaled it; nothing was changed")) from exc
            _refused_by_the_server(exc, deployment)
            raise KubernetesPlatformError(f"scaling deployment/{deployment} failed: {_one_line(exc)}") from exc
        return f"scaled deployment/{deployment} in {self._ns} from {expect} to {to} replica(s)"


class _Bound:
    """A write client held to one approved plan's target: a patch of any other Deployment, or in any other namespace,
    is refused before it is sent. On the server the RBAC (the served namespace) and the admission policy (what may
    change) are the boundary; this keeps one plan's session to its own Deployment."""

    def __init__(self, apps: Any, namespace: str, deployment: str) -> None:
        self._apps, self._target = apps, (namespace, deployment)

    def patch_namespaced_deployment(self, name: str, namespace: str, body: Any, **kw: Any) -> Any:
        if (namespace, name) != self._target:
            raise KubernetesPlatformRefused(f"deployment/{name} in {namespace} is not this plan's target "
                                          f"({self._target[1]} in {self._target[0]}); nothing was changed")
        return self._apps.patch_namespaced_deployment(name, namespace, body, **kw)


class _Fresh:
    """A client made again every `every` seconds. Its EKS token is signed once, when it is made, by the reader session's
    credentials - which platforms.reader_clients hands out with at least 300 s left (a 900 s session renewed after
    600 s) - so a client is never kept longer than that (review, PR 48)."""

    def __init__(self, make: Callable[[], Any], every: float = 240) -> None:
        self._make, self._every, self._held, self._until = make, every, None, 0.0
        self._lock = threading.Lock()

    def __getattr__(self, name: str) -> Any:
        with self._lock:
            if self._held is None or self._until < time.monotonic():
                self._held, self._until = self._make(), time.monotonic() + self._every
            return getattr(self._held, name)


def eks_from_environment() -> Any:
    """The Kubernetes platform of each watched environment's EKS cluster (WARDEN_EKS_CLUSTERS, `env=cluster`), for the
    cloud runtime. Reads: the environment's platform-reader role (`warden-<env>-platform-reader`; its access entry is
    view-only). Writes: an actor session (`warden-<env>-actor`) minted for one approved plan - SourceIdentity and session
    name the incident, tags the approvers - whose access entry maps it to the remediator group. Its session policy names
    the cluster and grants no AWS action (the actor role holds none for EKS): the session's one use is the cluster
    token. An environment with no cluster configured reads and writes nothing (platforms.Unconfigured): its plans are
    refused and go to a person."""
    import boto3
    from kubernetes import client

    from .. import identity
    from ..aws_stack import eks_cluster_of
    from ..environments import region
    from ..k8s_backend import eks_api_client
    from . import NotConfigured, PerEnvironment, reader_clients, role_arn, session_clients

    where = region()
    sts = boto3.client("sts", region_name=where)

    def build(env: str) -> KubernetesPlatform:
        cluster = eks_cluster_of(env)
        if not cluster:
            raise NotConfigured(f"no EKS cluster is configured for {env} (WARDEN_EKS_CLUSTERS)")
        reader, actor_arn = reader_clients(sts, where, role_arn(env, "platform-reader")), role_arn(env, "actor")

        def read_api() -> Any:
            return eks_api_client(reader("eks").describe_cluster(name=cluster)["cluster"], reader("sts"), cluster)

        def writer(who: dict[str, Any]) -> Any:
            described = reader("eks").describe_cluster(name=cluster)["cluster"]
            creds = identity.actor_session(sts, role_arn=actor_arn, incident=who["incident"],
                                           plan_hash=who["plan_hash"], approvers=who["approvers"],
                                           actions=["eks:DescribeCluster"], resources=[described["arn"]])
            return client.AppsV1Api(eks_api_client(described, session_clients(creds, where)("sts"), cluster))

        return KubernetesPlatform(apps=_Fresh(lambda: client.AppsV1Api(read_api())),
                                  autoscaling=_Fresh(lambda: client.AutoscalingV2Api(read_api())),
                                  custom=_Fresh(lambda: client.CustomObjectsApi(read_api())),
                                  writer=writer, cluster_name=cluster)

    return PerEnvironment(build, "Kubernetes")


def _own_check(refused: KubernetesPlatformRefused) -> KubernetesPlatformRefused:
    """Marked as WARDEN's own check: the target is known, and is not as the plan - or, undoing, the fix - left it.
    An undo refused this way is not a failed rollback and trips no kill switch (activities.rollback; the AWS platform
    marks its own the same way). A deployment that could not be read is not marked: its state is not known."""
    refused.own_check = True
    return refused


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


def _ignores_restart(rule: Any, deployment: str, namespace: str) -> bool:
    """An ignoreDifferences rule that applies to this Deployment and names the restart annotation, or a field holding
    it, by JSON Pointer."""
    if not isinstance(rule, dict) or rule.get("group") != "apps" or rule.get("kind") != "Deployment":
        return False
    if rule.get("name") not in (None, deployment) or rule.get("namespace") not in (None, namespace):
        return False
    return any(_covers(p) for p in rule.get("jsonPointers") or [])


def _covers(pointer: Any) -> bool:
    """A JSON Pointer (RFC 6901) that names the restart annotation or a field holding it, compared by whole segments
    (review, PR 48): `""` is the whole document, but `"/"` names the key "" at the root and `"/spec/"` the key "" under
    `spec` - neither covers the annotation, and Argo CD would not ignore it. Only a pointer that is a strict ancestor or
    the annotation itself counts; the whole document is not taken as proof either."""
    return (isinstance(pointer, str) and pointer.startswith("/") and not pointer.endswith("/")
            and (pointer == RESTART_POINTER or RESTART_POINTER.startswith(pointer + "/")))


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
