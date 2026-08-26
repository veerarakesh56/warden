"""A real evidence backend: read a live Kubernetes cluster.

Drops into `gather(alert, backend=KubernetesBackend())` with no change above it — the three-method
contract (`logs` / `metrics` / `deploys`) is the same one `FixtureBackend` satisfies, and the
boundary was drawn there precisely so this swap would be one class.

Things that are deliberate, most of them learned from an adversarial review of the first version:

1. **Read-only.** The client calls are `list_namespaced_pod`, `list_namespaced_event`,
   `read_namespaced_pod_log`, `read_namespaced_deployment`, `list_namespaced_replica_set`. Nothing
   else. A test greps this module for write-shaped calls — but that grep is a tripwire, not the
   boundary. **RBAC is the boundary**: the ServiceAccount in `k8s/` cannot mutate anything, so a bug
   here cannot either. Outside the cluster, with a developer kubeconfig, the boundary is whatever
   that kubeconfig allows — say so rather than pretend otherwise.

2. **Every client call carries a socket timeout.** Without one, a stalled API read leaves a worker
   thread blocked forever; `gather()` stops waiting after its deadline, the verdict prints, and
   then the interpreter blocks on that thread at exit — the Job never completes. Reproduced live.

3. **Metrics come from pod STATUS, not a metrics server.** Restart counts, `OOMKilled`
   terminations, `CrashLoopBackOff`, readiness, memory limits — counted across app, init AND
   ephemeral containers. Not utilisation; k3d ships no metrics-server. The key names say what the
   numbers are: `oom_killed_containers` is containers *currently showing* an OOM kill, not a tally.

4. **No pods matched is an ERROR, not a clean bill of health.** A typo in the namespace or
   selector used to yield six zero metrics that the verifier read as "inspected, fine". It now
   raises, which lands in `tool_errors` and fires the partial-context policy.

5. **Events are scoped to this workload.** A namespace-wide event list attributed every other
   service's crash loop to this alert. Pod events are now filtered to the matched pods, and
   ReplicaSet/Deployment events to this deployment's; node-level events are kept but labelled.
   ⚠ `OOMKilling` / `OOMKilled` event reasons come from node-problem-detector, not vanilla
   Kubernetes — on a plain cluster the OOM evidence is in pod status, not events.

6. **A deploy is a TEMPLATE CHANGE, not a timestamp.** The first version reported any Deployment
   whose Progressing condition moved inside a window — so a `kubectl rollout restart` (the single
   most common on-call action, image unchanged) counted as a deploy and satisfied policy P5. Now
   the current and previous ReplicaSets are compared; a deploy is reported only if the images
   differ (or it is the first rollout), dated by the new ReplicaSet's creation.

7. **Dead pods are excluded.** Evicted/Failed/Succeeded pods keep their labels and can outnumber
   the live ones; they would inflate counts and blow the log-read budget.

8. **A partial log failure is reported as a partial failure.** One container's log read failing
   used to become a log LINE, which the verifier counted as evidence. It is now emitted with the
   `TOOL-PARTIAL` prefix that `gather()` routes into `tool_errors`.

Mapping from an alert to a workload:
    namespace  = alert.labels["namespace"]  or $WARDEN_K8S_NAMESPACE  or "default"
    selector   = alert.labels["selector"]   or f"app={alert.service}"
    deployment = alert.labels["deployment"] or alert.service

The `kubernetes` client is an optional extra (`pip install -e ".[k8s]"`), imported lazily.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from .models import Alert
from .tools import PARTIAL_PREFIX, ToolError

# Socket timeouts for every API call: (connect, read). The read timeout must be shorter than the
# tool deadline in tools.py so the worker thread ends on its own instead of being abandoned.
REQUEST_TIMEOUT = (
    float(os.environ.get("WARDEN_K8S_CONNECT_TIMEOUT", "3.0")),
    float(os.environ.get("WARDEN_K8S_READ_TIMEOUT", "4.0")),
)
# How far back a template change counts as "recent" — this window IS the evidence policy P5 asks
# for before permitting a rollback.
RECENT_DEPLOY_WINDOW = timedelta(hours=float(os.environ.get("WARDEN_K8S_DEPLOY_WINDOW_H", "6")))
LOG_TAIL_LINES = int(os.environ.get("WARDEN_K8S_LOG_TAIL", "40"))
# Log reads are O(pods x containers) and sequential; cap them so a 40-replica service cannot eat
# the whole tool budget. Newest pods first — they are the ones crashing now.
LOG_MAX_PODS = int(os.environ.get("WARDEN_K8S_LOG_MAX_PODS", "5"))
EVENT_LIMIT = int(os.environ.get("WARDEN_K8S_EVENT_LIMIT", "500"))

# Event reasons that are evidence in their own right. Anything else is noise at incident time.
INTERESTING_EVENT_REASONS = {
    "OOMKilled", "OOMKilling", "BackOff", "CrashLoopBackOff", "Unhealthy", "Failed",
    "FailedScheduling", "Evicted", "Killing", "FailedMount", "Preempting", "FailedCreate",
}
DEAD_PHASES = {"Failed", "Succeeded"}


class KubernetesBackend:
    """Reads pods, events, logs and rollout history for the workload an alert points at."""

    name = "kubernetes"

    def __init__(self, *, core=None, apps=None, kubeconfig: str | None = None) -> None:
        # Injectable clients so the unit tests can stub the API without a cluster.
        if core is None or apps is None:
            from kubernetes import client, config

            try:
                config.load_incluster_config()  # running as a Job inside the cluster
            except config.ConfigException:
                try:
                    config.load_kube_config(config_file=kubeconfig)  # a developer's kubeconfig
                except config.ConfigException as exc:
                    raise ToolError(
                        "WARDEN_BACKEND=k8s but no cluster credentials were found (not in-cluster, "
                        f"and no usable kubeconfig): {exc}"
                    ) from exc
            core = core or client.CoreV1Api()
            apps = apps or client.AppsV1Api()
        self._core = core
        self._apps = apps

    # ------------------------------------------------------------------ alert -> workload

    @staticmethod
    def _namespace(alert: Alert) -> str:
        return alert.labels.get("namespace") or os.environ.get("WARDEN_K8S_NAMESPACE", "default")

    @staticmethod
    def _selector(alert: Alert) -> str:
        return alert.labels.get("selector", f"app={alert.service}")

    @staticmethod
    def _deployment(alert: Alert) -> str:
        return alert.labels.get("deployment", alert.service)

    def _live_pods(self, alert: Alert) -> list:
        """Pods matching the selector that are not already dead. Raises if there are none."""
        ns, sel = self._namespace(alert), self._selector(alert)
        items = self._core.list_namespaced_pod(
            ns, label_selector=sel, _request_timeout=REQUEST_TIMEOUT
        ).items
        live = [p for p in items if (p.status.phase or "") not in DEAD_PHASES]
        if not live:
            # Zero matches is a misconfiguration or a deleted workload, not a healthy service.
            # Raising puts it in tool_errors, where the verifier can see it.
            raise ToolError(
                f"no live pods match '{sel}' in namespace '{ns}' "
                f"({len(items)} matched in total, {len(items) - len(live)} dead)"
            )
        live.sort(key=lambda p: p.metadata.creation_timestamp or _EPOCH, reverse=True)
        return live

    # ------------------------------------------------------------------ the contract

    def logs(self, alert: Alert) -> list[str]:
        """Workload-scoped events first (the headline), then container log tails (the detail).

        Per-container log failures are emitted with the TOOL-PARTIAL prefix so `gather()` routes
        them into `tool_errors` instead of counting them as evidence.
        """
        ns = self._namespace(alert)
        pods = self._live_pods(alert)
        pod_names = {p.metadata.name for p in pods}
        deployment = self._deployment(alert)
        lines: list[str] = []

        # Events: own try, so an events 403 or a busy namespace cannot take the pod logs with it.
        try:
            events = self._core.list_namespaced_event(
                ns, limit=EVENT_LIMIT, _request_timeout=REQUEST_TIMEOUT
            ).items
        except Exception as exc:  # noqa: BLE001 - partial failure, reported as such
            events = []
            lines.append(f"{PARTIAL_PREFIX}events: {_one_line(exc)}")

        for ev in sorted(events, key=lambda e: (e.last_timestamp or e.event_time or _EPOCH)):
            if ev.reason not in INTERESTING_EVENT_REASONS:
                continue
            obj = ev.involved_object
            kind, name = obj.kind, obj.name
            if kind == "Pod" and name not in pod_names:
                continue  # another workload's pod
            if kind in ("ReplicaSet", "Deployment") and not name.startswith(deployment):
                continue  # another workload's rollout
            if kind not in ("Pod", "ReplicaSet", "Deployment", "Node"):
                continue
            tag = "NODE-EVENT" if kind == "Node" else "EVENT"
            lines.append(f"{tag} {ev.reason} {kind}/{name}: {_one_line(ev.message or '')}")

        for pod in pods[:LOG_MAX_PODS]:
            containers = list(pod.spec.init_containers or []) + list(pod.spec.containers or [])
            for container in containers:
                try:
                    resp = self._core.read_namespaced_pod_log(
                        pod.metadata.name, ns, container=container.name,
                        tail_lines=LOG_TAIL_LINES, timestamps=True,
                        # Read the raw response. The client's own deserialisation returned the
                        # REPR of bytes as a str against a real k3s cluster - one line, literal \n.
                        _preload_content=False,
                        _request_timeout=REQUEST_TIMEOUT,
                    )
                    text = _log_text(resp)
                except Exception as exc:  # noqa: BLE001
                    lines.append(
                        f"{PARTIAL_PREFIX}logs: {pod.metadata.name}/{container.name}: {_one_line(exc)}"
                    )
                    continue
                for raw in text.splitlines():
                    if raw.strip():
                        lines.append(f"{pod.metadata.name}/{container.name} {raw}")
        return lines

    def metrics(self, alert: Alert) -> dict[str, float]:
        """Counts read off pod status across app, init and ephemeral containers.

        Honest about what they are: not utilisation. Keys are named for what they count.
        """
        pods = self._live_pods(alert)
        restarts = oom = crashloop = ready = 0
        mem_limit_mib: float | None = None

        for pod in pods:
            conds = pod.status.conditions or []
            if any(c.type == "Ready" and c.status == "True" for c in conds):
                ready += 1
            statuses = (
                list(pod.status.container_statuses or [])
                + list(pod.status.init_container_statuses or [])
                + list(getattr(pod.status, "ephemeral_container_statuses", None) or [])
            )
            for cs in statuses:
                restarts += cs.restart_count or 0
                last = getattr(cs.last_state, "terminated", None)
                cur = getattr(cs.state, "terminated", None)
                if (last is not None and last.reason == "OOMKilled") or (
                    cur is not None and cur.reason == "OOMKilled"
                ):
                    oom += 1
                waiting = getattr(cs.state, "waiting", None)
                if waiting is not None and waiting.reason == "CrashLoopBackOff":
                    crashloop += 1
            for container in list(pod.spec.init_containers or []) + list(pod.spec.containers or []):
                limits = (container.resources and container.resources.limits) or {}
                if "memory" in limits:
                    mib = _to_mib(limits["memory"])
                    if mib is not None:
                        mem_limit_mib = max(mem_limit_mib or 0.0, mib)

        out = {
            "pods_total": float(len(pods)),
            "pods_ready": float(ready),
            "restart_count": float(restarts),
            "oom_killed_containers": float(oom),
            "crashloop_containers": float(crashloop),
        }
        if mem_limit_mib is not None:  # omitted, never 0 - zero looks like "no limit"
            out["memory_limit_mib"] = mem_limit_mib
        return out

    def deploys(self, alert: Alert) -> list[dict[str, str]]:
        """A recent TEMPLATE CHANGE for this Deployment, or nothing.

        Compares the current ReplicaSet's images with the previous ReplicaSet's. A `rollout restart`
        bumps the revision without changing an image and is therefore NOT a deploy.
        """
        ns, name = self._namespace(alert), self._deployment(alert)
        try:
            dep = self._apps.read_namespaced_deployment(name, ns, _request_timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            if getattr(exc, "status", None) == 404:
                return []  # bare pods / StatefulSets have no Deployment; P5 then refuses rollback
            raise

        match = (dep.spec.selector and dep.spec.selector.match_labels) or {}
        selector = ",".join(f"{k}={v}" for k, v in sorted(match.items()))
        rs_list = self._apps.list_namespaced_replica_set(
            ns, label_selector=selector, _request_timeout=REQUEST_TIMEOUT
        ).items
        owned = [rs for rs in rs_list if _owned_by(rs, dep.metadata.uid)]
        if not owned:
            return []
        owned.sort(key=_revision_of)
        current, previous = owned[-1], (owned[-2] if len(owned) > 1 else None)

        current_images = _images(current)
        if previous is not None and _images(previous) == current_images:
            return []  # revision moved, template did not: a restart, not a deploy

        changed_at = _aware(current.metadata.creation_timestamp)
        if changed_at is None or (datetime.now(UTC) - changed_at) > RECENT_DEPLOY_WINDOW:
            return []

        return [{
            "deployment": name,
            "revision": str(_revision_of(current)),
            "image": ",".join(current_images),
            "previous_image": ",".join(_images(previous)) if previous is not None else "",
            "at": changed_at.isoformat(),
            "by": "kubernetes",
        }]


# --------------------------------------------------------------------------- helpers

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _aware(dt: datetime | None) -> datetime | None:
    """The real client returns tz-aware datetimes; a stub might not. Never let that raise."""
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _owned_by(rs, deployment_uid: str | None) -> bool:
    for ref in rs.metadata.owner_references or []:
        if ref.kind == "Deployment" and (deployment_uid is None or ref.uid == deployment_uid):
            return True
    return False


def _revision_of(rs) -> int:
    try:
        return int((rs.metadata.annotations or {}).get("deployment.kubernetes.io/revision", "0"))
    except ValueError:
        return 0


def _images(rs) -> list[str]:
    # Init containers count too: a deploy that bumps ONLY a migration/init-container image is a real
    # template change, and comparing app containers alone misclassified it as a no-op restart -
    # hiding the deploy, so bad_deploy never fired and P5 blocked the legitimate rollback. This
    # matches metrics()/logs(), which already fold in init containers.
    spec = rs.spec.template.spec
    containers = list(getattr(spec, "init_containers", None) or []) + list(spec.containers or [])
    return sorted(c.image or "" for c in containers)


def _one_line(value) -> str:
    """ApiException's str() is multi-line and carries response headers. One line, no headers."""
    text = str(value).strip()
    first = text.splitlines()[0] if text else ""
    return first[:200]


def _log_text(resp) -> str:
    """Turn whatever the client returned for a log read into real text.

    Three shapes have been observed: a urllib3 response (`.data` is bytes) when preloading is off;
    raw bytes; or a str that is itself the REPR of bytes ("b'...'") from the client's deserialiser.
    """
    data = getattr(resp, "data", resp)
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    text = str(data or "")
    if (text.startswith("b'") and text.endswith("'")) or (text.startswith('b"') and text.endswith('"')):
        import ast

        try:
            decoded = ast.literal_eval(text)
            if isinstance(decoded, bytes):
                return decoded.decode("utf-8", errors="replace")
        except (ValueError, SyntaxError, RecursionError, MemoryError):
            pass
    return text


_SUFFIX = {
    "Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60,
    "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18, "m": 1e-3,
}


def _to_mib(quantity) -> float | None:
    """Parse a Kubernetes memory quantity into MiB, or None if it cannot be parsed.

    None rather than 0: a zero is indistinguishable from "no limit" in the prompt.
    """
    q = str(quantity or "").strip()
    if not q:
        return None
    for suffix in sorted(_SUFFIX, key=len, reverse=True):  # 'Mi' before 'M'
        if q.endswith(suffix):
            try:
                return float(q[: -len(suffix)]) * _SUFFIX[suffix] / 2**20
            except ValueError:
                return None
    try:
        return float(q) / 2**20  # plain bytes, possibly exponent form
    except ValueError:
        return None
