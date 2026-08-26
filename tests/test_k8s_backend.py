"""KubernetesBackend, against a stubbed API.

The live path is covered by tests/integration/ and the CI `k8s` job against a real k3d cluster.
These tests exist for the failure modes that are hard to stage on demand against a real API
server, and for the properties that must never regress. Several were written AFTER an adversarial
review found the first version wanting; those say so in their docstrings.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS

import pytest
import yaml

from warden import k8s_backend
from warden.k8s_backend import KubernetesBackend, _to_mib
from warden.models import ActionKind, Alert, RemediationProposal, RootCause, Severity, VerdictStatus
from warden.tools import PARTIAL_PREFIX, ToolError, gather
from warden.verifier import verify

ROOT = pathlib.Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- fakes


def _alert(**labels):
    return Alert(
        alert_id="k8s-1", name="PodOOMKilled", severity=Severity.high, service="checkout",
        environment="prod", summary="oom", started_at="2026-08-22T00:00:00Z", labels=labels,
    )


def _cs(name="checkout", *, restarts=0, last_reason=None, cur_reason=None, waiting=None):
    return NS(
        name=name,
        restart_count=restarts,
        last_state=NS(terminated=NS(reason=last_reason) if last_reason else None),
        state=NS(
            terminated=NS(reason=cur_reason) if cur_reason else None,
            waiting=NS(reason=waiting) if waiting else None,
        ),
    )


def _pod(name="checkout-abc", *, restarts=0, last_reason=None, cur_reason=None, waiting=None,
         ready=True, mem_limit="48Mi", phase="Running", init_statuses=(), created=None):
    return NS(
        metadata=NS(name=name, creation_timestamp=created or datetime.now(UTC)),
        spec=NS(
            containers=[NS(name="checkout", resources=NS(limits={"memory": mem_limit} if mem_limit else {}))],
            init_containers=[],
        ),
        status=NS(
            phase=phase,
            conditions=[NS(type="Ready", status="True" if ready else "False")],
            container_statuses=[_cs(restarts=restarts, last_reason=last_reason,
                                    cur_reason=cur_reason, waiting=waiting)],
            init_container_statuses=list(init_statuses),
            ephemeral_container_statuses=None,
        ),
    )


def _event(reason, msg="", kind="Pod", name="checkout-abc", ts=None):
    return NS(reason=reason, message=msg, last_timestamp=ts, event_time=None,
              involved_object=NS(kind=kind, name=name))


class FakeCore:
    def __init__(self, pods=(), events=(), log_text="line1\nline2", log_raises=False,
                 events_raise=False):
        self._pods, self._events = list(pods), list(events)
        self._log, self._log_raises, self._events_raise = log_text, log_raises, events_raise
        self.calls: list[str] = []

    def list_namespaced_pod(self, ns, label_selector=None, **kw):
        assert "_request_timeout" in kw, "every API call must carry a socket timeout"
        self.calls.append(f"list_namespaced_pod {ns} {label_selector}")
        return NS(items=self._pods)

    def list_namespaced_event(self, ns, **kw):
        assert "_request_timeout" in kw
        self.calls.append(f"list_namespaced_event {ns}")
        if self._events_raise:
            raise RuntimeError("events forbidden (403)")
        return NS(items=self._events)

    def read_namespaced_pod_log(self, name, ns, container=None, **kw):
        assert kw.get("_preload_content") is False, "logs must be read raw - see _log_text()"
        assert "_request_timeout" in kw
        self.calls.append(f"read_namespaced_pod_log {ns}/{name}/{container}")
        if self._log_raises:
            raise RuntimeError("(400)\nReason: Bad Request\nHTTP response headers: secret-ish")
        return self._log


def _rs(revision, images, *, created=None, owner_uid="dep-uid"):
    return NS(
        metadata=NS(
            annotations={"deployment.kubernetes.io/revision": str(revision)},
            creation_timestamp=created or datetime.now(UTC),
            owner_references=[NS(kind="Deployment", uid=owner_uid)],
        ),
        spec=NS(template=NS(spec=NS(containers=[NS(image=i) for i in images]))),
    )


class FakeApps:
    def __init__(self, deployment="present", replicasets=(), status=None):
        self._dep, self._rs, self._status = deployment, list(replicasets), status

    def read_namespaced_deployment(self, name, ns, **kw):
        assert "_request_timeout" in kw
        if self._status:
            raise _ApiErr(self._status)
        if self._dep is None:
            raise _ApiErr(404)
        return NS(metadata=NS(uid="dep-uid"), spec=NS(selector=NS(match_labels={"app": "checkout"})))

    def list_namespaced_replica_set(self, ns, label_selector=None, **kw):
        assert "_request_timeout" in kw
        return NS(items=self._rs)


class _ApiErr(Exception):
    def __init__(self, status):
        super().__init__(f"api {status}")
        self.status = status


def _backend(core=None, apps=None):
    return KubernetesBackend(core=core or FakeCore(pods=[_pod()]), apps=apps or FakeApps())


# --------------------------------------------------------------------------- metrics


def test_oom_kill_is_detected_from_last_state():
    m = _backend(FakeCore(pods=[_pod(restarts=4, last_reason="OOMKilled")])).metrics(_alert())
    assert m["oom_killed_containers"] == 1
    assert m["restart_count"] == 4
    assert m["pods_total"] == 1
    assert m["memory_limit_mib"] == 48.0


def test_oom_kill_in_current_state_also_counts():
    m = _backend(FakeCore(pods=[_pod(cur_reason="OOMKilled", ready=False)])).metrics(_alert())
    assert m["oom_killed_containers"] == 1


def test_oom_in_both_states_counts_once_per_container():
    m = _backend(FakeCore(pods=[_pod(last_reason="OOMKilled", cur_reason="OOMKilled")])).metrics(_alert())
    assert m["oom_killed_containers"] == 1, "it is a count of CONTAINERS showing OOM, not of states"


def test_restarts_sum_across_pods():
    m = _backend(FakeCore(pods=[_pod("a", restarts=2), _pod("b", restarts=5)])).metrics(_alert())
    assert m["restart_count"] == 7


def test_crashloop_and_readiness_are_counted():
    pods = [_pod("a", waiting="CrashLoopBackOff", ready=False), _pod("b", ready=True)]
    m = _backend(FakeCore(pods=pods)).metrics(_alert())
    assert m["crashloop_containers"] == 1 and m["pods_ready"] == 1 and m["pods_total"] == 2


def test_init_container_oom_is_visible():
    """Review finding: a pod stuck in Init:OOMKilled reported zero OOM kills, zero restarts.

    The kubelet puts the init container's status in a DIFFERENT list.
    """
    pod = _pod(ready=False, init_statuses=[_cs("migrate", restarts=7, last_reason="OOMKilled",
                                               waiting="CrashLoopBackOff")])
    m = _backend(FakeCore(pods=[pod])).metrics(_alert())
    assert m["oom_killed_containers"] == 1
    assert m["restart_count"] == 7
    assert m["crashloop_containers"] == 1


def test_dead_pods_are_not_the_workload():
    """Review finding: Evicted/Failed pods keep their labels and were being counted and log-read."""
    pods = [_pod("live", restarts=1), _pod("evicted", restarts=9, phase="Failed"),
            _pod("done", restarts=3, phase="Succeeded")]
    m = _backend(FakeCore(pods=pods)).metrics(_alert())
    assert m["pods_total"] == 1
    assert m["restart_count"] == 1


def test_no_matching_pods_is_an_error_not_a_clean_bill_of_health():
    """Review finding: a typo in the namespace yielded six zero metrics that the verifier read as
    'inspected, fine'. Zero pods means the backend inspected NOTHING."""
    b = _backend(FakeCore(pods=[]))
    with pytest.raises(ToolError, match="no live pods match"):
        b.metrics(_alert())
    with pytest.raises(ToolError):
        b.logs(_alert())


def test_no_pods_reaches_the_verifier_as_a_tool_error():
    ctx = gather(_alert(), _backend(FakeCore(pods=[])), timeout=2.0)
    assert any("no live pods match" in e for e in ctx.tool_errors)
    assert ctx.is_empty()


def test_unparseable_limit_is_omitted_not_zero():
    """Review finding: 0.0 is indistinguishable from 'no limit' in the prompt."""
    m = _backend(FakeCore(pods=[_pod(mem_limit="lots")])).metrics(_alert())
    assert "memory_limit_mib" not in m


# --------------------------------------------------------------------------- logs


def test_events_are_scoped_to_this_workload():
    """Review finding: every other service's crash loop in the namespace was attributed to this alert."""
    events = [
        _event("BackOff", "ours", name="checkout-abc"),
        _event("BackOff", "NOT ours", name="cart-7f9c"),
        _event("OOMKilling", "node-level", kind="Node", name="worker-1"),
        _event("FailedCreate", "ours", kind="ReplicaSet", name="checkout-5d9f"),
        _event("FailedCreate", "NOT ours", kind="ReplicaSet", name="cart-5d9f"),
        _event("Scheduled", "noise", name="checkout-abc"),
    ]
    lines = _backend(FakeCore(pods=[_pod()], events=events)).logs(_alert())
    joined = "\n".join(lines)
    assert "ours" in joined
    assert "NOT ours" not in joined
    assert "NODE-EVENT OOMKilling" in joined, "node-level events are kept, but labelled"
    assert "Scheduled" not in joined


def test_events_failing_does_not_lose_the_pod_logs():
    """Review finding: the events call sat outside any try, so an events 403 took the logs with it."""
    lines = _backend(FakeCore(pods=[_pod()], events_raise=True)).logs(_alert())
    assert any(line.endswith("line2") for line in lines)
    assert any(line.startswith(PARTIAL_PREFIX + "events") for line in lines)


@pytest.mark.parametrize(
    "payload,expected_lines",
    [
        ("2026-01-01T00:00:00Z a\n2026-01-01T00:00:01Z b", 2),
        (b"2026-01-01T00:00:00Z a\n2026-01-01T00:00:01Z b", 2),
        ("b'2026-01-01T00:00:00Z a\\n2026-01-01T00:00:01Z b'", 2),
        (NS(data=b"2026-01-01T00:00:00Z a\n2026-01-01T00:00:01Z b"), 2),
    ],
    ids=["str", "bytes", "bytes-repr-as-str", "response-object"],
)
def test_log_text_handles_every_shape_the_client_has_returned(payload, expected_lines):
    """Against a real k3s cluster the client returned the REPR of bytes as a str."""
    lines = [line for line in _backend(FakeCore(pods=[_pod()], log_text=payload)).logs(_alert())
             if not line.startswith(("EVENT", "NODE-EVENT", PARTIAL_PREFIX))]
    assert len(lines) == expected_lines, lines
    assert all("\\n" not in line and not line.split(" ", 1)[1].startswith("b'") for line in lines)


def test_a_failed_log_read_is_a_partial_failure_not_evidence():
    """Review finding: a log-read failure became a log LINE that policy P9 counted as evidence
    while P8 never fired. It now travels with the TOOL-PARTIAL prefix and gather() routes it."""
    ctx = gather(_alert(), _backend(FakeCore(pods=[_pod()], log_raises=True)), timeout=2.0)
    assert not any(PARTIAL_PREFIX in line or "Bad Request" in line for line in ctx.logs)
    assert any("logs: checkout-abc/checkout" in e for e in ctx.tool_errors)
    assert all("\n" not in e and "headers" not in e for e in ctx.tool_errors), "one line, no headers"


def test_log_reads_are_capped_and_newest_first(monkeypatch):
    """Review finding: O(pods x containers) sequential reads with no cap blew the tool budget."""
    monkeypatch.setattr(k8s_backend, "LOG_MAX_PODS", 2)
    t0 = datetime.now(UTC)
    pods = [_pod(f"p{i}", created=t0 - timedelta(minutes=i)) for i in range(5)]
    core = FakeCore(pods=pods)
    _backend(core).logs(_alert())
    reads = [c for c in core.calls if c.startswith("read_namespaced_pod_log")]
    assert len(reads) == 2
    assert reads[0].endswith("/p0/checkout") and reads[1].endswith("/p1/checkout")


# --------------------------------------------------------------------------- deploys


def test_image_change_is_a_deploy():
    rs = [_rs(1, ["acme/checkout:old"], created=datetime.now(UTC) - timedelta(days=2)),
          _rs(2, ["acme/checkout:new"], created=datetime.now(UTC) - timedelta(minutes=5))]
    d = _backend(apps=FakeApps(replicasets=rs)).deploys(_alert())
    assert len(d) == 1
    assert d[0]["revision"] == "2" and "new" in d[0]["image"] and "old" in d[0]["previous_image"]


def test_rollout_restart_is_not_a_deploy():
    """Review finding: a `kubectl rollout restart` bumps the revision with the image unchanged, and
    was reported as a deploy - so policy P5 would have allowed a 'rollback' that changes nothing."""
    rs = [_rs(1, ["acme/checkout:9f2c1ab"], created=datetime.now(UTC) - timedelta(days=2)),
          _rs(2, ["acme/checkout:9f2c1ab"], created=datetime.now(UTC) - timedelta(minutes=5))]
    assert _backend(apps=FakeApps(replicasets=rs)).deploys(_alert()) == []


def test_init_container_only_image_change_is_a_deploy():
    """A deploy that bumps ONLY a migration/init-container image (app container unchanged) is a real
    template change. _images() compared app containers alone, so it read as a no-op restart, hid the
    deploy, and P5 then blocked the legitimate rollback of a failing migration. Init images count."""
    def _rs_init(rev, app_img, init_img, created):
        return NS(
            metadata=NS(
                annotations={"deployment.kubernetes.io/revision": str(rev)},
                creation_timestamp=created,
                owner_references=[NS(kind="Deployment", uid="dep-uid")],
            ),
            spec=NS(template=NS(spec=NS(
                init_containers=[NS(image=init_img)],
                containers=[NS(image=app_img)],
            ))),
        )
    rs = [_rs_init(1, "app:v9", "migrate:v1", datetime.now(UTC) - timedelta(days=2)),
          _rs_init(2, "app:v9", "migrate:v2", datetime.now(UTC) - timedelta(minutes=5))]
    d = _backend(apps=FakeApps(replicasets=rs)).deploys(_alert())
    assert len(d) == 1, "an init-container-only image change must be detected as a deploy"


def test_first_rollout_counts():
    rs = [_rs(1, ["acme/checkout:v1"], created=datetime.now(UTC) - timedelta(minutes=5))]
    assert len(_backend(apps=FakeApps(replicasets=rs)).deploys(_alert())) == 1


def test_old_change_is_not_evidence():
    rs = [_rs(1, ["a:1"], created=datetime.now(UTC) - timedelta(days=9)),
          _rs(2, ["a:2"], created=datetime.now(UTC) - timedelta(days=3))]
    assert _backend(apps=FakeApps(replicasets=rs)).deploys(_alert()) == []


def test_replicasets_owned_by_another_deployment_are_ignored():
    rs = [_rs(1, ["a:1"], owner_uid="someone-else")]
    assert _backend(apps=FakeApps(replicasets=rs)).deploys(_alert()) == []


def test_naive_timestamps_do_not_raise():
    """Review finding: a stubbed client returning a naive datetime made aware-minus-naive raise."""
    rs = [_rs(1, ["a:1"], created=datetime.now())]  # noqa: DTZ005 - naive on purpose, that IS the test
    assert isinstance(_backend(apps=FakeApps(replicasets=rs)).deploys(_alert()), list)


def test_missing_deployment_is_an_empty_list_not_an_error():
    assert _backend(apps=FakeApps(deployment=None)).deploys(_alert()) == []


def test_non_404_api_errors_are_not_swallowed():
    """A 403 means the RBAC is wrong. Hiding it would make a broken deployment look healthy."""
    with pytest.raises(_ApiErr) as exc:
        _backend(apps=FakeApps(status=403)).deploys(_alert())
    assert exc.value.status == 403


# --------------------------------------------------------------------------- alert -> workload


def test_alert_labels_override_namespace_and_selector():
    core = FakeCore(pods=[_pod()])
    _backend(core).metrics(_alert(namespace="payments", selector="tier=web"))
    assert core.calls[-1] == "list_namespaced_pod payments tier=web"


def test_env_default_namespace(monkeypatch):
    monkeypatch.setenv("WARDEN_K8S_NAMESPACE", "shop")
    core = FakeCore(pods=[_pod()])
    _backend(core).metrics(_alert())
    assert core.calls[-1].startswith("list_namespaced_pod shop ")


# --------------------------------------------------------------------------- through gather()


def test_unreachable_api_becomes_partial_context_not_a_crash():
    class DeadCore:
        def list_namespaced_pod(self, *a, **k): raise ConnectionError("dial tcp: refused")
        def list_namespaced_event(self, *a, **k): raise ConnectionError("dial tcp: refused")
        def read_namespaced_pod_log(self, *a, **k): raise ConnectionError("dial tcp: refused")

    ctx = gather(_alert(), KubernetesBackend(core=DeadCore(), apps=FakeApps()), timeout=2.0)
    assert len(ctx.tool_errors) >= 2
    assert ctx.is_empty()


def test_live_shaped_oom_evidence_reaches_scale_up_verdict():
    pods = [_pod(restarts=6, last_reason="OOMKilled", ready=False)]
    events = [_event("BackOff", "Back-off restarting failed container")]
    b = _backend(FakeCore(pods=pods, events=events, log_text="starting\nKilled"))
    ctx = gather(_alert(), b, timeout=2.0)
    assert ctx.metrics["oom_killed_containers"] == 1 and not ctx.is_empty()
    verdict = verify(
        _alert(), ctx, RootCause(hypothesis="OOM", confidence=0.74),
        RemediationProposal(action=ActionKind.scale_up, target="checkout", reasoning="r",
                            expected_effect="e", blast_radius="single_service", reversible=True),
    )
    assert verdict.status is VerdictStatus.approved_for_human


# --------------------------------------------------------------------------- the invariants


def _dotted(node: ast.AST) -> str:
    """'self._core.delete_namespaced_pod' for an Attribute chain, '' otherwise."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def test_backend_cannot_write_checked_on_the_ast_not_the_text():
    """A tripwire, not the boundary. RBAC is the boundary, and this test says so.

    Review finding: the first version was a regex over the source text - bypassed by
    `connect_post_*_exec`, `api_client.call_api(..., "DELETE")`, `subprocess`, and `getattr` with a
    concatenated name; and it false-positived on the word "kubectl" in a docstring. This walks the
    AST: real call expressions and real imports, never prose.
    """
    src = pathlib.Path(inspect.getsourcefile(k8s_backend)).read_text(encoding="utf-8")
    tree = ast.parse(src)

    write_method = re.compile(
        r"^(create|patch|delete|replace|update|delete_collection)_|^connect_(post|put|delete|patch)_"
    )
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            leaf = name.rsplit(".", 1)[-1]
            if write_method.match(leaf):
                offenders.append(f"write-shaped call {name}")
            if leaf in ("call_api", "request", "system", "popen", "run", "Popen", "check_output"):
                offenders.append(f"escape hatch {name}")
            if leaf == "getattr" and node.args and _dotted(node.args[0]).startswith("self._"):
                offenders.append("dynamic lookup on the API client")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) else [])
            for m in mods:
                if m and m.split(".")[0] in ("subprocess", "shlex", "pty"):
                    offenders.append(f"import {m}")
    assert not offenders, f"k8s_backend.py must not be able to write; found: {offenders}"


def test_rbac_manifest_is_structurally_read_only():
    """Structural, not textual. Review finding: the old grep passed with `roleRef: cluster-admin`,
    with `verbs: [get, list, delete]` (unquoted), and with a block-list `- delete`."""
    docs = [d for d in yaml.safe_load_all((ROOT / "k8s" / "rbac.yaml").read_text(encoding="utf-8")) if d]
    kinds = {d["kind"] for d in docs}
    assert "ClusterRoleBinding" not in kinds, "cluster-wide binding"
    assert kinds == {"ServiceAccount", "ClusterRole", "RoleBinding"}

    roles = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ClusterRole"}
    allowed_verbs = {"get", "list"}
    allowed_resources = {"pods", "pods/log", "events", "deployments", "replicasets"}
    for name, role in roles.items():
        for rule in role["rules"]:
            assert set(rule["verbs"]) <= allowed_verbs, f"{name}: {rule}"
            assert set(rule["resources"]) <= allowed_resources, f"{name}: {rule}"
            assert "*" not in rule.get("apiGroups", []), f"{name}: wildcard apiGroup"

    bindings = [d for d in docs if d["kind"] == "RoleBinding"]
    assert bindings, "no RoleBinding"
    for b in bindings:
        ref = b["roleRef"]
        assert ref["kind"] == "ClusterRole" and ref["name"] in roles, (
            f"RoleBinding points at {ref} - must reference the ClusterRole defined in this file, "
            "never a built-in like cluster-admin/admin/edit"
        )
        for s in b["subjects"]:
            assert s["kind"] == "ServiceAccount" and s["name"] == "warden" and s["namespace"] == "warden"

    sa = next(d for d in docs if d["kind"] == "ServiceAccount")
    assert sa.get("automountServiceAccountToken") is False


def test_rbac_grants_exactly_what_the_code_calls():
    """'Minimal' is checkable by subtraction. Review finding: 12 of 16 granted pairs had no caller."""
    src = pathlib.Path(inspect.getsourcefile(k8s_backend)).read_text(encoding="utf-8")
    needed = set()
    if "list_namespaced_pod(" in src: needed.add(("", "pods", "list"))
    if "read_namespaced_pod_log(" in src: needed.add(("", "pods/log", "get"))
    if "list_namespaced_event(" in src: needed.add(("", "events", "list"))
    if "read_namespaced_deployment(" in src: needed.add(("apps", "deployments", "get"))
    if "list_namespaced_replica_set(" in src: needed.add(("apps", "replicasets", "list"))

    docs = [d for d in yaml.safe_load_all((ROOT / "k8s" / "rbac.yaml").read_text(encoding="utf-8")) if d]
    granted = set()
    for d in docs:
        if d["kind"] != "ClusterRole":
            continue
        for rule in d["rules"]:
            for g in rule["apiGroups"]:
                for r in rule["resources"]:
                    for v in rule["verbs"]:
                        granted.add((g, r, v))
    assert granted == needed, f"granted-but-unused: {granted - needed}; needed-but-missing: {needed - granted}"


def test_job_manifest_cannot_hang_or_lose_evidence():
    """Review findings: no activeDeadlineSeconds (a stalled run kept the Job active forever, proven
    live) and a 1-hour TTL that deleted the only record of the diagnosis."""
    job = yaml.safe_load((ROOT / "k8s" / "job.yaml").read_text(encoding="utf-8"))
    spec = job["spec"]
    assert 0 < spec["activeDeadlineSeconds"] <= 900
    assert spec["ttlSecondsAfterFinished"] >= 7 * 24 * 3600
    assert "generateName" in job["metadata"] and "name" not in job["metadata"], "Jobs are immutable"
    pod = spec["template"]["spec"]
    assert pod["serviceAccountName"] == "warden"
    assert pod["securityContext"]["runAsNonRoot"] is True and pod["securityContext"]["runAsUser"] == 10001
    c = pod["containers"][0]["securityContext"]
    assert c["readOnlyRootFilesystem"] is True and c["allowPrivilegeEscalation"] is False
    assert c["capabilities"]["drop"] == ["ALL"]


def test_job_pod_satisfies_restricted_pss_so_it_runs_on_eks_not_just_k3d():
    """EKS / GKE / AKS ENFORCE the `restricted` Pod Security Standard; k3d (the CI cluster) can be
    lax. A Job that is admitted on k3d but missing a `restricted` requirement would be REJECTED on
    EKS — the classic 'works in CI, fails in prod' gap. This checks every restricted rule that is
    visible in the manifest, cluster-independently, so the deploy-everywhere claim cannot regress.

    The one people forget is seccompProfile: RuntimeDefault — it is required by `restricted` and its
    absence is the single most common reason a hardened-looking pod is refused on managed Kubernetes.
    """
    job = yaml.safe_load((ROOT / "k8s" / "job.yaml").read_text(encoding="utf-8"))
    pod = job["spec"]["template"]["spec"]
    psc = pod.get("securityContext", {})
    csc = pod["containers"][0].get("securityContext", {})

    # seccomp must be set at pod OR container level, to RuntimeDefault (or Localhost)
    seccomp = psc.get("seccompProfile") or csc.get("seccompProfile") or {}
    assert seccomp.get("type") in ("RuntimeDefault", "Localhost"), "restricted requires a seccompProfile"

    assert psc.get("runAsNonRoot") is True
    assert csc.get("allowPrivilegeEscalation") is False
    assert csc.get("capabilities", {}).get("drop") == ["ALL"]
    # add is empty or only the one capability restricted permits
    assert set(csc.get("capabilities", {}).get("add", [])) <= {"NET_BIND_SERVICE"}
    assert csc.get("privileged") in (None, False)

    # host namespaces and hostPath volumes are forbidden by baseline/restricted
    for host_key in ("hostNetwork", "hostPID", "hostIPC"):
        assert pod.get(host_key) in (None, False), f"{host_key} is forbidden under restricted"
    for vol in pod.get("volumes", []):
        assert "hostPath" not in vol, "hostPath volumes are forbidden under restricted"

    # and the namespace must actually ENFORCE restricted, or none of the above is checked at admission
    ns = yaml.safe_load((ROOT / "k8s" / "namespace.yaml").read_text(encoding="utf-8"))
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"


# --------------------------------------------------------------------------- quantities


@pytest.mark.parametrize("q,mib", [
    ("48Mi", 48.0), ("1Gi", 1024.0), ("512Ki", 0.5), ("1048576", 1.0),
    ("1.5Gi", 1536.0), ("1Ti", 1024 * 1024.0), ("500k", 500e3 / 2**20), ("1e6", 1e6 / 2**20),
])
def test_memory_quantities_parse(q, mib):
    assert _to_mib(q) == pytest.approx(mib)


@pytest.mark.parametrize("q", ["lots", "", None])
def test_unparseable_quantity_is_none(q):
    assert _to_mib(q) is None
