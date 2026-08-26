"""Against a REAL cluster. Skipped unless opted into; FAILS if opted into and the cluster is absent.

    WARDEN_K8S_INTEGRATION=1 pytest tests/integration -q

Preconditions (the CI `k8s` job sets them up; locally: `k3d cluster create` then
`kubectl apply -f k8s/test/oom-workload.yaml` and wait for an OOMKilled status):
  - a kubeconfig that reaches a cluster
  - the synthetic OOM workload deployed as Deployment `checkout` in `default`

⛔ Review finding: the first version SKIPPED when `KubernetesBackend()` raised, so with the opt-in
set and no cluster every test skipped and the step was green. Opting in means "there IS a
cluster"; an unreachable one is a failure, and the CI step additionally asserts a pass count.

What this proves that the unit tests cannot: the real client's response shapes, the real kubelet's
termination reasons, the real events stream - and that the whole pipeline, run against them,
reaches the verdict the fixture version promised.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("WARDEN_K8S_INTEGRATION") != "1",
    reason="set WARDEN_K8S_INTEGRATION=1 with a reachable cluster and the OOM workload deployed",
)

kubernetes = pytest.importorskip("kubernetes", reason="pip install -e '.[k8s]'")

from warden.cli import DEMO_ALERTS
from warden.graph import run
from warden.k8s_backend import KubernetesBackend
from warden.llm import LLMClient
from warden.models import ActionKind, Alert, VerdictStatus
from warden.tools import PARTIAL_PREFIX, gather


@pytest.fixture(scope="module")
def backend():
    try:
        return KubernetesBackend()
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"WARDEN_K8S_INTEGRATION=1 but no cluster is reachable: {exc}")


@pytest.fixture(scope="module")
def alert():
    return Alert(**DEMO_ALERTS["inc-002"])


def test_cluster_is_reachable_and_workload_exists(backend, alert):
    m = backend.metrics(alert)
    assert m["pods_total"] >= 1, "Deployment `checkout` has no live pods in `default`"


def test_real_kubelet_reports_an_oom_kill(backend, alert):
    """The kernel killed it and the kubelet wrote it down. Read it back."""
    m = backend.metrics(alert)
    assert m["oom_killed_containers"] >= 1, f"no OOMKilled yet - wait for the pod to cycle: {m}"
    assert m["restart_count"] >= 1
    assert m["memory_limit_mib"] == 48.0, "the limit in the manifest should be what the API reports"


def test_real_container_log_lines_are_read_and_split(backend, alert):
    """Guards the bytes-repr bug AND the review finding that this test once passed on
    `LOG-UNAVAILABLE` markers with zero real log text."""
    lines = backend.logs(alert)
    partial = [line for line in lines if line.startswith(PARTIAL_PREFIX)]
    real = [line for line in lines if not line.startswith(("EVENT", "NODE-EVENT", PARTIAL_PREFIX))]
    assert not partial, f"a log read failed: {partial}"
    assert real, "no container log text came back at all"
    assert not any("\\n" in line for line in real), "log tail arrived as a bytes repr"
    assert not any(line.split(" ", 1)[1].startswith("b'") for line in real)
    assert any("allocating" in line for line in real), "expected the workload's own startup line"


def test_real_events_are_surfaced_and_scoped(backend, alert):
    events = [line for line in backend.logs(alert) if line.startswith("EVENT")]
    assert any("BackOff" in e for e in events), "a crash-looping pod must produce BackOff events"
    assert all("checkout" in e for e in events), f"an event for another workload leaked in: {events}"


def test_a_recent_template_change_is_reported_as_a_deploy(backend, alert):
    """The workload was created minutes ago: first rollout, so it counts. A later
    `kubectl rollout restart` would NOT - see the unit test for that case."""
    d = backend.deploys(alert)
    assert len(d) == 1 and d[0]["deployment"] == "checkout"
    assert "busybox" in d[0]["image"]


def test_gather_reports_no_tool_errors_against_a_healthy_api(backend, alert):
    ctx = gather(alert, backend, timeout=20.0)
    assert ctx.tool_errors == [], ctx.tool_errors
    assert not ctx.is_empty()


def test_end_to_end_reaches_scale_up_held_for_a_human(backend, alert):
    """The whole claim of the project, against a real cluster, in one assertion block."""
    report = run(alert, llm=LLMClient(mock=True), backend=backend)
    gather_step = next(s for s in report.audit if s["node"] == "gather")

    assert gather_step["backend"] == "kubernetes"
    assert gather_step["tool_errors"] == []
    assert "oom" in report.root_cause.hypothesis.lower()
    assert report.proposal.action is ActionKind.scale_up
    assert report.verdict.status is VerdictStatus.approved_for_human
    assert report.verdict.requires_approval is True
    assert report.audit[-1]["node"] == "await_approval"
