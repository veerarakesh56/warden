"""The live Kubernetes remediation backend — stubbed client, no cluster. Proves it patches the right
thing, clamps scaling, refuses everything it shouldn't do, and that a backend fault is a `failed`
result rather than a crash."""

from __future__ import annotations

import pytest

from warden.models import (
    ActionKind,
    Alert,
    RemediationProposal,
    Severity,
    Verdict,
    VerdictStatus,
)
from warden.remediation import (
    DryRunBackend,
    RemediationError,
    RemediationOutcome,
    RemediationRequest,
    decide_remediation,
)
from warden.remediation_k8s import KubernetesRemediationBackend, resolve_remediation_backend


class _Dep:
    def __init__(self, replicas):
        self.spec = type("S", (), {"replicas": replicas})()


class _Apps:
    """Records patches; returns a deployment with a settable replica count."""

    def __init__(self, replicas=2, fail=False):
        self.replicas = replicas
        self.fail = fail
        self.patches = []

    def read_namespaced_deployment(self, name, ns, **kw):
        if self.fail:
            raise RuntimeError("boom: API unreachable")
        return _Dep(self.replicas)

    def patch_namespaced_deployment(self, name, ns, body, **kw):
        if self.fail:
            raise RuntimeError("boom: 403 forbidden")
        self.patches.append((name, ns, body))
        return _Dep(self.replicas)


def _backend(**kw):
    return KubernetesRemediationBackend(apps=_Apps(**kw), namespace="default")


# ------------------------------------------------------------------ it does the two things

def test_it_declares_itself_live():
    assert _backend().live is True


def test_restart_patches_the_rollout_annotation():
    apps = _Apps()
    b = KubernetesRemediationBackend(apps=apps, namespace="default")
    msg = b.apply(ActionKind.restart_pods, "checkout", "staging")
    assert "rollout restart" in msg
    body = apps.patches[-1][2]
    assert "kubectl.kubernetes.io/restartedAt" in str(body)


def test_scale_up_increases_replicas():
    apps = _Apps(replicas=2)
    b = KubernetesRemediationBackend(apps=apps, namespace="default")
    msg = b.apply(ActionKind.scale_up, "checkout", "staging")
    assert apps.patches[-1][2] == {"spec": {"replicas": 3}}
    assert "from 2 to 3" in msg


def test_scale_down_decreases_replicas():
    apps = _Apps(replicas=3)
    b = KubernetesRemediationBackend(apps=apps, namespace="default")
    b.apply(ActionKind.scale_down, "checkout", "staging")
    assert apps.patches[-1][2] == {"spec": {"replicas": 2}}


# ------------------------------------------------------------------ the safety clamps

def test_scale_down_never_reaches_zero():
    apps = _Apps(replicas=1)
    b = KubernetesRemediationBackend(apps=apps, namespace="default")
    msg = b.apply(ActionKind.scale_down, "checkout", "staging")
    # No patch issued — clamped at 1. Scaling to zero is an outage, not a fix.
    assert apps.patches == []
    assert "no change" in msg


def test_scale_up_respects_the_max_replicas_ceiling(monkeypatch):
    monkeypatch.setattr("warden.remediation_k8s.MAX_REPLICAS", 3)
    apps = _Apps(replicas=3)
    b = KubernetesRemediationBackend(apps=apps, namespace="default")
    msg = b.apply(ActionKind.scale_up, "checkout", "staging")
    assert apps.patches == []
    assert "no change" in msg


# ------------------------------------------------------------------ it refuses what it must not do

@pytest.mark.parametrize("action", [
    ActionKind.rollback_deploy, ActionKind.failover_replica, ActionKind.clear_cache,
    # A database action must never be attempted against the cluster: the router sends it to the
    # database backend, and if it ever arrived here anyway this backend has to refuse it.
    ActionKind.terminate_connections,
])
def test_it_refuses_actions_outside_restart_and_scale(action):
    with pytest.raises(RemediationError, match="restart_pods / scale_up / scale_down only"):
        _backend().apply(action, "checkout", "prod")


def test_an_api_fault_becomes_a_remediation_error_not_a_raw_exception():
    b = KubernetesRemediationBackend(apps=_Apps(fail=True), namespace="default")
    with pytest.raises(RemediationError, match="boom"):  # the underlying API error is surfaced
        b.apply(ActionKind.scale_up, "checkout", "staging")


# ------------------------------------------------------------------ arming & the gate

def test_backend_factory_is_dry_run_unless_armed(monkeypatch):
    monkeypatch.delenv("WARDEN_REMEDIATION", raising=False)
    assert isinstance(resolve_remediation_backend(), DryRunBackend)
    monkeypatch.setenv("WARDEN_REMEDIATION", "off")
    assert isinstance(resolve_remediation_backend(), DryRunBackend)


def _alert(environment="staging"):
    return Alert(alert_id="i", name="PodOOMKilled", severity=Severity.high, service="checkout",
                 environment=environment, summary="OOM", started_at="2026-08-23T00:00:00Z")


def _prop(action=ActionKind.scale_up):
    return RemediationProposal(action=action, target="checkout", reasoning="r",
                               expected_effect="e", blast_radius="single_service", reversible=True)


def _approved():
    return Verdict(status=VerdictStatus.approved_for_human)


def test_gate_plus_live_backend_actually_applies_and_reports_changed_infra():
    apps = _Apps(replicas=2)
    backend = KubernetesRemediationBackend(apps=apps, namespace="default")
    r = decide_remediation(
        _alert(), _prop(), _approved(),
        RemediationRequest(principal="role:oncall", approved=True),
        backend=backend,
    )
    assert r.outcome is RemediationOutcome.applied
    assert r.changed_infrastructure is True
    assert apps.patches, "the backend should have patched the deployment"


def test_gate_turns_a_backend_fault_into_a_failed_result_not_a_crash():
    backend = KubernetesRemediationBackend(apps=_Apps(fail=True), namespace="default")
    r = decide_remediation(
        _alert(), _prop(), _approved(),
        RemediationRequest(principal="role:oncall", approved=True),
        backend=backend,
    )
    assert r.outcome is RemediationOutcome.failed
    assert r.changed_infrastructure is False
    assert "backend error" in r.detail


def test_prod_still_blocks_the_live_backend_before_it_is_ever_called():
    apps = _Apps(replicas=2)
    backend = KubernetesRemediationBackend(apps=apps, namespace="default")
    r = decide_remediation(
        _alert(environment="prod"), _prop(), _approved(),
        RemediationRequest(principal="role:oncall", approved=True),
        backend=backend,
    )
    assert r.outcome is RemediationOutcome.not_auto_remediable
    assert apps.patches == [], "prod must never reach the live backend"
