"""Every policy gets a test that proves it can FIRE, not just that the happy path passes.

A gate nobody has watched reject something is not a gate.
"""

import pytest

from warden.models import (
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Severity,
    VerdictStatus,
)
from warden.verifier import verify


def _alert(**kw):
    base = dict(
        alert_id="a-1",
        name="HighErrorRate",
        severity=Severity.critical,
        service="checkout",
        environment="prod",
        summary="5xx rate above 4%",
        started_at="2026-08-21T10:00:00Z",
    )
    base.update(kw)
    return Alert(**base)


def _ctx(**kw):
    # Deliberately realistic rather than minimal. An earlier version used a single log line and a
    # single metric, and P9 (thin evidence) correctly flagged it - the helper was describing a
    # situation no operator would act on, while the tests called it the "clean case".
    base = dict(
        logs=["err 500", "err 500", "NullPointerException"],
        metrics={"error_rate": 0.04, "p99_latency_ms": 2140.0},
        recent_deploys=[{"sha": "abc"}],
    )
    base.update(kw)
    return ContextBundle(**base)


def _rc(confidence=0.9):
    return RootCause(hypothesis="bad deploy", confidence=confidence, evidence=["err"])


def _prop(**kw):
    base = dict(
        action=ActionKind.rollback_deploy,
        target="checkout",
        reasoning="revert the deploy",
        expected_effect="errors return to baseline",
        blast_radius="single_service",
        reversible=True,
    )
    base.update(kw)
    return RemediationProposal(**base)


def test_clean_case_is_held_for_a_human_not_auto_run():
    v = verify(_alert(), _ctx(), _rc(), _prop())
    assert v.status is VerdictStatus.approved_for_human
    assert v.requires_approval is True


def test_p1_action_not_allowed_in_prod():
    v = verify(_alert(), _ctx(), _rc(), _prop(action=ActionKind.scale_down))
    assert v.status is VerdictStatus.rejected
    assert "P1-ENV-ALLOWLIST" in v.policy_ids


def test_p2_reads_the_action_table_not_the_models_claim():
    """⛔ The whole point of the table. The proposal claims a database failover is reversible;
    WARDEN classifies a promoted replica as irreversible, and the table decides. Before
    2026-09-12 this claim skipped P2 entirely, which is how two models got opposite verdicts for
    the identical operation (docs/live-model-run-2026-09-06.md §3)."""
    v = verify(_alert(), _ctx(), _rc(confidence=0.99),
               _prop(action=ActionKind.failover_replica, reversible=True))
    assert v.status is VerdictStatus.rejected
    assert "P2-IRREVERSIBLE-IN-PROD" in v.policy_ids
    assert "action table" in " ".join(v.reasons), "the reason must name what decided"


def test_p3_refuses_to_act_without_evidence():
    empty = ContextBundle()
    v = verify(_alert(), empty, _rc(), _prop())
    assert v.status is VerdictStatus.rejected
    assert "P3-NO-EVIDENCE" in v.policy_ids


def test_p4_low_confidence_escalates():
    v = verify(_alert(), _ctx(), _rc(confidence=0.2), _prop())
    assert v.status is VerdictStatus.escalated
    assert "P4-LOW-CONFIDENCE" in v.policy_ids


def test_p5_cannot_roll_back_a_deploy_that_is_not_in_evidence():
    v = verify(_alert(), _ctx(recent_deploys=[]), _rc(), _prop())
    assert v.status is VerdictStatus.rejected
    assert "P5-NO-DEPLOY-TO-ROLL-BACK" in v.policy_ids


def test_p6_wide_blast_radius_escalates():
    v = verify(_alert(), _ctx(), _rc(), _prop(blast_radius="region"))
    assert v.status is VerdictStatus.escalated
    assert "P6-BLAST-RADIUS" in v.policy_ids


def test_p7_heavy_action_on_low_severity_escalates():
    v = verify(_alert(severity=Severity.low), _ctx(), _rc(), _prop())
    assert v.status is VerdictStatus.escalated
    assert "P7-DISPROPORTIONATE" in v.policy_ids


def test_p8_partial_context_escalates():
    v = verify(_alert(), _ctx(tool_errors=["metrics timed out"]), _rc(), _prop())
    assert v.status is VerdictStatus.escalated
    assert "P8-PARTIAL-CONTEXT" in v.policy_ids


def test_inert_actions_need_no_approval():
    v = verify(_alert(), ContextBundle(), _rc(), _prop(action=ActionKind.escalate_to_human))
    assert v.status is VerdictStatus.auto_safe
    assert v.requires_approval is False


def test_rejection_beats_escalation_when_both_apply():
    """A hard no must not be softened into 'ask a human' by a second, weaker finding."""
    v = verify(_alert(), _ctx(recent_deploys=[]), _rc(confidence=0.1), _prop())
    assert v.status is VerdictStatus.rejected


# --------------------------------------------------------------------------- P9
# Added after a LIVE model run returned confidence 0.85 on all four bundled incidents, including
# the one whose evidence is two vague log lines. Self-reported confidence is not calibrated, so the
# gate needed a signal it measures itself.


def test_p9_thin_evidence_escalates_even_at_high_confidence():
    thin = ContextBundle(logs=["one line"], metrics={}, recent_deploys=[])
    v = verify(_alert(), thin, _rc(confidence=0.99), _prop(action=ActionKind.restart_pods))
    assert v.status is VerdictStatus.escalated
    assert "P9-THIN-EVIDENCE" in v.policy_ids


def test_p9_does_not_fire_on_a_well_evidenced_incident():
    v = verify(_alert(), _ctx(), _rc(), _prop())
    assert "P9-THIN-EVIDENCE" not in v.policy_ids


def test_p9_accepts_two_independent_kinds_of_evidence():
    """Logs plus metrics, no deploy - enough to reason about."""
    ctx = ContextBundle(
        logs=["a", "b", "c"], metrics={"error_rate": 0.1, "p99": 900.0}, recent_deploys=[]
    )
    v = verify(_alert(), ctx, _rc(), _prop(action=ActionKind.restart_pods))
    assert "P9-THIN-EVIDENCE" not in v.policy_ids


def test_p9_ignores_inert_actions():
    thin = ContextBundle(logs=["one line"])
    v = verify(_alert(), thin, _rc(), _prop(action=ActionKind.escalate_to_human))
    assert "P9-THIN-EVIDENCE" not in v.policy_ids


# --------------------------------------------------------------------------- what counts as inert
# Only doing nothing and handing off to a human skip approval. Everything that can touch running
# infrastructure - clear_cache included - is held for a person, because that is the project's claim.


def test_only_no_action_and_escalate_are_auto_safe():
    """Unchanged contract: only these two skip approval once policy has passed."""
    from warden.verifier import AUTO_SAFE_ACTIONS

    assert AUTO_SAFE_ACTIONS == {ActionKind.no_action, ActionKind.escalate_to_human}


def test_only_escalate_to_human_is_exempt_from_the_evidence_floor():
    """The narrower set, and the point of the split. Handing an incident to a person is the right
    answer to weak evidence, so measuring evidence before allowing it would be circular. Saying
    "nothing is wrong" is a claim ABOUT the evidence and gets no such exemption: 14 of 42 runs on a
    real account closed a broken service with `no_action` and the gate allowed every one."""
    from warden.verifier import EVIDENCE_EXEMPT_ACTIONS

    assert EVIDENCE_EXEMPT_ACTIONS == {ActionKind.escalate_to_human}


def test_clear_cache_in_prod_is_held_for_a_human_not_auto_run():
    """A cache flush can cause a stampede/latency spike, so it is a real action behind approval."""
    v = verify(_alert(), _ctx(), _rc(), _prop(action=ActionKind.clear_cache))
    assert v.status is VerdictStatus.approved_for_human
    assert v.requires_approval is True


def test_thin_evidence_clear_cache_escalates_rather_than_slipping_through_as_safe():
    """The regression this guards: while clear_cache was 'auto_safe' it skipped P9 entirely, so a
    cache flush on two log lines passed unattended. Now it is subject to the evidence floor."""
    thin = ContextBundle(logs=["one line"], metrics={}, recent_deploys=[])
    v = verify(_alert(), thin, _rc(confidence=0.99), _prop(action=ActionKind.clear_cache))
    assert v.status is VerdictStatus.escalated
    assert "P9-THIN-EVIDENCE" in v.policy_ids


# --- environment policy is config-driven now (environments.yaml), not a hardcoded dict -----------

def test_p1_uses_the_env_config_qa_staging_denies_failover():
    """qa-staging is not one of the old three environments; the policy config governs it, and it
    denies a DB failover even though it auto-remediates everything else."""
    v = verify(
        _alert(environment="qa-staging"),
        _ctx(),
        _rc(),
        _prop(action=ActionKind.failover_replica),
    )
    assert v.status is VerdictStatus.rejected
    assert "P1-ENV-ALLOWLIST" in v.policy_ids


def test_p1_unknown_environment_fails_closed():
    """An environment string the policy has never heard of can do nothing but escalate."""
    v = verify(
        _alert(environment="brand-new-region-7"),
        _ctx(),
        _rc(),
        _prop(action=ActionKind.restart_pods),
    )
    assert v.status is VerdictStatus.rejected
    assert "P1-ENV-ALLOWLIST" in v.policy_ids


def test_a_permitted_action_in_a_new_prod_tier_env_still_blocks_irreversible():
    """P2 keys on the env TIER, not the literal string 'prod', so any prod-tier env blocks
    irreversible. Uses failover_replica because reversibility now comes from the action table -
    `restart_pods` with a `reversible: false` claim is P10's business, not P2's."""
    v = verify(
        _alert(environment="prod"),
        _ctx(),
        _rc(confidence=0.99),
        _prop(action=ActionKind.failover_replica, reversible=True),
    )
    assert v.status is VerdictStatus.rejected
    assert "P2-IRREVERSIBLE-IN-PROD" in v.policy_ids


# --------------------------------------------------------------------------- the action table
# Added 2026-09-12. Two of the nine policies used to read fields the MODEL wrote, in a gate whose
# entire claim is that the model does not decide. These tests are that hole, closed.


def test_the_table_covers_every_action_kind():
    """A missing entry would be a KeyError raised from inside the gate, mid-decision."""
    from warden.models import ACTION_FACTS

    assert set(ACTION_FACTS) == set(ActionKind)


def test_p6_uses_the_table_floor_when_the_model_understates_the_radius():
    """A failover claimed as single_pod is still multi_service. Run in `dev` so the tier is not
    prod and P2 does not mask what P6 is doing."""
    v = verify(_alert(environment="dev"), _ctx(), _rc(),
               _prop(action=ActionKind.failover_replica, blast_radius="single_pod"))
    assert v.status is VerdictStatus.escalated
    assert "P6-BLAST-RADIUS" in v.policy_ids


def test_p6_honours_a_model_that_widens_beyond_the_floor():
    """Tightening is always allowed: a restart claimed as region-wide gets a human."""
    v = verify(_alert(), _ctx(), _rc(),
               _prop(action=ActionKind.restart_pods, blast_radius="region"))
    assert v.status is VerdictStatus.escalated
    assert "P6-BLAST-RADIUS" in v.policy_ids


def test_a_model_claiming_irreversible_escalates_rather_than_being_rejected():
    """P10. The table says a rollback can be undone; the proposal says it cannot. WARDEN does not
    reject on the model's word - P2 exists so the model cannot decide - but it does not overrule a
    warning either. Nothing runs either way; a human reconciles it."""
    v = verify(_alert(), _ctx(), _rc(), _prop(reversible=False))
    assert v.status is VerdictStatus.escalated
    assert "P10-CLAIM-CONTRADICTS-TABLE" in v.policy_ids
    assert "P2-IRREVERSIBLE-IN-PROD" not in v.policy_ids


# ------------------------------------------------------------------- "nothing is wrong" is a claim


def test_no_action_on_thin_evidence_escalates_rather_than_closing_the_incident():
    thin = ContextBundle(logs=["one line"], metrics={}, recent_deploys=[])
    v = verify(_alert(), thin, _rc(confidence=0.99), _prop(action=ActionKind.no_action))
    assert v.status is VerdictStatus.escalated
    assert "P9-THIN-EVIDENCE" in v.policy_ids


def test_no_action_at_low_confidence_escalates():
    v = verify(_alert(), _ctx(), _rc(confidence=0.25), _prop(action=ActionKind.no_action))
    assert v.status is VerdictStatus.escalated
    assert "P4-LOW-CONFIDENCE" in v.policy_ids


def test_no_action_with_a_failed_tool_escalates():
    """The case seen on a real account: WARDEN could not read the logs, recorded that in
    tool_errors, and still closed the incident as auto_safe."""
    v = verify(_alert(), _ctx(tool_errors=["logs: AccessDeniedException"]), _rc(),
               _prop(action=ActionKind.no_action))
    assert v.status is VerdictStatus.escalated
    assert "P8-PARTIAL-CONTEXT" in v.policy_ids


def test_no_action_with_no_evidence_escalates_rather_than_being_rejected():
    """P3 still exempts the passive actions deliberately: "rejected - you may not conclude nothing
    is wrong" is not a verdict an operator can act on. P9 catches the same condition with the verb
    that makes sense, so the incident reaches a person either way."""
    v = verify(_alert(), ContextBundle(), _rc(), _prop(action=ActionKind.no_action))
    assert v.status is VerdictStatus.escalated
    assert "P9-THIN-EVIDENCE" in v.policy_ids
    assert "P3-NO-EVIDENCE" not in v.policy_ids


def test_a_well_evidenced_confident_no_action_is_still_auto_safe():
    """The other side of the change, so it is not simply "escalate everything": the tool looked
    properly, found nothing wrong, and says so without needing a human."""
    v = verify(_alert(), _ctx(), _rc(confidence=0.9), _prop(action=ActionKind.no_action))
    assert v.status is VerdictStatus.auto_safe
    assert v.requires_approval is False


# --------------------------------------------------------------------------- P11 / P12 (2026-09-25)
#
# Written after the EKS and RDS waves, from their failures - see the policy comments. Every rule has
# a case where it MUST fire and a case where it must NOT, so it cannot drift into blocking the
# correct answer. Replaying all 48 recorded EKS/RDS runs changed no correct run's verdict.

P11, P12 = "P11-ACTION-CONTRADICTS-EVIDENCE", "P12-NO-ACTION-WITH-SYMPTOMS"


def _fires(policy, action, **ctx):
    v = verify(_alert(), _ctx(**ctx), _rc(), _prop(action=action))
    return policy in v.policy_ids, v


@pytest.mark.parametrize("action,ctx,why", [
    (ActionKind.scale_up, dict(metrics={"oom_killed_containers": 2.0, "pods_ready": 0.0, "pods_total": 2.0}),
     "no pod ready, OOM-killed at startup: new replicas die the same way (EKS k8s-02/03)"),
    (ActionKind.scale_up,
     dict(logs=["EVENT BackOff Pod/checkout-a: Back-off restarting failed container", "OOMKilled", "x"],
          metrics={"oom_killed_containers": 1.0, "pods_ready": 1.0, "pods_total": 1.0}),
     "ready between crashes but backing off: still failing (CI's flapping readiness)"),
    (ActionKind.scale_down, dict(logs=["kubelet OOMKilled pod=x", "err", "err"]),
     "fewer replicas never lower memory per replica"),
    (ActionKind.restart_pods, dict(logs=["EVENT Failed Pod/x: Error: ImagePullBackOff", "a", "b"]),
     "a restart re-pulls the same unpullable image"),
    (ActionKind.terminate_connections,
     dict(metrics={"long_running_queries": 1.0, "idle_in_transaction": 0.0, "locks_waiting": 0.0}),
     "only an ACTIVE query is long - terminating destroys work in progress (RDS db-04's harmful case)"),
    (ActionKind.failover_replica, dict(metrics={"replica_lag_seconds": 0.0, "error_rate": 0.1}),
     "nothing is lagging"),
])
def test_p11_escalates_an_action_that_cannot_fix_the_evidence(action, ctx, why):
    fired, v = _fires(P11, action, **ctx)
    assert fired, f"{why}: {v.policy_ids}"
    # Held back either way: P11 escalates, and a stronger policy (P2 on an irreversible action in
    # prod) may reject outright - rejection outranks escalation.
    assert v.status in (VerdictStatus.escalated, VerdictStatus.rejected), v.status


@pytest.mark.parametrize("action,ctx,why", [
    (ActionKind.scale_up, dict(metrics={"oom_killed_containers": 1.0, "pods_ready": 1.0, "pods_total": 2.0}),
     "a pod is serving: memory may grow with load, and scaling out can relieve it (inc-002's case)"),
    (ActionKind.scale_up, dict(logs=["kubelet OOMKilled", "a", "b"], metrics={"memory_utilisation": 0.94, "rps": 1420.0}),
     "no pod counts at all - the rule must not guess that none is ready"),
    (ActionKind.scale_up,
     dict(logs=["EVENT BackOff Pod/checkout-a: Back-off restarting failed container", "kubelet OOMKilled", "x"],
          metrics={"oom_killed_containers": 1.0, "pods_ready": 4.0, "pods_total": 5.0}),
     "one of five pods failing: the other four serve, and load-driven memory may be relieved by scaling"),
    (ActionKind.restart_pods, dict(logs=["OOMKilled", "a", "b"]), "restart is not contradicted by OOM"),
    (ActionKind.terminate_connections,
     dict(metrics={"long_running_queries": 1.0, "idle_in_transaction": 3.0, "locks_waiting": 0.0}),
     "sessions ARE stuck idle in a transaction - that is what terminate is for"),
    (ActionKind.terminate_connections,
     dict(metrics={"long_running_queries": 2.0, "idle_in_transaction": 1.0, "locks_waiting": 2.0}),
     "lock contention (RDS db-05): the blocker must go"),
    (ActionKind.failover_replica, dict(metrics={"replica_lag_seconds": 47.0, "error_rate": 0.1}),
     "real lag (inc-003)"),
])
def test_p11_does_not_fire_where_the_action_can_help(action, ctx, why):
    fired, v = _fires(P11, action, **ctx)
    assert not fired, f"{why}: {v.reasons}"


@pytest.mark.parametrize("ctx,symptom", [
    (dict(metrics={"oom_killed_containers": 2.0, "pods_ready": 0.0, "pods_total": 2.0}), "OOM-killed"),
    (dict(metrics={"crashloop_containers": 1.0, "error_rate": 0.0}), "crash-looping"),
    (dict(logs=["EVENT Failed Pod/x: Error: ErrImagePull", "a", "b"]), "cannot be pulled"),
    (dict(metrics={"pods_ready": 1.0, "pods_total": 2.0}), "1 of 2 pods are ready"),
    (dict(metrics={"pods_total": 0.0, "pods_ready": 0.0, "replicas_desired": 2.0}), "0 ready of 2 replicas desired"),
    (dict(metrics={"tasks_running": 0.0, "tasks_desired": 2.0}), "0 of 2 tasks running"),
    (dict(logs=["postgres stuck connection: pid=1 idle in transaction for 400s: SELECT 1", "a", "b"]), "stuck threshold"),
    (dict(metrics={"locks_waiting": 2.0, "x": 0.0}), "2 sessions are waiting on a lock"),
    (dict(metrics={"long_running_queries": 1.0, "x": 0.0}), "1 query has been running over 60s"),
    (dict(metrics={"replica_lag_seconds": 47.0, "x": 0.0}), "replica lag is 47s"),
])
def test_p12_escalates_no_action_when_the_evidence_shows_a_symptom(ctx, symptom):
    fired, v = _fires(P12, ActionKind.no_action, **ctx)
    assert fired and v.status is VerdictStatus.escalated
    assert any(symptom in r for r in v.reasons), v.reasons


@pytest.mark.parametrize("ctx", [
    dict(metrics={"pods_ready": 2.0, "pods_total": 2.0, "restart_count": 0.0, "oom_killed_containers": 0.0,
                  "crashloop_containers": 0.0, "replicas_desired": 2.0}, logs=["heartbeat ok"] * 3),
    dict(metrics={"active_connections": 8.0, "idle_in_transaction": 0.0, "locks_waiting": 0.0,
                  "long_running_queries": 0.0, "max_connections": 79.0}),
    dict(metrics={"replica_lag_seconds": 2.0, "error_rate": 0.0}),
])
def test_p12_leaves_a_healthy_no_action_alone(ctx):
    """The healthy controls of every wave: a confident no_action on clean evidence stays auto_safe."""
    fired, v = _fires(P12, ActionKind.no_action, **ctx)
    assert not fired, v.reasons


def test_p12_does_not_touch_other_actions():
    fired, _ = _fires(P12, ActionKind.escalate_to_human, metrics={"oom_killed_containers": 2.0, "x": 0.0})
    assert not fired


@pytest.mark.parametrize("action", list(ActionKind))
@pytest.mark.parametrize("ctx", [
    dict(metrics={"oom_killed_containers": 2.0, "pods_ready": 0.0, "pods_total": 2.0}, tool_errors=["logs: x"]),
    dict(logs=[], metrics={}, recent_deploys=[]),
    dict(metrics={"replica_lag_seconds": 0.0, "long_running_queries": 1.0, "idle_in_transaction": 0.0,
                  "locks_waiting": 0.0}),
])
def test_every_policy_that_fires_has_exactly_one_reason_in_the_same_position(action, ctx):
    """The report pairs reasons with policy ids by position to find the gate's own finding (P11) and
    put it first under "Before you act". That only works if they stay aligned."""
    v = verify(_alert(severity=Severity.low), _ctx(**ctx), _rc(confidence=0.3), _prop(action=action))
    if v.policy_ids:
        assert len(v.reasons) == len(v.policy_ids), (v.policy_ids, v.reasons)


@pytest.mark.parametrize("metrics,full", [
    ({"connection_pool_used": 100.0, "connection_pool_size": 100.0}, True),
    ({"connection_pool_used": 99.0, "connection_pool_size": 100.0}, False),
    ({"connections_used_pct": 1.0}, True),
    ({"connections_used_pct": 0.97}, False),
    ({}, False),
])
def test_a_full_connection_pool_is_a_symptom(metrics, full):
    """inc-005's report said "no failing component" beside a 100/100 pool."""
    from warden.models import ContextBundle
    from warden.verifier import symptoms
    assert ("the connection pool is full" in symptoms(ContextBundle(metrics=metrics))) is full
