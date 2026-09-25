"""The incident report as an on-call engineer, a developer and a DBA would use it.

Written after the owner's review of real reports in Slack: placeholders like `<namespace>`, warnings
printed AFTER the command they warn about, no statement of what was read or when, and nothing for
any team but on-call. Each test pins one of those.
"""

from __future__ import annotations

import itertools
import re

import pytest

from warden.models import (
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Severity,
    Verdict,
    VerdictStatus,
)
from warden.playbook import detect
from warden.reporting import build_report

# A real redaction placeholder looks like <EMAIL_1>. Anything else in angle brackets is a hole the
# reader has to fill in - which is what the owner asked never to see.
_HOLE = re.compile(r"<(?![A-Z]+_\d+>)[^>\n]{1,40}>")


def _alert(**labels):
    return Alert(alert_id="inc-x", name="PodOOMKilled", severity=Severity.high, service="checkout",
                 environment="prod", summary="checkout restarting", started_at="2026-09-24T12:31:22Z",
                 labels=labels)


OOM = ContextBundle(
    logs=["EVENT BackOff Pod/checkout-748c-bmwck: Back-off restarting failed container checkout",
          "checkout-748c-bmwck/checkout 2026-09-24T12:30:24Z checkout: allocating 900MiB cache",
          "EVENT OOMKilled Pod/checkout-748c-bmwck: container killed"],
    metrics={"oom_killed_containers": 2.0, "pods_ready": 0.0, "pods_total": 2.0, "replicas_desired": 2.0,
             "memory_limit_mib": 48.0, "restart_count": 8.0},
    recent_deploys=[{"deployment": "checkout", "image": "python:3.12.7-alpine", "at": "2026-09-24T12:28:48Z"}],
)


def _report(action=ActionKind.scale_up, ctx=OOM, backend="k8s", status=VerdictStatus.escalated, **labels):
    return build_report(
        _alert(**labels), context=ctx, backend=backend, show_identifiers=False,
        root_cause=RootCause(hypothesis="OOM at startup", confidence=0.7),
        proposal=RemediationProposal(action=action, target="checkout", reasoning="r", expected_effect="e",
                                     blast_radius="single_service", reversible=True),
        verdict=Verdict(status=status, reasons=["r"], policy_ids=[]),
    )


@pytest.mark.parametrize("action,backend,labels", list(itertools.product(
    list(ActionKind), ["k8s", "aws", "postgres", None],
    [{}, {"namespace": "shop", "deployment": "checkout"}, {"cluster": "prod-c"}],
)))
def test_no_report_contains_a_placeholder_to_fill_in(action, backend, labels):
    md = _report(action=action, backend=backend, **labels).markdown
    holes = _HOLE.findall(md)
    assert not holes, f"{action.value}/{backend}/{labels}: {holes}"


def test_the_warning_comes_before_the_command_it_warns_about():
    """A warning printed after the fix is read after the damage."""
    md = _report(action=ActionKind.terminate_connections, backend="postgres",
                 ctx=ContextBundle(logs=["postgres stuck connection: pid=4242 idle in transaction for 400s: SELECT 1"],
                                   metrics={"idle_in_transaction": 1.0})).markdown
    assert "## ⚠ Before you act" in md
    assert md.index("## ⚠ Before you act") < md.index("**2. Fix**")
    assert "IRREVERSIBLE" in md[:md.index("**2. Fix**")]


@pytest.mark.parametrize("backend,must,must_not", [
    ("aws", ["CloudWatch Logs `/ecs/checkout`: 12:16 to 12:46 UTC on 2026-09-24"], []),
    ("k8s", ["last 40 log lines per container", "Not read: CloudWatch"], ["CloudWatch Logs `"]),
    ("postgres", ["pg_stat_activity", "Not read: database logs, CloudWatch, Performance Insights"], []),
    (None, ["recorded demo incident"], ["CloudWatch Logs"]),
])
def test_every_report_says_what_was_read_and_over_what_window(backend, must, must_not, monkeypatch):
    """The owner asked whether WARDEN reads CloudWatch around the alert time. For ECS it does, for a
    window the report now states in clock time; for Kubernetes and PostgreSQL it does not, and the
    report says so instead of leaving it to be assumed."""
    monkeypatch.delenv("WARDEN_BACKEND", raising=False)
    md = _report(backend=backend).markdown
    section = md[md.index("## What WARDEN read"):md.index("## What WARDEN thinks")]
    for text in must:
        assert text in section, section
    for text in must_not:
        assert text not in section


def test_the_summary_states_impact_from_the_evidence_not_the_model():
    md = _report().markdown
    summary = md[md.index("## Summary"):md.index("## What WARDEN read")]
    assert "containers were OOM-killed" in summary and "only 0 of 2 pods are ready" in summary


def test_oom_guidance_quotes_the_numbers_in_the_evidence():
    """Not "raise the limit": the limit is 48 MiB and the app logged 900 MiB, so the advice says so
    and derives a value from them - stating how."""
    oom = next(p for p in detect(_alert(), OOM) if p.key == "oom")
    sizing = " ".join(oom.platform)
    assert "48 MiB" in sizing and "900 MiB" in sizing and "1152 MiB" in sizing
    assert "peak + 25%" in sizing


def test_follow_ups_reach_every_team_the_pattern_involves():
    md = _report().markdown
    follow = md[md.index("## Follow-ups by team"):]
    for team in ("**On-call - now**", "**Developers**", "**Platform / DevOps**", "**Prevention**"):
        assert team in follow, team


def test_scale_up_is_computed_from_the_evidence_and_undo_returns_to_it():
    md = _report(namespace="shop", deployment="checkout").markdown
    assert "kubectl -n shop scale deploy/checkout --replicas=3   # currently 2" in md
    assert "kubectl -n shop scale deploy/checkout --replicas=2" in md


def test_an_unknown_namespace_is_found_by_a_real_command():
    md = _report(action=ActionKind.rollback_deploy).markdown
    assert "NS=$(kubectl get deploy -A --field-selector metadata.name=checkout" in md
    assert 'kubectl -n "$NS" rollout undo deploy/checkout' in md


def test_an_irreversible_action_with_no_target_prints_no_command():
    """A failover aimed by guesswork is worse than none: WARDEN says it cannot identify the primary."""
    md = _report(action=ActionKind.failover_replica, backend="postgres",
                 ctx=ContextBundle(metrics={"replica_lag_seconds": 47.0})).markdown
    assert "--force-failover" not in md
    assert "cannot identify the primary" in md


@pytest.mark.parametrize("ctx,key", [
    (ContextBundle(logs=["EVENT Failed Pod/x: Error: ImagePullBackOff"]), "image_pull"),
    (ContextBundle(logs=["EVENT Unhealthy Pod/x: Liveness probe failed:"]), "probe"),
    (ContextBundle(metrics={"replicas_desired": 0.0, "pods_total": 0.0}), "scaled_to_zero"),
    (ContextBundle(logs=["postgres stuck connection: pid=1 idle in transaction for 400s: SELECT 1"]), "db_idle_tx"),
    (ContextBundle(logs=["postgres blocked session: pid=5 waiting 300s on pid(s) 4: LOCK TABLE t"]), "db_lock"),
    (ContextBundle(logs=["postgres long-running query: pid=7 running 540s user=u app=a client=c: SELECT 1"]),
     "db_long_query"),
    (ContextBundle(metrics={"connections_used_pct": 0.8}), "db_pool"),
    (ContextBundle(metrics={"replica_lag_seconds": 47.0}), "replica_lag"),
    (ContextBundle(tool_errors=["metrics: connection timeout expired"]), "evidence_unreachable"),
    (ContextBundle(metrics={"crashloop_containers": 1.0}), "crashloop"),
])
def test_each_pattern_is_detected_from_its_evidence(ctx, key):
    assert key in [p.key for p in detect(_alert(), ctx)]


def test_a_healthy_service_detects_no_pattern():
    healthy = ContextBundle(logs=["heartbeat ok"] * 3,
                            metrics={"pods_ready": 2.0, "pods_total": 2.0, "replicas_desired": 2.0,
                                     "oom_killed_containers": 0.0, "crashloop_containers": 0.0})
    assert detect(_alert(), healthy) == []


def test_when_the_gate_says_the_action_cannot_work_that_is_the_first_warning():
    """⛔ Reviewing a real EKS report: the gate escalated scale_up on OOM-killed pods (P11), and the
    runbook below it still read as a recipe for scaling up."""
    from warden.verifier import verify

    rc = RootCause(hypothesis="OOM at startup", confidence=0.8)
    prop = RemediationProposal(action=ActionKind.scale_up, target="checkout", reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)
    v = verify(_alert(), OOM, rc, prop)
    assert "P11-ACTION-CONTRADICTS-EVIDENCE" in v.policy_ids
    md = build_report(_alert(), context=OOM, backend="k8s", root_cause=rc, proposal=prop, verdict=v,
                      show_identifiers=False).markdown
    before = md[md.index("## ⚠ Before you act"):md.index("## Runbook")]
    first = before.splitlines()[1]
    assert first.startswith("- ⛔ **The gate found this action cannot fix what the evidence shows.**"), first


def test_oom_back_off_is_not_reported_as_a_separate_crash_loop():
    """The back-off after an OOM kill IS the OOM; a second pattern added irrelevant config advice."""
    keys = [p.key for p in detect(_alert(), OOM)]
    assert "oom" in keys and "crashloop" not in keys


LIVE = ContextBundle(
    logs=["STATUS checkout-748c-bmwck/checkout: restarts 6; last exit: OOMKilled (code 137); now waiting: CrashLoopBackOff",
          "checkout-748c-bmwck/checkout (previous) 2026-09-24T12:30:24Z checkout: allocating 900MiB cache",
          "ROLLOUT revision 2 (current): python:3.12.7-alpine created 2026-09-24T12:28:48Z",
          "ROLLOUT revision 1: python:3.12-alpine created 2026-09-24T11:40:06Z",
          "EVENT BackOff Pod/checkout-748c-bmwck: Back-off restarting failed container checkout"],
    metrics={"oom_killed_containers": 1.0, "pods_ready": 0.0, "pods_total": 1.0, "replicas_desired": 1.0,
             "memory_limit_mib": 48.0},
)


def test_the_checks_warden_ran_are_shown_as_results_not_as_homework():
    """⛔ The owner: "why all kubectl commands in suggestions - aren't you using them yourself?" WARDEN
    now reads container status, the crashed container's output and the rollout history itself, and
    the report shows what it found."""
    md = _report(ctx=LIVE, backend="k8s", namespace="shop", deployment="checkout").markdown
    section = md[md.index("## Checked by WARDEN"):md.index("## Metrics at the time")]
    assert "last exit: OOMKilled (code 137)" in section
    assert "allocating 900MiB cache" in section
    assert "revision 2 (current): python:3.12.7-alpine" in section
    key = md[md.index("## Key log lines"):md.index("```", md.index("## Key log lines") + 20) + 400]
    assert "ROLLOUT revision" not in key and "STATUS checkout" not in key, "a check result shown twice"


def test_when_warden_read_the_cluster_the_runbook_only_rechecks_current_state():
    md = _report(action=ActionKind.rollback_deploy, ctx=LIVE, backend="k8s",
                 namespace="shop", deployment="checkout").markdown
    step1 = md[md.index("**1. Re-check right before acting"):md.index("**2. Fix**")]
    assert "state may have moved since" in step1
    assert "get events" not in step1 and "describe pods" not in step1 and "logs deploy/" not in step1
    assert "rollout history" in step1 and "get pods" in step1


def test_a_demo_incident_keeps_the_full_check_list():
    """Nothing was read live, so nothing was checked: the person still has to look."""
    md = _report(action=ActionKind.rollback_deploy, ctx=OOM, backend=None, namespace="shop",
                 deployment="checkout").markdown
    assert "**1. Check - read-only, confirm the diagnosis first**" in md
    assert "get events" in md
