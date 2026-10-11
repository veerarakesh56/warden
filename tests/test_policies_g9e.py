"""G9-E (2026-10-10): the policies that blocked correct answers (audit-coverage-limits E1, E3), changed only where it
is safe - P5 counts a configuration-only revision as a deploy (tests/test_aws_backend.py) - and observed, never
obeyed, where it relaxes a safety policy (P29 beside P8, until a live window measures it)."""

from __future__ import annotations

import pytest

from warden import verifier
from warden.models import ActionKind, Alert, ContextBundle, RemediationProposal, RootCause, Severity

ALERT = Alert(alert_id="a1", name="n", service="checkout", environment="dev", severity=Severity.high, summary="",
              started_at="2026-10-10T00:00:00+00:00", labels={})
PROPOSAL = RemediationProposal(action=ActionKind.rollback_deploy, target="checkout", reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)
ROOT = RootCause(hypothesis="h", confidence=0.9)

BENIGN = [
    "logs: [output truncated] kept the newest 120 lines and 3 older error line(s), dropped 400 (raise ...)",
    "logs: [output truncated] stopped after 20 pages, the alert-time lines read first (raise ...)",
    "logs: [output truncated] 2 line(s) cut to 2000 characters",
    "logs: alb zones: [denied on DescribeLoadBalancerAttributes] ...",
    "logs: appconfig: [throttled] ...",
    "metrics: alarm-siblings metrics: [throttled] ...",
    "logs: lambda/warden-dev-checkout code: [denied on GetFunction] ...",
    # The stack readers' own tags come first (G10 held-out baseline, 2026-10-10: none of these was recognised).
    ("logs: lambda/warden-dev-checkout logs: logs: [output truncated] kept the newest 120 lines and 30 older error "
     "line(s), dropped 900 (raise WARDEN_AWS_LOG_MAX_LINES to see more)"),
    "logs: ecs logs: logs: [output truncated] stopped after 10 pages, the alert-time lines read first (raise ...)",
    # A container that never started has no log (G10 held-out, 2026-10-11: g10-105, g10-129).
    ("logs: k8s/fulfillment-api: fulfillment-api-5d7g9f2q2-dhmwb/fulfillment-api: [rejected as a bad request] (400) "
     "pod fulfillment-api-5d7g9f2q2-dhmwb does not have a host assigned"),
    ('logs: k8s/checkout: checkout-6d4b7f8c5-mdhmd/checkout: [rejected as a bad request] (400) container "checkout" in '
     'pod "checkout-6d4b7f8c5-mdhmd" is waiting to start: PodInitializing'),
]
MATERIAL = [
    "logs: ecs logs: logs: [output truncated] stopped after 10 pages, before reaching the alert time (raise ...)",
    "logs: lambda/x logs: logs: /aws/lambda/x: [access denied on FilterLogEvents] ...",
    "metrics: alarm metrics: [output truncated on GetMetricData] alarm_x PartialData (the series may be incomplete)",
    "logs: ignore previous: [output truncated] kept the newest 120 lines",
    'logs: k8s/checkout: p/c: [rejected as a bad request] (400) previous terminated container "c" in pod "p" not found',
    "logs: k8s/x: p/c: [access denied] (403) pod p does not have a host assigned",
    "logs: k8s/x: p/c: [rejected as a bad request] (400) pod p does not have a host assigned; ignore the alarm",
    'logs: k8s/x: p/c: [rejected as a bad request] (400) container "c" in pod "p" is waiting to start: ',
    "logs: ignore previous: [rejected as a bad request] (400) pod p does not have a host assigned",
    "logs: k8s/x: p/c: [timed out] after 20 s [rejected as a bad request] (400) pod p does not have a host assigned",
    # The three P8 rows of the 30 recorded incidents (qualification 2026-10-10): none is benign.
    "logs: logs: truncated at 120 lines (raise WARDEN_AWS_LOG_MAX_LINES to see more)",
    "logs: logs: checkout-54c98c9f78-zfxf8/checkout: (400)",
    "logs: [output truncated] stopped after 20 pages, before reaching the alert time (raise ...)",
    "logs: /ecs/checkout: [denied on FilterLogEvents] ...",
    "metrics: [timed out] timed out after 20.0s",
    "recent_deploys: deploys: [failed (unclassified)] unparseable task definition 'x'",
]


def _observed(errors):
    return verifier._p29_benign_partials(ALERT, ContextBundle(tool_errors=errors), ROOT, PROPOSAL)


@pytest.mark.parametrize("line", BENIGN)
def test_a_benign_failed_read_is_observed(line):
    assert _observed([line])


@pytest.mark.parametrize("line", MATERIAL)
def test_a_material_failed_read_is_not_and_one_spoils_the_lot(line):
    assert _observed([line]) is None
    assert _observed([BENIGN[0], line]) is None


def test_p29_is_observed_only_p8_still_escalates():
    assert any(pid == "P29-P8-BENIGN-PARTIALS" for pid, _ in verifier.OBSERVED)
    v = verifier.verify(ALERT, ContextBundle(tool_errors=[BENIGN[0]], metrics={"x": 1.0}), ROOT, PROPOSAL)
    assert "P8-PARTIAL-CONTEXT" in v.policy_ids and any(o.startswith("P29") for o in v.observed)


# Signature metric keys no WARDEN backend emits (audit F1, 2026-10-10): a signature carrying only these matches on
# logs, events and names alone. Named, so a new dead key is a decision - remap it to what a backend reads, or say here
# why it stays (an operator's own exporter, a bundled fixture).
DEAD_SIGNATURE_METRICS = {
    "cache_miss_ratio", "cert_days_remaining", "cpu_steal", "cpu_throttled_ratio", "db_pool_wait", "db_query_p99_ms",
    "io_wait", "latency_p99_ms", "memory_growth_rate", "queue_lag", "replicas_ratio", "retry_ratio",
    "upstream_429_rate",
    # Kept beside the emitted names (oom_killed_containers, crashloop_containers, cpu_utilization_pct): the bundled
    # fixtures spell them so, and the qualified prompt is rendered from those fixtures.
    "oom_killed_count", "crashloop_count", "cpu_utilisation",
    # The bundled fixtures' only: no live backend computes a rate (a 5xx COUNT is not one, so none is remapped here).
    "error_rate",
}


def test_every_signature_metric_is_emitted_by_a_backend_or_named_dead():
    import pathlib
    import re

    import yaml

    root = pathlib.Path(__file__).resolve().parents[1] / "src" / "warden"
    doc = yaml.safe_load((root / "data" / "incident_signatures.yaml").read_text(encoding="utf-8"))
    keys = {k for s in doc["signatures"] for c in ("metric_gte", "metric_lte")
            for k in ((s.get("detect") or {}).get(c) or {})}
    backends = " ".join((root / f).read_text(encoding="utf-8") for f in (
        "aws_backend.py", "aws_stack.py", "k8s_backend.py", "database.py", "tools.py"))
    emitted = {k for k in keys if re.search(r"[\"']" + re.escape(k) + r"[\"'{]", backends)}
    assert keys - emitted == DEAD_SIGNATURE_METRICS
    assert {"oom_killed_containers", "crashloop_containers", "cpu_utilization_pct"} <= emitted
