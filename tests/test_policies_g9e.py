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
]
MATERIAL = [
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
