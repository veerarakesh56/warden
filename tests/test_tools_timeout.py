"""The timeout has to be able to fire, or the docstring claiming it is a lie.

This test exists because an earlier version of tools.py said "each tool has a timeout" in its
docstring while implementing none. A claim in a comment is not a feature.
"""

import time

from warden.models import ActionKind, Alert, RemediationProposal, RootCause, Severity, VerdictStatus
from warden.tools import FixtureBackend, gather
from warden.verifier import verify


def _alert():
    return Alert(
        alert_id="inc-001",
        name="HighErrorRate",
        severity=Severity.critical,
        service="checkout",
        environment="prod",
        summary="5xx spike",
        started_at="2026-08-21T10:00:00Z",
    )


class HangingBackend(FixtureBackend):
    """Stands in for a logging backend that has stopped responding mid-incident."""

    def logs(self, alert):
        # 1.0s against a 0.3s ceiling: long enough to prove the deadline fires, short enough that
        # interpreter teardown does not sit joining an abandoned worker thread. Measured: a 5s hang
        # cost ~10s of pure teardown across this file for no extra coverage.
        time.sleep(1.0)
        return ["never returned"]


def test_a_hanging_tool_does_not_hang_the_run():
    started = time.monotonic()
    ctx = gather(_alert(), HangingBackend(), timeout=0.3)
    elapsed = time.monotonic() - started

    assert elapsed < 3, f"gather() waited {elapsed:.1f}s on a hanging tool"
    assert any("timed out" in e for e in ctx.tool_errors)
    # The tools that did respond are still used - degrade, don't collapse.
    assert ctx.metrics
    assert not ctx.logs


def test_a_timed_out_tool_reaches_the_verifier_as_partial_context():
    """The point of recording the failure: policy P8 must be able to see it.

    A partial picture that looks complete is how an agent acts confidently on half the evidence.
    """
    ctx = gather(_alert(), HangingBackend(), timeout=0.3)
    verdict = verify(
        _alert(),
        ctx,
        RootCause(hypothesis="bad deploy", confidence=0.9),
        RemediationProposal(
            action=ActionKind.rollback_deploy,
            target="checkout",
            reasoning="revert",
            expected_effect="errors drop",
            blast_radius="single_service",
            reversible=True,
        ),
    )
    assert verdict.status is VerdictStatus.escalated
    assert "P8-PARTIAL-CONTEXT" in verdict.policy_ids


def test_healthy_tools_are_unaffected_by_the_ceiling():
    ctx = gather(_alert(), FixtureBackend(), timeout=5.0)
    assert ctx.tool_errors == []
    assert ctx.logs and ctx.metrics and ctx.recent_deploys


def test_a_tool_error_message_is_redacted_before_it_reaches_the_audit_or_telemetry():
    """A backend exception can name a host/IP/credential (a connection error). That message lands in
    tool_errors (the operator-facing audit trail) and on the tool span (exported to a third-party
    tracing backend) - so a raw identifier there is a leak, even though the model never sees
    tool_errors. The error text must be scrubbed at the source."""
    class LeakyBackend(FixtureBackend):
        def logs(self, alert):
            raise RuntimeError("connect to redis://:S3cretRedisPass@10.0.0.9 failed")

    ctx = gather(_alert(), LeakyBackend(), timeout=2.0)
    joined = " ".join(ctx.tool_errors)
    assert "S3cretRedisPass" not in joined, "credential leaked into tool_errors"
    assert "10.0.0.9" not in joined, "IP leaked into tool_errors"
    assert "<URLCRED" in joined or "<IPV4" in joined, "the error was recorded, just scrubbed"
