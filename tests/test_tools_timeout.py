"""The timeout has to be able to fire, or the docstring claiming it is a lie.

This test exists because an earlier version of tools.py said "each tool has a timeout" in its
docstring while implementing none. A claim in a comment is not a feature.
"""

import json
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


def test_a_tool_error_message_is_redacted_before_it_reaches_the_audit_or_the_report():
    """A backend exception can name a host/IP/credential (a connection error). Since audit A-C-5 the
    text is raw straight out of gather() - like the logs - and node_redact scrubs it with the run's
    one map. Nothing after that point, audit included, may hold the raw value."""
    from warden.graph import apply_node, node_gather, node_redact

    class LeakyBackend(FixtureBackend):
        def logs(self, alert):
            raise RuntimeError("connect to redis://:S3cretRedisPass@10.0.0.9 failed")

    state = {"alert": _alert(), "backend": LeakyBackend(), "audit": []}
    apply_node(state, node_gather(state))
    apply_node(state, node_redact(state))
    after = json.dumps({"audit": state["audit"], "errors": state["context"].tool_errors}, default=str)
    assert "S3cretRedisPass" not in after, "credential leaked into the audit or tool_errors"
    assert "10.0.0.9" not in after, "IP leaked into the audit or tool_errors"
    assert "<URLCRED" in after or "<IPV4" in after, "the error was recorded, just scrubbed"


def test_one_placeholder_means_one_value_across_tool_errors_and_logs():
    """Audit A-C-5: tool errors were scrubbed with their own fresh map, so `<IPV4_1>` in a tool error
    and `<IPV4_1>` in a log line could be two different hosts."""
    from warden.graph import node_redact
    from warden.models import ContextBundle

    ctx = ContextBundle(logs=["conn to 10.0.0.9 ok", "retry 10.0.0.5"],
                        tool_errors=["metrics: connection to 10.0.0.5 refused", "logs: 10.0.0.7 timed out"])
    out = node_redact({"alert": _alert(), "context": ctx})
    logs, errors, mapping = out["context"].logs, out["context"].tool_errors, out["redaction_map"]
    by_value = {v: k for k, v in mapping.items()}
    assert by_value["10.0.0.5"] in logs[1] and by_value["10.0.0.5"] in errors[0], "same host, same name"
    assert by_value["10.0.0.7"] in errors[1] and by_value["10.0.0.7"] not in " ".join(logs)
    assert len({by_value[ip] for ip in ("10.0.0.9", "10.0.0.5", "10.0.0.7")}) == 3, "three hosts, three names"
