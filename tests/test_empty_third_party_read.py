"""fs-22 run 2: Grafana's "no error lines for catalog-api" was recorded as a failed read, and P8 held the
plan. A third-party source that answered and found nothing is an EMPTY read - unknown, never a sign of health - not a
failed one: P8 does not hold a fix for it, and P23 still refuses "no action" on it."""

from __future__ import annotations

from warden import tools
from warden.models import ActionKind, Alert, Citation, RemediationProposal, RootCause
from warden.verifier import verify

ALERT = Alert(alert_id="a", name="n", severity="high", service="catalog-api", environment="dev", summary="s",
              started_at="2026-10-15T12:00:00+00:00")
P = tools.PARTIAL_PREFIX
EMPTY = [P + "grafana logs: no error lines for catalog-api between 11:50 and 12:10 (late, not instrumented, or none)",
         P + "datadog traces: no failed spans for catalog-api between 11:50 and 12:10 - not a sign of health",
         P + "logs: xray traces: no failed traces for catalog-api between 11:50 and 12:10"]


class _Backend:
    def logs(self, alert):
        return ["CONFIG k8s shop/catalog-api replicas=2", "LOG k8s/shop/catalog-api ERROR invalid configuration",
                "LOG k8s/shop/catalog-api ERROR invalid configuration", *EMPTY,
                P + "datadog logs: HTTP 429 - not read (late, limited or refused)"]

    def metrics(self, alert):
        return {"pod_restarts": 4.0}

    def deploys(self, alert):
        return []


def _verdict(action):
    ctx = tools.gather(ALERT, _Backend(), timeout=5)
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote="CONFIG k8s shop/catalog-api")])
    prop = RemediationProposal(action=action, target="catalog-api", reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)
    return ctx, verify(ALERT, ctx, rc, prop)


def test_an_empty_third_party_answer_is_an_empty_read_not_a_failed_one():
    ctx, _ = _verdict(ActionKind.restart_pods)
    assert set(ctx.empty_reads) >= {"grafana logs", "datadog traces", "xray traces"}
    assert not any("no error lines" in e or "no failed" in e for e in ctx.tool_errors)
    assert any("HTTP 429" in e for e in ctx.tool_errors)  # a read that was refused still is a failed read


def test_p8_holds_for_the_refused_read_only_and_no_action_on_empty_reads_is_still_refused():
    class _Answered(_Backend):
        def logs(self, alert):
            return super().logs(alert)[:-1]  # without the refused read

    ctx = tools.gather(ALERT, _Answered(), timeout=5)
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote="CONFIG k8s shop/catalog-api")])
    prop = RemediationProposal(action=ActionKind.restart_pods, target="catalog-api", reasoning="r",
                               expected_effect="e", blast_radius="single_service", reversible=True)
    assert "P8-PARTIAL-CONTEXT" not in verify(ALERT, ctx, rc, prop).policy_ids
    _, held = _verdict(ActionKind.restart_pods)
    assert "P8-PARTIAL-CONTEXT" in held.policy_ids
    nothing = prop.model_copy(update={"action": ActionKind.no_action})
    assert any(p.startswith("P23") for p in verify(ALERT, ctx, rc, nothing).policy_ids)
