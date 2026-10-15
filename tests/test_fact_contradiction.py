"""Research 2026-10-15, item 11: a measured fact the diagnosis cannot argue with. When the IAM policy simulator says the
role's own policies deny the workload's call, an action that only runs the workload again under the same role is a
contradiction (P11) - the same call is denied again."""

from __future__ import annotations

import pytest

from warden.models import ActionKind, Alert, Citation, ContextBundle, RemediationProposal, RootCause
from warden.verifier import verify

ALERT = Alert(alert_id="v", name="n", severity="high", service="orders", environment="dev", summary="s",
              started_at="2026-10-15T10:00:00Z")
DENIES = ("STATE iam simulate role=warden-dev-orders-task action=dynamodb:PutItem "
          "resource=arn:aws:dynamodb:r:a:table/warden-dev-orders decision=implicitDeny by=none")
ALLOWS = DENIES.replace("decision=implicitDeny", "decision=allowed")


def _policies(action, fact):
    ctx = ContextBundle(logs=[fact, "orders ERROR AccessDeniedException a", "orders ERROR b"],
                        metrics={"error_rate": 0.4})
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote=fact[:40])])
    prop = RemediationProposal(action=action, target="orders", reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)
    return verify(ALERT, ctx, rc, prop)


@pytest.mark.parametrize("action", [ActionKind.restart_pods, ActionKind.scale_up, ActionKind.redrive_messages,
                                    ActionKind.resume_flow, ActionKind.raise_limit])
def test_rerunning_a_call_the_roles_own_policies_deny_is_a_contradiction(action):
    v = _policies(action, DENIES)
    assert "P11-ACTION-CONTRADICTS-EVIDENCE" in v.policy_ids
    assert any("dynamodb:PutItem" in r and "same call is denied again" in r for r in v.reasons)


@pytest.mark.parametrize(("action", "fact"), [
    (ActionKind.restart_pods, ALLOWS),               # the role allows it: the denial is elsewhere
    (ActionKind.rollback_deploy, DENIES),            # an earlier version may run under another role
    (ActionKind.revert_change, DENIES),
    (ActionKind.pause_flow, DENIES),                 # holding still harms nothing
])
def test_no_contradiction_when_the_role_allows_it_or_the_action_can_change_the_role(action, fact):
    assert not any("same call is denied again" in r for r in _policies(action, fact).reasons)
