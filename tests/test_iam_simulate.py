"""An AccessDenied in the evidence, checked against the role's own policies with the IAM
policy simulator - only for a role the trusted configuration names (a TASKROLE line) in the incident's environment."""

from __future__ import annotations

from warden.aws_stack import StackBackend, _Out
from warden.evidence import _kind
from warden.models import Alert, Severity

ACCOUNT = "1" * 12
OTHER = "9" * 12  # another account, built from parts
DENIED = (f"LOG ecs/warden-dev-orders ERROR AccessDeniedException: User: arn:aws:sts::{ACCOUNT}:assumed-role/"
          f"warden-dev-orders-task/x is not authorized to perform: dynamodb:PutItem on resource: "
          f"arn:aws:dynamodb:region-1:{ACCOUNT}:table/warden-dev-orders because no identity-based policy allows it")


class _Iam:
    def __init__(self):
        self.asked = []

    def simulate_principal_policy(self, **kw):
        self.asked.append(kw)
        return {"EvaluationResults": [{"EvalDecision": "implicitDeny", "MatchedStatements": []}]}


def _backend(iam):
    b = StackBackend.__new__(StackBackend)
    b._iam, b._account_id = iam, ACCOUNT
    return b


def _alert():
    return Alert(alert_id="a", name="n", service="warden-dev-orders", environment="dev", severity=Severity.high,
                 summary="", started_at="2026-10-15T09:00:00+00:00", labels={"ecs_service": "warden-dev-orders"})


def test_a_denied_call_is_simulated_for_the_trusted_role_and_said_as_a_fact():
    iam, out = _Iam(), _Out()
    out.lines = ["TASKROLE ecs/warden-dev-orders role=warden-dev-orders-task", DENIED]
    _backend(iam)._simulate_denials(out, _alert())
    assert iam.asked == [{"PolicySourceArn": f"arn:aws:iam::{ACCOUNT}:role/warden-dev-orders-task",
                          "ActionNames": ["dynamodb:PutItem"],
                          "ResourceArns": [f"arn:aws:dynamodb:region-1:{ACCOUNT}:table/warden-dev-orders"]}]
    said = out.lines[-1]
    assert said == (f"STATE iam simulate role=warden-dev-orders-task action=dynamodb:PutItem "
                    f"resource=arn:aws:dynamodb:region-1:{ACCOUNT}:table/warden-dev-orders decision=implicitDeny by=none")
    assert _kind(said) == "C"


def test_a_log_line_never_chooses_whose_permissions_are_read():
    for roles in ([], ["TASKROLE ecs/warden-prod-orders role=warden-prod-orders-task"]):  # none, or another env's
        iam, out = _Iam(), _Out()
        out.lines = [*roles, DENIED]
        _backend(iam)._simulate_denials(out, _alert())
        assert iam.asked == []
        assert out.lines == [*roles, DENIED]


def test_another_accounts_resource_is_not_named_and_no_client_means_no_simulation():
    iam, out = _Iam(), _Out()
    out.lines = ["TASKROLE lambda/warden-dev-orders role=warden-dev-fn",
                 DENIED.replace(f"region-1:{ACCOUNT}:table", f"region-1:{OTHER}:table")]
    _backend(iam)._simulate_denials(out, _alert())
    assert iam.asked[0]["ResourceArns"] == ["*"]
    out2 = _Out()
    out2.lines = list(out.lines[:2])
    _backend(None)._simulate_denials(out2, _alert())
    assert out2.lines == out.lines[:2]
