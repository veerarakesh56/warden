"""The redaction WIRING in the graph, not the redactor itself.

`redact()` is well tested in test_redaction.py. This file guards the thing an adversarial review
actually found broken: the graph fed the model `recent_deploys` WITHOUT redacting them, so an
identifier the redactor masks in a log line (an AWS account id embedded in an ECR image ref, a
deployer email) reached the LLM in the clear via `_evidence_blob`. The unit test below is the
regression: the assembled prompt must carry no raw identifier from ANY field.
"""

from __future__ import annotations

from aegis.cli import DEMO_ALERTS
from aegis.graph import _evidence_blob, node_redact, run
from aegis.llm import LLMClient
from aegis.models import Alert, ContextBundle, Severity


def test_runreport_context_is_redacted_not_raw():
    """RunReport is the exported, serialisable, auditor-facing artifact - so its .context must carry
    placeholders, not raw identifiers. node_redact scrubbed into separate state keys but left
    state['context'] RAW, so model_dump_json() of the report leaked every raw log email/ARN/AWS id
    while redaction_map_size falsely signalled 'scrubbed'."""
    report = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(mock=True))
    serialized = report.model_dump_json()
    for raw in ("priya.nair@corp.io", "acme-42", "arn:aws:iam::", "10.4.12.9"):
        assert raw not in serialized, f"{raw} leaked into the serialised RunReport"
    assert report.redaction_map_size > 0, "sanity: redaction did run"


def test_alert_labels_are_redacted_in_the_report():
    """Alertmanager labels routinely carry an instance IP, a pod name, an owner email or a token,
    and they reach the serialised RunReport.alert. node_redact scrubbed only the summary, so labels
    leaked raw. Now every label value is scrubbed (service/env stay structural)."""
    alert = Alert(
        alert_id="inc-x", name="HighErrorRate", severity=Severity.high, service="checkout",
        environment="prod", summary="5xx spike", started_at="2026-08-21T10:00:00Z",
        labels={"instance": "10.0.3.14:9100", "owner_email": "oncall@corp.io",
                "trace_token": "Bearer abcdef0123456789ABCDEF"},
    )
    serialized = run(alert, llm=LLMClient(mock=True)).model_dump_json()
    for raw in ("10.0.3.14", "oncall@corp.io", "abcdef0123456789ABCDEF"):
        assert raw not in serialized, f"label value {raw} leaked into the serialised report"
    assert "checkout" in serialized, "service stays structural (the proposal target needs it)"


def _state_after_redact():
    alert = Alert(
        alert_id="x", name="HighErrorRate", severity=Severity.high, service="checkout",
        environment="prod", summary="5xx spike, contact priya.nair@corp.io",
        started_at="2026-08-21T10:00:00Z",
    )
    ctx = ContextBundle(
        logs=["err 10.4.12.9 tenant_id=acme-42"],
        metrics={"error_rate": 0.04},
        # An ECR image ref embeds the 12-digit AWS account id; the 'by' field can be an email.
        recent_deploys=[{
            "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout:9f2c1ab",
            "by": "alice@corp.io",
            "revision": "2",
        }],
    )
    state = {"alert": alert, "context": ctx}
    state.update(node_redact(state))
    return state


def test_deploy_identifiers_do_not_reach_the_model():
    blob = _evidence_blob(_state_after_redact())
    for secret in ("123456789012", "alice@corp.io", "priya.nair@corp.io", "10.4.12.9", "acme-42"):
        assert secret not in blob, f"{secret} reached the model unredacted"


def test_deploy_structure_survives_so_the_model_can_still_reason():
    """Redaction must mask the account id, not destroy the fact that this was an ECR deploy."""
    blob = _evidence_blob(_state_after_redact())
    assert "<ACCOUNTID_1>" in blob
    assert ".dkr.ecr.us-east-1.amazonaws.com/checkout" in blob
    assert "revision" in blob


def test_the_same_value_masks_consistently_across_logs_and_deploys():
    """One shared mapping: an identifier in both a log and a deploy gets ONE placeholder, so the
    model can still tell they refer to the same thing."""
    alert = Alert(
        alert_id="x", name="n", severity=Severity.high, service="checkout", environment="prod",
        summary="s", started_at="2026-08-21T10:00:00Z",
    )
    ctx = ContextBundle(
        logs=["deploy by alice@corp.io failed"],
        recent_deploys=[{"by": "alice@corp.io", "revision": "2"}],
    )
    state = {"alert": alert, "context": ctx}
    state.update(node_redact(state))
    blob = _evidence_blob(state)
    assert "alice@corp.io" not in blob
    # exactly one placeholder label for that email, used in both places
    assert blob.count("<EMAIL_1>") == 2
