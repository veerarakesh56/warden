"""The MCP surface.

`call_tool` is deliberately pure dispatch with no transport, so the tools are testable without
standing up a client. The transport is the SDK's problem; the contract is ours.
"""

import json

from aegis.mcp_server import _tools, build_server, call_tool


def _payload(result):
    assert not result.is_error, result.content[0].text
    return json.loads(result.content[0].text)


def test_every_declared_tool_has_a_schema_and_a_real_description():
    tools = _tools()
    assert {t.name for t in tools} == {
        "verify_remediation", "redact_text", "gather_incident_context", "describe_policy",
    }
    for t in tools:
        assert t.input_schema["type"] == "object"
        assert len(t.description or "") > 60, f"{t.name} needs a description an agent can act on"


def test_the_action_enum_is_published_so_a_client_cannot_invent_one():
    """The closed action set has to reach the client, or the constraint only exists server-side."""
    verify_tool = next(t for t in _tools() if t.name == "verify_remediation")
    actions = verify_tool.input_schema["properties"]["action"]["enum"]
    assert "rollback_deploy" in actions
    assert "delete_database" not in actions


def test_verify_approves_a_clean_case_but_still_requires_a_human():
    out = _payload(call_tool("verify_remediation", {
        "environment": "prod", "severity": "critical", "service": "checkout",
        "action": "rollback_deploy", "target": "checkout", "blast_radius": "single_service",
        "reversible": True, "confidence": 0.9, "log_lines": 5, "metric_count": 4, "has_recent_deploy": True,
    }))
    assert out["verdict"] == "approved_for_human"
    assert out["requires_approval"] is True
    assert out["may_execute"] is False


def test_verify_rejects_a_rollback_with_no_deploy_in_evidence():
    """P5 - the classic confident hallucination, now callable by any agent."""
    out = _payload(call_tool("verify_remediation", {
        "environment": "prod", "severity": "critical", "service": "checkout",
        "action": "rollback_deploy", "target": "checkout", "blast_radius": "single_service",
        "reversible": True, "confidence": 0.95, "log_lines": 5, "metric_count": 4, "has_recent_deploy": False,
    }))
    assert out["verdict"] == "rejected"
    assert "P5-NO-DEPLOY-TO-ROLL-BACK" in out["policies_fired"]


def test_verify_rejects_irreversible_production_actions():
    out = _payload(call_tool("verify_remediation", {
        "environment": "prod", "severity": "critical", "service": "checkout",
        "action": "rollback_deploy", "target": "checkout", "blast_radius": "single_service",
        "reversible": False, "confidence": 0.99, "log_lines": 5, "metric_count": 4, "has_recent_deploy": True,
    }))
    assert out["verdict"] == "rejected"
    assert "P2-IRREVERSIBLE-IN-PROD" in out["policies_fired"]


def test_every_verdict_says_the_client_may_not_execute():
    """The most important field in the response, asserted across all four verdict shapes."""
    cases = [
        {"confidence": 0.9, "has_recent_deploy": True, "blast_radius": "single_service"},
        {"confidence": 0.2, "has_recent_deploy": True, "blast_radius": "single_service"},
        {"confidence": 0.9, "has_recent_deploy": True, "blast_radius": "region"},
        {"confidence": 0.9, "has_recent_deploy": False, "blast_radius": "single_service"},
    ]
    for extra in cases:
        out = _payload(call_tool("verify_remediation", {
            "environment": "prod", "severity": "critical", "service": "checkout",
            "action": "rollback_deploy", "target": "checkout", "reversible": True,
            "log_lines": 5, "metric_count": 4, **extra,
        }))
        assert out["may_execute"] is False


def test_redact_tool_masks_and_reports():
    out = _payload(call_tool("redact_text", {
        "text": "user priya@corp.io from 10.0.0.4 tenant_id=acme-42"
    }))
    assert "priya@corp.io" not in out["redacted"]
    assert "10.0.0.4" not in out["redacted"]
    assert out["identifiers_masked"] == 3


def test_gather_returns_redacted_logs_never_raw_ones():
    out = _payload(call_tool("gather_incident_context", {"alert_id": "inc-001"}))
    assert out["metrics"]
    assert out["identifiers_masked"] >= 5
    assert all("@corp.io" not in line for line in out["logs"])


def test_describe_policy_lists_all_nine():
    out = _payload(call_tool("describe_policy", {}))
    assert len(out["policies"]) == 9
    assert "prod" in out["environment_allowlist"]


def test_an_unknown_tool_is_an_error_not_a_crash():
    result = call_tool("drop_database", {})
    assert result.is_error


def test_bad_arguments_return_an_error_result_rather_than_killing_the_server():
    result = call_tool("verify_remediation", {"environment": "prod"})
    assert result.is_error


def test_the_server_builds():
    server = build_server()
    assert server.name == "aegis"


def test_thin_evidence_escalates_over_mcp_even_at_high_confidence():
    """P9 through the MCP surface.

    Observed on a live model: it reported confidence 0.85 on an incident whose entire evidence was
    two vague log lines. An external agent claiming high confidence must not be able to talk its
    way past the gate either.
    """
    out = _payload(call_tool("verify_remediation", {
        "environment": "prod", "severity": "critical", "service": "gateway",
        "action": "restart_pods", "target": "gateway", "blast_radius": "single_pod",
        "reversible": True, "confidence": 0.99, "log_lines": 2, "metric_count": 0,
    }))
    assert out["verdict"] == "escalated"
    assert "P9-THIN-EVIDENCE" in out["policies_fired"]
