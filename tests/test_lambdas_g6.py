"""G6: the runtime's Lambda entry points. A CloudWatch alarm state change (EventBridge's own shape, from AWS's docs)
becomes an intake event; Alertmanager's webhook refuses a delivery without its bearer secret and drops alerts
Alertmanager no longer lists; the approval page is served from API Gateway's event; each Lambda loads only its own
settings (the webhook's secret reaches the webhook Lambda alone)."""

from __future__ import annotations

import base64
import json

import pytest

from warden import lambdas, settings

EVENT = {
    "version": "0", "id": "x", "detail-type": "CloudWatch Alarm State Change", "source": "aws.cloudwatch",
    "time": "2026-10-03T10:00:05Z", "region": "test-region-1", "resources": ["arn:x"],
    "detail": {
        "alarmName": "warden-dev-checkout-errors",
        "state": {"value": "ALARM", "reason": "Threshold Crossed", "timestamp": "2026-10-03T10:00:04.989+0000"},
        "previousState": {"value": "OK", "timestamp": "2026-10-03T09:00:00.000+0000"},
        "configuration": {"description": "Checkout function invocations are ending in errors.", "metrics": [
            {"id": "m1", "metricStat": {"metric": {"namespace": "AWS/Lambda", "name": "Errors",
                                                   "dimensions": {"FunctionName": "warden-dev-checkout"}},
                                        "period": 60, "stat": "Sum"}, "returnData": True}]}}}


def test_an_alarm_state_change_becomes_an_intake_event():
    ev = lambdas.alarm_event(EVENT, "unused")
    assert ev.rule == "warden-dev-checkout-errors" and ev.state == "ALARM"
    assert ev.transitioned_at.isoformat() == "2026-10-03T10:00:04.989000+00:00"
    a = ev.alert
    assert (a.service, a.environment) == ("warden-dev-checkout", "dev")  # the dimension, and the name's environment
    assert a.summary.startswith("Checkout function") and a.labels["FunctionName"] == "warden-dev-checkout"
    assert lambdas.alarm_event({**EVENT, "detail-type": "CloudWatch Alarm Configuration Change"}, "dev") is None
    assert lambdas.alarm_event({**EVENT, "source": "aws.ec2"}, "dev") is None
    ok = lambdas.alarm_event({**EVENT, "detail": {**EVENT["detail"], "state": {"value": "OK",
                                                                              "timestamp": "2026-10-03T10:30:00Z"}}}, "dev")
    assert ok.state == "OK"  # a recovery reaches intake too (it closes a flap window, starts nothing)


@pytest.fixture
def submitted(monkeypatch):
    got = []
    monkeypatch.setattr(lambdas, "_configure", lambda name: None)
    monkeypatch.setattr(lambdas, "_submit", lambda events: got.extend(events) or [{"action": "start"}] * len(events))
    return got


def test_the_alarm_lambda_submits_alarms_and_ignores_the_rest(submitted):
    assert lambdas.alarm(EVENT)["decisions"] == [{"action": "start"}] and len(submitted) == 1
    assert "ignored" in lambdas.alarm({"source": "aws.health"})


def _am(token="t-current", alerts=None):
    body = json.dumps({"alerts": alerts if alerts is not None else [{
        "status": "firing", "fingerprint": "f1", "labels": {"alertname": "HighErrors", "service": "orders"},
        "annotations": {"summary": "x"}, "startsAt": "2026-10-03T10:00:00.123456789Z"}]})
    return {"headers": {"Authorization": f"Bearer {token}"}, "isBase64Encoded": True,
            "body": base64.b64encode(body.encode()).decode(), "requestContext": {"http": {"method": "POST"}}}


def test_the_webhook_needs_its_secret_and_drops_what_alertmanager_no_longer_fires(submitted, monkeypatch):
    monkeypatch.setenv("WARDEN_ALERTMANAGER_TOKEN", "t-current")
    monkeypatch.setenv("WARDEN_ALERTMANAGER_TOKEN_PREVIOUS", "t-old")
    monkeypatch.setenv("WARDEN_ENV", "dev")
    monkeypatch.delenv("WARDEN_ALERTMANAGER_URL", raising=False)
    assert lambdas.alertmanager(_am("wrong"))["statusCode"] == 401 and submitted == []
    assert lambdas.alertmanager(_am("t-old"))["statusCode"] == 202 and len(submitted) == 1  # during a rotation
    monkeypatch.setenv("WARDEN_ALERTMANAGER_URL", "https://alertmanager.example")
    monkeypatch.setattr("warden.webhooks.alertmanager_active", lambda url: (lambda: set()))
    r = lambdas.alertmanager(_am())
    assert r["statusCode"] == 202 and json.loads(r["body"]) == {"accepted": 0, "dropped": 1} and len(submitted) == 1


def test_the_approval_lambda_serves_the_page(monkeypatch):
    seen = []

    class Page:
        def handle(self, method, path, body=""):
            seen.append((method, path, body))
            from warden.approval_page import Response
            return Response(404, {"content-type": "application/json"}, "{}")

    monkeypatch.setattr(lambdas, "_configure", lambda name: None)
    monkeypatch.setattr(lambdas, "approval_page", lambda: Page())
    out = lambdas.approval({"rawPath": "/a/tok/login", "body": "{}", "requestContext": {"http": {"method": "POST"}}})
    assert out == {"statusCode": 404, "headers": {"content-type": "application/json"}, "body": "{}"}
    assert seen == [("POST", "/a/tok/login", "{}")]


def test_each_lambda_loads_only_its_own_settings(monkeypatch):
    loaded = []
    monkeypatch.setattr(settings, "load", lambda only=None, **kw: loaded.append(only) or [])
    monkeypatch.setattr(lambdas, "_CONFIGURED", set())
    for name in ("lambda-alarm", "lambda-alertmanager", "lambda-approval"):
        lambdas._configure(name)
        lambdas._configure(name)  # once per container
    alarm, webhook, page = loaded
    assert "WARDEN_ALERTMANAGER_TOKEN" in webhook and "WARDEN_ALERTMANAGER_TOKEN" not in alarm | page
    assert all({"WARDEN_TEMPORAL_API_KEY", "WARDEN_AUDIT_DSN"} <= s for s in loaded)
    assert not any("WARDEN_GITHUB_TOKEN" in s or "WARDEN_DB_ADMIN_DSN" in s for s in loaded)


def test_the_approver_policy_comes_from_the_file_or_else_from_ssm(monkeypatch, tmp_path):
    """G6: a Lambda has no policy file, so the runtime reads /warden/<env>/approvers (public keys and tiers only)."""
    import boto3

    from warden import runtime

    text = "approvers:\n  owner:\n    public_key: k\n    tiers: [T1]\n"
    (tmp_path / "a.yaml").write_text(text, encoding="utf-8")
    monkeypatch.setenv("WARDEN_APPROVERS", str(tmp_path / "a.yaml"))
    assert runtime.approver_policy().approvers["owner"].tiers == ["T1"]
    asked = []

    class _Ssm:
        def get_parameter(self, Name):
            asked.append(Name)
            return {"Parameter": {"Value": text.replace("T1", "T2")}}

    monkeypatch.delenv("WARDEN_APPROVERS")
    monkeypatch.setenv("WARDEN_ENV", "dev")
    monkeypatch.setattr(boto3, "client", lambda *a, **kw: _Ssm())
    monkeypatch.setattr("warden.environments.region", lambda: "test-region-1")
    assert runtime.approver_policy().approvers["owner"].tiers == ["T2"] and asked == ["/warden/dev/approvers"]
    monkeypatch.delenv("WARDEN_ENV")
    with pytest.raises(RuntimeError):
        runtime.approver_policy()
