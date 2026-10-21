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
    assert ev.rule == "warden-dev-checkout-errors"
    assert ev.state == "ALARM"
    assert ev.transitioned_at.isoformat() == "2026-10-03T10:00:04.989000+00:00"
    a = ev.alert
    assert (a.service, a.environment) == ("warden-dev-checkout", "dev")  # the dimension, and the name's environment
    assert a.summary.startswith("Checkout function")
    assert a.labels["FunctionName"] == "warden-dev-checkout"
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
    assert lambdas.alarm(EVENT)["decisions"] == [{"action": "start"}]
    assert len(submitted) == 1
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
    assert lambdas.alertmanager(_am("wrong"))["statusCode"] == 401
    assert submitted == []
    assert lambdas.alertmanager(_am("t-old"))["statusCode"] == 202  # during a rotation
    assert len(submitted) == 1
    monkeypatch.setenv("WARDEN_ALERTMANAGER_URL", "https://alertmanager.example")
    monkeypatch.setattr("warden.webhooks.alertmanager_active", lambda url: (lambda: set()))
    r = lambdas.alertmanager(_am())
    assert r["statusCode"] == 202
    assert json.loads(r["body"]) == {"accepted": 0, "dropped": 1}
    assert len(submitted) == 1


def test_the_approval_lambda_serves_the_page(monkeypatch):
    seen = []

    class Page:
        def handle(self, method, path, body="", query="", cookies=()):
            seen.append((method, path, body))
            assert (query, cookies) == ("a=1", ["c=2"])  # the query string and the cookies reach the page
            from warden.approval_page import Response
            return Response(404, {"content-type": "application/json"}, "{}")

    monkeypatch.setattr(lambdas, "_configure", lambda name: None)
    monkeypatch.setattr(lambdas, "approval_page", lambda: Page())
    out = lambdas.approval({"rawPath": "/a/tok/login", "body": "{}", "requestContext": {"http": {"method": "POST"}},
                            "rawQueryString": "a=1", "cookies": ["c=2"]})
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
    assert "WARDEN_DATADOG_WEBHOOK_TOKEN" in webhook
    assert "WARDEN_DATADOG_WEBHOOK_TOKEN" not in alarm | page
    assert "WARDEN_SLACK_CLIENT_SECRET" in page
    assert "WARDEN_SLACK_CLIENT_SECRET" not in alarm | webhook
    assert all("WARDEN_TEMPORAL_API_KEY" in s for s in loaded)
    # The audit's address is each Lambda's own environment (frontdoor.tf), never a secret it reads.
    assert not any("WARDEN_AUDIT_DSN" in s or "WARDEN_AUDIT_KEY_PASSPHRASE" in s for s in loaded)
    assert not any("WARDEN_GITHUB_TOKEN" in s or "WARDEN_DB_TERMINATE_DSN" in s for s in loaded)


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
    assert runtime.approver_policy().approvers["owner"].tiers == ["T2"]
    assert asked == ["/warden/dev/approvers"]
    monkeypatch.delenv("WARDEN_ENV")
    with pytest.raises(RuntimeError):
        runtime.approver_policy()


def test_slacks_note_of_a_button_click_is_answered_before_anything_is_loaded(monkeypatch):
    """Live, 2026-10-12: Slack showed "Operation timed out. Apps need to respond within 3 seconds." beside the
    approval button - a cold start read its settings and opened the audit (6.5 s) before answering a note it ignores."""
    def never(*a, **k):
        raise AssertionError("nothing is configured or opened to answer Slack's note")
    monkeypatch.setattr(lambdas, "_configure", never)
    monkeypatch.setattr(lambdas, "approval_page", never)
    for path in ("/s/interact", "/s/interact/"):
        out = lambdas.approval({"rawPath": path, "body": "payload=%7B%7D", "requestContext": {"http": {"method": "POST"}}})
        assert out["statusCode"] == 200
        assert out["body"] == ""
    with pytest.raises(AssertionError):  # every other request is served as before
        lambdas.approval({"rawPath": "/s/interact", "requestContext": {"http": {"method": "GET"}}})


def test_a_cold_start_says_where_its_time_went_once_and_the_one_a_person_waits_for_has_a_whole_cpu(monkeypatch, caplog):
    """Live, 2026-10-12: the approval page's first request after a quiet period took 5.6 s to 9.5 s. Before choosing
    a fix: measure where the time goes (this line), and give the function the CPU its start-up work needs - both
    instead of keeping it warm, which would hide the cause and hold rotated secrets stale for hours."""
    import logging
    import pathlib
    import re

    class Page:
        def handle(self, method, path, body="", query="", cookies=()):
            from warden.approval_page import Response
            return Response(404, {}, "{}")

    monkeypatch.setattr(lambdas, "_CONFIGURED", set())
    monkeypatch.setattr(lambdas, "_configure", lambda name: lambdas._CONFIGURED.add(name))
    monkeypatch.setattr(lambdas, "approval_page", lambda: Page())
    event = {"rawPath": "/a/tok", "requestContext": {"http": {"method": "GET"}}}
    with caplog.at_level(logging.INFO, logger="warden.lambda"):
        lambdas.approval(event)
        lambdas.approval(event)  # warm: nothing more is said
    [line] = [r.getMessage() for r in caplog.records]
    assert re.fullmatch(r"approval cold start: settings=\d+ms page=\d+ms request=\d+ms", line)  # durations, nothing else
    tf = (pathlib.Path(__file__).resolve().parents[2] / "infra" / "terraform" / "modules" / "warden-runtime" / "frontdoor.tf").read_text(encoding="utf-8")
    assert re.search(r'approval\s+= \{ handler = "warden\.lambdas\.approval", timeout = 30, memory = 1769 \}', tf)
    assert "memory_size   = each.value.memory" in tf
    assert tf.count("memory = 512 }") == 3
