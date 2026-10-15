"""Datadog monitors start incidents in WARDEN (register G10-53), and Datadog is set up as code (scripts/datadog_setup.py).

Owner, 2026-10-14: "set the total ... logs traces monitoring and dashboards ... and also alerts too for warden to
see and immediately work on them". The same who / how much / is it real as Alertmanager's webhook."""

from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import urllib.error
from datetime import UTC, datetime

import pytest

from warden import lambdas, settings, webhooks
from warden.models import Severity

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOKEN = "dd-hook-" + "x" * 24
WHEN = datetime(2026, 10, 14, 7, 14, 13, tzinfo=UTC)


def _delivery(transition="Triggered", monitor="12345", **over):
    return {"event": "987", "monitor": monitor, "transition": transition,
            "title": "[Triggered] warden dev: catalog-api error logs", "date": str(int(WHEN.timestamp() * 1000)),
            "tags": "env:dev,service:catalog-api,kube_deployment:catalog-api,team:shop",
            "scope": "kube_namespace:shop", "priority": "P1", "cycle": "c1", **over}


def _receive(body, token=TOKEN):
    raw = json.dumps(body).encode() if not isinstance(body, bytes) else body
    return webhooks.receive_datadog({"Authorization": f"Bearer {token}"}, raw, secrets=[TOKEN], environment="dev")


def test_a_triggered_monitor_is_an_alarm_with_wardens_labels_and_datadogs_own_time():
    got = _receive(_delivery())
    [ev] = got.events
    assert got.status == 202 and ev.state == "ALARM" and ev.transitioned_at == WHEN
    assert ev.alert.alert_id == "datadog-12345" and ev.rule == "datadog-12345"
    assert ev.alert.name == "warden dev: catalog-api error logs" and ev.alert.severity == Severity.critical
    assert (ev.alert.service, ev.alert.environment) == ("catalog-api", "dev")
    assert ev.alert.labels == {"environment": "dev", "service": "catalog-api", "deployment": "catalog-api",
                               "namespace": "shop", "datadog_monitor": "12345", "alarm": "datadog-12345", "via": "datadog"}
    assert [e.state for e in _receive(_delivery("Recovered")).events] == ["OK"]
    assert [e.state for e in _receive(_delivery("No Data")).events] == ["ALARM"]  # silence is a signal
    assert _receive(_delivery("Warn")).events == []  # a warning starts nothing


def test_who_how_much_and_what_is_refused():
    assert _receive(_delivery(), token="wrong").status == 401
    assert webhooks.receive_datadog({}, b"{}", secrets=[TOKEN], environment="dev").status == 401
    assert webhooks.receive_datadog({"Authorization": f"Bearer {TOKEN}"}, b"x", secrets=[""], environment="dev").status == 401
    assert _receive(b"x" * (webhooks.MAX_BODY + 1)).status == 413
    assert _receive(b"not json").status == 400 and _receive(b"[]").status == 400
    bad = _receive(_delivery(monitor="12 OR 1=1"))
    assert bad.status == 202 and bad.events == [] and bad.refused == ["datadog monitor 12 OR 1=1: ValueError"]


def test_only_a_monitor_datadog_itself_says_is_alerting_starts_anything():
    asked = []

    def get(url, headers):
        asked.append((url, headers))
        return {"overall_state": "Alert" if url.endswith("/12345") else "OK"}

    alerting = webhooks.datadog_alerting("ap1.datadoghq.com", "k", "a", get=get)
    assert alerting("12345") and not alerting("999")
    assert asked[0][0] == "https://api.ap1.datadoghq.com/api/v1/monitor/12345"
    assert asked[0][1]["DD-APPLICATION-KEY"] == "a"
    assert not webhooks.datadog_alerting("evil.example", "k", "a", get=get)("12345")  # not Datadog's site
    assert not webhooks.datadog_alerting("ap1.datadoghq.com", "", "a", get=get)("12345")  # no keys: nothing confirmed

    def down(url, headers):
        raise OSError("down")
    assert not webhooks.datadog_alerting("ap1.datadoghq.com", "k", "a", get=down)("12345")  # a failed check confirms nothing
    events = _receive(_delivery()).events + _receive(_delivery(monitor="999")).events + _receive(_delivery("Recovered", monitor="999")).events
    kept, dropped = webhooks.confirm_datadog(events, alerting)
    assert [e.alert.alert_id for e in kept] == ["datadog-12345", "datadog-999"] and kept[1].state == "OK"
    assert dropped == ["datadog monitor 999: Datadog does not say it is alerting - not acted on"]


def test_the_route_reaches_intake_with_its_own_secret(monkeypatch):
    got = []
    monkeypatch.setattr(lambdas, "_configure", lambda name: None)
    monkeypatch.setattr(lambdas, "_submit", lambda events: got.extend(events) or [{"action": "start"}] * len(events))
    monkeypatch.setattr(webhooks, "datadog_alerting", lambda site, api, app: (lambda monitor: monitor == "12345"))
    monkeypatch.setenv("WARDEN_DATADOG_WEBHOOK_TOKEN", TOKEN)
    monkeypatch.setenv("WARDEN_ALERTMANAGER_TOKEN", "the-alertmanager-one")

    def call(body, token=TOKEN):
        return lambdas.alertmanager({"rawPath": "/datadog", "headers": {"Authorization": f"Bearer {token}"},
                                     "isBase64Encoded": True, "body": base64.b64encode(json.dumps(body).encode()).decode(),
                                     "requestContext": {"http": {"method": "POST", "path": "/datadog"}}})
    assert call(_delivery(), token="the-alertmanager-one")["statusCode"] == 401  # each webhook its own secret
    r = call(_delivery())
    assert r["statusCode"] == 202 and json.loads(r["body"]) == {"accepted": 1, "dropped": 0} and len(got) == 1
    assert json.loads(call(_delivery(monitor="999"))["body"]) == {"accepted": 0, "dropped": 1}
    assert settings.RESTRICTED["WARDEN_DATADOG_WEBHOOK_TOKEN"] == {"lambda-alertmanager"}
    tf = (ROOT / "terraform" / "modules" / "warden-runtime" / "frontdoor.tf").read_text(encoding="utf-8")
    assert 'route_key = "POST /datadog"' in tf


# ------------------------------------------------------------------ the setup script


def _setup():
    spec = importlib.util.spec_from_file_location("datadog_setup", ROOT / "scripts" / "datadog_setup.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Aws:
    def __init__(self):
        self.stored = {}

    def __call__(self, service):
        return self

    def get_parameter(self, Name):
        return {"Parameter": {"Value": {"/warden/ops/env/WARDEN_DATADOG_SITE": "ap1.datadoghq.com",
                                        "/warden/ops/env/WARDEN_APPROVAL_RP_ID": "approve.example.test"}[Name]}}

    def get_secret_value(self, SecretId):
        return {"SecretString": "dd-api-" + "k" * 10}

    def put_secret_value(self, SecretId, SecretString):
        self.stored[SecretId] = SecretString


class DD:
    """Datadog's API as the script sees it: a webhook and monitors that exist after they are made."""

    def __init__(self, stored=None):
        self.calls, self.webhook, self.monitors, self.boards = [], None, {}, {}
        self.stored = stored if stored is not None else {}

    def __call__(self, method, url, body):
        path = url.split(".com", 1)[1]
        self.calls.append((method, path, body))
        if body and "custom_headers" in body:  # the token a webhook carries is already WARDEN's
            sent = json.loads(body["custom_headers"])["Authorization"].removeprefix("Bearer ")
            assert sent == self.stored.get("warden/ops/datadog-webhook-token"), "a token WARDEN does not hold"
        if path.endswith("/webhooks/warden"):
            if method == "GET" and self.webhook is None:
                raise urllib.error.HTTPError(url, 404, "nf", {}, None)
            if method == "PUT":
                self.webhook = {**self.webhook, **body}
            return self.webhook
        if path.endswith("/webhooks") and method == "POST":
            self.webhook = body
            return body
        if path.startswith("/api/v1/monitor?"):
            name = __import__("urllib.parse").parse.parse_qs(path.split("?", 1)[1])["name"][0]
            return [m for m in self.monitors.values() if m["name"] == name]
        if path == "/api/v1/monitor" and method == "POST":
            mid = len(self.monitors) + 1
            self.monitors[mid] = {**body, "id": mid}
            return self.monitors[mid]
        if path.startswith("/api/v1/monitor/") and method == "PUT":
            mid = int(path.rsplit("/", 1)[1])
            self.monitors[mid] = {**body, "id": mid}
            return self.monitors[mid]
        if path == "/api/v1/dashboard" and method == "GET":
            return {"dashboards": [{"id": i, "title": b["title"]} for i, b in self.boards.items()]}
        if path == "/api/v1/dashboard" and method == "POST":
            self.boards[f"d{len(self.boards) + 1}"] = body
            return body
        if path.startswith("/api/v1/dashboard/") and method == "PUT":
            self.boards[path.rsplit("/", 1)[1]] = body
            return body
        raise AssertionError((method, path))


def test_setup_makes_the_webhook_monitors_and_dashboard_once_and_never_prints_the_token(tmp_path, monkeypatch, capsys):
    mod = _setup()
    key = tmp_path / "setup-key.txt"
    key.write_text("dd-app-" + "s" * 10 + "\n", encoding="utf-8")
    monkeypatch.setenv("WARDEN_DATADOG_SETUP_KEY_FILE", str(key))
    api = tmp_path / "api-key.txt"
    api.write_text("dd-api-" + "k" * 10, encoding="utf-8")
    monkeypatch.setenv("WARDEN_DATADOG_API_KEY_FILE", str(api))
    aws = Aws()
    dd = DD(aws.stored)
    assert mod.main(["--env", "ops", "--stack", "dev"], aws=aws, call=dd) == 0
    token = aws.stored["warden/ops/datadog-webhook-token"]
    assert len(token) >= 40 and dd.webhook["url"] == "https://approve.example.test/datadog"
    assert json.loads(dd.webhook["custom_headers"]) == {"Authorization": f"Bearer {token}"}
    assert json.loads(dd.webhook["payload"]) == webhooks.DATADOG_PAYLOAD and dd.webhook["encode_as"] == "json"
    assert len(dd.monitors) == 4 and all("@webhook-warden" in m["message"] for m in dd.monitors.values())
    assert all("env:dev" in m["tags"] and "managed-by:warden" in m["tags"] for m in dd.monitors.values())
    assert len(dd.boards) == 1
    # Stored before the webhook carries it (DD checks that as each webhook write arrives).
    out = capsys.readouterr().out
    assert token not in out and "dd-app-" not in out and "dd-api-" not in out
    # Again: everything updated by its name, nothing duplicated; a new token, stored and carried.
    assert mod.main(["--env", "ops", "--stack", "dev"], aws=aws, call=dd) == 0
    assert len(dd.monitors) == 4 and len(dd.boards) == 1
    again = aws.stored["warden/ops/datadog-webhook-token"]
    assert again != token and json.loads(dd.webhook["custom_headers"]) == {"Authorization": f"Bearer {again}"}
    with pytest.raises(SystemExit):
        mod.Datadog("evil.example", "k", "a")


def test_monitors_only_updates_the_monitors_and_leaves_the_webhook_and_its_token(tmp_path, monkeypatch):
    """2026-10-15: a full run rotates the webhook token, which a warm webhook Lambda refuses until it restarts; the
    monitors' new grouping (kube_cluster_name, kube_namespace) needs no new token."""
    mod = _setup()
    for name, value in (("WARDEN_DATADOG_SETUP_KEY_FILE", "dd-app-" + "s" * 10), ("WARDEN_DATADOG_API_KEY_FILE",
                                                                               "dd-api-" + "k" * 10)):
        f = tmp_path / name
        f.write_text(value, encoding="utf-8")
        monkeypatch.setenv(name, str(f))
    aws, dd = Aws(), DD()
    assert mod.main(["--env", "ops", "--stack", "dev", "--monitors-only"], aws=aws, call=dd) == 0
    assert aws.stored == {} and dd.webhook is None and not dd.boards
    assert len(dd.monitors) == 4
    assert all("kube_cluster_name" in m["query"] for m in dd.monitors.values() if m["type"] == "query alert")


def test_a_report_says_where_its_alert_came_from_in_wardens_own_words():
    """Owner, 2026-10-15: "i dont know whats their sources are i mean datadog or grafana or xray". Each intake stamps
    `via` last; the report names it only from WARDEN's own list, never a value a sender chose."""
    from warden import reporting
    from warden.models import Alert, Severity

    def header(via):
        a = Alert(alert_id="a", name="n", service="s", environment="dev", severity=Severity.high, summary="",
                  started_at="2026-10-15T00:00:00+00:00", labels={"via": via} if via else {})
        return reporting.build_report(a).markdown
    assert "Source **Datadog monitor**" in header("datadog") and "Source **CloudWatch alarm**" in header("cloudwatch")
    assert "Source" not in header("") and "Source" not in header("grafana-forged")
