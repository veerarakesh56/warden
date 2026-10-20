"""Egress (owner, 2026-10-20): every destination on one inventory, nothing unmasked leaves, every egress recorded.

Canaries are built from parts (tests/fakes.py's rule): no tracked file holds a value of the shape it stands for.
"""

from __future__ import annotations

import json
import logging
import pathlib
import re
import subprocess
import sys
import textwrap

import pytest

from warden import egress, providers
from warden.audit import AuditLog
from warden.egress import EgressBlocked

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "warden"

EMAIL = "canary.person" + "@" + "example.org"
IP = "203.0.113." + "77"
PHONE = "+1 415 555 " + "0142"
ACCOUNT = "1234" + "56789012"
CANARIES = (EMAIL, IP, PHONE, ACCOUNT)

# Every module that opens a network client, and the destinations it may reach (egress.destinations()). A module that
# starts opening one is a new egress: it must be added here AND covered by egress.py (a destination, and a check).
INVENTORY = {
    "audit.py": {"database", "aws"},  # the audit (psycopg, an IAM token from RDS), KMS signing
    "aws_docs.py": {"aws-docs"},
    "aws_stack.py": {"aws"},  # boto3 reads, and a Lambda's deployment package from its presigned S3 address
    "changes.py": {"github"},
    "chatops.py": {"slack", "slack-webhook", "teams-webhook", "generic-webhook", "pagerduty"},
    "database.py": {"database"},
    "datadog.py": {"datadog"},
    "discuss.py": {"slack"},
    "grafana.py": {"grafana"},
    "k8s_backend.py": {"aws", "in-network"},
    "lambdas.py": {"aws", "database"},
    "observability.py": {"tracing"},
    "platforms/aws.py": {"aws"},
    "platforms/k8s.py": {"aws", "in-network"},
    "providers.py": {"anthropic", "openai", "groq", "openrouter", "gemini", "model-api", "aws"},
    "runtime.py": {"aws"},
    "runtime_base.py": {"aws", "temporal"},
    "settings.py": {"aws"},
    "slack_login.py": {"slack"},
    "timeline.py": {"github"},
    "webhooks.py": {"datadog", "alertmanager"},
}
_CLIENT = re.compile(
    r"urlopen\(|urllib\.request\.Request\(|\bhttpx\.|import httpx|\brequests\.(?:get|post|put|Session)|aiohttp|slack_sdk"
    r"|socket\.socket\(|create_connection\(|subprocess\.(?:run|Popen|call|check_output)|Anthropic\(|OpenAI\("
    r"|genai\.Client|OTLPSpanExporter\(|boto3\.client\(|boto3\.Session\(|psycopg\.connect|pymysql\.connect"
    r"|redis\.from_url|redis\.Redis\(|MongoClient|pymssql\.connect|kubernetes\.client|from kubernetes import")
_CONFIGURED_NAMES = {name for _, name, *_ in egress._CONFIGURED} | {"database"}


def _modules_with_clients() -> set[str]:
    return {p.relative_to(SRC).as_posix() for p in SRC.rglob("*.py")
            if p.name != "egress.py" and _CLIENT.search(p.read_text(encoding="utf-8"))}


def test_every_module_that_opens_a_network_client_is_on_the_inventory():
    """A new outbound call in a new module fails here until it is named - the static half of 'nothing bypasses it'."""
    assert _modules_with_clients() == set(INVENTORY)


def test_the_inventory_names_only_destinations_egress_knows():
    known = {d.name for d in egress.STATIC} | _CONFIGURED_NAMES
    assert set().union(*INVENTORY.values()) <= known


def test_every_registered_model_provider_is_guarded():
    for cls in set(providers._REGISTRY.values()):
        assert getattr(cls.complete, "warden_egress", False), cls.__name__


class _Spy:
    """A model client that records whether anything reached it."""

    def __init__(self):
        self.calls = []

    def create(self, **kw):
        self.calls.append(kw)
        raise AssertionError("the prompt reached the model")


@pytest.mark.parametrize("canary", CANARIES)
def test_a_prompt_with_any_raw_value_never_reaches_the_model(canary, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    provider = providers.AnthropicProvider(model="claude-sonnet-5")
    spy = _Spy()
    provider._client = type("C", (), {"messages": spy})()
    with pytest.raises(EgressBlocked) as caught:
        provider.complete(system="You diagnose.", user=f"ERROR checkout user={canary} timed out")
    assert spy.calls == []
    assert canary not in str(caught.value)
    assert caught.value.sent is False and caught.value.status_code == 0


def test_a_masked_prompt_is_sent_and_recorded_without_its_text(monkeypatch, caplog):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    provider = providers.AnthropicProvider(model="claude-sonnet-5")
    sent = []

    class Messages:
        def create(self, **kw):
            sent.append(kw)
            usage = type("U", (), {"input_tokens": 1, "output_tokens": 1})()
            text = type("B", (), {"type": "text", "text": "{}"})()
            return type("R", (), {"content": [text], "usage": usage, "stop_reason": "end_turn"})()

    provider._client = type("C", (), {"messages": Messages()})()
    with caplog.at_level(logging.INFO, logger="warden.egress"):
        provider.complete(system="You diagnose.", user="ERROR checkout user=<EMAIL_1> src=<IPV4_1> secret-word")
    assert len(sent) == 1
    [line] = [r.getMessage() for r in caplog.records if r.name == "warden.egress"]
    row = json.loads(line.removeprefix("egress "))
    assert row["destination"] == "anthropic" and row["verdict"] == "PASS"
    assert row["placeholders"] == {"EMAIL": 1, "IPV4": 1}
    assert "secret-word" not in line and "checkout" not in line


def test_the_model_guard_holds_for_eldanes_way_of_building_a_provider():
    """Eldane builds its provider from the registry directly (never resolve()): the guard is on the class."""
    cls = providers._REGISTRY["claude_cli"]
    provider = cls.__new__(cls)  # no CLI needed: the guard runs before the subprocess is started
    with pytest.raises(EgressBlocked):
        provider.complete(system="s", user=f"user {EMAIL}")


# --------------------------------------------------------------------------- the request check

def _slack(text: str) -> bytes:
    return json.dumps({"channel": "C0123456", "text": text, "thread_ts": "1700000000.000200"}).encode()


JSON = {"Content-Type": "application/json"}


def test_an_unlisted_host_is_refused():
    with pytest.raises(EgressBlocked, match="no destination"):
        egress.check_request("https://exfil.example.net/x", None, {}, "GET")
    with pytest.raises(EgressBlocked):
        egress.check_host("exfil.example.net")
    with pytest.raises(EgressBlocked):
        egress.check_host("198.51.100.9")  # a public address no destination names


@pytest.mark.parametrize("canary", CANARIES)
def test_a_slack_message_holding_a_raw_value_is_refused(canary):
    with pytest.raises(EgressBlocked) as caught:
        egress.check_request("https://slack.com/api/chat.postMessage", _slack(f"user {canary} failed"), JSON, "POST")
    assert canary not in str(caught.value)


def test_a_masked_slack_message_passes_and_is_recorded(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    egress.ledger_to(log)
    try:
        egress.check_request("https://slack.com/api/chat.postMessage",
                             _slack("user <EMAIL_1> failed at 2026-10-20T06:00:00Z"), JSON, "POST")
    finally:
        egress._SINK.clear()
    [row] = log.entries(kinds=(egress.SENT,))
    body = row["body"]
    assert body["destination"] == "slack" and body["purpose"] == "POST /api/chat.postMessage"
    assert body["placeholders"] == {"EMAIL": 1} and len(body["sha256"]) == 64


def test_an_egress_the_audit_cannot_hold_is_not_made(tmp_path):
    class Broken:
        def append(self, *_a):
            raise OSError("the audit is down")

    egress.ledger_to(Broken())
    try:
        with pytest.raises(EgressBlocked, match="ledger row"):
            egress.check_request("https://slack.com/api/chat.postMessage", _slack("ok"), JSON, "POST")
    finally:
        egress._SINK.clear()


def test_identifiers_an_operator_could_show_are_not_shown_in_slack():
    """gate.G5 lets emails, tenants and IPs through for WARDEN_REPORT_SHOW_IDENTIFIERS; the egress check does not."""
    for value in (EMAIL, IP, "tenant_id=" + "acme-42"):
        with pytest.raises(EgressBlocked):
            egress.check_request("https://hooks.slack.com/" + "services/T0/B0/x", _slack(value), JSON, "POST")


def test_wardens_own_approval_link_is_the_one_capability_that_may_go_to_slack(monkeypatch):
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", "approve.example.org")
    link = "https://approve.example.org/a/" + "Ab3" * 14 + "x"
    blocks = {"channel": "C0123456", "blocks": [{"type": "actions", "elements": [{"type": "button", "url": link}]}]}
    egress.check_request("https://slack.com/api/chat.postMessage", json.dumps(blocks).encode(), JSON, "POST")
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", "elsewhere.example.org")
    with pytest.raises(EgressBlocked):  # the same token on any other address is a token
        egress.check_request("https://slack.com/api/chat.postMessage", json.dumps(blocks).encode(), JSON, "POST")


def test_a_destinations_own_credential_fields_go_to_it():
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    secret = "Ab3Cd4" * 8
    egress.check_request("https://slack.com/api/openid.connect.token",
                         f"client_id={ACCOUNT}.{ACCOUNT}&client_secret={secret}&code={secret}".encode(), form, "POST")
    egress.check_request("https://events.pagerduty.com/v2/enqueue",
                         json.dumps({"routing_key": secret, "payload": {"summary": "inc-1 down"}}).encode(), JSON, "POST")
    with pytest.raises(EgressBlocked):  # the same value in any other field is a leak
        egress.check_request("https://events.pagerduty.com/v2/enqueue",
                             json.dumps({"routing_key": "k", "payload": {"summary": secret}}).encode(), JSON, "POST")


def test_a_query_is_checked_and_a_number_in_it_is_a_number():
    egress.check_request("https://api.datadoghq.com/api/v1/query?from=1760940000&to=1760943600&query=avg:x", None,
                         {}, "GET")
    with pytest.raises(EgressBlocked):
        egress.check_request(f"https://api.github.com/search?q={EMAIL}", None, {}, "GET")


def test_the_networks_own_destinations_are_not_content_checked():
    """WARDEN's own AWS account and the private network are inside: recorded on connect, not scanned."""
    egress.check_request("https://logs.ap-south-1.amazonaws.com/", f"user {EMAIL}".encode(), {}, "POST")
    egress.check_request("http://10.0.3.22:8080/x", f"user {EMAIL}".encode(), {}, "POST")
    egress.check_host("169.254.170.2")  # the ECS task's credentials


def test_a_webhook_path_is_never_on_the_ledger(caplog):
    with caplog.at_level(logging.INFO, logger="warden.egress"):
        egress.check_request("https://hooks.slack.com/" + "services/T0SECRET/B0SECRET/XSECRETXSECRET", _slack("ok"),
                             JSON, "POST")
    assert "SECRET" not in caplog.text and "/services" in caplog.text


def test_configured_addresses_are_their_destinations(monkeypatch):
    monkeypatch.setenv("WARDEN_WEBHOOK_URL", "https://hooks.example.net/in/abc")
    monkeypatch.setenv("WARDEN_AUDIT_DSN", "postgresql://w@audit.cluster-x.example.net:5432/warden")
    assert egress.destination_of("hooks.example.net").name == "generic-webhook"
    assert egress.destination_of("audit.cluster-x.example.net").name == "database"
    monkeypatch.delenv("WARDEN_WEBHOOK_URL")
    assert egress.destination_of("hooks.example.net") is None


# --------------------------------------------------------------------------- the interpreter hook, for real

_HOOKED = textwrap.dedent("""
    import json, socket, sys, urllib.request
    from warden import egress
    egress.install()
    out = {}
    def attempt(name, fn):
        try:
            fn()
            out[name] = "sent"
        except egress.EgressBlocked as exc:
            out[name] = "blocked"
        except OSError as exc:
            out[name] = "network:" + type(exc).__name__
    email = "canary.person" + "@" + "example.org"
    attempt("unlisted_lookup", lambda: socket.getaddrinfo("exfil.example.net", 443))
    attempt("unlisted_urlopen", lambda: urllib.request.urlopen("https://exfil.example.net/x", timeout=2))
    req = urllib.request.Request("https://slack.com/api/chat.postMessage", method="POST",
                                 data=json.dumps({"text": "user " + email}).encode(),
                                 headers={"Content-Type": "application/json"})
    attempt("raw_value_to_slack", lambda: urllib.request.urlopen(req, timeout=2))
    opener = urllib.request.build_opener()
    attempt("own_opener", lambda: opener.open(req, timeout=2))
    attempt("in_network_lookup", lambda: socket.getaddrinfo("localhost", 1))
    print(json.dumps(out))
""")


def test_the_hook_refuses_before_any_connection_in_a_real_interpreter():
    """No network is needed for this to pass: every refusal happens before a name is looked up."""
    got = subprocess.run([sys.executable, "-c", _HOOKED], capture_output=True, text=True, timeout=60, check=True)
    out = json.loads(got.stdout.strip().splitlines()[-1])
    assert out["unlisted_lookup"] == "blocked"
    assert out["unlisted_urlopen"] == "blocked"
    assert out["raw_value_to_slack"] == "blocked"
    assert out["own_opener"] == "blocked"  # any OpenerDirector, not only urlopen's
    assert out["in_network_lookup"] == "sent"
    assert "canary.person" not in got.stderr  # the ledger's lines name kinds, never values


def test_install_for_environment_leaves_a_demo_alone(monkeypatch):
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    assert egress.install_for_environment() is False
