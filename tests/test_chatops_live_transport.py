"""ChatOps against a REAL HTTP server — the transport, not a mock of it.

Every other ChatOps test stops at the sink boundary: it asserts what `send()` was handed. That leaves
the last mile unproven — that `urllib` actually POSTs, that the JSON shape is what a webhook receives,
that a non-2xx is reported as undelivered rather than raised, and (the one that matters) that what
crosses the wire is REDACTED.

This runs a throwaway `http.server` on localhost and points the sinks at it. No network egress, no
credentials, nothing external — but it is a real socket, a real request and a real response, so the
claim "the payload that leaves is redacted" is tested where it is actually made.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from warden.chatops import GenericWebhookSink, SlackWebhookSink, TeamsWebhookSink, notify
from warden.models import ActionKind, Alert, RemediationProposal, RootCause, Severity
from warden.reporting import build_report

RECEIVED: list[dict] = []


class _Handler(BaseHTTPRequestHandler):
    status = 200

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        RECEIVED.append({
            "path": self.path,
            "content_type": self.headers.get("Content-Type"),
            "body": raw,
        })
        self.send_response(type(self).status)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # keep pytest output clean
        return


@pytest.fixture
def server():
    RECEIVED.clear()
    _Handler.status = 200
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}/hook"
    httpd.shutdown()
    httpd.server_close()


def _report():
    alert = Alert(
        alert_id="inc-005", name="DBConnectionsStuck", severity=Severity.high, service="payments",
        environment="staging", started_at="2026-08-26T00:00:00Z",
        summary="pool exhausted for priya.nair@corp.io from 10.2.3.4 tenant_id=acme-42",
    )
    return build_report(
        alert,
        root_cause=RootCause(hypothesis="connections stuck idle in transaction", confidence=0.71),
        proposal=RemediationProposal(
            action=ActionKind.terminate_connections, target="payments-db", reasoning="r",
            expected_effect="pool frees", blast_radius="single_service", reversible=True,
        ),
    )


SECRETS = ("priya.nair@corp.io", "10.2.3.4", "acme-42")


def test_slack_really_posts_and_what_crosses_the_wire_is_redacted(server):
    note = SlackWebhookSink(server, live=True).send("hello", {})
    assert note.delivered is True and note.detail == "HTTP 200"
    assert len(RECEIVED) == 1
    assert RECEIVED[0]["content_type"] == "application/json"
    assert json.loads(RECEIVED[0]["body"]) == {"text": "hello"}


def test_teams_posts_a_message_card_a_real_webhook_would_accept(server):
    note = TeamsWebhookSink(server, live=True).send("hello", {})
    assert note.delivered is True
    payload = json.loads(RECEIVED[0]["body"])
    assert payload["@type"] == "MessageCard"
    assert payload["text"] == "hello"


def test_the_bytes_on_the_wire_carry_no_identifier(server):
    """The end-to-end claim, at the only place it can be checked: the actual request body."""
    notes = notify(_report(), sinks=[
        SlackWebhookSink(server, live=True),
        GenericWebhookSink(server, live=True),
    ])
    assert all(n.delivered for n in notes), notes
    assert len(RECEIVED) == 2
    for request in RECEIVED:
        for secret in SECRETS:
            assert secret not in request["body"], f"{secret} crossed the wire in {request['path']}"
        assert "<EMAIL_" in request["body"] or "<IPV4_" in request["body"], (
            "nothing was masked at all - is this the right payload?"
        )


def test_a_non_2xx_is_reported_undelivered_not_raised(server):
    _Handler.status = 500
    note = GenericWebhookSink(server, live=True).send("x", {"a": 1})
    assert note.delivered is False
    assert "500" in note.detail
    assert len(RECEIVED) == 1, "the request was still made; only the response was bad"


def test_dry_run_opens_no_socket_at_all(server):
    """Not armed means not sent — proven by the server receiving nothing, not by a returned flag."""
    for sink in (SlackWebhookSink(server, live=False), TeamsWebhookSink(server, live=False),
                 GenericWebhookSink(server, live=False)):
        note = sink.send("hello", {"a": 1})
        assert note.delivered is False and "dry-run" in note.detail
    assert RECEIVED == [], "a dry run reached the network"
