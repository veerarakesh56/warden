"""Register H3: WARDEN's own Slack noise. Through a bot token, an incident is one thread: its first line is a status
updated in place, and every report, reminder and expiry goes into the thread - found again through the audit, so
any worker continues it."""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from warden import audit, chatops, settings
from warden.activities import AuditThreads
from warden.chatops import SlackBotSink

TOKEN = "xox" + "b-" + "0" * 4 + "-test"  # built from parts: never a real-looking literal


class _FakeSlack:
    def __init__(self):
        self.calls, self.n = [], 0

    def __call__(self, method, payload, token):
        assert token == TOKEN
        self.calls.append((method, payload))
        if method == "chat.postMessage":
            self.n += 1
            return {"ok": True, "ts": f"1700000000.{self.n:06d}"}, "ok"
        return {"ok": True}, "ok"


@pytest.fixture
def slack(monkeypatch):
    fake = _FakeSlack()
    monkeypatch.setattr(chatops, "_slack_call", fake)
    return fake


def _send(sink, text, incident="inc-7"):
    return sink.send(text, {"alert": {"id": incident}})


def test_an_incident_is_one_thread_whose_first_line_is_updated_in_place(slack, tmp_path):
    threads = AuditThreads(audit.AuditLog(tmp_path / "a.db"))
    sink = SlackBotSink(TOKEN, "C123", live=True, threads=threads)
    assert _send(sink, "## Diagnosis: memory pressure\nbody").delivered
    root = slack.calls[0][1]
    assert slack.calls[0][0] == "chat.postMessage" and "thread_ts" not in root
    assert root["text"].startswith("WARDEN · inc-7 · ") and root["unfurl_links"] is False
    ts = threads.get("inc-7")
    assert slack.calls[1][0] == "chat.postMessage" and slack.calls[1][1]["thread_ts"] == ts

    # A later message, from another worker: same thread, the first line updated, no new top-level message.
    later = SlackBotSink(TOKEN, "C123", live=True, threads=AuditThreads(audit.AuditLog(tmp_path / "a.db")))
    slack.calls.clear()
    assert _send(later, "WARDEN's plan expired without an approval.").delivered
    assert slack.calls[0] == ("chat.update", {"channel": "C123", "ts": ts,
                                             "text": "WARDEN · inc-7 · WARDEN's plan expired without an approval."})
    assert [c[1].get("thread_ts") for c in slack.calls[1:]] == [ts]


def test_two_incidents_are_two_threads(slack):
    sink = SlackBotSink(TOKEN, "C123", live=True)
    _send(sink, "a", "inc-1")
    _send(sink, "b", "inc-2")
    roots = [c[1] for c in slack.calls if c[0] == "chat.postMessage" and "thread_ts" not in c[1]]
    assert len(roots) == 2 and sink.threads["inc-1"] != sink.threads["inc-2"]


def test_unarmed_it_sends_nothing(slack):
    note = SlackBotSink(TOKEN, "C123", live=False).send("x", {"alert": {"id": "inc-1"}})
    assert not note.delivered and slack.calls == []


def _http_error(code, retry_after=None):
    headers = {"Retry-After": retry_after} if retry_after else {}
    return urllib.error.HTTPError("https://slack.com/api/x", code, "x", headers, io.BytesIO(b""))


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_a_rate_limit_is_waited_out_once_and_slack_errors_are_failures(monkeypatch):
    answers = [_http_error(429, "2"), _Resp(json.dumps({"ok": True, "ts": "1.2"}).encode())]
    slept = []

    def urlopen(req, timeout):
        assert req.get_header("Authorization") == f"Bearer {TOKEN}"
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    monkeypatch.setattr(chatops.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(chatops.time, "sleep", slept.append)
    assert chatops._slack_call("chat.postMessage", {}, TOKEN) == ({"ok": True, "ts": "1.2"}, "ok")
    assert slept == [2.0]
    answers[:] = [_Resp(json.dumps({"ok": False, "error": "channel_not_found"}).encode())]
    answer, detail = chatops._slack_call("chat.postMessage", {}, TOKEN)
    assert answer is None and detail == "slack error: channel_not_found" and TOKEN not in detail


def test_the_bot_token_is_a_secret_and_the_sink_is_configured_by_it(monkeypatch):
    assert "WARDEN_SLACK_BOT_TOKEN" in settings.SECRETS and "WARDEN_SLACK_CHANNEL" not in settings.SECRETS
    monkeypatch.setenv("WARDEN_SLACK_BOT_TOKEN", TOKEN)
    monkeypatch.setenv("WARDEN_SLACK_CHANNEL", "C123")
    monkeypatch.delenv("WARDEN_SLACK_WEBHOOK", raising=False)
    assert chatops.resolve_sinks()[0].name == "slack-bot"
