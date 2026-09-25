"""ChatOps egress: dry-run by default, redacts the transmitted payload, fails soft."""

from __future__ import annotations

import pytest

from warden.chatops import (
    ConsoleSink,
    GenericWebhookSink,
    Notification,
    SlackWebhookSink,
    notify,
    resolve_sinks,
)
from warden.models import ActionKind, Alert, RemediationProposal, RootCause, Severity
from warden.reporting import build_report


def _report():
    a = Alert(
        alert_id="inc", name="PodOOMKilled", severity=Severity.high, service="checkout",
        environment="staging", summary="OOM for user priya.nair@corp.io on 10.2.3.4",
        started_at="2026-08-23T00:00:00Z",
    )
    return build_report(
        a,
        root_cause=RootCause(hypothesis="leak", confidence=0.8),
        proposal=RemediationProposal(
            action=ActionKind.scale_up, target="checkout", reasoning="r",
            expected_effect="relief", blast_radius="single_service", reversible=True,
        ),
    )


class _CaptureSink:
    """A fake live sink that records exactly what bytes it was asked to transmit."""

    name = "capture"
    live = True

    def __init__(self):
        self.text = None
        self.data = None

    def send(self, text, data):
        self.text = text
        self.data = data
        return Notification(sink=self.name, delivered=True, detail="captured")


# ------------------------------------------------------------------ defaults & safety

def test_no_webhook_configured_falls_back_to_console(monkeypatch):
    for var in ("WARDEN_SLACK_WEBHOOK", "WARDEN_TEAMS_WEBHOOK", "WARDEN_WEBHOOK_URL"):
        monkeypatch.delenv(var, raising=False)
    sinks = resolve_sinks()
    assert len(sinks) == 1 and isinstance(sinks[0], ConsoleSink)


def test_slack_sink_is_dry_run_unless_explicitly_armed(monkeypatch):
    monkeypatch.setenv("WARDEN_SLACK_WEBHOOK", "https://hooks.example.invalid/xxx")
    monkeypatch.delenv("WARDEN_CHATOPS_LIVE", raising=False)
    [sink] = resolve_sinks()
    assert isinstance(sink, SlackWebhookSink)
    note = sink.send("hi", {})
    assert note.delivered is False and "dry-run" in note.detail  # never actually POSTed


def test_the_transmitted_text_is_redacted_even_if_the_report_had_a_hole():
    """notify() re-redacts the exact payload; a raw secret injected after build_report must not leave."""
    rep = _report()
    # Simulate an upstream bug: shove a raw identifier into the already-built markdown.
    leaky = rep.__class__(markdown=rep.markdown + "\nDEBUG token AKIA" + "IOSFODNN7EXAMPLE",
                          data=rep.data, promotion=rep.promotion)
    cap = _CaptureSink()
    notify(leaky, sinks=[cap])
    assert "AKIA" + "IOSFODNN7EXAMPLE" not in cap.text, "notify must redact the payload it transmits"


def test_notify_delivers_a_redacted_report_to_a_live_sink():
    cap = _CaptureSink()
    notes = notify(_report(), sinks=[cap])
    assert notes[0].delivered is True
    assert "priya.nair@corp.io" not in cap.text and "10.2.3.4" not in cap.text


def test_a_transport_failure_is_a_status_not_an_exception():
    # An unroutable URL, armed live: send() must return delivered=False, never raise.
    sink = GenericWebhookSink("http://127.0.0.1:1/never", live=True)
    note = sink.send("x", {"a": 1})
    assert isinstance(note, Notification)
    assert note.delivered is False


def test_console_sink_transmits_nothing():
    note = ConsoleSink().send("x", {})
    assert note.delivered is True and "not transmitted" in note.detail


def test_the_transmitted_json_data_is_recursively_redacted():
    """The generic-webhook path sends report.data; every string in it is scrubbed before transmit."""
    from warden.reporting import _scrub

    cap = _CaptureSink()
    notify(_report(), sinks=[cap])
    blob = str(cap.data)
    assert "priya.nair@corp.io" not in blob and "10.2.3.4" not in blob
    # nested structures are walked, not just top-level keys
    nested, _ = _scrub({"x": ["ip 10.0.0.1", {"y": "u@e.io"}]}, {})
    assert "10.0.0.1" not in str(nested) and "u@e.io" not in str(nested)


# --------------------------------------------------------------------------- identifiers + Slack format


class _SlackCapture:
    """The real SlackWebhookSink's formatting, without the network."""

    name = "slack"

    def __init__(self):
        self.text = None

    def send(self, text, data):
        from warden.chatops import to_slack_mrkdwn

        self.text = to_slack_mrkdwn(text)
        self.data = data
        from warden.chatops import Notification

        return Notification(sink=self.name, delivered=True, detail="captured")


def _evidence_report(show: bool):
    from warden.models import ContextBundle
    from warden.redaction import redact_many

    ctx = ContextBundle(logs=[
        ("2026-08-26T04:10:20Z payments ERROR could not acquire connection tenant_id=initech-4 "
        "user=priya.nair@corp.io host=10.0.7.22"),
        "2026-08-26T04:10:21Z payments WARN retry with password=hunter2-Sup3r-s3cret",
    ])
    _, mapping = redact_many(ctx.logs)
    alert = Alert(alert_id="inc-005", name="DBConnectionsStuck", severity=Severity.high,
                  service="payments", environment="prod", started_at="2026-08-26T04:10:00Z",
                  summary="pool exhausted")
    return build_report(
        alert,
        root_cause=RootCause(hypothesis="stuck transactions", confidence=0.7),
        proposal=RemediationProposal(action=ActionKind.terminate_connections, target="payments-db",
                                     reasoning="r", expected_effect="pool frees",
                                     blast_radius="single_service", reversible=True),
        context=ctx, redaction_map=mapping, show_identifiers=show,
    )


def test_identifiers_the_operator_asked_to_see_survive_the_trip_to_slack():
    """⛔ notify() re-redacts before sending. Until 2026-09-25 that silently re-masked every identifier
    WARDEN_REPORT_SHOW_IDENTIFIERS had revealed, so the switch did nothing in Slack."""
    cap = _SlackCapture()
    notify(_evidence_report(show=True), sinks=[cap])
    for identifier in ("initech-4", "priya.nair@corp.io", "10.0.7.22"):
        assert identifier in cap.text, f"{identifier} was re-masked on the way to Slack"
        assert identifier in str(cap.data)


def test_with_identifiers_off_slack_gets_none_of_them():
    cap = _SlackCapture()
    notify(_evidence_report(show=False), sinks=[cap])
    for identifier in ("initech-4", "priya.nair@corp.io", "10.0.7.22"):
        assert identifier not in cap.text and identifier not in str(cap.data)


@pytest.mark.parametrize("show", [True, False])
def test_a_secret_never_reaches_slack_whatever_the_setting(show):
    cap = _SlackCapture()
    notify(_evidence_report(show=show), sinks=[cap])
    assert "hunter2-Sup3r-s3cret" not in cap.text and "hunter2-Sup3r-s3cret" not in str(cap.data)


def test_slack_gets_mrkdwn_not_github_markdown():
    """Slack showed `# heading` and `**bold**` as literal characters, and reads `<...>` as a link."""
    from warden.chatops import to_slack_mrkdwn

    md = "# Title\n## Section\n- **Service**: x <TENANT_1> & co\n```\nSELECT 1 WHERE a < 2;\n```"
    out = to_slack_mrkdwn(md)
    assert "**" not in out
    assert not any(line.startswith("#") for line in out.splitlines())
    assert "*Title*" in out and "*Section*" in out and "*Service*" in out
    assert "&lt;TENANT_1&gt;" in out and "&amp; co" in out
    assert "```\nSELECT 1 WHERE a &lt; 2;\n```" in out, "code blocks keep their lines (escaped)"


def test_the_real_slack_sink_sends_mrkdwn(monkeypatch):
    """The conversion must be wired into the sink that posts, not just exist."""
    from warden import chatops

    sent = {}
    monkeypatch.setattr(chatops, "_post_json",
                        lambda url, payload, sink: sent.update(payload) or chatops.Notification(sink, True, "ok"))
    chatops.SlackWebhookSink("https://example.invalid/hook", live=True).send("## Heading\n**bold**", {})
    assert sent["text"] == "*Heading*\n*bold*"


# --------------------------------------------------------------------------- splitting for Slack


def _long_report_text() -> str:
    body = ["# Report", "## Runbook"] + [f"context line {i} " + "x" * 60 for i in range(40)]
    code = ["```"] + [f"SELECT pg_terminate_backend({4000 + i});   -- named in the evidence" for i in range(80)] + ["```"]
    return "\n".join(body + code + ["## Promotion", "- done"])


def test_a_long_message_is_split_under_slacks_limit_without_cutting_a_command():
    """⛔ Slack cut a real report at ~4,000 characters in the middle of a code block: `2. Fix` in one
    message, its SQL in the next, the closing fence swallowed."""
    from warden.chatops import SLACK_PART_CHARS, split_for_slack

    text = _long_report_text()
    parts = split_for_slack(text)
    assert len(parts) > 1
    for i, part in enumerate(parts, 1):
        assert len(part) <= SLACK_PART_CHARS, f"part {i} is {len(part)} chars"
        assert part.startswith(f"_(part {i}/{len(parts)})_")
        fences = sum(1 for ln in part.splitlines() if ln.startswith("```"))
        assert fences % 2 == 0, f"part {i} leaves a code block open"
        for ln in part.splitlines():
            assert not (ln.startswith("SELECT") and not ln.endswith("evidence")), f"a command was cut: {ln!r}"
    # Nothing lost or reordered: the content lines come back in order once part headers and the
    # fences added at the boundaries are removed.
    content = [ln for part in parts for ln in part.splitlines()[1:] if ln != "```"]
    assert content == [ln for ln in text.splitlines() if ln != "```"]


def test_a_short_message_is_sent_as_it_is():
    from warden.chatops import split_for_slack

    assert split_for_slack("short") == ["short"]


def test_the_slack_sink_posts_every_part_and_fails_if_any_part_fails(monkeypatch):
    from warden import chatops

    sent, calls = [], {"n": 0}

    def post(url, payload, sink):
        calls["n"] += 1
        sent.append(payload["text"])
        ok = calls["n"] != 2  # the second part fails
        return chatops.Notification(sink, ok, "HTTP 200" if ok else "HTTP 500")

    monkeypatch.setattr(chatops, "_post_json", post)
    note = chatops.SlackWebhookSink("https://example.invalid/hook", live=True).send(_long_report_text(), {})
    assert len(sent) > 1 and all(t.startswith("_(part ") for t in sent)
    assert note.delivered is False and "1 of" in note.detail and "HTTP 500" in note.detail
