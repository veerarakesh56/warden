"""ChatOps egress: dry-run by default, redacts the transmitted payload, fails soft."""

from __future__ import annotations

from aegis.chatops import (
    ConsoleSink,
    GenericWebhookSink,
    Notification,
    SlackWebhookSink,
    notify,
    resolve_sinks,
)
from aegis.models import ActionKind, Alert, RemediationProposal, RootCause, Severity
from aegis.reporting import build_report


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
    for var in ("AEGIS_SLACK_WEBHOOK", "AEGIS_TEAMS_WEBHOOK", "AEGIS_WEBHOOK_URL"):
        monkeypatch.delenv(var, raising=False)
    sinks = resolve_sinks()
    assert len(sinks) == 1 and isinstance(sinks[0], ConsoleSink)


def test_slack_sink_is_dry_run_unless_explicitly_armed(monkeypatch):
    monkeypatch.setenv("AEGIS_SLACK_WEBHOOK", "https://hooks.example.invalid/xxx")
    monkeypatch.delenv("AEGIS_CHATOPS_LIVE", raising=False)
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
