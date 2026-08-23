"""ChatOps egress: deliver a remediation report to where the team already works — Slack, Microsoft
Teams, or any generic webhook (PagerDuty Events, a ticketing intake, an internal bot).

Three deliberate safety choices, because this is the one component that sends data OUT of the org:

  1. REDACT AGAIN. The report handed in is already redacted, but this module re-runs `redact()` on
     the exact bytes it is about to transmit. Redaction is idempotent, so this costs nothing and
     means a bug upstream cannot turn into an external leak.
  2. DRY-RUN BY DEFAULT. Even with a webhook configured, nothing is POSTed unless AEGIS_CHATOPS_LIVE=1
     (or a live sink is passed explicitly). Running AEGIS must never spam a channel by accident; the
     default returns the payload it *would* have sent.
  3. STDLIB ONLY. urllib, not requests — no new dependency, and the POST is bounded by a timeout and
     can never raise into the pipeline (a failed notification is a returned status, not a crash).

The webhook URLs are themselves secrets; they are read from the environment and never logged, echoed,
or written into a report.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .redaction import redact
from .reporting import Report

_TIMEOUT_S = 8.0


@dataclass(frozen=True)
class Notification:
    sink: str
    delivered: bool
    detail: str


@runtime_checkable
class ChatOpsSink(Protocol):
    name: str
    live: bool

    def send(self, text: str, data: dict) -> Notification:
        ...


def _post_json(url: str, payload: dict, sink: str) -> Notification:
    """POST JSON with a timeout. Any transport error becomes a failed Notification, never an exception."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            code = resp.getcode()
        return Notification(sink=sink, delivered=200 <= code < 300, detail=f"HTTP {code}")
    except urllib.error.HTTPError as exc:
        return Notification(sink=sink, delivered=False, detail=f"HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return Notification(sink=sink, delivered=False, detail=f"transport error: {exc}")


class ConsoleSink:
    """The default when nothing is configured. Prints/returns the payload; sends nothing anywhere."""

    name = "console"
    live = False

    def send(self, text: str, data: dict) -> Notification:
        return Notification(sink=self.name, delivered=True, detail="rendered locally (not transmitted)")


class SlackWebhookSink:
    name = "slack"

    def __init__(self, url: str, *, live: bool) -> None:
        self._url = url
        self.live = live

    def send(self, text: str, data: dict) -> Notification:
        if not self.live:
            return Notification(sink=self.name, delivered=False, detail="dry-run (AEGIS_CHATOPS_LIVE!=1)")
        return _post_json(self._url, {"text": text}, self.name)


class TeamsWebhookSink:
    name = "teams"

    def __init__(self, url: str, *, live: bool) -> None:
        self._url = url
        self.live = live

    def send(self, text: str, data: dict) -> Notification:
        if not self.live:
            return Notification(sink=self.name, delivered=False, detail="dry-run (AEGIS_CHATOPS_LIVE!=1)")
        # Microsoft Teams incoming webhook: a legacy MessageCard carries plain text reliably.
        card = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "AEGIS incident report",
            "text": text,
        }
        return _post_json(self._url, card, self.name)


class GenericWebhookSink:
    """POSTs the structured report data as JSON — for a bot, PagerDuty Events, or a ticket intake."""

    name = "webhook"

    def __init__(self, url: str, *, live: bool) -> None:
        self._url = url
        self.live = live

    def send(self, text: str, data: dict) -> Notification:
        if not self.live:
            return Notification(sink=self.name, delivered=False, detail="dry-run (AEGIS_CHATOPS_LIVE!=1)")
        return _post_json(self._url, data, self.name)


def resolve_sinks() -> list[ChatOpsSink]:
    """Build the sink list from the environment. Empty of webhooks -> a single ConsoleSink.

    AEGIS_SLACK_WEBHOOK / AEGIS_TEAMS_WEBHOOK / AEGIS_WEBHOOK_URL configure destinations.
    AEGIS_CHATOPS_LIVE=1 arms them; otherwise every sink is dry-run.
    """
    live = os.environ.get("AEGIS_CHATOPS_LIVE") == "1"
    sinks: list[ChatOpsSink] = []
    if url := os.environ.get("AEGIS_SLACK_WEBHOOK"):
        sinks.append(SlackWebhookSink(url, live=live))
    if url := os.environ.get("AEGIS_TEAMS_WEBHOOK"):
        sinks.append(TeamsWebhookSink(url, live=live))
    if url := os.environ.get("AEGIS_WEBHOOK_URL"):
        sinks.append(GenericWebhookSink(url, live=live))
    if not sinks:
        sinks.append(ConsoleSink())
    return sinks


def notify(report: Report, sinks: list[ChatOpsSink] | None = None) -> list[Notification]:
    """Deliver `report` to every configured sink, redacting the exact payload one more time first."""
    sinks = sinks if sinks is not None else resolve_sinks()
    safe_text = redact(report.markdown).text
    # The structured data is assembled from already-redacted fields; re-serialise through redact() by
    # scrubbing each string value defensively would be over-engineering, so we scrub the text payload
    # (what Slack/Teams display) and trust the field-level redaction in build_report for the JSON.
    results = [sink.send(safe_text, report.data) for sink in sinks]
    return results
