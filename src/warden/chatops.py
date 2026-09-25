"""ChatOps egress: deliver a remediation report to where the team already works — Slack, Microsoft
Teams, or any generic webhook (PagerDuty Events, a ticketing intake, an internal bot).

Three deliberate safety choices, because this is the one component that sends data OUT of the org:

  1. REDACT AGAIN. The report handed in is already redacted, but this module re-runs `redact()` on
     the exact bytes it is about to transmit. Redaction is idempotent, so this costs nothing and
     means a bug upstream cannot turn into an external leak.
  2. DRY-RUN BY DEFAULT. Even with a webhook configured, nothing is POSTed unless WARDEN_CHATOPS_LIVE=1
     (or a live sink is passed explicitly). Running WARDEN must never spam a channel by accident; the
     default returns the payload it *would* have sent.
  3. STDLIB ONLY. urllib, not requests — no new dependency, and the POST is bounded by a timeout and
     can never raise into the pipeline (a failed notification is a returned status, not a crash).

The webhook URLs are themselves secrets; they are read from the environment and never logged, echoed,
or written into a report.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .redaction import redact
from .reporting import Report, _scrub, reveal_identifiers

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
            return Notification(sink=self.name, delivered=False, detail="dry-run (WARDEN_CHATOPS_LIVE!=1)")
        return _post_json(self._url, {"text": to_slack_mrkdwn(text)}, self.name)


class TeamsWebhookSink:
    name = "teams"

    def __init__(self, url: str, *, live: bool) -> None:
        self._url = url
        self.live = live

    def send(self, text: str, data: dict) -> Notification:
        if not self.live:
            return Notification(sink=self.name, delivered=False, detail="dry-run (WARDEN_CHATOPS_LIVE!=1)")
        # Microsoft Teams incoming webhook: a legacy MessageCard carries plain text reliably.
        card = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "WARDEN incident report",
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
            return Notification(sink=self.name, delivered=False, detail="dry-run (WARDEN_CHATOPS_LIVE!=1)")
        return _post_json(self._url, data, self.name)


def resolve_sinks() -> list[ChatOpsSink]:
    """Build the sink list from the environment. Empty of webhooks -> a single ConsoleSink.

    WARDEN_SLACK_WEBHOOK / WARDEN_TEAMS_WEBHOOK / WARDEN_WEBHOOK_URL configure destinations.
    WARDEN_CHATOPS_LIVE=1 arms them; otherwise every sink is dry-run.
    """
    live = os.environ.get("WARDEN_CHATOPS_LIVE") == "1"
    sinks: list[ChatOpsSink] = []
    if url := os.environ.get("WARDEN_SLACK_WEBHOOK"):
        sinks.append(SlackWebhookSink(url, live=live))
    if url := os.environ.get("WARDEN_TEAMS_WEBHOOK"):
        sinks.append(TeamsWebhookSink(url, live=live))
    if url := os.environ.get("WARDEN_WEBHOOK_URL"):
        sinks.append(GenericWebhookSink(url, live=live))
    if not sinks:
        sinks.append(ConsoleSink())
    return sinks


_BOLD = re.compile(r"\*\*(.+?)\*\*")
_HEADING = re.compile(r"^#{1,6}\s+(.*)$")


def to_slack_mrkdwn(md: str) -> str:
    """GitHub Markdown -> Slack mrkdwn, for the one sink that renders the latter.

    Slack shows `# heading` and `**bold**` as literal characters (which is how the reports looked
    in the channel), and reads `<...>` as link syntax - so a placeholder like `<TENANT_1>` must be
    escaped. Order matters: escape first, so the `*` Slack uses for bold is never escaped away.
    Code blocks and inline code are left alone; Slack renders both.
    """
    text = md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    out, in_code = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            in_code = not in_code
            out.append(line)
            continue
        if not in_code:
            heading = _HEADING.match(line)
            line = f"*{heading.group(1)}*" if heading else line
            line = _BOLD.sub(r"*\1*", line)
        out.append(line)
    return "\n".join(out)


def notify(report: Report, sinks: list[ChatOpsSink] | None = None) -> list[Notification]:
    """Deliver `report` to every configured sink, redacting the exact payload one more time first."""
    sinks = sinks if sinks is not None else resolve_sinks()
    # Both payloads that leave the process are re-redacted here: the text (Slack/Teams display) and
    # the structured JSON (a generic webhook). redact() is idempotent, so re-scrubbing an already
    # clean payload costs nothing and closes any upstream hole before data crosses the boundary.
    #
    # ⛔ ...and then the operator's identifiers are put back IF the report was built to show them.
    # Without this step the re-scrub masked them again, so WARDEN_REPORT_SHOW_IDENTIFIERS never
    # reached Slack. One mapping for text and data so a tenant is the same placeholder in both, and
    # reveal_identifiers is the same function build_report uses - secrets can never be revealed here.
    final = redact(report.markdown)
    safe_text, mapping = final.text, final.mapping
    safe_data, mapping = _scrub(report.data, mapping)
    if report.data.get("identifiers_shown"):
        safe_text = reveal_identifiers(safe_text, mapping)
        safe_data = reveal_identifiers(safe_data, mapping)
    results = [sink.send(safe_text, safe_data) for sink in sinks]
    return results
