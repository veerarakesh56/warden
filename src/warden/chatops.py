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
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .gate import enforce, sanitise_data
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
    # A webhook is a secret endpoint: plain http would send the report (and the URL's token) in the
    # clear, and file:// or a custom scheme is not a webhook at all. Loopback http stays allowed for
    # a local relay (and the transport tests' local server). urlopen below is reached only after this.
    parts = urllib.parse.urlsplit(url)
    loopback = parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")
    if parts.scheme != "https" and not loopback:
        return Notification(sink=sink, delivered=False, detail="refused: webhook URL is not https")
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # nosec B310
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
        parts = split_for_slack(to_slack_mrkdwn(text))
        # ⛔ No unfurling: with it on, a URL in a message makes Slack's servers FETCH it - data in the
        # query string leaves without anyone clicking (the outbound gate removes URLs too; this is
        # the second lock).
        notes = [_post_json(self._url, {"text": part, "unfurl_links": False, "unfurl_media": False},
                            self.name) for part in parts]
        failed = [n for n in notes if not n.delivered]
        if failed:
            return Notification(sink=self.name, delivered=False,
                                detail=f"{len(failed)} of {len(parts)} part(s) failed: {failed[0].detail}")
        return Notification(sink=self.name, delivered=True,
                            detail=notes[0].detail + (f" ({len(parts)} parts)" if len(parts) > 1 else ""))


_SLACK_API = "https://slack.com/api/"
_MAX_RETRY_AFTER_S = 10.0


def _slack_call(method: str, payload: dict, token: str) -> tuple[dict | None, str]:
    """One Slack Web API call with the bot token: (response, detail), never an exception. Slack answers HTTP 200 with
    `ok: false` for most failures, so `ok` is what counts. A rate limit (HTTP 429; chat.postMessage allows about one
    message a second per channel) is waited out once, as its Retry-After says, up to a ceiling."""
    body = json.dumps(payload).encode("utf-8")
    for attempt in (1, 2):
        req = urllib.request.Request(_SLACK_API + method, data=body, method="POST", headers={
            "Content-Type": "application/json; charset=utf-8", "Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # nosec B310 - a fixed https host
                answer = json.loads(resp.read() or b"{}")
            return (answer, "ok") if answer.get("ok") else (None, f"slack error: {answer.get('error', 'unknown')}")
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt == 1:
                time.sleep(min(float(exc.headers.get("Retry-After") or 1), _MAX_RETRY_AFTER_S))
                continue
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            return None, f"transport error: {type(exc).__name__}"
    return None, "rate limited"


class SlackBotSink:
    """Slack through a bot token (decision D8, register H3): one thread per incident instead of a new message for
    every report, reminder and expiry. The first message for an incident is a one-line status - "WARDEN · inc-<id> ·
    <headline>" - and every report goes into its thread; each later message updates that first line in place, so the
    channel shows one line per incident, current. The thread is found again through `threads` (the audit, in the
    workers), so any worker continues the same thread. Rate limits are waited out; Slack is never the record."""

    name = "slack-bot"

    def __init__(self, token: str, channel: str, *, live: bool, threads=None) -> None:
        self._token, self.channel, self.live = token, channel, live
        self.threads = threads if threads is not None else {}

    def _post(self, text: str, **extra) -> tuple[dict | None, str]:
        # No unfurling, as the webhook sink: a URL would make Slack's servers fetch it.
        return _slack_call("chat.postMessage", {"channel": self.channel, "text": text, "unfurl_links": False,
                                                "unfurl_media": False, **extra}, self._token)

    def send(self, text: str, data: dict) -> Notification:
        if not self.live:
            return Notification(sink=self.name, delivered=False, detail="dry-run (WARDEN_CHATOPS_LIVE!=1)")
        incident = str((data.get("alert") or {}).get("id", "")) or "unknown"
        parts = split_for_slack(to_slack_mrkdwn(text))
        status = f"WARDEN · inc-{incident.removeprefix('inc-')} · {parts[0].strip().splitlines()[0][:150]}"
        root = self.threads.get(incident)
        if root is None:
            answer, detail = self._post(status)
            if answer is None:
                return Notification(sink=self.name, delivered=False, detail=detail)
            root = answer["ts"]
            self.threads[incident] = root
        else:
            _slack_call("chat.update", {"channel": self.channel, "ts": root, "text": status}, self._token)
        failed = [d for d in (self._post(part, thread_ts=root)[1] for part in parts) if d != "ok"]
        if failed:
            return Notification(sink=self.name, delivered=False,
                                detail=f"{len(failed)} of {len(parts)} part(s) failed: {failed[0]}")
        return Notification(sink=self.name, delivered=True, detail=f"thread {root} ({len(parts)} part(s))")


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


def resolve_sinks(threads=None) -> list[ChatOpsSink]:
    """Build the sink list from the environment. Empty of webhooks -> a single ConsoleSink.

    WARDEN_SLACK_BOT_TOKEN with WARDEN_SLACK_CHANNEL (one thread per incident; `threads` remembers them),
    WARDEN_SLACK_WEBHOOK / WARDEN_TEAMS_WEBHOOK / WARDEN_WEBHOOK_URL configure destinations.
    WARDEN_CHATOPS_LIVE=1 arms them; otherwise every sink is dry-run.
    """
    live = os.environ.get("WARDEN_CHATOPS_LIVE") == "1"
    sinks: list[ChatOpsSink] = []
    token, channel = os.environ.get("WARDEN_SLACK_BOT_TOKEN"), os.environ.get("WARDEN_SLACK_CHANNEL")
    if token and channel:
        sinks.append(SlackBotSink(token, channel, live=live, threads=threads))
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
# A space or tab after the hashes, as CommonMark requires: `\s` also took a no-break space, so
# "#<NBSP>Fix - approved" became a bold Slack line that renders as plain text everywhere else.
_HEADING = re.compile(r"^#{1,6}[ \t]+(.*)$")
# Line and paragraph separators: not line breaks in Markdown, but splitlines() - and some viewers -
# broke on them, so "ok<U+2028># Fix - approved" became a heading (fourth review, 2026-09-30, A-3).
_TILDE_FENCE = re.compile(r"^[ \t>*+\-\d.)]*~{3,}")
_SEPARATORS = re.compile("[\u2028\u2029]")


def to_slack_mrkdwn(md: str) -> str:
    """GitHub Markdown -> Slack mrkdwn, for the one sink that renders the latter.

    Slack shows `# heading` and `**bold**` as literal characters (which is how the reports looked
    in the channel), and reads `<...>` as link syntax - so a placeholder like `<TENANT_1>` must be
    escaped. Order matters: escape first, so the `*` Slack uses for bold is never escaped away.
    Code blocks and inline code are left alone; Slack renders both.
    """
    text = md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = _SEPARATORS.sub(" ", text)
    out, fence = [], ""
    # A fence anywhere in the line: the gate keeps fences inside list items and quotes, and leaves ```
    # nowhere but on fence lines (fourth review, 2026-09-30, A-2: column 0 only desynchronised here).
    # A `~~~` block is code too, closed only by `~~~` as CommonMark reads it: its heading was made bold
    # (fifth review, 2026-10-01).
    for line in text.split("\n"):
        tilde = _TILDE_FENCE.match(line)
        if (fence in ("", "```") and "```" in line) or (fence in ("", "~~~") and tilde):
            fence = "" if fence else ("```" if "```" in line else "~~~")
            out.append(line)
            continue
        if not fence:
            heading = _HEADING.match(line)
            line = f"*{heading.group(1)}*" if heading else line
            line = _BOLD.sub(r"*\1*", line)
        out.append(line)
    return "\n".join(out)


SLACK_PART_CHARS = 3500


def split_for_slack(text: str, limit: int = SLACK_PART_CHARS) -> list[str]:
    """Split a long message into numbered parts Slack will not cut for us.

    Slack splits long messages itself (at about 4,000 characters) wherever the limit falls - on a real
    report that was the middle of a code block, so `2. Fix` ended up in one message and its SQL in
    the next. Here the split happens at line boundaries, and a code block that straddles a boundary is
    closed at the end of one part and reopened at the start of the next, so a command is never cut.
    """
    if len(text) <= limit:
        return [text]
    parts: list[list[str]] = [[]]
    size, in_code = 0, False
    for line in text.split("\n"):
        fence = "```" in line
        if size + len(line) + 1 > limit - 16 and parts[-1]:
            if in_code:
                parts[-1].append("```")
            parts.append(["```"] if in_code else [])
            size = 4 if in_code else 0
        parts[-1].append(line)
        size += len(line) + 1
        if fence:
            in_code = not in_code
    total = len(parts)
    return [f"_(part {i}/{total})_\n" + "\n".join(lines) for i, lines in enumerate(parts, 1)]


def notify(report: Report, sinks: list[ChatOpsSink] | None = None, threads=None) -> list[Notification]:
    """Deliver `report` to every configured sink, redacting the exact payload one more time first."""
    sinks = sinks if sinks is not None else resolve_sinks(threads)
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
    # ⛔ The outbound gate sees exactly what would leave, after the reveal step (Phase 0 gate v0).
    gate = enforce(safe_text, alert_id=str((report.data.get("alert") or {}).get("id", "")),  # the report keys it "id" (A-C-24)
                   before_redaction=report.markdown, data_before_redaction=report.data)
    if gate.verdict == "BLOCK":
        safe_data = {"withheld": True, "gate": gate.verdict, "reasons": gate.reasons}
    else:
        safe_data = {**sanitise_data(safe_data), "gate": gate.verdict, "gate_reasons": gate.reasons}
    return [sink.send(gate.text, safe_data) for sink in sinks]
