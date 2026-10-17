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
from typing import Any, Protocol, runtime_checkable

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
        parts = slack_messages(split_for_slack(name_people(to_slack_mrkdwn(text), data.get("people"), slack=True)), data)
        # ⛔ No unfurling: with it on, a URL in a message makes Slack's servers FETCH it - data in the
        # query string leaves without anyone clicking (the outbound gate removes URLs too; this is
        # the second lock).
        notes = [_post_json(self._url, {**part, "unfurl_links": False, "unfurl_media": False},
                            self.name) for part in parts]
        failed = [n for n in notes if not n.delivered]
        if failed:
            return Notification(sink=self.name, delivered=False,
                                detail=f"{len(failed)} of {len(parts)} part(s) failed: {failed[0].detail}")
        return Notification(sink=self.name, delivered=True,
                            detail=notes[0].detail + (f" ({len(parts)} parts)" if len(parts) > 1 else ""))


_SLACK_API = "https://slack.com/api/"
_MAX_RETRY_AFTER_S = 10.0


def _slack_call(method: str, payload: dict, token: str, *, form: bool = False) -> tuple[dict | None, str]:
    """One Slack Web API call with the bot token: (response, detail), never an exception. Slack answers HTTP 200 with
    `ok: false` for most failures, so `ok` is what counts. A rate limit (HTTP 429; chat.postMessage allows about one
    message a second per channel) is waited out once, as its Retry-After says, up to a ceiling. `form`: the arguments
    form-encoded - Slack documents its read methods (conversations.replies, auth.test) as GET, with their arguments in
    the query or a form; JSON bodies are documented for the methods that write."""
    body = (urllib.parse.urlencode(payload) if form else json.dumps(payload)).encode("utf-8")
    kind = "application/x-www-form-urlencoded" if form else "application/json; charset=utf-8"
    for attempt in (1, 2):
        req = urllib.request.Request(_SLACK_API + method, data=body, method="POST", headers={
            "Content-Type": kind, "Authorization": f"Bearer {token}"})
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
        parts = split_for_slack(name_people(to_slack_mrkdwn(text), data.get("people"), slack=True))
        messages = slack_messages(parts, data)
        status = f"WARDEN · inc-{incident.removeprefix('inc-')} · {parts[0].strip().splitlines()[0][:150]}"
        # The thread is kept with the channel it is in: one in another channel - the incident's environment was routed
        # elsewhere before - is never continued or updated from this one. A row from before the channel was kept has
        # only its ts: it was posted in the one WARDEN_SLACK_CHANNEL of that time, so it is continued only when that is
        # this channel; with that setting gone, the old channel is unknown and a new thread starts (CodeRabbit, PR 36).
        kept = self.threads.get(incident) or {}
        old = os.environ.get("WARDEN_SLACK_CHANNEL", "").strip() or None
        root = kept.get("ts") if kept.get("channel", old) == self.channel else None
        if root is None:
            answer, detail = self._post(status)
            if answer is None:
                return Notification(sink=self.name, delivered=False, detail=detail)
            root = answer["ts"]
            self.threads[incident] = {"ts": root, "channel": self.channel}
        else:
            _slack_call("chat.update", {"channel": kept.get("channel", self.channel), "ts": root, "text": status},
                        self._token)
        failed = [d for d in (self._post(m["text"], thread_ts=root, **{k: v for k, v in m.items() if k != "text"})[1]
                              for m in messages) if d != "ok"]
        if failed:
            return Notification(sink=self.name, delivered=False,
                                detail=f"{len(failed)} of {len(parts)} part(s) failed: {failed[0]}")
        return Notification(sink=self.name, delivered=True, detail=f"thread {root} ({len(parts)} part(s))")


class SlackThreadSink:
    """One reply in one Slack thread, with the bot's token (discuss.py): the thread a person mentioned WARDEN in - or,
    with no thread, one new message in the channel."""

    name = "slack-thread"

    def __init__(self, token: str, channel: str, thread_ts: str, *, live: bool) -> None:
        self._token, self.channel, self.thread_ts, self.live = token, channel, thread_ts, live

    def send(self, text: str, data: dict) -> Notification:
        if not self.live:
            return Notification(sink=self.name, delivered=False, detail="dry-run (WARDEN_CHATOPS_LIVE!=1)")
        parts = slack_messages(split_for_slack(name_people(to_slack_mrkdwn(text), data.get("people"), slack=True)), data)
        thread, failed = self.thread_ts, []
        for m in parts:
            # No thread given (the dependency review, depwatch.py): the first part is a new message in the channel and
            # the rest go in its thread.
            answer, detail = _slack_call("chat.postMessage", {"channel": self.channel, **({"thread_ts": thread} if thread
                                                                                          else {}),
                                                              "unfurl_links": False, "unfurl_media": False, **m},
                                         self._token)
            if detail != "ok":
                failed.append(detail)
            elif not thread:
                thread = str((answer or {}).get("ts") or "")
        if failed:
            return Notification(sink=self.name, delivered=False, detail=f"{len(failed)} part(s) failed: {failed[0]}")
        return Notification(sink=self.name, delivered=True, detail=f"thread {thread}")


# Decision D13: PagerDuty through its Events API v2 (read 2026-10-04: https://events.pagerduty.com/v2/enqueue; a
# 32-character routing key; trigger, acknowledge or resolve; dedup_key up to 255 characters; summary up to 1024;
# severity critical, error, warning or info).
PAGERDUTY_URL = "https://events.pagerduty.com/v2/enqueue"
_PD_SEVERITY = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}


def _dedup(incident: str) -> str:
    """One PagerDuty alert per incident: every message about it - the report, a reminder, an expiry - updates that one
    alert instead of paging again, and the resolve closes it."""
    return f"inc-{incident.removeprefix('inc-')}"[:255]


class PagerDutySink:
    """Pages the on-call through PagerDuty (decision D13). The summary is the gated message's first line; nothing
    else of the message leaves - no evidence, no link."""

    name = "pagerduty"

    def __init__(self, routing_key: str, *, live: bool) -> None:
        self._key, self.live = routing_key, live

    def send(self, text: str, data: dict) -> Notification:
        if not self.live:
            return Notification(sink=self.name, delivered=False, detail="dry-run (WARDEN_CHATOPS_LIVE!=1)")
        alert = data.get("alert") or {}
        incident = str(alert.get("id", "")) or "unknown"
        summary = next((line.strip() for line in text.splitlines() if line.strip()), "WARDEN incident")[:1024]
        event = {"routing_key": self._key, "event_action": "trigger", "dedup_key": _dedup(incident),
                 "payload": {"summary": summary, "source": f"warden/{alert.get('service') or 'unknown'}"[:255],
                             "severity": _PD_SEVERITY.get(str(alert.get("severity", "")).lower(), "error"),
                             "component": str(alert.get("service") or "")[:255],
                             "group": str(alert.get("environment") or "")[:255], "class": "warden-incident",
                             "custom_details": {"incident": incident, "gate": data.get("gate", "")}}}
        return _post_json(PAGERDUTY_URL, event, self.name)


def page_resolve(incident: str) -> Notification | None:
    """Resolve the incident's PagerDuty alert (decision D13): called once a fix is verified. None when PagerDuty is not
    configured."""
    key = os.environ.get("WARDEN_PAGERDUTY_ROUTING_KEY", "").strip()
    if not key:
        return None
    if os.environ.get("WARDEN_CHATOPS_LIVE") != "1":
        return Notification(sink="pagerduty", delivered=False, detail="dry-run (WARDEN_CHATOPS_LIVE!=1)")
    return _post_json(PAGERDUTY_URL, {"routing_key": key, "event_action": "resolve", "dedup_key": _dedup(incident)},
                      "pagerduty")


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


WITHHELD = "withheld:"  # how a WithheldSink's detail starts


class WithheldSink:
    """Slack, for an environment WARDEN_SLACK_CHANNELS gives no channel: nothing is sent - never to another
    environment's channel - and the Notification says why, for the caller's audit row."""

    name, live = "slack-bot", False

    def __init__(self, detail: str) -> None:
        self.detail = detail

    def send(self, text: str, data: dict) -> Notification:
        import logging

        logging.getLogger("warden.incident").warning("a message about %s was %s",
                                                     str((data.get("alert") or {}).get("id", ""))[:80], self.detail)
        return Notification(sink=self.name, delivered=False, detail=self.detail)


def resolve_sinks(threads=None, environment: str | None = None) -> list[ChatOpsSink]:
    """Build the sink list from the environment. Empty of webhooks -> a single ConsoleSink.

    WARDEN_SLACK_CHANNELS (`env=channel,...`) with WARDEN_SLACK_BOT_TOKEN: the incident's `environment`'s own channel,
    one thread per incident (`threads` remembers them), and no Slack webhook - one webhook is one channel for every
    environment. An environment the map does not name gets no Slack message (WithheldSink). Without the map:
    WARDEN_SLACK_BOT_TOKEN with WARDEN_SLACK_CHANNEL, and WARDEN_SLACK_WEBHOOK, as before.
    WARDEN_TEAMS_WEBHOOK / WARDEN_WEBHOOK_URL / PagerDuty are added either way.
    WARDEN_CHATOPS_LIVE=1 arms them; otherwise every sink is dry-run.
    """
    from .settings import by_environment

    live = os.environ.get("WARDEN_CHATOPS_LIVE") == "1"
    sinks: list[ChatOpsSink] = []
    token, channel = os.environ.get("WARDEN_SLACK_BOT_TOKEN"), os.environ.get("WARDEN_SLACK_CHANNEL")
    if channels := by_environment("WARDEN_SLACK_CHANNELS"):
        here = channels.get(environment or "")
        if not here:
            sinks.append(WithheldSink(f"{WITHHELD} no channel for {environment or 'an incident with no environment'}"))
        elif not token:
            sinks.append(WithheldSink(f"{WITHHELD} WARDEN_SLACK_CHANNELS is set but WARDEN_SLACK_BOT_TOKEN is not"))
        else:
            sinks.append(SlackBotSink(token, here, live=live, threads=threads))
    else:
        if token and channel:
            sinks.append(SlackBotSink(token, channel, live=live, threads=threads))
        if url := os.environ.get("WARDEN_SLACK_WEBHOOK"):
            sinks.append(SlackWebhookSink(url, live=live))
    if url := os.environ.get("WARDEN_TEAMS_WEBHOOK"):
        sinks.append(TeamsWebhookSink(url, live=live))
    if url := os.environ.get("WARDEN_WEBHOOK_URL"):
        sinks.append(GenericWebhookSink(url, live=live))
    if key := os.environ.get("WARDEN_PAGERDUTY_ROUTING_KEY", "").strip():
        sinks.append(PagerDutySink(key, live=live))
    if not sinks:
        sinks.append(ConsoleSink())
    return sinks


_BOLD = re.compile(r"\*\*(.+?)\*\*")
# A space or tab after the hashes, as CommonMark requires: `\s` also took a no-break space, so
# "#<NBSP>Fix - approved" became a bold Slack line that renders as plain text everywhere else.
_HEADING = re.compile(r"^#{1,6}[ \t]++(.*)$")  # possessive: the spaces are never handed back to `.*` (Sonar python:S8786, 2026-10-16)
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
    closed at the end of one part and reopened at the start of the next, so a code line is never cut.
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


LINK_LABEL = "Open the plan to approve or deny"
_APPROVAL_LABEL = re.compile(re.escape(LINK_LABEL) + r"( \(link of [A-Za-z0-9._-]{1,64}\))?")
# The incident's page on WARDEN's records (records.py): everything about it, where Slack gets one message.
RECORD_LABEL = "Full record"
# Every incident on WARDEN's records, in one place (owner, 2026-10-15: "all the previous ones too ... that link is
# missing").
ALL_LABEL = "All incidents"


_SLACK_MEMBER = re.compile(r"[UW][A-Z0-9]{6,14}")


_MARK = re.compile(r"@@([A-Za-z0-9._-]{1,64})@@")  # ApproverPolicy.said's mark for an approver, by their id


def name_people(text: str, people: Any, *, slack: bool) -> str:
    """Each approver's mark, as the reader sees it, where the sentence names them (owner, 2026-10-12: the list's id
    stood in the text - "owner" - and the mention alone at the foot of the message). In Slack: Slack's own mention
    of the member the approver list gives. Anywhere else, or with no member: the name the list gives. `people`:
    (approver id, member id, name) rows handed over by WARDEN from the approver list - only a member id of exactly
    Slack's shape becomes a mention, one typed into a message stays text (to_slack_mrkdwn), and a mark typed into
    one can name nobody the list does not."""
    known = {str(row[0]): (str(row[1]), str(row[2])) for row in people or () if len(row) == 3}

    def one(mark: re.Match[str]) -> str:
        member, name = known.get(mark.group(1), ("", mark.group(1)))
        return f"<@{member}>" if slack and _SLACK_MEMBER.fullmatch(member) else f"`{name.replace('`', '')}`"
    return _MARK.sub(one, text)


def approval_links(actions: tuple[tuple[str, str], ...]) -> list[tuple[str, str]]:
    """The approval links that may leave, as (label, link): each exactly `https://<the approval domain>/a/<a
    43-character token>` with WARDEN's own label (LINK_LABEL; whose link it is, where several approvers have one).
    The gate removes every URL from a message - anything a model or an alert wrote could carry data out - so
    WARDEN's own links go beside the gated text, and nothing else can."""
    rp = os.environ.get("WARDEN_APPROVAL_RP_ID", "").strip()
    if not rp:
        return []
    url = re.compile(rf"https://{re.escape(rp)}/a/[A-Za-z0-9_-]{{43}}")
    record = re.compile(rf"https://{re.escape(rp)}/r/[A-Za-z0-9._-]{{1,120}}")
    return [(label, link) for label, link in actions
            if (_APPROVAL_LABEL.fullmatch(label) and url.fullmatch(link))
            or (label == RECORD_LABEL and record.fullmatch(link))
            or (label == ALL_LABEL and link == f"https://{rp}/r")]


SLACK_SECTION_CHARS = 3000  # Block Kit's limit for a section's text (docs.slack.dev, read 2026-10-12)
# Slack's page for the context block states no limit for its text (read 2026-10-14); WARDEN's footer is about 250
# characters, and this cap only keeps something unforeseen from failing the whole message.
SLACK_CONTEXT_CHARS = 1900
_FOOT_RULE = "\n---\n"  # the rule WARDEN's own messages put before their footer (activities.announce, notify)


def slack_messages(parts: list[str], data: dict) -> list[dict[str, Any]]:
    """The messages Slack gets for these parts. WARDEN's own approval link is a button under the last one, its
    address not printed (owner, 2026-10-12: "the link should be hidden under a button") - a Block Kit button that
    opens the page. Slack sends the app a note of each click, which the approval API answers and ignores
    (`POST /s/interact`); the click decides nothing - the page and the passkey do."""
    messages: list[dict[str, Any]] = [{"text": part} for part in parts]
    links = [(str(pair[0]), str(pair[1])) for pair in data.get("links") or () if len(pair) == 2]
    # The approval is the one primary button, where it is the only one; the record never looks like a decision.
    deciding = [label for label, _ in links if label not in (RECORD_LABEL, ALL_LABEL)]
    buttons = {"type": "actions", "elements": [
        {"type": "button", "text": {"type": "plain_text", "text": label[:75]}, "url": link,
         **({"style": "primary"} if label in deciding and len(deciding) == 1 else {})} for label, link in links]}
    last = messages[-1]["text"] if messages else ""
    # WARDEN's own footer - the incident, the audit head - stands after a rule in the text. In Slack it is the small
    # grey line under the message, with no rule (owner, 2026-10-14, of the "---" between a message and its footer:
    # "it doesn't look good"). The `text` stays whole: it is what a notification and a client without blocks show.
    body, rule, foot = last.rpartition(_FOOT_RULE)
    if not rule or not body.strip() or not foot.strip():
        body, foot = last, ""
    if messages and len(body) <= SLACK_SECTION_CHARS and (links or foot):
        blocks: list[dict[str, Any]] = [{"type": "section", "text": {"type": "mrkdwn", "text": body.rstrip()}}]
        if links:
            blocks.append(buttons)
        if foot:
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": foot.strip()[:SLACK_CONTEXT_CHARS]}]})
        messages[-1]["blocks"] = blocks
    elif links:  # too long for a section: the buttons are their own message
        messages.append({"text": LINK_LABEL, "blocks": [buttons]})
    return messages


def notify(report: Report, sinks: list[ChatOpsSink] | None = None, threads=None) -> list[Notification]:
    """Deliver `report` to every configured sink, redacting the exact payload one more time first."""
    # The incident's environment picks its Slack channel (WARDEN_SLACK_CHANNELS).
    sinks = sinks if sinks is not None else resolve_sinks(
        threads, environment=str((report.data.get("alert") or {}).get("environment") or ""))
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
        import logging

        from .gate import where_withheld

        safe_data = {"withheld": True, "gate": gate.verdict, "reasons": gate.reasons}
        # Where and what kind, never the value: a withheld message is diagnosable from the log (2026-10-16).
        logging.getLogger("warden.incident").warning(
            "a message about %s was withheld by the outbound gate (%s) - at %s",
            str((report.data.get("alert") or {}).get("id", ""))[:80], "; ".join(gate.reasons),
            where_withheld(report.markdown) or "no single line (a value spans lines)")
    else:
        safe_data = {**sanitise_data(safe_data), "gate": gate.verdict, "gate_reasons": gate.reasons}
    links = approval_links(report.actions)
    text = gate.text
    if links:
        safe_data = {**safe_data, "links": [list(pair) for pair in links]}
    # After the gate and the scrub: WARDEN's own, from the approver list - and only the people this text names.
    people = [list(row) for row in report.people if f"@@{row[0]}@@" in text]
    if people:
        safe_data = {**safe_data, "people": people}
    # Only Slack has a mention to make of an approver's mark; every other reader gets the name.
    # ...and only Slack has a button for WARDEN's link; every other reader gets it as a line under the text.
    plain = name_people(text, people, slack=False) + (
        "\n\n" + "\n".join(f"{label}: {link}" for label, link in links) if links else "")
    return [sink.send(text if isinstance(sink, (SlackWebhookSink, SlackBotSink, SlackThreadSink)) else plain, safe_data)
            for sink in sinks]
