"""Eldane in Slack (owner, 2026-10-17, B2): its review of a fix plan, as a conversation in the incident's environment's
discussion channel - its objections, WARDEN's answers, at most critique.MAX_ROUNDS rounds, then it agrees or a person
decides.

- Always said to be an AI: every message Eldane posts starts with approvals.AI_LABEL ("Eldane · AI critic"; EU AI Act
  Art. 50), whatever name its Slack app is given. WARDEN's answers are posted by WARDEN's own bot, in the same thread,
  each starting with "WARDEN", so nobody reads one for the other.
- Its own Slack bot token (ELDANE_BOT_ENV, `warden/<env>/eldane-slack-token`), read only by the critic zone
  (settings.ZONE_SECRETS); WARDEN's answers go out with WARDEN's token from the notify zone, as every message it sends.
- It only POSTS. It never reads the channel (register R12: anyone can write there, so nothing said there reaches
  Eldane): nothing here calls a Slack method that reads, and Eldane's input stays eldane.READS.
- What it posts is what is on the record (critique.OBJECTION and REBUTTAL rows, autonomy.VERDICT): model text made
  from the redacted evidence, which holds placeholders and stable ids, never a real value. Each piece is made inert
  (models.inert: one line, no code) with any write command withheld (gate G4), and the whole message goes through
  chatops.notify - redacted once more and through the outbound gate, which withholds it if a secret is still there.
  Nothing here can reach a masked value: this module, eldane.py and critique.py import no vault or reveal code
  (tests/test_eldane_slack.py walks their imports).
- Slack is never the record: a message that cannot be posted changes nothing, and each message is posted once per
  plan and run (POSTED), so a retried activity does not post it twice.
"""

from __future__ import annotations

import os
from typing import Any

from . import approvals, autonomy, critique
from .gate import withhold_commands
from .models import inert

ELDANE_BOT_ENV = "WARDEN_ELDANE_SLACK_TOKEN"  # the environment variable that holds Eldane's bot token
THREAD, POSTED = "eldane.thread", "eldane.posted"
OPENING, CLOSING = 0, critique.MAX_ROUNDS + 1  # the steps: 0 opens the thread, 1..MAX_ROUNDS a round, then the end
ELDANE, WARDEN = f"*{approvals.AI_LABEL}*", "*WARDEN*"  # how each message starts: who says it
NOTHING = -1  # no review of this plan on the record: nothing is said


def channel_for(environment: str) -> str:
    """The discussion channel of `environment` (discuss.channels: WARDEN_DISCUSS_CHANNELS, else the one
    WARDEN_DISCUSS_CHANNEL for every environment), or "" when it has none."""
    from .discuss import channels

    by_env = {env: channel for channel, env in channels().items()}
    return by_env.get(environment) or by_env.get("", "")


def _of(rows: list[dict[str, Any]], plan: Any, run_id: str) -> list[dict[str, Any]]:
    return [b for b in rows if b.get("workflow_id") == plan.workflow_id and b.get("run_id", "") == run_id
            and b.get("plan_hash") == plan.plan_hash]


def _rows(log: Any, plan: Any, run_id: str, kind: str) -> list[dict[str, Any]]:
    return _of([e["body"] for e in log.entries(plan.incident_id, kinds=(kind,))], plan, run_id)


def rounds(log: Any, plan: Any, run_id: str) -> int:
    """How many rounds of this plan's debate are on the record - never more than critique.MAX_ROUNDS."""
    seen = [int(o.get("round") or 0) for o in _rows(log, plan, run_id, critique.OBJECTION)]
    return min(max(seen, default=0), critique.MAX_ROUNDS)


def _said(text: Any) -> str:
    """Model-written text as it may be shown: one inert line (models.inert), any write command withheld (G4)."""
    return withhold_commands(inert(str(text or ""), 600))


def _cites(ids: Any) -> str:
    shown = [_said(i)[:12] for i in (ids or [])[:12] if str(i).strip()]
    return f" [evidence: {', '.join(shown)}]" if shown else ""


def opening(plan: Any) -> str:
    return (f"{ELDANE} - an AI, not a person - reviews WARDEN's fix plan for "
            f"inc-{plan.incident_id.removeprefix('inc-')}: `{plan.entry}` in {plan.environment}. Its objections and "
            f"WARDEN's answers follow in this thread, at most {critique.MAX_ROUNDS} rounds; then it agrees, or a person "
            "decides. A person's decision always overrides Eldane's. To ask WARDEN about this incident, mention @WARDEN "
            "in this thread.")


def objections(log: Any, plan: Any, run_id: str, round_no: int) -> str:
    """Eldane's objections in round `round_no`, as it says them; "" when there are none (or past MAX_ROUNDS)."""
    if not 1 <= round_no <= critique.MAX_ROUNDS:
        return ""
    said = sorted((o for o in _rows(log, plan, run_id, critique.OBJECTION) if o.get("round") == round_no),
                  key=lambda o: int(o.get("index") or 0))
    if not said:
        return ""
    lines = [f"{ELDANE} · round {round_no} of at most {critique.MAX_ROUNDS}: it does not agree yet."]
    lines += [f"{int(o.get('index') or 0) + 1}. ({_said(o.get('kind'))}) {_said(o.get('text'))}{_cites(o.get('evidence'))}"
              for o in said]
    return "\n".join(lines)


def answers(log: Any, plan: Any, run_id: str, round_no: int) -> str:
    """WARDEN's answers to round `round_no`, as WARDEN's own bot says them; "" when there are none."""
    if not 1 <= round_no <= critique.MAX_ROUNDS:
        return ""
    said = sorted((r for r in _rows(log, plan, run_id, critique.REBUTTAL) if r.get("round") == round_no),
                  key=lambda r: int(r.get("objection") or 0))
    if not said:
        return ""
    lines = [f"{WARDEN} answers {approvals.AI_LABEL}, round {round_no}:"]
    lines += [f"{int(r.get('objection') or 0) + 1}. {'concedes' if r.get('concede') else 'answers'}: "
              f"{_said(r.get('text'))}{_cites(r.get('evidence'))}" for r in said]
    return "\n".join(lines)


def closing(log: Any, plan: Any, run_id: str) -> str:
    """How the review ended: it agrees, or not and a person decides, or it did not review."""
    v = autonomy.verdict_of(log, plan, run_id)
    if v is None:
        return ""
    head = ELDANE
    if v.get("skipped"):
        return f"{head} did not review this plan: {_said(v['skipped'])}. A person decides."
    if v.get("agree"):
        return (f"{head} agrees with this plan. {_said(v.get('level_said'))} A person's \"no\" still stops it "
                "before it is applied.")
    return f"{head} does not agree with this plan, so it approves nothing: a person decides."


def _posted(log: Any, plan: Any, run_id: str, step: str) -> bool:
    return any(p.get("step") == step and p.get("delivered") for p in _rows(log, plan, run_id, POSTED))


def thread_of(log: Any, plan: Any, run_id: str) -> dict[str, Any] | None:
    """The thread Eldane opened for this plan and run: {channel, ts}, or None."""
    rows = _rows(log, plan, run_id, THREAD)
    return {"channel": rows[-1]["channel"], "ts": rows[-1]["ts"]} if rows else None


class _NewThread:
    """chatops' sink for the one message that opens Eldane's thread: posted at the top of the channel, its ts kept."""

    name = "slack-eldane"

    def __init__(self, token: str, channel: str) -> None:
        self._token, self.channel, self.ts = token, channel, ""

    def send(self, text: str, data: dict) -> Any:
        from .chatops import (
            Notification,
            _slack_call,
            slack_messages,
            split_for_slack,
            to_slack_mrkdwn,
        )

        [first, *_] = slack_messages(split_for_slack(to_slack_mrkdwn(text)), data)
        answer, detail = _slack_call("chat.postMessage", {"channel": self.channel, "unfurl_links": False,
                                                          "unfurl_media": False, **first}, self._token)
        if answer is None:
            return Notification(sink=self.name, delivered=False, detail=detail)
        self.ts = str(answer.get("ts") or "")
        return Notification(sink=self.name, delivered=bool(self.ts), detail=f"thread {self.ts}")


class _AsSaid:
    """A sink that posts only what its speaker says: a text that does not start with the speaker's label - the outbound
    gate's notice for a message it withheld - is never posted under that speaker's name (EU AI Act Art. 50)."""

    def __init__(self, sink: Any, label: str) -> None:
        self.sink, self.label, self.name = sink, label, sink.name

    def send(self, text: str, data: dict) -> Any:
        from .chatops import Notification

        if not text.startswith(self.label):
            return Notification(sink=self.name, delivered=False, detail="withheld by the outbound gate: nothing posted")
        return self.sink.send(text, data)


def post(log: Any, plan: Any, run_id: str, step: str, text: str, *, token: str, label: str,
         opens: bool = False) -> bool:
    """`text` in this plan's Eldane thread with `token`, through chatops.notify (the redactor and the outbound gate),
    once, and only as `label` says it; `opens`: it is the message that starts the thread. Whether it was delivered
    (now or before)."""
    if not text or not token or not text.startswith(label):
        return False
    if _posted(log, plan, run_id, step):
        return True
    from .chatops import SlackThreadSink, notify
    from .reporting import Report

    report = Report(markdown=text, data={"alert": {"id": plan.incident_id}}, promotion=())
    thread = thread_of(log, plan, run_id)
    if opens and thread is None:
        channel = channel_for(plan.environment)
        if not channel:
            return False
        sink: Any = _NewThread(token, channel)
        [sent] = notify(report, sinks=[_AsSaid(sink, label)])
        if sent.delivered:
            log.append(plan.incident_id, THREAD, {"workflow_id": plan.workflow_id, "run_id": run_id,
                                                  "plan_hash": plan.plan_hash, "channel": channel, "ts": sink.ts})
    elif thread is None:
        return False  # Eldane opens the thread; nothing is posted into one that was never opened
    else:
        # Live with a token: only the critic zone holds Eldane's and only the notify zone WARDEN's (settings.ZONE_SECRETS).
        [sent] = notify(report, sinks=[_AsSaid(SlackThreadSink(token, thread["channel"], thread["ts"], live=True), label)])
    log.append(plan.incident_id, POSTED, {"workflow_id": plan.workflow_id, "run_id": run_id, "plan_hash": plan.plan_hash,
                                          "step": step, "delivered": sent.delivered, "detail": sent.detail[:200]})
    return sent.delivered


def eldane_says(log: Any, plan: Any, run_id: str, step: int) -> int:
    """Eldane's part of step `step` (OPENING, a round, CLOSING), with its own token; how many rounds there are on the
    record, or NOTHING when it made no review of this plan."""
    if autonomy.verdict_of(log, plan, run_id) is None:
        return NOTHING
    token = os.environ.get(ELDANE_BOT_ENV, "").strip()
    if step == OPENING:
        post(log, plan, run_id, "open", opening(plan), token=token, label=ELDANE, opens=True)
        if thread_of(log, plan, run_id) is None:
            return NOTHING  # no thread (no token, no channel, or not delivered): nothing more is said
    elif step == CLOSING:
        post(log, plan, run_id, "close", closing(log, plan, run_id), token=token, label=ELDANE)
    else:
        post(log, plan, run_id, f"objections-{step}", objections(log, plan, run_id, step), token=token, label=ELDANE)
    return rounds(log, plan, run_id)


def warden_says(log: Any, plan: Any, run_id: str, round_no: int) -> bool:
    """WARDEN's answers to round `round_no`, with WARDEN's own token (the notify zone), in Eldane's thread."""
    token = os.environ.get("WARDEN_SLACK_BOT_TOKEN", "").strip()
    return post(log, plan, run_id, f"answers-{round_no}", answers(log, plan, run_id, round_no), token=token,
                label=WARDEN)
