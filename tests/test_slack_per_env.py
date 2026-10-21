"""Each environment's own Slack channels: a dev incident is told only in dev's alerts channel and
discussed only in dev's discussion channel, a prod one only in prod's - never another environment's, whatever is
missing or mistyped. WARDEN_SLACK_CHANNELS and WARDEN_DISCUSS_CHANNELS, `env=channel,...`, are runtime settings."""

from __future__ import annotations

import argparse
import asyncio
import itertools
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from test_discuss_g10v import INCIDENT, _turn
from test_discuss_g10v import world as discuss_world
from warden import audit, chatops, cli, codec, discuss, settings
from warden.activities import AuditThreads, _send
from warden.models import Alert
from warden.reporting import Report
from warden.workflows import DiscussWorkflow

HOOK = "https://hooks." + "slack.com/services/" + "x"  # built from parts, as TOKEN
TOKEN = "xox" + "b-" + "0" * 4 + "-test"  # built from parts: never a real-looking literal
DEV, PROD = "C" + "0" * 3 + "DEVALRT", "C" + "0" * 3 + "PRDALRT"
DEV_TALK, PROD_TALK = "C" + "0" * 3 + "DEVTALK", "C" + "0" * 3 + "PRDTALK"


@pytest.fixture
def world(tmp_path, monkeypatch):
    return discuss_world.__wrapped__(tmp_path, monkeypatch)


@pytest.fixture
def slack(monkeypatch):
    calls, n = [], itertools.count(1)

    def fake(method, payload, token, form=False):
        calls.append((method, payload))
        return {"ok": True, "ts": f"1700000000.{next(n):06d}"}, "ok"

    def no_network(*a, **k):
        raise AssertionError("no test sends over the network")

    monkeypatch.setattr(chatops, "_slack_call", fake)
    monkeypatch.setattr(chatops.urllib.request, "urlopen", no_network)
    monkeypatch.setattr(chatops.web, "urlopen", no_network)
    for name in ("WARDEN_SLACK_WEBHOOK", "WARDEN_SLACK_CHANNEL", "WARDEN_TEAMS_WEBHOOK", "WARDEN_WEBHOOK_URL",
                 "WARDEN_PAGERDUTY_ROUTING_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("WARDEN_SLACK_BOT_TOKEN", TOKEN)
    monkeypatch.setenv("WARDEN_CHATOPS_LIVE", "1")
    return calls


def _report(env, incident="inc-7"):
    return Report(markdown="## Diagnosis: memory pressure\nbody", data={"alert": {"id": incident, "environment": env}},
                  promotion=())


def test_each_environments_incident_goes_to_its_own_channel_and_no_webhook(slack, monkeypatch):
    monkeypatch.setenv("WARDEN_SLACK_CHANNELS", f"dev={DEV}, prod={PROD}")
    monkeypatch.setenv("WARDEN_SLACK_WEBHOOK", HOOK)  # one channel for all: not used
    monkeypatch.setenv("WARDEN_PAGERDUTY_ROUTING_KEY", "k" * 32)
    for env, channel in (("dev", DEV), ("prod", PROD)):
        sinks = chatops.resolve_sinks(environment=env)
        assert [s.name for s in sinks] == ["slack-bot", "pagerduty"]  # PagerDuty is not routed by the map
        assert sinks[0].channel == channel
    monkeypatch.delenv("WARDEN_PAGERDUTY_ROUTING_KEY")
    slack.clear()
    assert all(n.delivered for n in chatops.notify(_report("prod"), sinks=chatops.resolve_sinks(environment="prod")))
    assert {p["channel"] for _, p in slack} == {PROD}


def test_an_environment_with_no_channel_is_withheld_and_recorded_never_cross_posted(slack, monkeypatch, tmp_path):
    monkeypatch.setenv("WARDEN_SLACK_CHANNELS", f"dev={DEV}")
    log = audit.AuditLog(tmp_path / "a.db")
    for env in ("prod", ""):
        slack.clear()
        [sent] = _send(log, "inc-9", _report(env, "inc-9"))
        assert not sent.delivered
        assert sent.detail.startswith(chatops.WITHHELD)
        assert slack == []
    rows = [e["body"]["detail"] for e in log.entries("inc-9", kinds=("chatops.withheld",))]
    assert rows == ["withheld: no channel for prod", "withheld: no channel for an incident with no environment"]
    monkeypatch.delenv("WARDEN_SLACK_BOT_TOKEN")
    [sent] = chatops.notify(_report("dev"))
    assert not sent.delivered
    assert "WARDEN_SLACK_BOT_TOKEN" in sent.detail
    assert slack == []


@pytest.mark.parametrize("value", [
    "dev=C0", "dev:" + DEV, "staging=" + DEV, "ops=" + DEV, f"dev={DEV},dev={PROD}", f"dev={DEV},prod={DEV}",
    f"dev={DEV},", "dev=c000devalrt", "=" + DEV])
def test_a_malformed_map_refuses(value, monkeypatch, slack):
    monkeypatch.setenv("WARDEN_SLACK_CHANNELS", value)
    with pytest.raises(ValueError, match="WARDEN_SLACK_CHANNELS"):
        settings.by_environment("WARDEN_SLACK_CHANNELS")
    with pytest.raises(ValueError):
        chatops.resolve_sinks(environment="dev")  # never a guess at send time either
    monkeypatch.delenv("WARDEN_SLACK_CHANNELS")
    monkeypatch.setenv("WARDEN_DISCUSS_CHANNELS", value)
    with pytest.raises(ValueError, match="WARDEN_DISCUSS_CHANNELS"):
        discuss.channels()
    # The worker refuses to start, before it connects to anything.
    outs = []
    monkeypatch.setattr(cli, "_out", lambda line, err=False: outs.append(line))
    assert asyncio.run(cli._workflow_command(argparse.Namespace(cmd="worker"))) == 1
    assert outs[0].startswith("error: WARDEN_DISCUSS_CHANNELS")


def test_both_settings_are_plain_and_loadable():
    for name in ("WARDEN_SLACK_CHANNELS", "WARDEN_DISCUSS_CHANNELS"):
        assert name in settings.LOADABLE - settings.SECRETS
        assert name not in settings.RESTRICTED


def test_a_thread_is_continued_and_updated_only_in_the_channel_it_is_in(slack, tmp_path, monkeypatch):
    threads = AuditThreads(audit.AuditLog(tmp_path / "a.db"))
    assert chatops.SlackBotSink(TOKEN, DEV, live=True, threads=threads).send("first", {"alert": {"id": "inc-7"}}).delivered
    assert threads.get("inc-7") == {"ts": "1700000000.000001", "channel": DEV}
    root = threads.get("inc-7")["ts"]
    slack.clear()
    chatops.SlackBotSink(TOKEN, DEV, live=True, threads=threads).send("later", {"alert": {"id": "inc-7"}})
    assert slack[0] == ("chat.update", {"channel": DEV, "ts": root, "text": "WARDEN · inc-7 · later"})
    # Routed elsewhere since: a new thread there - the old one is neither updated nor replied to from another channel.
    slack.clear()
    chatops.SlackBotSink(TOKEN, PROD, live=True, threads=threads).send("moved", {"alert": {"id": "inc-7"}})
    assert all(m == "chat.postMessage" and p["channel"] == PROD and p.get("thread_ts") != root for m, p in slack)
    assert threads.get("inc-7")["channel"] == PROD
    # A row from before the channel was kept: its ts, in the one WARDEN_SLACK_CHANNEL there was - continued only there.
    monkeypatch.setenv("WARDEN_SLACK_CHANNEL", DEV)
    old = {"inc-1": {"ts": "1.000001"}}
    slack.clear()
    chatops.SlackBotSink(TOKEN, DEV, live=True, threads=old).send("x", {"alert": {"id": "inc-1"}})
    assert slack[0] == ("chat.update", {"channel": DEV, "ts": "1.000001", "text": "WARDEN · inc-1 · x"})
    # The old single channel is not this one, or is not known any more: a new thread, the old ts is never used here
    # (chat.update and replies with another channel's ts fail).
    for single in (PROD, None):
        if single:
            monkeypatch.setenv("WARDEN_SLACK_CHANNEL", single)
        else:
            monkeypatch.delenv("WARDEN_SLACK_CHANNEL", raising=False)
        old = {"inc-2": {"ts": "2.000002"}}
        slack.clear()
        chatops.SlackBotSink(TOKEN, DEV, live=True, threads=old).send("y", {"alert": {"id": "inc-2"}})
        assert slack, single
        assert all(m == "chat.postMessage" and p.get("thread_ts") != "2.000002" for m, p in slack), single
        assert old["inc-2"]["channel"] == DEV, old
        assert old["inc-2"]["ts"] != "2.000002", old


def test_without_the_map_slack_is_as_before(slack, monkeypatch):
    monkeypatch.delenv("WARDEN_SLACK_CHANNELS", raising=False)
    monkeypatch.setenv("WARDEN_SLACK_CHANNEL", DEV)
    monkeypatch.setenv("WARDEN_SLACK_WEBHOOK", HOOK)
    for env in ("dev", "prod", None):
        sinks = chatops.resolve_sinks(environment=env)
        assert [s.name for s in sinks] == ["slack-bot", "slack"]
        assert sinks[0].channel == DEV
    monkeypatch.delenv("WARDEN_DISCUSS_CHANNELS", raising=False)
    monkeypatch.setenv("WARDEN_DISCUSS_CHANNEL", DEV_TALK)
    assert discuss.channels() == {DEV_TALK: ""}


def test_each_discussion_channel_carries_its_environment(monkeypatch):
    monkeypatch.setenv("WARDEN_DISCUSS_CHANNELS", f"dev={DEV_TALK},prod={PROD_TALK}")
    monkeypatch.setenv("WARDEN_DISCUSS_CHANNEL", "C" + "0" * 3 + "IGNORED")  # the map wins
    ours = discuss.channels()
    assert ours == {DEV_TALK: "dev", PROD_TALK: "prod"}
    event = {"type": "app_mention", "user": "U" + "0" * 3 + "PERSON1", "text": "x", "ts": "1760000000.000100"}
    assert discuss.turn_of({**event, "channel": PROD_TALK}, ours).environment == "prod"
    assert discuss.turn_of({**event, "channel": DEV_TALK}, ours).environment == "dev"
    assert discuss.turn_of({**event, "channel": "C" + "0" * 3 + "IGNORED"}, ours) is None


def _alarm(log, incident, env):
    log.append(incident, "incident.alert", {"alert": Alert(alert_id=incident, name="n", service="svc", environment=env,
                                                           severity="high", summary="s").model_dump(mode="json")})


def test_a_discussion_channel_refuses_another_environments_incident_before_reading_it(world):
    acts, log = world["acts"], world["log"]
    _alarm(log, INCIDENT, "prod")
    dev_turn = _turn("<@UWARDEN> why?").model_copy(update={"environment": "dev"})
    thread = acts.discuss_thread(dev_turn)
    assert thread.elsewhere
    assert thread.incident == ""
    assert thread.lines == []
    [row] = [e["body"] for e in log.entries(f"discuss-{INCIDENT}", kinds=("discuss.turn",))]
    assert row["refused"]
    assert row["environment"] == "dev"
    prod_turn = dev_turn.model_copy(update={"environment": "prod"})
    assert acts.discuss_thread(prod_turn).incident == INCIDENT
    assert not acts.discuss_thread(prod_turn).elsewhere
    assert acts.discuss_thread(_turn("<@UWARDEN> why?")).incident == INCIDENT  # one channel for every environment

    async def main(turn):
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="discuss-env", workflows=[DiscussWorkflow],
                               activities=[acts.discuss_thread, acts.discuss_evidence, acts.discuss_answer,
                                           acts.discuss_reply, acts.discuss_facts],
                               activity_executor=ThreadPoolExecutor(2)):
            return await env.client.execute_workflow(DiscussWorkflow.run, turn, id="discuss-env",
                                                     task_queue="discuss-env")

    world["posted"].clear()
    said = asyncio.run(main(dev_turn))
    assert said == discuss.ELSEWHERE.format(environment="dev")
    assert "prod" not in said
    assert [m for m, *_ in world["posted"]].count("chat.postMessage") == 1  # the refusal; nothing else of it



def test_a_message_from_the_record_goes_to_the_incidents_environments_channel(world, monkeypatch):
    monkeypatch.setenv("WARDEN_SLACK_CHANNELS", f"dev={DEV},prod={PROD}")
    for incident, env, channel in (("inc-d", "dev", DEV), ("inc-p", "prod", PROD)):
        _alarm(world["log"], incident, env)
        world["posted"].clear()
        assert world["inc"].no_plan(incident, "nothing in the catalogue fits") == ["slack-bot"]
        assert {p["channel"] for m, p, _ in world["posted"] if m.startswith("chat.")} == {channel}
