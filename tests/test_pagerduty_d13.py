"""Decision D13: PagerDuty through its Events API v2. One alert per incident (dedup_key inc-<id>): every message about
the incident updates it instead of paging again, and a verified fix resolves it - on the record. Only the gated
message's first line leaves; the routing key reaches only the commands that send."""

from __future__ import annotations

import pytest

from warden import chatops, settings

KEY = "R" * 32


@pytest.fixture
def posted(monkeypatch):
    sent = []
    monkeypatch.setattr(chatops, "_post_json", lambda url, payload, sink: sent.append((url, payload)) or
                        chatops.Notification(sink=sink, delivered=True, detail="HTTP 202"))
    return sent


def test_a_report_triggers_one_alert_per_incident(posted):
    sink = chatops.PagerDutySink(KEY, live=True)
    data = {"alert": {"id": "inc-42", "severity": "high", "service": "orders", "environment": "dev"}, "gate": "PASS"}
    sink.send("\n# Incident inc-42: orders is failing\nmore text https://x", data)
    sink.send("A reminder about the same incident", data)
    (url, first), (_, second) = posted
    assert url == "https://events.pagerduty.com/v2/enqueue"
    assert first["event_action"] == "trigger" and first["routing_key"] == KEY
    assert first["dedup_key"] == second["dedup_key"] == "inc-42"  # one alert, updated, never a second page
    p = first["payload"]
    assert p["summary"] == "# Incident inc-42: orders is failing" and p["severity"] == "error"
    assert p["source"] == "warden/orders" and p["group"] == "dev" and "more text" not in str(first)


def test_an_unarmed_sink_sends_nothing(posted):
    out = chatops.PagerDutySink(KEY, live=False).send("x", {"alert": {"id": "inc-1"}})
    assert not out.delivered and posted == []


def test_the_sink_is_configured_by_its_secret_alone(monkeypatch):
    monkeypatch.delenv("WARDEN_SLACK_BOT_TOKEN", raising=False)
    for n in ("WARDEN_SLACK_WEBHOOK", "WARDEN_TEAMS_WEBHOOK", "WARDEN_WEBHOOK_URL"):
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setenv("WARDEN_PAGERDUTY_ROUTING_KEY", KEY)
    assert [s.name for s in chatops.resolve_sinks()] == ["pagerduty"]
    assert "WARDEN_PAGERDUTY_ROUTING_KEY" in settings.SECRETS
    assert settings.loadable_for("worker") >= {"WARDEN_PAGERDUTY_ROUTING_KEY"}
    assert "WARDEN_PAGERDUTY_ROUTING_KEY" not in settings.loadable_for("mcp")


def test_a_verified_fix_resolves_the_page_on_the_record(posted, monkeypatch, tmp_path):
    from test_remediation_workflow import _approve_with, _run
    from test_remediation_workflow import owner as owner_fixture
    from test_remediation_workflow import world as world_fixture

    monkeypatch.setenv("WARDEN_PAGERDUTY_ROUTING_KEY", KEY)
    monkeypatch.setenv("WARDEN_CHATOPS_LIVE", "1")
    key = owner_fixture.__wrapped__()
    world = world_fixture.__wrapped__(tmp_path, key)
    out = _run(world, _approve_with(key))
    assert out.status == "recovered"
    resolves = [p for _, p in posted if p["event_action"] == "resolve"]
    assert resolves == [{"routing_key": KEY, "event_action": "resolve", "dedup_key": "inc-42"}]
    rows = [e["body"] for e in world["log"].entries("inc-42", kinds=("page.resolved",))]
    assert rows and rows[0]["delivered"] is True


def test_a_fix_that_did_not_recover_resolves_nothing(posted, monkeypatch, tmp_path):
    from test_remediation_workflow import FakePlatform, _approve_with, _run
    from test_remediation_workflow import owner as owner_fixture
    from test_remediation_workflow import world as world_fixture

    monkeypatch.setenv("WARDEN_PAGERDUTY_ROUTING_KEY", KEY)
    monkeypatch.setenv("WARDEN_CHATOPS_LIVE", "1")
    key = owner_fixture.__wrapped__()
    world = world_fixture.__wrapped__(tmp_path, key)
    world["platform"] = FakePlatform(healthy_after=None)
    assert _run(world, _approve_with(key)).status == "rolled_back"
    assert not [p for _, p in posted if p["event_action"] == "resolve"]
    assert world["log"].entries("inc-42", kinds=("page.resolved",)) == []
