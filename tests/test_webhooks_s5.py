"""Registers S5 and N10: the alert webhook. Only a caller holding the secret gets in, a flood is refused before it is
parsed, and a firing alert is acted on only when Alertmanager itself lists it as active."""

from __future__ import annotations

import json

import pytest

from warden import intake, webhooks

SECRET = "s" * 8 + "-current"
OLD = "s" * 8 + "-previous"
AUTH = {"Authorization": f"Bearer {SECRET}"}


def _alert(fp="a1b2c3d4", status="firing", **labels):
    return {"status": status, "fingerprint": fp,
            "labels": {"alertname": "HighErrorRate", "service": "checkout", "severity": "critical", **labels},
            "annotations": {"summary": "5xx above 5% for 10m"},
            "startsAt": "2026-10-03T09:00:00.123456789Z", "endsAt": "2026-10-03T09:30:00Z"}


def _body(*alerts):
    return json.dumps({"version": "4", "groupKey": "{}:{alertname=\"HighErrorRate\"}", "status": "firing",
                       "alerts": list(alerts)}).encode()


def test_only_a_caller_with_the_secret_gets_in_and_learns_nothing_else():
    for headers in ({}, {"Authorization": "Bearer nope"}, {"Authorization": SECRET}, {"authorization": "Basic x"}):
        r = webhooks.receive(headers, _body(_alert()), secrets=[SECRET], environment="dev")
        assert r.status == 401 and r.events == [] and r.refused == []
    assert webhooks.receive(AUTH, _body(_alert()), secrets=[SECRET], environment="dev").status == 202
    # During a rotation both the new and the old secret work; an empty secret never matches.
    old = {"Authorization": f"Bearer {OLD}"}
    assert webhooks.receive(old, _body(_alert()), secrets=[SECRET, OLD], environment="dev").status == 202
    assert not webhooks.authorized("Bearer ", ["", ""])


def test_a_flood_is_refused_before_it_is_read():
    big = b"{" + b" " * (webhooks.MAX_BODY + 1) + b"}"
    assert webhooks.receive(AUTH, big, secrets=[SECRET], environment="dev").status == 413
    many = _body(*[_alert(fp=f"{i:08x}") for i in range(webhooks.MAX_ALERTS + 1)])
    assert webhooks.receive(AUTH, many, secrets=[SECRET], environment="dev").status == 422
    assert webhooks.receive(AUTH, b"not json", secrets=[SECRET], environment="dev").status == 400


def test_each_alert_becomes_one_event_and_an_unreadable_one_is_refused_alone():
    r = webhooks.receive(AUTH, _body(_alert(), _alert(fp="e5f6", status="resolved"),
                                     _alert(fp="bad", environment="prod; rm -rf")), secrets=[SECRET],
                         environment="dev")
    assert r.status == 202 and [e.state for e in r.events] == ["ALARM", "OK"]
    first = r.events[0]
    assert first.alert.alert_id == "a1b2c3d4" and first.rule == "HighErrorRate" and first.alert.environment == "dev"
    assert first.transitioned_at.isoformat().startswith("2026-10-03T09:00:00")
    assert len(r.refused) == 1 and r.refused[0].startswith("alert bad")


def test_a_forged_alert_alertmanager_never_fired_is_not_acted_on():
    events = webhooks.receive(AUTH, _body(_alert(), _alert(fp="f0r63d")), secrets=[SECRET], environment="dev").events
    kept, dropped = webhooks.confirm_firing(events, active=lambda: {"a1b2c3d4"})
    assert [e.alert.alert_id for e in kept] == ["a1b2c3d4"] and "f0r63d" in dropped[0]
    nothing, _ = webhooks.confirm_firing(events, active=set)  # Alertmanager unreadable: nothing is confirmed
    assert nothing == []
    decision = intake.decide(kept[0], recent=[], open_incidents={}, verifying={}, open_count=0)
    assert decision.action == "start"


def test_the_alertmanager_check_is_https_and_fails_to_nothing(monkeypatch):
    with pytest.raises(ValueError):
        webhooks.alertmanager_active("http://alertmanager.example.test")
    active = webhooks.alertmanager_active("https://alertmanager.example.test")

    def down(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", down)
    assert active() == set()
