"""The AWS platform hands each health check exactly what it reads: the target's name, the plan's parameters, or
both (platforms/aws.py _health_check). A check that reads the name must be asked about that name - never about the
parameters - and a check that reads the parameters is handed them whole."""

from __future__ import annotations

from datetime import UTC, datetime

from warden.platforms.aws import AwsPlatform

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


class _Reader:
    """Read clients that record what each health check asked about."""

    def __init__(self) -> None:
        self.asked: list[object] = []

    def get_event_source_mapping(self, UUID):
        self.asked.append(UUID)
        return {"State": "Enabled"}

    def describe_rule(self, Name, EventBusName="default"):
        self.asked.append((EventBusName, Name))
        return {"State": "DISABLED"}

    def describe_key(self, KeyId):
        self.asked.append(KeyId)
        return {"KeyMetadata": {"KeyState": "Disabled"}}


def _platform(reader: _Reader) -> AwsPlatform:
    return AwsPlatform(reader=lambda service: reader, actor=lambda *a: None, clock=lambda: NOW, sleep=lambda s: None)


def test_a_mapping_is_judged_by_the_mapping_named_not_by_the_plans_parameters():
    r = _Reader()
    assert _platform(r).healthy("u-1", entry="lambda_enable_esm", params={"mapping": "u-2"}) is True
    assert r.asked == ["u-1"]


def test_a_paused_rule_is_read_on_its_own_bus_by_the_name_given():
    r = _Reader()
    assert _platform(r).healthy("orders-bus/reconcile", entry="events_disable_rule", params={"rule": "x"}) is True
    assert r.asked == [("orders-bus", "reconcile")]


def test_a_kept_key_is_read_by_the_key_named():
    r = _Reader()
    assert _platform(r).healthy("k-1", entry="kms_cancel_key_deletion", params={"key": "k-2"}) is True
    assert r.asked == ["k-1"]


def test_an_entry_with_no_health_check_is_never_healthy():
    r = _Reader()
    assert _platform(r).healthy("u-1", entry="not_an_entry", params={}) is False
    assert r.asked == []
