"""One fault, one incident (fs-22, 2026-10-15: a broken config became three incidents - two Datadog monitors and a
CloudWatch alarm on the same workload). An alarm naming a resource an incident opened in the last GROUP_WINDOW also
names, in the same environment, joins that incident; its record says which alert said the same, and from where."""

from __future__ import annotations

from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import audit, intake, records, resolver
from warden.models import Alert, Severity


def _ev(rule, labels, env="dev", service="catalog-api", source="alarm"):
    return intake.AlarmEvent(source=source, rule=rule, state="ALARM", transitioned_at=datetime(2026, 10, 15, 5, 29, tzinfo=UTC),
                             alert=Alert(alert_id="x", name=rule, severity=Severity.high, service=service,
                                         environment=env, summary="", started_at="2026-10-15T05:29:00+00:00",
                                         labels=labels))


OPEN = {"inc-aaaa-20261015T052925Z": ("dev", {"catalog-api"})}


def _decide(ev, related=OPEN):
    return intake.decide(ev, recent=[], open_incidents={}, verifying={}, open_count=1, related=related)


def test_an_alarm_on_the_same_resource_joins_the_open_incident():
    d = _decide(_ev("warden-dev-catalog-errors", {"deployment": "catalog-api", "via": "cloudwatch"}))
    assert (d.action, d.workflow_id, d.grouped) == ("signal_incident", "inc-aaaa-20261015T052925Z", True)
    assert "catalog-api" in d.reason


def test_another_resource_another_environment_or_a_person_asking_starts_its_own():
    assert _decide(_ev("orders", {"deployment": "orders-api"}, service="orders-api")).action == "start"
    assert _decide(_ev("x", {"deployment": "catalog-api"}, env="staging")).action == "start"
    assert _decide(_ev("x", {"deployment": "catalog-api"}, source="mcp")).action == "start"
    assert _decide(_ev("x", {"deployment": "catalog-api"}), related={}).action == "start"


def test_where_an_alert_came_from_is_never_a_resource():
    a = _ev("r", {"via": "datadog", "datadog_monitor": "123", "alarm": "datadog-123"}, service="s").alert
    assert resolver.named_resources(a) == {"s"}


def test_the_record_says_which_alert_joined_and_from_where(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=Ed25519PrivateKey.generate())
    inc = "aaaa-20261015T052925Z"
    log.append(inc, "incident.ingest", {"node": "ingest", "alert_id": inc, "env": "dev"})
    log.append(inc, "intake.grouped", {"rule": "datadog-9", "name": "warden dev: unavailable replicas",
                                       "via": "datadog", "at": "2026-10-15T05:29:26+00:00"})
    r = records.record(log, inc)
    assert r.also == ["warden dev: unavailable replicas (Datadog monitor)"]
    page = records.incident_page(r)
    assert "Also fired" in page and "Another alert on the same resource joined this incident" in page
