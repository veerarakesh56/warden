"""The alert webhook's front door (registers S5 and N10): who may send an alert, how much, and is it real.

Prometheus Alertmanager is the sender. It does not sign its webhooks; what it can do is send an `Authorization`
header (`http_config.authorization`, Alertmanager 0.22+; read 2026-10-03). So:

- **Who.** The header must carry one of the configured bearer secrets (Secrets Manager; two during a rotation,
  register S4), compared in constant time. A wrong or missing one gets a bare 401: nothing about why.
- **How much (N10).** A body over 256 KiB, or more than 50 alerts in one delivery, is refused before it is parsed.
  Throttling per caller is API Gateway's (G6); the open-incident cap and the flap rule are intake's.
- **Is it real (S5).** A forged alert that passes the secret still names an alert Alertmanager never fired. Before
  intake acts on a firing alert, `confirm_firing` asks Alertmanager itself whether an alert with that fingerprint is
  active; an alert it does not know is dropped and counted.

The payload becomes intake's AlarmEvents: one per alert, its fingerprint the alert id (the group key would merge
alerts that are different incidents), `firing` as ALARM and `resolved` as OK.
"""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from pydantic import ValidationError

from . import web
from .intake import AlarmEvent
from .models import Alert, Severity

MAX_BODY = 256 * 1024
MAX_ALERTS = 50
_SEVERITY = {"critical": Severity.critical, "page": Severity.critical, "error": Severity.high, "high": Severity.high,
             "warning": Severity.medium, "medium": Severity.medium, "info": Severity.low, "low": Severity.low}


@dataclass
class Received:
    status: int
    events: list[AlarmEvent] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)  # alerts dropped, and why (never the request's secrets)


def authorized(header: str | None, secrets: list[str]) -> bool:
    """The Authorization header names one of the current secrets. Every secret is compared, in constant time."""
    if not header or not header.startswith("Bearer "):
        return False
    given = header[len("Bearer "):].encode()
    results = [hmac.compare_digest(given, s.encode()) for s in secrets if s]
    return any(results)


# Alertmanager writes nanoseconds (`09:00:00.123456789Z`); an Alert holds at most microseconds.
_FRACTION = re.compile(r"(\.\d{6})\d+")


def _event(alert: dict, environment: str) -> AlarmEvent:
    labels = {str(k): str(v) for k, v in (alert.get("labels") or {}).items()}
    firing = alert.get("status") == "firing"
    started = _FRACTION.sub(r"\1", str(alert.get("startsAt") or ""))
    when = started if firing else _FRACTION.sub(r"\1", str(alert.get("endsAt") or started))
    return AlarmEvent(
        source="alarm", rule=labels.get("alertname", "unnamed"), state="ALARM" if firing else "OK",
        transitioned_at=datetime.fromisoformat(when),
        alert=Alert(alert_id=str(alert.get("fingerprint", "")), name=labels.get("alertname", "unnamed"),
                    severity=_SEVERITY.get(labels.get("severity", "").lower(), Severity.high),
                    service=labels.get("service") or labels.get("job") or "unknown",
                    environment=labels.get("environment") or environment,
                    summary=str((alert.get("annotations") or {}).get("summary", ""))[:4000],
                    # Where the alert came from, set last: a sender's own `via` label never says it.
                    started_at=started, labels={**labels, "via": "alertmanager"}))


def receive(headers: dict[str, str], body: bytes, *, secrets: list[str], environment: str) -> Received:
    """One Alertmanager delivery: refused whole (401, 413, 400, 422), or turned into events with each alert that
    could not be read listed in `refused`."""
    auth = next((v for k, v in headers.items() if k.lower() == "authorization"), None)
    if not authorized(auth, secrets):
        return Received(401)
    if len(body) > MAX_BODY:
        return Received(413)
    try:
        payload = json.loads(body)
        alerts = payload["alerts"]
        if not isinstance(alerts, list):
            raise TypeError("alerts is not a list")
    except (ValueError, KeyError, TypeError):
        return Received(400)
    if len(alerts) > MAX_ALERTS:
        return Received(422)
    out = Received(202)
    for alert in alerts:
        try:
            out.events.append(_event(alert, environment))
        except (ValidationError, ValueError, TypeError, AttributeError) as exc:
            out.refused.append(f"alert {str(alert.get('fingerprint', '?'))[:32] if isinstance(alert, dict) else '?'}: "
                               f"{type(exc).__name__}")
    return out


def confirm_firing(events: list[AlarmEvent], active: Callable[[], set[str]]) -> tuple[list[AlarmEvent], list[str]]:
    """Keep each ALARM event whose fingerprint Alertmanager itself lists as active (`active` asks its API,
    /api/v2/alerts?active=true); drop the rest, saying so. OK events pass: a resolved alert starts nothing."""
    live = active()
    kept, dropped = [], []
    for ev in events:
        if ev.state == "ALARM" and ev.alert.alert_id not in live:
            dropped.append(f"alert {ev.alert.alert_id}: Alertmanager has no such active alert - not acted on")
        else:
            kept.append(ev)
    return kept, dropped


def alertmanager_active(base_url: str, *, timeout: float = 5.0) -> Callable[[], set[str]]:
    """`active` for confirm_firing: the fingerprints of Alertmanager's active, unsilenced, uninhibited alerts, read
    from its API v2. https only (or loopback), bounded by a timeout; an unreadable answer is an empty set, so nothing
    is confirmed - a failure to check never counts as a check."""
    if not web.allowed(base_url, loopback_http=True):
        raise ValueError("the Alertmanager URL must be https")
    url = base_url.rstrip("/") + "/api/v2/alerts?active=true&silenced=false&inhibited=false"

    def active() -> set[str]:
        try:
            with web.urlopen_loopback(url, timeout=timeout) as resp:
                return {str(a.get("fingerprint")) for a in json.loads(resp.read()) if isinstance(a, dict)}
        except (OSError, ValueError):
            return set()

    return active


# ------------------------------------------------------------------ Datadog monitors (register G10-53)
# Owner, 2026-10-14: alerts from Datadog "for warden to see and immediately work on them". A Datadog webhook carries
# WARDEN's own payload template (DATADOG_PAYLOAD, read 2026-10-14 from docs.datadoghq.com/integrations/webhooks) and a
# bearer secret in a custom header - the same who / how much / is it real as Alertmanager's: the secret compared in
# constant time, the same size limits, and before intake acts the monitor is asked of Datadog itself.
DATADOG_PAYLOAD = {"event": "$ID", "monitor": "$ALERT_ID", "transition": "$ALERT_TRANSITION", "title": "$EVENT_TITLE",
                   "date": "$DATE", "tags": "$TAGS", "scope": "$ALERT_SCOPE", "priority": "$ALERT_PRIORITY",
                   "cycle": "$ALERT_CYCLE_KEY"}
_DD_STATE = {"Triggered": "ALARM", "Re-Triggered": "ALARM", "Renotify": "ALARM", "No Data": "ALARM",
             "Re-No Data": "ALARM", "Recovered": "OK"}
_DD_PRIORITY = {"P1": Severity.critical, "P2": Severity.high, "P3": Severity.medium, "P4": Severity.low,
                "P5": Severity.low}
# A Datadog tag WARDEN reads, as the label the rest of WARDEN knows it by.
_DD_LABELS = {"service": "service", "env": "environment", "kube_deployment": "deployment",
              "kube_namespace": "namespace", "kube_cluster_name": "eks_cluster", "functionname": "lambda",
              "dbinstanceidentifier": "aurora_instance"}


def _dd_event(alert: dict, environment: str) -> AlarmEvent | None:
    """One delivery as intake's event, or None for a transition that starts nothing (a warning)."""
    state = _DD_STATE.get(str(alert.get("transition") or ""))
    if state is None:
        return None
    monitor = str(alert.get("monitor") or "")
    if not re.fullmatch(r"\d{1,20}", monitor):
        raise ValueError("no monitor id")
    tags = _dd_tags(alert)
    when = datetime.fromtimestamp(int(str(alert.get("date") or "0")) / 1000, UTC)
    title = re.sub(r"^\[[^\]]*\]\s*", "", str(alert.get("title") or "datadog monitor")).strip()[:200]
    labels = {**tags, "datadog_monitor": monitor, "alarm": f"datadog-{monitor}", "via": "datadog"}
    return AlarmEvent(source="alarm", rule=f"datadog-{monitor}", state=state, transitioned_at=when,
                      alert=Alert(alert_id=f"datadog-{monitor}", name=title or "datadog monitor",
                                  severity=_DD_PRIORITY.get(str(alert.get("priority") or ""), Severity.high),
                                  service=tags.get("service") or "unknown",
                                  environment=tags.get("environment") or environment,
                                  summary=title, started_at=when.isoformat(), labels=labels))


def _dd_tags(alert: dict) -> dict[str, str]:
    """The monitor's scope and tags WARDEN reads, as labels: the first value of each wins."""
    tags = {}
    for tag in re.split(r"[,\s]+", f"{alert.get('scope') or ''},{alert.get('tags') or ''}"):
        key, _, value = tag.partition(":")
        if key in _DD_LABELS and value and _DD_LABELS[key] not in tags:
            tags[_DD_LABELS[key]] = value[:200]
    return tags


def receive_datadog(headers: dict[str, str], body: bytes, *, secrets: list[str], environment: str) -> Received:
    """One Datadog webhook delivery: refused whole (401, 413, 400), or one event (or none, for a warning)."""
    auth = next((v for k, v in headers.items() if k.lower() == "authorization"), None)
    if not authorized(auth, secrets):
        return Received(401)
    if len(body) > MAX_BODY:
        return Received(413)
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise TypeError("not an object")
    except (ValueError, TypeError):
        return Received(400)
    out = Received(202)
    try:
        ev = _dd_event(payload, environment)
        if ev is not None:
            out.events.append(ev)
    except (ValidationError, ValueError, TypeError, OverflowError) as exc:
        out.refused.append(f"datadog monitor {str(payload.get('monitor', '?'))[:24]}: {type(exc).__name__}")
    return out


def datadog_alerting(site: str, api_key: str, app_key: str, *, timeout: float = 5.0,
                     get: Callable[[str, dict], dict] | None = None) -> Callable[[str], bool]:
    """Is a monitor alerting now? Asked of Datadog's own API (GET /api/v1/monitor/<id>, the read key's monitors_read)
    before intake acts - a forged delivery that passes the secret still names a monitor Datadog is not alerting on.
    A site that is not Datadog's, or an answer that cannot be read, confirms nothing."""
    import urllib.request

    from .datadog import SITES

    def fetch(url: str, hdrs: dict) -> dict:
        req = urllib.request.Request(url, headers=hdrs)
        with web.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"{}")

    fetch = get or fetch

    def alerting(monitor: str) -> bool:
        if site not in SITES or not re.fullmatch(r"\d{1,20}", monitor) or not (api_key and app_key):
            return False
        try:
            got = fetch(f"https://api.{site}/api/v1/monitor/{monitor}",
                        {"DD-API-KEY": api_key, "DD-APPLICATION-KEY": app_key, "Accept": "application/json"})
        except (OSError, ValueError):
            return False
        return str(got.get("overall_state")) in ("Alert", "No Data")

    return alerting


def confirm_datadog(events: list[AlarmEvent], alerting: Callable[[str], bool]) -> tuple[list[AlarmEvent], list[str]]:
    """Keep each ALARM whose monitor Datadog says is alerting; OK events pass (a recovery starts nothing)."""
    kept, dropped = [], []
    for ev in events:
        monitor = ev.alert.labels.get("datadog_monitor", "")
        if ev.state == "ALARM" and not alerting(monitor):
            dropped.append(f"datadog monitor {monitor}: Datadog does not say it is alerting - not acted on")
        else:
            kept.append(ev)
    return kept, dropped
