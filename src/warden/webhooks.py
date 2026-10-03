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
from datetime import datetime

from pydantic import ValidationError

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
                    started_at=started, labels=labels))


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
    import urllib.parse
    import urllib.request

    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme != "https" and parts.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("the Alertmanager URL must be https")
    url = base_url.rstrip("/") + "/api/v2/alerts?active=true&silenced=false&inhibited=false"

    def active() -> set[str]:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # nosec B310 - https checked above
                return {str(a.get("fingerprint")) for a in json.loads(resp.read()) if isinstance(a, dict)}
        except (OSError, ValueError):
            return set()

    return active
