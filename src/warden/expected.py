"""Expected to be down: an alarm on something a person declared off, or not in use, is not an incident.

Owner, 2026-10-12: non-production environments are shut down at night for cost - "that is expected state, not an
incident" - and "not only night shutdown, even sometimes on holidays and weekends and some other times when not
needed, and maybe even complete or temporary not using those environments or AWS services or application services".

A declaration says WHAT (environments, services, resources - every one given must match the alarm) and WHEN (every
one given must hold; none given means always):

    - name: dev nights
      environments: [dev]
      zone: Asia/Kolkata
      hours: "20:00-08:00"          # wall-clock, may cross midnight
    - name: dev weekends
      environments: [dev]
      zone: Asia/Kolkata
      days: [sat, sun]
    - name: Diwali
      environments: [dev]
      zone: Asia/Kolkata
      dates: ["2026-11-08", "2026-11-09"]
    - name: reports service parked
      services: [reports]
      zone: Asia/Kolkata
      until: "2026-11-01T09:00"     # `from` and `until` bound it; neither means until the declaration is removed
    - name: old search cluster, not in use
      resources: [search-v1]

Read from WARDEN_EXPECTED_DOWN (the runtime loads it from Parameter Store). The opposite of a change freeze: a
declaration that cannot be read covers NOTHING, so a typing mistake brings the alarms back and never hides one.
While an alarm is covered no incident starts; when the cover ends, the alarm is looked at again and, still firing,
becomes an incident then (intake.py). Declared by a person: WARDEN infers no schedule.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import yaml

from .models import Alert

_log = logging.getLogger("warden.expected")
_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_KEYS = {"name", "environments", "services", "resources", "zone", "hours", "days", "dates", "from", "until"}
HORIZON = timedelta(days=14)  # how far ahead the end of a cover is walked to, minute by minute


def _minutes(text: str) -> int:
    hours, minutes = text.strip().split(":")
    if not (0 <= int(hours) < 24 and 0 <= int(minutes) < 60):
        raise ValueError(text)
    return int(hours) * 60 + int(minutes)


def _entry(raw: Any) -> dict[str, Any]:
    """One declaration, checked: ValueError (or a KeyError, a TypeError) for anything it does not say clearly."""
    if not isinstance(raw, dict) or set(raw) - _KEYS:
        raise ValueError("unknown keys")
    scope = {k: {str(v) for v in raw[k]} for k in ("environments", "services", "resources") if raw.get(k)}
    if not scope or any(isinstance(raw[k], str) for k in scope):
        raise ValueError("names no environment, service or resource")
    zone = ZoneInfo(str(raw.get("zone") or "UTC"))
    entry: dict[str, Any] = {"name": str(raw.get("name") or "unnamed"), "scope": scope, "zone": zone}
    if "hours" in raw:
        start, end = (_minutes(part) for part in str(raw["hours"]).split("-"))
        if start == end:
            raise ValueError("hours")
        entry["hours"] = (start, end)
    if "days" in raw:
        entry["days"] = {_DAYS.index(str(d).lower()[:3]) for d in raw["days"]}
    if "dates" in raw:
        entry["dates"] = {datetime.fromisoformat(str(d)).date() for d in raw["dates"]}
    for edge in ("from", "until"):
        if edge in raw:
            entry[edge] = datetime.fromisoformat(str(raw[edge])).replace(tzinfo=zone)
    # Never "down forever" for a production environment (owner, 2026-10-14: complete the proposed guard): a
    # declaration with no hours, days, dates or end may name only environments of the nonprod tier - an unknown
    # environment counts as production. A named service or resource "not in use" may still be declared so.
    if not any(k in raw for k in ("hours", "days", "dates", "until")) and "environments" in scope:
        from .environments import default_environment_policies

        policies = default_environment_policies()
        if any(policies.for_env(e).tier != "nonprod" for e in scope["environments"]):
            raise ValueError("an endless declaration may not cover a production environment")
    return entry


def declarations(text: str | None = None) -> list[dict[str, Any]]:
    """The declarations that can be read. One that cannot is left out and said in the log - it covers nothing."""
    text = os.environ.get("WARDEN_EXPECTED_DOWN", "") if text is None else text
    try:
        raw = yaml.safe_load(text) if text.strip() else []
    except yaml.YAMLError as exc:
        _log.warning("the expected-down declarations cannot be read (%s): none applies", type(exc).__name__)
        return []
    if not isinstance(raw, list):
        _log.warning("the expected-down declarations are not a list: none applies")
        return []
    read = []
    for number, one in enumerate(raw, 1):
        try:
            read.append(_entry(one))
        except Exception as exc:  # noqa: BLE001 - whatever is wrong with it, it covers nothing
            _log.warning("expected-down declaration %d cannot be read (%s): it does not apply", number, type(exc).__name__)
    return read


def _names(entry: dict[str, Any], alert: Alert) -> bool:
    scope = entry["scope"]
    values = {v.strip() for value in alert.labels.values() for v in str(value).split(",")}
    return (alert.environment in scope.get("environments", {alert.environment})
            and alert.service in scope.get("services", {alert.service})
            and ("resources" not in scope or bool(scope["resources"] & values)))


def _holds(entry: dict[str, Any], at: datetime) -> bool:
    local = at.astimezone(entry["zone"])
    if "from" in entry and local < entry["from"] or "until" in entry and local >= entry["until"]:
        return False
    if "days" in entry and local.weekday() not in entry["days"]:
        return False
    if "dates" in entry and local.date() not in entry["dates"]:
        return False
    if "hours" in entry:
        start, end = entry["hours"]
        minute = local.hour * 60 + local.minute
        return start <= minute < end if start < end else minute >= start or minute < end
    return True


def covering(alert: Alert, at: datetime, text: str | None = None) -> tuple[str, datetime | None] | None:
    """(the declaration's name, when the cover ends) if this alarm is expected at `at` (aware) - the end is None
    when nothing ends it. None: not expected. Covers that follow one another (a night, then a weekend) end where
    the last one does."""
    mine = [e for e in declarations(text) if _names(e, alert)]
    first = next((e for e in mine if _holds(e, at)), None)
    if first is None:
        return None
    # ponytail: a minute-by-minute walk (20,160 steps at most); edge arithmetic if declarations grow to hundreds
    end = at.replace(second=0, microsecond=0)
    for _ in range(int(HORIZON.total_seconds() // 60)):
        end += timedelta(minutes=1)
        if not any(_holds(e, end) for e in mine):
            return first["name"], end
    # Covered for the whole HORIZON: it ends where the declarations still holding do - if every one of them does.
    still = [e for e in mine if _holds(e, end)]
    ends = [e["until"].astimezone(UTC) for e in still if "until" in e]
    return first["name"], max(ends) if ends and len(ends) == len(still) else None
