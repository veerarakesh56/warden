"""Post-deploy watch (owner item U3-4): an alarm that fires on a service inside a set window after a deploy of it is
reported as any alarm is - its own incident, its own record, its own Slack message - with that deploy named under the
title as a SUSPECT, never the cause.

How it watches. The window is measured from the deploy: an alarm at T is inside the watch of a deploy at D when
D <= T <= D + WATCH. That is the same as looking back WATCH from the alarm, so WARDEN keeps no watch state and opens
no new read: the deploys are the ones its readers already put in the incident's evidence (an ECS service's new task
definition, a Lambda alias's new version, an EKS Deployment's new pod template - an Argo CD sync that changes one is
one - and the AppConfig deployment of a configuration whose monitors name the alarm). A deploy that breaks a service
is seen when something about that service fires: an alarm, a Datadog monitor, an ECS service's own WARN or ERROR event.
A breakage nothing fires on is not seen - as before.

What it never does. It decides nothing: intake starts the incident as it always does, the diagnosis names the cause
or not from the evidence, the policies and the verifier judge any fix, and nothing is rolled back for the timing
alone. Only the incident's message and record read it (activities.notify): no prompt, no policy, no plan.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from .environments import both_times

DEFAULT_MINUTES = 60
MIN_MINUTES, MAX_MINUTES = 5, 6 * 60  # never longer than the deploy reads look back (RECENT_DEPLOY_WINDOW, 6 h)
MOST = 3  # deploys named under the title; the evidence lists every one
# The kinds WARDEN's readers give a deploy (aws_stack, aws_backend: `config` is an ECS revision whose settings changed).
KINDS = ("ecs", "lambda", "k8s", "appconfig", "config")
KIND = "incident.after_deploy"  # the record's row: what the message says, as data

# What WARDEN's readers record for the AppConfig deployment of a configuration the alarm guards
# (aws_stack._read_appconfig). `completed=not yet`: still deploying when it was read.
_APPCONFIG = re.compile(r"^CONFIG appconfig (?P<name>[^ ]{1,260}) monitors this alarm: deployment=(?P<number>\d{1,9}) "
                        r"state=(?P<state>[A-Z_]{1,40}) version=(?P<version>[^ ]{1,64}) "
                        r"completed=(?P<completed>not yet|[0-9TZ:.+-]{10,40})", re.ASCII)


def watch(raw: str | None = None) -> timedelta:
    """The watch after a deploy: WARDEN_DEPLOY_WATCH_MIN minutes, bounded to MIN_MINUTES..MAX_MINUTES; a value that is
    not a whole number is the default (a typo never turns the watch off or makes it unbounded)."""
    text = os.environ.get("WARDEN_DEPLOY_WATCH_MIN", "") if raw is None else raw
    try:
        minutes = int(text.strip())
    except ValueError:
        minutes = DEFAULT_MINUTES
    return timedelta(minutes=min(max(minutes, MIN_MINUTES), MAX_MINUTES))


def _when(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        at = value
    else:
        try:
            at = datetime.fromisoformat(str(value).strip())
        except ValueError:
            return None
    return at if at.tzinfo else at.replace(tzinfo=UTC)


def _kind(d: dict[str, Any]) -> str:
    """The deploy's kind as WARDEN's readers name it; anything else is a `deploy` (the text is never shown raw)."""
    kind = str(d.get("kind") or "")
    return kind if kind in KINDS else "deploy"


def _version(d: dict[str, Any]) -> str:
    """What was deployed, by its version - never an image's address, which names the registry's account."""
    for key in ("version", "revision", "sha"):
        if str(d.get(key) or "").strip():
            return str(d[key]).strip()
    return ""


def _appconfig(context: Any, started: datetime) -> list[dict[str, Any]]:
    """The AppConfig deployments WARDEN's own reader recorded, as deploys - only its trusted configuration lines (an
    evidence C item: a line at its start, never inside an application's log text, and no steering words), so a log
    line that copies the shape names no deploy (CodeRabbit, PR 146). One still deploying when it was read is placed at
    the alarm itself: it was going on then."""
    from .evidence import index

    out = []
    for item in index(context).values():
        m = _APPCONFIG.match(item.text) if item.id.startswith("C") else None
        if not m:
            continue
        at = started if m["completed"] == "not yet" else _when(m["completed"])
        if at is not None:
            out.append({"kind": "appconfig", "service": m["name"], "version": m["version"], "at": at,
                        "deploying": m["completed"] == "not yet"})
    return out


def suspects(alert: Any, context: Any, *, window: timedelta | None = None) -> list[dict[str, Any]]:
    """The deploys whose watch this alarm fired in, newest first, at most MOST: each with its kind, service, version,
    when, and how many minutes before the alarm. Nothing when the alarm's start is unknown - it cannot be placed."""
    started = _when(getattr(alert, "started_at", "") or "")
    if started is None:
        return []
    span = window or watch()
    found = []
    deploys = [d for d in getattr(context, "recent_deploys", None) or [] if isinstance(d, dict)]
    rows = [{**d, "at": _when(d.get("at"))} for d in deploys if d.get("kind") != "secret"]  # a rotation is no deploy
    for d in rows + _appconfig(context, started):
        at = d["at"]
        if at is None or not at <= started <= at + span:
            continue
        found.append({"kind": _kind(d), "service": str(d.get("service") or alert.service),
                      "version": _version(d), "at": at, "minutes": int((started - at).total_seconds() // 60),
                      "deploying": bool(d.get("deploying"))})
    found.sort(key=lambda d: d["at"], reverse=True)
    return found[:MOST]


def banner(found: list[dict[str, Any]], window: timedelta) -> str:
    """The line under the report's title: which deploy this alarm fired after, inside the watch - a suspect, and the
    diagnosis below decides. Empty when no deploy's watch covers the alarm."""
    if not found:
        return ""
    from .reporting import untrusted_inline

    def one(d: dict[str, Any]) -> str:
        what = untrusted_inline(d["service"], limit=120) + (
            f" version {untrusted_inline(d['version'], limit=64)}" if d["version"] else "")
        if d["deploying"]:
            return f"{what} ({d['kind']}), still deploying when WARDEN read it"
        return f"{what} ({d['kind']}), deployed {both_times(d['at'], seconds=False)}, {d['minutes']} min before it fired"

    minutes = int(window.total_seconds() // 60)
    return (f"**After a deploy:** this alarm fired inside WARDEN's {minutes}-min watch after a deploy: "
            + "; ".join(one(d) for d in found)
            + ". The deploy is a suspect, not the cause: the diagnosis below decides from the evidence, and nothing "
              "is rolled back for the timing alone.")


def record_row(found: list[dict[str, Any]], window: timedelta) -> dict[str, Any]:
    """The record's row (KIND): the watch and each deploy it named, as data."""
    return {"watch_minutes": int(window.total_seconds() // 60), "role": "suspect",
            "deploys": [{**d, "at": d["at"].isoformat()} for d in found]}


def mark(log: Any, alert_id: str, alert: Any, context: Any, markdown: str, *, run_id: str = "") -> str:
    """The report with the banner under its title, and the record's row - or the report as it was when no deploy's
    watch covers the alarm."""
    span = watch()
    found = suspects(alert, context, window=span)
    if not found:
        return markdown
    log.append(alert_id, KIND, {"run_id": run_id, **record_row(found, span)})
    title, _, rest = markdown.partition("\n")
    return f"{title}\n\n{banner(found, span)}\n{rest}"
