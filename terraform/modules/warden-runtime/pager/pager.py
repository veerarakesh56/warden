"""WARDEN's own pages, repeated until a person acknowledges them - with WARDEN itself down (owner, 2026-10-16).

CloudWatch sends an alarm's action once, on the change into ALARM, and never again while it stays there; AWS's own
paging service with acknowledgement (Incident Manager) takes no new customers since 2025-11-07. So this function,
on its own: no container image, no VPC, no Temporal, no audit database - only boto3 and the standard library, as
the Lambda runtime ships them - so a dead worker, a dead database or a broken image does not silence it.

- A self-alarm going into ALARM (EventBridge, paging.tf) opens a page: said in Slack now (the alarm's own action
  already emailed it).
- A worker task that stopped on its own (an exit, or a start that failed) opens one: Slack and email.
- Every few minutes (an EventBridge schedule) each open page not acknowledged is said again, Slack and email,
  once every REPEAT_MINUTES, with how long it has been open and why. A Temporal API key that expires within
  KEY_WARN_DAYS opens one too.

A page is `pages/<key>.json` in this runtime's anchors bucket, written only here. Its acknowledgement is
`acks/<key>.json`, written only by the approval page after an approver's passkey signed it (warden.paging): one
writer per object, so neither overwrites the other. An acknowledgement ends the page it names by its opening time;
the same alarm going into ALARM again later is a new page.

Email goes through the alarm REPEAT_ALARM, whose action is the page topic: set to ALARM with the page's words as
its reason, CloudWatch emails exactly that reason - no SNS permission outside what CloudWatch already holds.
"""

import datetime as _dt
import json
import logging
import os
import re
import urllib.request

import boto3

_KEY = re.compile(r"[A-Za-z0-9._-]{1,200}")
_ACCOUNT = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
_LOG = logging.getLogger("warden.pager")
_LOG.setLevel(logging.INFO)
_SLACK = "https://hooks." + "slack.com/"  # the only place a page is posted; built from parts, as every such literal
_REASON_MAX = 1023  # CloudWatch's limit on an alarm state's reason
_SLACK_MAX = 3500
# How a worker task ends when nobody asked it to: the container exited, or the task never started. A deploy's or a
# pause's stop is ServiceSchedulerInitiated, and pages nobody.
STOPPED_ON_ITS_OWN = ("EssentialContainerExited", "TaskFailedToStart")


def _now():
    return _dt.datetime.now(_dt.UTC)


def _iso(t):
    return t.isoformat(timespec="seconds")


def _when(value):
    """A page's own time, or None when it cannot be read: a page is never silenced for a bad field."""
    try:
        t = _dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=_dt.UTC)


class Pages:
    """The anchors bucket's pages: `pages/` written here, `acks/` written by the approval page."""

    def __init__(self, bucket, s3=None):
        self.bucket, self.s3 = bucket, s3 or boto3.client("s3")

    def _get(self, key):
        try:
            return json.loads(self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read())
        except self.s3.exceptions.NoSuchKey:
            return None

    def page(self, key):
        return self._get(f"pages/{key}.json")

    def acked(self, page):
        ack = self._get(f"acks/{page['key']}.json")
        return bool(ack) and ack.get("opened_at") == page.get("opened_at")

    def put(self, page):
        # The anchors bucket is under Object Lock, which refuses a write without a checksum.
        self.s3.put_object(Bucket=self.bucket, Key=f"pages/{page['key']}.json", Body=json.dumps(page).encode(),
                           ContentType="application/json", ChecksumAlgorithm="SHA256")

    def keys(self):
        out = []
        for got in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix="pages/"):
            out += [o["Key"][len("pages/"):-len(".json")] for o in got.get("Contents", []) if o["Key"].endswith(".json")]
        return out


class Pager:
    def __init__(self, pages, *, env, repeat_minutes, ack_url, slack, email, alarm_states=None, clock=_now):
        self.pages, self.env, self.repeat = pages, env, _dt.timedelta(minutes=repeat_minutes)
        self.ack_url, self.slack, self.email, self.clock = ack_url, slack, email, clock
        self.alarm_states = alarm_states or (lambda names: {})

    def open(self, key, why, *, emailed=False, alarm="", about=""):
        """A page for `key`, unless one is open for it (acknowledged or not) - or, with `about`, one for the same
        condition was already acknowledged: a key that expires on the same date is one page, however often it is
        seen. Said at once: in Slack, and by email unless the alarm's own action already emailed it.

        Written first as not yet said (`sent` 0, no `last_sent`), then said, then marked said (CodeRabbit, PR 43): a
        page whose first saying failed on every channel is due at the next tick, and the event's retry says it again,
        instead of waiting a whole REPEAT_MINUTES as one already said."""
        if not _KEY.fullmatch(key):
            raise ValueError("a page's key is a plain name")
        old = self.pages.page(key)
        if old and self._acked(old) and about and old.get("about") == about:
            return None
        if old and not self._acked(old):
            if old.get("sent"):
                return None
            page = old  # written, never said: say it now
        else:
            now = self.clock()
            page = {"key": key, "why": str(why)[:600], "opened_at": _iso(now), "last_sent": "", "sent": 0,
                    "alarm": alarm, "about": about}
            self.pages.put(page)
        said = f"WARDEN {self.env} page: {key}: {str(page.get('why', ''))[:600]} {self._ack_line()}"
        failed = self._send(said, email=not emailed)
        if len(failed) < (2 if not emailed else 1):  # said on at least one channel
            page.update(last_sent=_iso(self.clock()), sent=1)
            self.pages.put(page)
        _raise_if(failed)
        return page

    def _acked(self, page):
        """An acknowledgement that cannot be read acknowledges nothing (CodeRabbit, PR 43): the page goes on."""
        try:
            return self.pages.acked(page)
        except Exception as exc:  # noqa: BLE001 - never silenced by an unreadable acknowledgement
            _LOG.warning("the acknowledgement of %s could not be read (%s): not acknowledged", page.get("key"),
                         type(exc).__name__)
            return False

    def _due(self, key, now):
        """The page for `key` when it is to be said again now; None otherwise. One that cannot be read is said
        again rather than silenced (CodeRabbit, PR 43): a page whose times are unreadable is due at every tick, and
        a key whose object is not a page is logged and skipped - the other pages still go."""
        try:
            page = self.pages.page(key)
        except Exception as exc:  # noqa: BLE001 - one broken object never stops the others
            _LOG.warning("page %s could not be read (%s): skipped", key, type(exc).__name__)
            return None
        if not isinstance(page, dict) or not _KEY.fullmatch(str(page.get("key", ""))):
            _LOG.warning("page %s is not a page: skipped", key)
            return None
        if self._acked(page):
            return None
        last = _when(page.get("last_sent"))
        # A minute's slack: the schedule's ticks drift by seconds, and a page a few seconds early waits a tick.
        return page if last is None or now - last >= self.repeat - _dt.timedelta(minutes=1) else None

    def _line(self, page, now, state):
        opened = _when(page.get("opened_at"))
        sent = page.get("sent") if isinstance(page.get("sent"), int) else 0
        how_long = f"open {int((now - opened).total_seconds() // 60)} min" if opened else "open since a time that cannot be read"
        now_is = {"ALARM": " Its alarm is still in ALARM.", "OK": " Its alarm is OK now; acknowledge to stop this."}
        page.update(last_sent=_iso(now), sent=sent + 1, opened_at=page.get("opened_at") if opened else _iso(now))
        return (f"{page['key']}: {how_long}, said {sent + 1} times - {str(page.get('why', ''))[:600]}"
                + now_is.get(state, ""))

    def tick(self):
        """Every open page not acknowledged, said again once each REPEAT_MINUTES: how long, and why. Said first, then
        marked said (CodeRabbit, PR 43): a repeat no channel took is not recorded as sent, and is due again at the
        next tick; one a channel took but that could not be marked is at worst said twice - the safe way for a pager."""
        now = self.clock()
        due = [p for p in (self._due(k, now) for k in sorted(self.pages.keys())) if p]
        if not due:
            return []
        try:
            states = self.alarm_states([p["alarm"] for p in due if p.get("alarm")])
        except Exception as exc:  # noqa: BLE001 - an alarm's state only decorates the repeat; it never stops it
            _LOG.warning("the alarms' states could not be read (%s): repeated without them", type(exc).__name__)
            states = {}
        lines = [self._line(page, now, states.get(page.get("alarm") or "")) for page in due]
        said = (f"WARDEN {self.env}: {len(due)} page{'s' if len(due) > 1 else ''} not acknowledged. "
                + " | ".join(lines) + " " + self._ack_line())
        failed = self._send(said, email=True)
        if len(failed) < 2:  # said on at least one channel
            for page in due:
                try:
                    self.pages.put(page)
                except Exception as exc:  # noqa: BLE001 - the others are still marked; this one is said again
                    _LOG.warning("page %s could not be marked as said (%s)", page["key"], type(exc).__name__)
        _raise_if(failed)
        return [p["key"] for p in due]

    def _ack_line(self):
        every = int(self.repeat.total_seconds() // 60)
        where = f"Acknowledge with your passkey at {self.ack_url}" if self.ack_url else \
            "Acknowledge on the approval page"
        return f"{where}; until then this repeats every {every} min."

    def _send(self, text, *, email):
        """Slack, then email: either failing still tries the other. The channels that failed; the caller raises them
        (_raise_if) after recording what did go out - the function's errors alarm pages by its own action."""
        failed = []
        for name, send, on in (("slack", self.slack, True), ("email", self.email, email)):
            if on:
                try:
                    send(text)
                except Exception as exc:  # noqa: BLE001 - the other channel still goes
                    failed.append(f"{name}: {type(exc).__name__}")
        return failed


def _raise_if(failed):
    if failed:
        raise RuntimeError("a page was not sent: " + "; ".join(failed))


def slack_sender(secret_id, secrets=None):
    def send(text):
        url = (secrets or boto3.client("secretsmanager")).get_secret_value(SecretId=secret_id)["SecretString"].strip()
        if not url.startswith(_SLACK):
            raise ValueError("the page webhook is not a Slack webhook")
        req = urllib.request.Request(url, data=json.dumps({"text": text[:_SLACK_MAX]}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
    return send


def email_sender(alarm, cloudwatch=None):
    def send(text):
        cw = cloudwatch or boto3.client("cloudwatch")
        # OK first, so the ALARM below is a change of state - the only thing CloudWatch sends an action for.
        cw.set_alarm_state(AlarmName=alarm, StateValue="OK", StateReason="before a WARDEN page is repeated")
        cw.set_alarm_state(AlarmName=alarm, StateValue="ALARM", StateReason=text[:_REASON_MAX])
    return send


def alarm_states(cloudwatch=None):
    def states(names):
        if not names:
            return {}
        got = (cloudwatch or boto3.client("cloudwatch")).describe_alarms(AlarmNames=sorted(set(names))[:100])
        return {a["AlarmName"]: a["StateValue"] for a in got.get("MetricAlarms", []) + got.get("CompositeAlarms", [])}
    return states


def key_expiry(param, now, warn_days, ssm=None):
    """(about, why) when a Temporal API key recorded in `param` (ISO times, comma-separated: each zone's key's end)
    expires within `warn_days`; None otherwise, or with nothing recorded."""
    try:
        raw = (ssm or boto3.client("ssm")).get_parameter(Name=param)["Parameter"]["Value"]
    except Exception:  # noqa: BLE001 - nothing recorded: nothing to warn of (the heartbeat alarm still pages a dead key)
        return None
    ends = []
    for part in raw.split(","):
        try:
            t = _dt.datetime.fromisoformat(part.strip())
            ends.append(t if t.tzinfo else t.replace(tzinfo=_dt.UTC))
        except ValueError:
            continue
    if not ends:
        return None
    first = min(ends)
    if first - now > _dt.timedelta(days=warn_days):
        return None
    left = "has expired" if first <= now else f"expires in {(first - now).days} days"
    return _iso(first), (f"a Temporal Cloud API key of WARDEN's {left} ({_iso(first)} UTC): make a new key, put it in "
                         "Secrets Manager, then record its end in the expiry parameter")


def worker_stopped(event, cluster_arn):
    """(key, why) for a worker task of this runtime's cluster that stopped on its own; None for any other."""
    d = event.get("detail") or {}
    if (event.get("source") != "aws.ecs" or event.get("detail-type") != "ECS Task State Change"
            or d.get("clusterArn") != cluster_arn or d.get("lastStatus") != "STOPPED"
            or d.get("stopCode") not in STOPPED_ON_ITS_OWN):
        return None
    group = str(d.get("group") or "worker").replace("service:", "")
    key = re.sub(r"[^A-Za-z0-9._-]", "-", f"task-{group}")[:200]
    # A bare 12-digit number is an account id to WARDEN's redaction (redaction.py): never in a page (CodeRabbit, PR 43).
    reason = _ACCOUNT.sub("<ACCOUNTID>", " ".join(str(d.get("stoppedReason") or "").split()))[:200]
    return key, f"a worker task of {group} stopped on its own ({d.get('stopCode')}): {reason}"


def _from_environment():
    return Pager(Pages(os.environ["PAGES_BUCKET"]), env=os.environ["WARDEN_ENV"],
                 repeat_minutes=int(os.environ["REPEAT_MINUTES"]), ack_url=os.environ.get("ACK_URL", ""),
                 slack=slack_sender(os.environ["SLACK_SECRET_ID"]), email=email_sender(os.environ["REPEAT_ALARM"]),
                 alarm_states=alarm_states())


def _on_alarm(pager, detail):
    name = str(detail.get("alarmName") or "")
    if (detail.get("state") or {}).get("value") != "ALARM" or name == os.environ.get("REPEAT_ALARM"):
        return {"ignored": "not a self-alarm going into ALARM"}
    why = str((detail.get("configuration") or {}).get("description") or "")
    return {"opened": bool(pager.open(name, why or "a WARDEN self-alarm is in ALARM", emailed=True, alarm=name))}


def _on_tick(pager, now):
    param = os.environ.get("KEY_EXPIRY_PARAM", "")
    expiring = key_expiry(param, now or pager.clock(), int(os.environ.get("KEY_WARN_DAYS", "7"))) if param else None
    opened = bool(expiring and pager.open("temporal-key-expiry", expiring[1], about=expiring[0]))
    return {"opened": opened, "repeated": pager.tick()}


def handler(event, context=None, *, pager=None, now=None):
    pager = pager or _from_environment()
    if event.get("source") == "aws.cloudwatch" and event.get("detail-type") == "CloudWatch Alarm State Change":
        return _on_alarm(pager, event.get("detail") or {})
    if event.get("source") == "aws.ecs":
        found = worker_stopped(event, os.environ.get("CLUSTER_ARN", ""))
        return {"opened": bool(found and pager.open(*found))}
    if event.get("detail-type") == "Scheduled Event":
        return _on_tick(pager, now)
    return {"ignored": "not an event the pager takes"}
