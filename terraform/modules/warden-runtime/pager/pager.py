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

A page is `pages/<key>.json` in this runtime's pages bucket, written only here. Its acknowledgement is
`acks/<key>.json`, written only by the approval page after an approver's passkey signed it (warden.paging): one
writer per object, so neither overwrites the other. An acknowledgement ends the page it names by its opening time;
the same alarm going into ALARM again later is a new page.

Email goes through the alarm REPEAT_ALARM, whose action is the page topic: set to ALARM with the page's words as
its reason, CloudWatch emails exactly that reason - no SNS permission outside what CloudWatch already holds.
"""

import datetime as _dt
import json
import os
import re
import urllib.request

import boto3

_KEY = re.compile(r"[A-Za-z0-9._-]{1,200}")
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


class Pages:
    """The pages bucket: `pages/` written here, `acks/` written by the approval page."""

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
        self.s3.put_object(Bucket=self.bucket, Key=f"pages/{page['key']}.json", Body=json.dumps(page).encode(),
                           ContentType="application/json")

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
        seen. Said at once: in Slack, and by email unless the alarm's own action already emailed it."""
        if not _KEY.fullmatch(key):
            raise ValueError("a page's key is a plain name")
        old = self.pages.page(key)
        if old and (not self.pages.acked(old) or (about and old.get("about") == about)):
            return None
        now = self.clock()
        page = {"key": key, "why": str(why)[:600], "opened_at": _iso(now), "last_sent": _iso(now), "sent": 1,
                "alarm": alarm, "about": about}
        self.pages.put(page)
        said = (f"WARDEN {self.env} page: {key}: {page['why']} {self._ack_line()}")
        self._send(said, email=not emailed)
        return page

    def tick(self):
        """Every open page not acknowledged, said again once each REPEAT_MINUTES: how long, and why."""
        now, due = self.clock(), []
        for key in sorted(self.pages.keys()):
            page = self.pages.page(key)
            if not page or self.pages.acked(page):
                continue
            # A minute's slack: the schedule's ticks drift by seconds, and a page a few seconds early waits a tick.
            if now - _dt.datetime.fromisoformat(page["last_sent"]) >= self.repeat - _dt.timedelta(minutes=1):
                due.append(page)
        if not due:
            return []
        states = self.alarm_states([p["alarm"] for p in due if p.get("alarm")])
        lines = []
        for page in due:
            minutes = int((now - _dt.datetime.fromisoformat(page["opened_at"])).total_seconds() // 60)
            state = states.get(page.get("alarm") or "")
            now_is = {"ALARM": " Its alarm is still in ALARM.", "OK": " Its alarm is OK now; acknowledge to stop this."}
            lines.append(f"{page['key']}: open {minutes} min, said {page['sent'] + 1} times - {page['why']}"
                         + now_is.get(state, ""))
            page.update(last_sent=_iso(now), sent=page["sent"] + 1)
            self.pages.put(page)
        said = (f"WARDEN {self.env}: {len(due)} page{'s' if len(due) > 1 else ''} not acknowledged. "
                + " | ".join(lines) + " " + self._ack_line())
        self._send(said, email=True)
        return [p["key"] for p in due]

    def _ack_line(self):
        every = int(self.repeat.total_seconds() // 60)
        where = f"Acknowledge with your passkey at {self.ack_url}" if self.ack_url else \
            "Acknowledge on the approval page"
        return f"{where}; until then this repeats every {every} min."

    def _send(self, text, *, email):
        """Slack, then email: either failing still tries the other, and a failure is raised after both - the
        function's errors alarm pages by its own action."""
        failed = []
        for name, send, on in (("slack", self.slack, True), ("email", self.email, email)):
            if on:
                try:
                    send(text)
                except Exception as exc:  # noqa: BLE001 - the other channel still goes
                    failed.append(f"{name}: {type(exc).__name__}")
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
    reason = " ".join(str(d.get("stoppedReason") or "").split())[:200]
    return key, f"a worker task of {group} stopped on its own ({d.get('stopCode')}): {reason}"


def handler(event, context=None, *, pager=None, now=None):
    env = os.environ["WARDEN_ENV"]
    if pager is None:
        pager = Pager(Pages(os.environ["PAGES_BUCKET"]), env=env, repeat_minutes=int(os.environ["REPEAT_MINUTES"]),
                      ack_url=os.environ.get("ACK_URL", ""), slack=slack_sender(os.environ["SLACK_SECRET_ID"]),
                      email=email_sender(os.environ["REPEAT_ALARM"]), alarm_states=alarm_states())
    detail = event.get("detail") or {}
    if event.get("source") == "aws.cloudwatch" and event.get("detail-type") == "CloudWatch Alarm State Change":
        name = str(detail.get("alarmName") or "")
        if (detail.get("state") or {}).get("value") != "ALARM" or name == os.environ.get("REPEAT_ALARM"):
            return {"ignored": "not a self-alarm going into ALARM"}
        why = str((detail.get("configuration") or {}).get("description") or "")
        return {"opened": bool(pager.open(name, why or "a WARDEN self-alarm is in ALARM", emailed=True, alarm=name))}
    if event.get("source") == "aws.ecs":
        found = worker_stopped(event, os.environ.get("CLUSTER_ARN", ""))
        return {"opened": bool(found and pager.open(*found))}
    if event.get("detail-type") == "Scheduled Event":
        expiring = key_expiry(os.environ.get("KEY_EXPIRY_PARAM", ""), now or pager.clock(),
                              int(os.environ.get("KEY_WARN_DAYS", "7"))) if os.environ.get("KEY_EXPIRY_PARAM") else None
        opened = bool(expiring and pager.open("temporal-key-expiry", expiring[1], about=expiring[0]))
        return {"opened": opened, "repeated": pager.tick()}
    return {"ignored": "not an event the pager takes"}
