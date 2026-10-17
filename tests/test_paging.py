"""WARDEN's own pages repeat every 15 minutes until a person acknowledges them, and keep repeating with WARDEN down
(owner, 2026-10-16): the kill switch going on, the heartbeat or synthetic missing, the dead-letter queue, an
unapproved actor, a worker's or a front door's errors, the audit database, a Temporal key about to expire.

The pager is a function of its own (terraform/modules/warden-runtime/pager/pager.py: boto3 and the standard library,
no WARDEN code, no VPC); the approval page's `/p` writes the acknowledgement after an approver's passkey signed
exactly the pages shown. Both sides are driven here against one bucket, so their layouts are held together."""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import re
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from test_killswitch_reset_g10m import World
from warden import bounds, paging

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "terraform" / "modules" / "warden-runtime"
T0 = datetime(2026, 10, 16, 1, 0, tzinfo=UTC)


def _pager_module():
    spec = importlib.util.spec_from_file_location("pager", MODULE / "pager" / "pager.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


pager = _pager_module()


class _NoSuchKey(Exception):
    pass


class FakeS3:
    """The anchors bucket's pages, as both the pager's and the approval function's S3 clients see it."""

    exceptions = type("E", (), {"NoSuchKey": _NoSuchKey})

    def __init__(self):
        self.objects = {}

    def get_object(self, Bucket, Key):
        if Key not in self.objects:
            raise _NoSuchKey(Key)
        return {"Body": io.BytesIO(self.objects[Key])}

    def put_object(self, Bucket, Key, Body, ContentType="", ChecksumAlgorithm=""):
        assert ChecksumAlgorithm, "the anchors bucket is under Object Lock: a write without a checksum is refused"
        self.objects[Key] = Body

    def get_paginator(self, name):
        objects = self.objects

        class P:
            def paginate(self, Bucket, Prefix):
                yield {"Contents": [{"Key": k} for k in sorted(objects) if k.startswith(Prefix)]}
        return P()


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


def _world():
    s3, clock, said = FakeS3(), Clock(), []
    p = pager.Pager(pager.Pages("b", s3=s3), env="ops", repeat_minutes=15, ack_url="https://approve.example.test/p",
                    slack=lambda t: said.append(("slack", t)), email=lambda t: said.append(("email", t)), clock=clock)
    return p, s3, clock, said


def _alarm(name="warden-ops-killswitch-on", state="ALARM"):
    return {"source": "aws.cloudwatch", "detail-type": "CloudWatch Alarm State Change",
            "detail": {"alarmName": name, "state": {"value": state},
                       "configuration": {"description": "WARDEN's kill switch went on."}}}


def _tick(p, clock, minutes):
    clock.t = T0 + timedelta(minutes=minutes)
    return pager.handler({"source": "aws.events", "detail-type": "Scheduled Event"}, pager=p)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("WARDEN_ENV", "ops")
    monkeypatch.setenv("REPEAT_ALARM", "warden-ops-page-repeat")
    monkeypatch.delenv("KEY_EXPIRY_PARAM", raising=False)


def test_a_page_repeats_every_15_minutes_saying_how_long_and_why_until_acknowledged():
    p, s3, clock, said = _world()
    assert pager.handler(_alarm(), pager=p) == {"opened": True}
    # The alarm's own action emailed it; the pager says it in Slack at once.
    assert [c for c, _ in said] == ["slack"]
    assert "kill switch went on" in said[0][1]
    assert "/p" in said[0][1]
    assert _tick(p, clock, 10)["repeated"] == []  # not yet
    assert _tick(p, clock, 15)["repeated"] == ["warden-ops-killswitch-on"]
    assert [c for c, _ in said[1:]] == ["slack", "email"]
    assert "open 15 min, said 2 times" in said[-1][1]
    assert "kill switch went on" in said[-1][1]
    assert "repeats every 15 min" in said[-1][1]
    assert _tick(p, clock, 20)["repeated"] == []
    assert _tick(p, clock, 30)["repeated"] == ["warden-ops-killswitch-on"]
    assert "open 30 min" in said[-1][1]
    # The same alarm again while its page is open: one page, not two.
    assert pager.handler(_alarm(), pager=p) == {"opened": False}
    # Acknowledged on the approval page's side of the same bucket: the repeats stop.
    store = paging.S3Pages("b", s3=s3)
    [shown] = paging.open_pages(store)
    paging.acknowledge(store, _Log(), [shown], approver="owner", nonce="n", credential_id="c", at=clock.t)
    assert paging.open_pages(store) == []
    before = len(said)
    for m in (45, 60, 75, 90):
        assert _tick(p, clock, m)["repeated"] == []
    assert len(said) == before
    # A later ALARM of the same alarm is a new page.
    assert pager.handler(_alarm(), pager=p) == {"opened": True}
    assert len(said) == before + 1


class _Log:
    def __init__(self):
        self.rows = []

    def append(self, cid, kind, body):
        self.rows.append((cid, kind, body))

    def checkpoint(self):
        self.rows.append(("checkpoint",))


def test_an_acknowledgement_of_an_earlier_opening_does_not_end_a_later_one():
    p, s3, clock, _ = _world()
    pager.handler(_alarm(), pager=p)
    s3.objects["acks/warden-ops-killswitch-on.json"] = json.dumps({"opened_at": "2026-10-15T00:00:00+00:00"}).encode()
    assert _tick(p, clock, 15)["repeated"] == ["warden-ops-killswitch-on"]


def test_only_a_self_alarm_into_alarm_opens_a_page_and_never_the_repeat_alarm():
    p, _, _, said = _world()
    assert "ignored" in pager.handler(_alarm(state="OK"), pager=p)
    assert "ignored" in pager.handler(_alarm(name="warden-ops-page-repeat"), pager=p)
    assert said == []


def test_a_worker_task_that_stopped_on_its_own_pages_and_a_deploys_stop_does_not(monkeypatch):
    monkeypatch.setenv("CLUSTER_ARN", "arn:cluster")
    p, _, _, said = _world()

    def task(code, cluster="arn:cluster"):
        return {"source": "aws.ecs", "detail-type": "ECS Task State Change", "detail": {
            "clusterArn": cluster, "lastStatus": "STOPPED", "stopCode": code, "group": "service:warden-ops-core",
            "stoppedReason": "Essential container in task exited"}}
    assert pager.handler(task("ServiceSchedulerInitiated"), pager=p) == {"opened": False}
    assert pager.handler(task("EssentialContainerExited", cluster="arn:other"), pager=p) == {"opened": False}
    assert said == []
    assert pager.handler(task("EssentialContainerExited"), pager=p) == {"opened": True}
    # Not an alarm: nothing emailed it yet, so both channels.
    assert [c for c, _ in said] == ["slack", "email"]
    assert "warden-ops-core stopped on its own" in said[0][1]


class _Ssm:
    def __init__(self, value):
        self.value = value

    def get_parameter(self, Name):
        if self.value is None:
            raise KeyError(Name)
        return {"Parameter": {"Value": self.value}}


def test_a_temporal_key_near_its_end_pages_once_per_end_date():
    now = T0
    assert pager.key_expiry("/p", now, 7, ssm=_Ssm(None)) is None  # nothing recorded
    assert pager.key_expiry("/p", now, 7, ssm=_Ssm("2026-11-30T00:00:00+00:00")) is None  # far off
    about, why = pager.key_expiry("/p", now, 7, ssm=_Ssm("2026-12-01T00:00:00Z, 2026-10-20T00:00:00+00:00"))
    assert about == "2026-10-20T00:00:00+00:00"
    assert "expires in 3 days" in why
    p, s3, clock, _ = _world()
    assert p.open("temporal-key-expiry", why, about=about)
    store = paging.S3Pages("b", s3=s3)
    paging.acknowledge(store, _Log(), paging.open_pages(store), approver="owner", nonce="n", credential_id="c",
                       at=clock.t)
    # Seen again at every tick: acknowledged for this end date, so no new page...
    assert p.open("temporal-key-expiry", why, about=about) is None
    # ...until a new key with a new end date nears its end.
    assert p.open("temporal-key-expiry", why, about="2026-12-01T00:00:00+00:00")


def test_a_channel_that_fails_still_tries_the_other_and_the_failure_is_raised():
    s3, said = FakeS3(), []

    def broken(text):
        raise OSError("slack is down")
    p = pager.Pager(pager.Pages("b", s3=s3), env="ops", repeat_minutes=15, ack_url="", slack=broken,
                    email=lambda t: said.append(t))
    with pytest.raises(RuntimeError, match="slack: OSError"):
        p.open("task-x", "why")
    assert said  # email still went


def test_email_is_the_repeat_alarm_set_to_alarm_with_the_pages_words():
    calls = []

    class Cw:
        def set_alarm_state(self, **kw):
            calls.append(kw)
    pager.email_sender("warden-ops-page-repeat", cloudwatch=Cw())("x" * 5000)
    assert [c["StateValue"] for c in calls] == ["OK", "ALARM"]  # a change of state, every time
    assert len(calls[1]["StateReason"]) == 1023
    assert calls[1]["AlarmName"] == "warden-ops-page-repeat"


def test_a_page_goes_only_to_a_slack_webhook():
    class Secrets:
        def get_secret_value(self, SecretId):
            return {"SecretString": "https://elsewhere.example.test/hook"}
    send = pager.slack_sender("warden/ops/slack-webhook", secrets=Secrets())
    with pytest.raises(ValueError):
        send("hello")


# ------------------------------------------------------------------ independent of WARDEN being alive

def test_the_pager_holds_no_warden_code_no_vpc_and_is_deployed_as_reviewed():
    source = (MODULE / "pager" / "pager.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from|import)\s+warden", source, re.MULTILINE)  # a broken image or package does not stop it
    with zipfile.ZipFile(MODULE / "pager.zip") as z:
        assert z.namelist() == ["pager.py"]
        assert z.read("pager.py") == source.encode().replace(b"\r\n", b"\n")
    tf = (MODULE / "paging.tf").read_text(encoding="utf-8")
    fn = tf[tf.index('resource "aws_lambda_function" "pager"'):]
    fn = fn[:fn.index("\n}\n")]
    assert "vpc_config" not in fn
    assert "image_uri" not in fn
    assert 'runtime          = "python3.13"' in fn
    assert 'schedule_expression = "rate(5 minutes)"' in tf


def _self_alarms(tf: str) -> str:
    return tf[tf.index("self_alarms = "):tf.index("paged_functions")]


def test_every_self_alarm_reaches_the_pager_and_paused_workers_page_nobody():
    tf = (MODULE / "paging.tf").read_text(encoding="utf-8")
    alarms = _self_alarms(tf)
    for name in ("killswitch", "alarm_dlq", "unapproved_actor", "approvers_changed", "lambda_errors",
                 "lambda_throttles", "audit_db_cpu", "audit_db_connections", "audit_db_storage"):
        assert f"aws_cloudwatch_metric_alarm.{name}.alarm_name" in alarms, name
    paused_part = alarms[:alarms.index("], [")]
    assert "var.paused ? [] :" in paused_part
    for name in ("heartbeat", "synthetic", "worker_errors"):
        assert f"aws_cloudwatch_metric_alarm.{name}.alarm_name" in paused_part, name
    assert "page_repeat" not in alarms  # the repeat's own email never opens a page
    assert 'detail        = { alarmName = local.self_alarms, state = { value = ["ALARM"] } }' in tf
    assert 'metric_name         = "KillSwitchTripped"' in tf
    assert paging.KILLSWITCH_METRIC == "KillSwitchTripped"
    for fn in ("front_door", "ack", "pager"):
        assert f"aws_lambda_function.{fn}" in tf[tf.index("paged_functions"):tf.index("audit_db_dimensions")]


def test_the_front_door_routes_the_acknowledgement_and_the_approval_function_may_write_it():
    front = (MODULE / "frontdoor.tf").read_text(encoding="utf-8")
    assert '"GET /p", "POST /p/{step}", "GET /s/p"' in front
    assert "WARDEN_PAGES_BUCKET" in front
    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    assert '[for s in local.acknowledge_pages : s if each.key == "approval"]' in iam
    assert 'approval     = { secrets = ["temporal-key", "temporal-api-key", "slack-client-secret"], approvers = true, metrics = true }' in iam


# ------------------------------------------------------------------ the kill switch counts, and the ack page

def test_every_trip_of_the_kill_switch_is_counted_for_its_page(tmp_path, monkeypatch):
    sent = []

    class Cw:
        def put_metric_data(self, **kw):
            sent.append(kw)
    monkeypatch.setenv("WARDEN_HEARTBEAT_NAMESPACE", "WARDEN/ops")
    monkeypatch.setattr("boto3.client", lambda *a, **k: Cw())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from warden import audit

    log = audit.AuditLog(tmp_path / "a.db", key=Ed25519PrivateKey.generate())
    bounds.trip(log, "operator", "a person stopped it")
    bounds.trip(log, "inc-1", "a rollback failed")
    assert [(s["Namespace"], s["MetricData"][0]["MetricName"]) for s in sent] == [("WARDEN/ops", "KillSwitchTripped")] * 2


def test_a_trip_stands_when_its_count_cannot_be_sent(tmp_path, monkeypatch):
    def down(*a, **k):
        raise OSError("no route")
    monkeypatch.setenv("WARDEN_HEARTBEAT_NAMESPACE", "WARDEN/ops")
    monkeypatch.setattr("boto3.client", down)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from warden import audit

    log = audit.AuditLog(tmp_path / "a.db", key=Ed25519PrivateKey.generate())
    bounds.trip(log, "operator", "stop")
    assert bounds.killswitch(log) is not None


def _page(store, key="warden-ops-heartbeat-missing", opened="2026-10-16T01:00:00+00:00"):
    store.put(f"pages/{key}.json", {"key": key, "why": "the workers stopped beating", "opened_at": opened,
                                    "last_sent": opened, "sent": 3})


def _ack_world(tmp_path, **kw):
    """The approval page with its pages, Slack's sign-in, and the owner's entry naming the Slack member who reads."""
    import dataclasses

    from test_slack_login_g10q import MEMBER, _login
    from warden import slack_login

    w = World(tmp_path, **kw)
    w.page = dataclasses.replace(w.page, pages=paging.MemoryPages(), slack=_login())
    w.policy.approvers["owner"].slack = MEMBER
    w.me = ["warden_who=" + slack_login.remember(w.page.slack, MEMBER)]
    return w


def _show(w):
    shown = w.page.handle("POST", "/p/pages", cookies=w.me)
    assert shown.status == 200, shown.body
    return json.loads(shown.body)


def _ack(w, shown, answer=None, **over):
    answer = answer or w.device.assert_(json.dumps(shown["options"]))
    return w.page.handle("POST", "/p/ack", json.dumps({"ask": shown["ask"], "response": answer, **over}), cookies=w.me)


def test_an_approvers_passkey_acknowledges_exactly_the_pages_shown_on_the_record(tmp_path):
    w = _ack_world(tmp_path)
    assert w.page.handle("GET", "/p", cookies=w.me).status == 200
    assert _show(w) == {"open": []}
    _page(w.page.pages)
    shown = _show(w)
    assert [p["key"] for p in shown["open"]] == ["warden-ops-heartbeat-missing"]
    assert shown["open"][0]["sent"] == 3
    answer = w.device.assert_(json.dumps(shown["options"]))
    done = _ack(w, shown, answer)
    assert done.status == 200
    assert json.loads(done.body) == {"acknowledged": 1}
    assert paging.open_pages(w.page.pages) == []
    [row] = [e["body"] for e in w.log.entries(kinds=(paging.ACK,))]
    assert row["approver"] == "owner"
    assert row["method"] == "passkey"
    assert row["pages"] == [
        {"key": "warden-ops-heartbeat-missing", "opened_at": "2026-10-16T01:00:00+00:00"}]
    # The same answer again acknowledges nothing.
    assert _ack(w, shown, answer).status == 403


def test_a_page_opened_after_they_were_shown_is_not_acknowledged_unseen(tmp_path):
    w = _ack_world(tmp_path)
    _page(w.page.pages)
    shown = _show(w)
    _page(w.page.pages, key="warden-ops-killswitch-on")
    assert _ack(w, shown).status == 409
    assert len(paging.open_pages(w.page.pages)) == 2
    assert not w.log.entries(kinds=(paging.ACK,))


def test_an_approver_limited_to_some_environments_cannot_silence_the_runtimes_pages(tmp_path):
    w = _ack_world(tmp_path)
    w.policy.approvers["owner"].environments = ["dev"]
    _page(w.page.pages)
    assert w.page.handle("POST", "/p/pages", cookies=w.me).status == 403


def test_no_pages_store_no_acknowledgement_page(tmp_path):
    w = World(tmp_path)
    assert w.page.handle("GET", "/p").status == 404


def test_signed_for_covers_every_page_by_its_opening():
    a = {"key": "k", "opened_at": "1"}
    assert paging.signed_for([a]) != paging.signed_for([{"key": "k", "opened_at": "2"}])
    assert paging.signed_for([a, {"key": "j", "opened_at": "1"}]) == paging.signed_for([{"key": "j", "opened_at": "1"}, a])


def test_an_acknowledgements_challenge_answers_once_even_if_a_store_gave_it_back(tmp_path):
    """Defence in depth: the challenge is taken once, and the record's own nonces refuse it again besides."""
    from warden.approval_page import MemoryLinkStore

    w = _ack_world(tmp_path)
    w.page.store = MemoryLinkStore()
    _page(w.page.pages)
    shown = _show(w)
    [key] = list(w.page.store.pending)
    pending = w.page.store.challenge(key)
    assert _ack(w, shown).status == 200
    _page(w.page.pages, opened="2026-10-16T02:00:00+00:00")  # paging again, as a replay would want
    w.page.store.put_challenge(key, pending)
    assert _ack(w, shown).status == 403
    assert len(w.log.entries(kinds=(paging.ACK,))) == 1


# ------------------------------------------------------------------ PR 43 review: who reads `/p`, and its challenges

def test_with_no_slack_sign_in_nobody_reads_or_acknowledges_the_pages(tmp_path):
    """CodeRabbit, PR 43 (CWE-306): with no Slack sign-in, anyone could list the pages and their reasons."""
    import dataclasses

    w = _ack_world(tmp_path)
    _page(w.page.pages)
    w.page = dataclasses.replace(w.page, slack=None)
    for method, path in (("GET", "/p"), ("POST", "/p/pages"), ("POST", "/p/ack")):
        out = w.page.handle(method, path, json.dumps({"ask": "a" * 22, "response": {}}))
        assert out.status == 503, (method, path)
        assert "heartbeat" not in out.body, (method, path)


def test_only_a_signed_in_approver_sees_the_pages(tmp_path):
    from test_slack_login_g10q import OTHER
    from warden import slack_login

    w = _ack_world(tmp_path)
    _page(w.page.pages)
    signed_out = w.page.handle("GET", "/p")
    assert signed_out.status == 200
    assert 'data-slack="1"' in signed_out.body
    assert "heartbeat" not in signed_out.body
    assert w.page.handle("POST", "/p/pages").status == 403
    stranger = ["warden_who=" + slack_login.remember(w.page.slack, OTHER)]
    out = w.page.handle("POST", "/p/pages", cookies=stranger)
    assert out.status == 403
    assert "heartbeat" not in out.body


def test_each_look_has_its_own_challenge_and_a_bad_answer_takes_none(tmp_path):
    """CodeRabbit, PR 43: one shared challenge let any look replace another's, and a malformed answer consume it."""
    w = _ack_world(tmp_path)
    _page(w.page.pages)
    first, second = _show(w), _show(w)
    assert first["ask"] != second["ask"]
    # Answers that name no passkey of this approver, or no look, take nothing.
    assert w.page.handle("POST", "/p/ack", "not json", cookies=w.me).status == 403
    assert _ack(w, first, {"id": "someone-elses-passkey"}).status == 403
    assert _ack(w, first, ask="../../other").status == 403
    assert not w.log.entries(kinds=("approval.challenge_taken",))
    # The first look still answers, after the second was made.
    assert _ack(w, first).status == 200


def test_a_malformed_page_never_stops_the_others_being_acknowledged(tmp_path):
    """CodeRabbit, PR 43: one bad object in `pages/` stopped `/p` showing any."""
    w = _ack_world(tmp_path)
    _page(w.page.pages)
    _page(w.page.pages, key="warden-ops-alarm-dlq")
    w.page.pages.objects["pages/warden-ops-alarm-dlq.json"].update(sent="many", opened_at="not a time")
    w.page.pages.objects["pages/junk.json"] = [1, 2]  # type: ignore[assignment]
    w.page.pages.objects["pages/nokey.json"] = {"why": "no key"}
    w.page.pages.objects["pages/notes.txt"] = {"key": "notes", "opened_at": "x"}

    class Broken(paging.MemoryPages):
        def get(self, key):
            if key == "acks/warden-ops-heartbeat-missing.json":
                raise OSError("403")
            return super().get(key)
    broken = Broken()
    broken.objects = w.page.pages.objects
    w.page.pages = broken
    shown = _show(w)
    rows = {p["key"]: p for p in shown["open"]}
    assert set(rows) == {"warden-ops-heartbeat-missing", "warden-ops-alarm-dlq"}
    assert rows["warden-ops-alarm-dlq"]["sent"] == 0
    assert "cannot be read" in rows["warden-ops-alarm-dlq"]["opened"]
    assert _ack(w, shown).status == 200


def test_one_unreadable_page_never_stops_the_others_repeating(caplog):
    """CodeRabbit, PR 43: one page with a bad time made every tick fail, and no page repeated."""
    p, s3, clock, said = _world()
    pager.handler(_alarm(), pager=p)
    pager.handler(_alarm(name="warden-ops-alarm-dlq"), pager=p)
    broken = json.loads(s3.objects["pages/warden-ops-alarm-dlq.json"])
    broken.update(last_sent="not a time", opened_at=None)
    s3.objects["pages/warden-ops-alarm-dlq.json"] = json.dumps(broken).encode()
    s3.objects["pages/junk.json"] = b"[1, 2]"  # not a page at all
    caplog.set_level("WARNING", logger="warden.pager")
    assert _tick(p, clock, 15)["repeated"] == ["warden-ops-alarm-dlq", "warden-ops-killswitch-on"]
    assert "open since a time that cannot be read" in said[-1][1]
    assert "open 15 min" in said[-1][1]
    assert any("junk" in r.getMessage() for r in caplog.records)
    # Said again, its times now readable: it repeats on the schedule from here.
    assert _tick(p, clock, 20)["repeated"] == []
    assert _tick(p, clock, 30)["repeated"] == ["warden-ops-alarm-dlq", "warden-ops-killswitch-on"]


def test_the_page_state_is_in_the_anchors_bucket_tls_only_and_under_object_lock():
    """SonarCloud, PR 43: a bucket of its own had no TLS-only policy and no access log - and the boundary lets only
    the anchors and witness buckets have a policy. The anchors bucket has both TLS-only and Object Lock."""
    tf = (MODULE / "paging.tf").read_text(encoding="utf-8")
    assert 'resource "aws_s3_bucket"' not in tf
    assert "aws_s3_bucket.pages" not in tf
    assert 'PAGES_BUCKET     = aws_s3_bucket.anchors.bucket' in tf
    assert '"${aws_s3_bucket.anchors.arn}/pages/*"' in tf
    anchors = (MODULE / "anchors.tf").read_text(encoding="utf-8")
    assert '"aws:SecureTransport" = "false"' in anchors
    assert "object_lock_enabled = true" in anchors
    front = (MODULE / "frontdoor.tf").read_text(encoding="utf-8")
    assert "WARDEN_PAGES_BUCKET        = aws_s3_bucket.anchors.bucket" in front


# ------------------------------------------------------------------ PR 43 review: the pager never goes quiet

def _failing(fail):
    """A channel that fails while `fail[0]` is true."""
    said = []

    def send(text):
        if fail[0]:
            raise OSError("down")
        said.append(text)
    return send, said


def test_a_page_whose_first_saying_failed_everywhere_is_said_at_the_next_tick_and_on_the_retry():
    """CodeRabbit, PR 43: the page was written as said before it was, and waited a whole repeat when it was not."""
    s3, clock, down = FakeS3(), Clock(), [True]
    slack, said = _failing(down)
    p = pager.Pager(pager.Pages("b", s3=s3), env="ops", repeat_minutes=15, ack_url="", slack=slack, email=slack,
                    clock=clock)
    with pytest.raises(RuntimeError, match="a page was not sent"):
        p.open("task-x", "the worker stopped")
    page = json.loads(s3.objects["pages/task-x.json"])
    assert page["sent"] == 0
    assert page["last_sent"] == ""  # written, not said
    down[0] = False
    assert p.open("task-x", "the worker stopped")  # EventBridge's retry of the same event says it now
    assert said
    assert json.loads(s3.objects["pages/task-x.json"])["sent"] == 1
    assert p.open("task-x", "the worker stopped") is None  # said once: one page


def test_an_unsaid_page_is_due_at_the_next_tick():
    s3, clock, down = FakeS3(), Clock(), [True]
    slack, said = _failing(down)
    p = pager.Pager(pager.Pages("b", s3=s3), env="ops", repeat_minutes=15, ack_url="", slack=slack, email=slack,
                    clock=clock)
    with pytest.raises(RuntimeError):
        p.open("task-x", "the worker stopped")
    down[0] = False
    assert _tick(p, clock, 5)["repeated"] == ["task-x"]
    assert "said 1 times" in said[-1]


def test_a_repeat_no_channel_took_is_not_recorded_as_sent():
    """CodeRabbit, PR 43: `last_sent` and `sent` were written before the send, so a failed repeat waited 15 minutes."""
    p, s3, clock, _ = _world()
    pager.handler(_alarm(), pager=p)
    down = [True]
    p.slack, said = _failing(down)
    p.email = p.slack
    with pytest.raises(RuntimeError):
        _tick(p, clock, 15)
    assert json.loads(s3.objects["pages/warden-ops-killswitch-on.json"])["sent"] == 1  # not said: not counted
    down[0] = False
    assert _tick(p, clock, 20)["repeated"] == ["warden-ops-killswitch-on"]
    assert "said 2 times" in said[-1]


def test_an_alarm_state_or_acknowledgement_that_cannot_be_read_never_stops_the_repeats(caplog):
    """CodeRabbit, PR 43: a DescribeAlarms failure, or an unreadable `acks/` object, aborted the whole tick."""
    p, s3, clock, said = _world()
    pager.handler(_alarm(), pager=p)
    pager.handler(_alarm(name="warden-ops-alarm-dlq"), pager=p)

    def no_states(names):
        raise RuntimeError("Throttling")
    p.alarm_states = no_states
    s3.objects["acks/warden-ops-alarm-dlq.json"] = b"{not json"
    caplog.set_level("WARNING", logger="warden.pager")
    assert _tick(p, clock, 15)["repeated"] == ["warden-ops-alarm-dlq", "warden-ops-killswitch-on"]
    assert "said 2 times" in said[-1][1]
    assert any("could not be read" in r.getMessage() for r in caplog.records)


def test_a_worker_stop_reason_never_carries_an_account_id(monkeypatch):
    """CodeRabbit, PR 43: ECS's stoppedReason went into Slack and email unredacted."""
    account = "1234" + "5678" + "9012"  # a placeholder, built from parts
    event = {"source": "aws.ecs", "detail-type": "ECS Task State Change", "detail": {
        "clusterArn": "arn:cluster", "lastStatus": "STOPPED", "stopCode": "TaskFailedToStart", "group": "service:w",
        "stoppedReason": f"CannotPullContainerError: {account}.dkr.ecr.example/warden:1 not found"}}
    _, why = pager.worker_stopped(event, "arn:cluster")
    assert account not in why
    assert "<ACCOUNTID>.dkr.ecr" in why
