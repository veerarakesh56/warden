"""Pilot metrics (`warden report pilot`, `/r/pilot`): the client's weekly numbers, read only from audit rows whose hash
chain and checkpoint signatures check out (owner item 3, FDE course alignment, 2026-10-21).

The fixture log is written by the repo's own AuditLog with an Ed25519 key made at run time, at fixed times, so every
expected number below is exact - p90 by nearest rank included."""

from __future__ import annotations

import dataclasses
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_approval_page import setup as page_setup  # noqa: F401
from test_slack_login_g10q import MEMBER, OTHER, Slack, _login
from warden import activities, audit, pilot, slack_login
from warden.cli import main

SINCE = datetime(2026, 10, 14, tzinfo=UTC)
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
CHANGED = "changed after it was written"
DAY, DB, PAGE, QUERY = "2026-10-14", "audit.db", "/r/pilot", "since=2026-10-14"
# B's end row, rewritten as a fix.
FORGED = '{"checklist":{"approved":true},"run_id":"r1","status":"recovered","workflow_id":"rem-b"}'
NOT_RECORDED_YET = "not recorded (no llm.call or llm.fallback rows in the audit)"
SPEND, ESCALATED = "incident.llm_spend", "1 of 7 incidents (14.3%)"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def _at(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 10, day, hour, minute, tzinfo=UTC)


class Writer:
    """Rows of one incident at the times given, through the real AuditLog."""

    def __init__(self, log: audit.AuditLog, clock: Clock) -> None:
        self.log, self.clock = log, clock

    def row(self, when: datetime, cid: str, kind: str, body: dict) -> None:
        self.clock.now = when
        self.log.append(cid, kind, body)

    def start(
        self, cid: str, alarm: datetime, env: str = "dev", verdict: str = "approved_for_human"
    ) -> None:
        self.row(
            alarm + timedelta(minutes=1),
            cid,
            "incident.ingest",
            {"node": "ingest", "alert_id": cid, "env": env},
        )
        self.row(
            alarm + timedelta(minutes=1),
            cid,
            "incident.alert",
            {
                "alert": {
                    "alert_id": cid,
                    "name": "TickSilent",
                    "environment": env,
                    "service": "tick",
                    "started_at": alarm.isoformat().replace("+00:00", "Z"),
                }
            },
        )
        self.row(
            alarm + timedelta(minutes=1),
            cid,
            "incident.verify",
            {"node": "verify", "status": verdict},
        )

    def plan(self, when: datetime, cid: str, wid: str, run: str = "r1") -> None:
        self.row(
            when,
            cid,
            "remediation.plan",
            {
                "workflow_id": wid,
                "run_id": run,
                "entry": "events_enable_rule",
                "tier": "T1",
                "target": "dev/rule/tick",
                "plan_hash": "h-" + run,
            },
        )

    def end(
        self, when: datetime, cid: str, wid: str, status: str, approved: bool, run: str = "r1"
    ) -> None:
        self.row(
            when,
            cid,
            pilot.END,
            {
                "workflow_id": wid,
                "run_id": run,
                "status": status,
                "checklist": {"approved": approved},
            },
        )

    def result(self, when: datetime, cid: str, wid: str, ok: bool, run: str = "r1") -> None:
        self.row(
            when,
            cid,
            "remediation.result",
            {"workflow_id": wid, "run_id": run, "ok": ok, "service": "x"},
        )

    def spend(self, when: datetime, cid: str, calls: int, usd: float) -> None:
        self.row(
            when,
            cid,
            SPEND,
            {"calls": calls, "usd": usd, "input_tokens": 1, "output_tokens": 1},
        )


def _fixture(w: Writer) -> None:
    """Seven incidents from 14 October, and one before it (the `since` filter must leave it out)."""
    w.start("old", _at(10, 9))
    w.plan(_at(10, 9, 3), "old", "rem-old")
    w.end(_at(10, 9, 30), "old", "rem-old", "recovered", True)
    w.spend(_at(10, 9, 2), "old", 50, 5.0)
    # A: fixed. Alarm 10:00, plan 10:05, healthy 10:20, recovered after the watch.
    w.start("a", _at(15, 10))
    w.spend(_at(15, 10, 2), "a", 3, 0.06)
    w.plan(_at(15, 10, 5), "a", "rem-a")
    w.row(_at(15, 10, 6), "a", "eldane.call", {"ok": True, "input_tokens": 5, "output_tokens": 5})
    w.result(_at(15, 10, 20), "a", "rem-a", True)
    w.end(_at(15, 11, 20), "a", "rem-a", "recovered", True)
    # B: denied, plan after 10 minutes.
    w.start("b", _at(16, 8))
    w.spend(_at(16, 8, 2), "b", 2, 0.04)
    w.plan(_at(16, 8, 10), "b", "rem-b")
    w.end(_at(16, 8, 40), "b", "rem-b", "denied", False)
    # C (prod): approved, drifted, planned again, did not work, undone; a question in its discussion.
    w.start("c", _at(17, 12), env="prod")
    w.spend(_at(17, 12, 1), "c", 4, 0.10)
    w.plan(_at(17, 12, 2), "c", "rem-c")
    w.end(_at(17, 12, 20), "c", "rem-c", "drifted", True)
    w.plan(_at(17, 12, 30), "c", "rem-c", run="r2")
    w.result(_at(17, 12, 50), "c", "rem-c", False, run="r2")
    w.row(
        _at(17, 12, 51),
        "c",
        "remediation.rollback",
        {"workflow_id": "rem-c", "run_id": "r2", "undone": True},
    )
    w.row(
        _at(17, 12, 52),
        "c",
        "remediation.rollback",
        {"workflow_id": "rem-c", "run_id": "r2", "undone": True},
    )
    w.end(_at(17, 12, 53), "c", "rem-c", "rolled_back", True, run="r2")
    w.spend(_at(17, 14), "discuss-c", 1, 0.01)
    # D (prod): WARDEN declined to decide - no plan.
    w.start("d", _at(18, 9), env="prod", verdict="escalated")
    w.spend(_at(18, 9, 2), "d", 1, 0.02)
    # E: approved, the apply failed - a person takes over.
    w.start("e", _at(19, 7))
    w.plan(_at(19, 7, 30), "e", "rem-e")
    w.end(_at(19, 7, 45), "e", "rem-e", "apply_failed", True)
    # F: a plan still waiting.
    w.start("f", _at(20, 6))
    w.plan(_at(20, 6, 6), "f", "rem-f")
    # G: verified 40 minutes after its alarm.
    w.start("g", _at(20, 10))
    w.plan(_at(20, 10, 4), "g", "rem-g")
    w.result(_at(20, 10, 40), "g", "rem-g", True)
    w.end(_at(20, 10, 41), "g", "rem-g", "verified", True)


@pytest.fixture
def made(tmp_path):
    key, clock = Ed25519PrivateKey.generate(), Clock()
    log = audit.AuditLog(tmp_path / DB, key=key, clock=clock)
    _fixture(Writer(log, clock))
    log.checkpoint()
    return log, key, tmp_path / DB


def _raw(path):
    db = sqlite3.connect(path, isolation_level=None)
    for t in ("entries", "checkpoints"):
        for op in ("update", "delete"):
            db.execute(f"DROP TRIGGER {t}_no_{op}")
    return db


def _seq(log, cid, kind):
    return next(e["seq"] for e in log.entries(cid, kinds=(kind,)))


def _lines(log, key, since=SINCE, **kw):
    return dict(pilot.lines(pilot.report(pilot.read(log, key.public_key()), since, now=NOW, **kw)))


# ------------------------------------------------------------------ the numbers, exact


def test_every_metric_from_the_fixture_is_exact(made):
    log, key, _ = made
    got = _lines(log, key)
    assert got["Incidents"] == "7"
    assert got["Plans"] == "7 (6 ended, 1 open)"
    assert got["Plans approved"] == "5 of 6 ended (83.3%)"
    assert got["Plans denied"] == "1 of 6 ended (16.7%)"
    assert got["Plans re-planned"] == "1 of 6 ended (16.7%)"
    assert got["Plans escalated"] == "1 of 6 ended (16.7%)"
    # 2, 4, 5, 6, 10, 30 minutes: median (5 + 6) / 2; p90 nearest rank, sorted[ceil(5.4) - 1] = 30 (interpolation: 20)
    assert got["Alarm to plan"] == "median 5.5 min, p90 30.0 min (6 incident(s))"
    assert got["Alarm to fixed"] == "median 30.0 min, p90 40.0 min (2 incident(s))"
    assert got["Not fixed (open or ended otherwise)"] == "5"
    assert got["Escalation rate"] == ESCALATED
    assert got["Model calls per incident"].startswith("1.71 (12 in all from incident.llm_spend")
    assert got["Spend ledger (incident.llm_spend)"].startswith("US$0.2300 in all")
    # No llm.call or llm.fallback row in this audit: not recorded, never 0.
    assert got["Cost per incident"] == NOT_RECORDED_YET
    assert got["Fallbacks"] == NOT_RECORDED_YET
    assert "Fallback rate per model call" not in got
    assert got["Undo count"] == "1 (undo failed: 0)"  # two rollback rows of one run: one undo
    assert got["Audit rows"].startswith(
        f"{log.signed_through()} read; {log.signed_through()} verified"
    )
    assert "Times left out" not in got


def _llm_rows(log):
    """llm.call and llm.fallback rows (lane FDE-F's shapes) beside the fixture's incidents, then signed."""

    def call(cid, cost=None):
        body = {"latency_ms": 900, "prompt_tokens": 1000, "completion_tokens": 200}
        log.append(cid, pilot.LLM_CALL, body if cost is None else {**body, "cost": cost})

    for cid, cost in (
        ("old", 9.0),
        ("a", 0.05),
        ("a", 0.03),
        ("c", 0.10),
        ("c", None),
        ("discuss-c", 0.02),
        ("g", 0.01),
    ):
        call(cid, cost)
    for cid, reason in (
        ("old", "budget_cap"),
        ("a", "model_refused"),
        ("c", "budget_cap"),
        ("d", "rules_only"),
        ("d", "rules_only"),
        ("e", "weird_reason"),
    ):
        log.append(cid, pilot.FALLBACK, {"reason": reason})
    log.checkpoint()


def test_cost_and_fallbacks_come_from_llm_rows_and_a_missing_cost_is_not_recorded(made):
    log, key, _ = made
    _llm_rows(log)
    got = _lines(log, key)
    # 0.05 + 0.03 + 0.10 + 0.02 (its discussion) + 0.01 = 0.21 over 7 incidents; c's second call has no cost
    assert got["Cost per incident"] == (
        "US$0.0300 (US$0.2100 in all over 5 llm.call row(s) with a cost; "
        "1 row(s) without one: not recorded for those)"
    )
    assert got["Fallbacks"] == "5; per incident 0.71 (5 / 7 incidents)"
    assert got["Fallback rate per model call"] == "83.3% (5 / 6 llm.call rows)"
    assert got["Fallbacks by reason"] == (
        "rules_only 2, model_refused 1, budget_cap 1, provider_unavailable 0, other 1"
    )


def test_once_llm_rows_exist_no_fallback_is_a_measured_zero(made):
    log, key, _ = made
    log.append("a", pilot.LLM_CALL, {"cost": 0.04})
    log.checkpoint()
    got = _lines(log, key)
    assert got["Fallbacks"] == "0; per incident 0.00 (0 / 7 incidents)"
    assert got["Fallback rate per model call"] == "0.0% (0 / 1 llm.call rows)"
    assert got["Cost per incident"].startswith(
        "US$0.0057 (US$0.0400 in all over 1 llm.call row(s) with a cost)"
    )


def test_p90_is_the_nearest_rank_and_the_median_the_middle():
    assert pilot.p90([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]) == 9.0
    assert pilot.p90([10.0, 1.0, 5.0]) == 10.0
    assert pilot.p90([7.0]) == 7.0
    assert pilot.p90([]) is None
    assert pilot.median([3.0, 1.0, 2.0, 10.0]) == 2.5
    assert pilot.median([]) is None


def test_the_escalation_statuses_are_the_workers_own():
    assert pilot.PERSON_TAKES_OVER == activities.PERSON_TAKES_OVER


def test_an_approvers_new_plan_re_plans_the_plan_before_it(made):
    log, key, _ = made
    log.append("discuss-b", "discuss.replan", {"started": "b2", "why": ""})
    log.append(
        "discuss-g", "discuss.replan", {"started": "", "why": "not an approver"}
    )  # refused: no new plan
    log.checkpoint()
    assert _lines(log, key)["Plans re-planned"] == "2 of 6 ended (33.3%)"


def test_a_second_opinion_that_disagrees_escalates_the_incident(made):
    log, key, _ = made
    log.append("f", "incident.second_opinion", {"agree": False})
    log.checkpoint()
    assert _lines(log, key)["Escalation rate"] == "2 of 7 incidents (28.6%)"


def test_an_alarm_time_after_the_plan_is_left_out_and_said(tmp_path):
    key, clock = Ed25519PrivateKey.generate(), Clock()
    log = audit.AuditLog(tmp_path / "a.db", key=key, clock=clock)
    w = Writer(log, clock)
    w.start("x", _at(15, 10))
    w.plan(_at(15, 9, 50), "x", "rem-x")  # the alarm source's clock ahead of WARDEN's
    log.checkpoint()
    got = _lines(log, key)
    assert got["Alarm to plan"] == "median n/a, p90 n/a (0 incident(s))"
    assert got["Times left out"].startswith("1:")


# ------------------------------------------------------------------ guards


def test_the_since_filter_leaves_out_earlier_incidents(made):
    log, key, _ = made
    assert _lines(log, key, since=_at(1, 0))["Incidents"] == "8"
    assert _lines(log, key, since=_at(20, 0))["Incidents"] == "2"


def test_no_incidents_gives_n_a_and_never_divides_by_zero(made):
    log, key, _ = made
    _llm_rows(log)
    got = _lines(log, key, since=NOW)
    assert got["Incidents"] == "0"
    assert got["Plans"] == "0 (0 ended, 0 open)"
    for name in pilot.OUTCOMES:
        assert got[f"Plans {name}"] == "0 of 0 ended (n/a)"
    assert got["Escalation rate"] == "0 of 0 incidents (n/a)"
    assert got["Model calls per incident"].startswith("n/a")
    assert got["Cost per incident"].startswith("n/a")
    assert got["Fallbacks"] == "0; per incident n/a (0 incidents)"
    assert got["Fallback rate per model call"] == "n/a (0 / 0 llm.call rows)"
    assert got["Alarm to fixed"] == "median n/a, p90 n/a (0 incident(s))"


def test_an_edited_row_is_not_counted_and_is_named(made):
    log, key, path = made
    seq = _seq(log, "b", pilot.END)
    body = FORGED
    _raw(path).execute("UPDATE entries SET body = ? WHERE seq = ?", (body, seq))
    checked = pilot.read(log, key.public_key())
    reasons = dict(checked.failed)
    assert reasons.pop(seq) == CHANGED
    # Its own hash fails, so the `prev` it names proves nothing: no row before it is reached by the checkpoint.
    assert reasons == dict.fromkeys(range(1, seq), "no valid signature covers it")
    assert min(e["seq"] for e in checked.rows) == seq + 1
    got = dict(pilot.lines(pilot.report(checked, SINCE, now=NOW)))
    assert got["Incidents"] == "5"  # C D E F G: A and B started before the edited row
    assert got["Plans"] == "5 (4 ended, 1 open)"  # C's two runs, E, G ended; F open
    assert got["Plans denied"] == "0 of 4 ended (0.0%)"
    assert f"row {seq} {CHANGED}" in got["Audit rows"]


def test_a_row_rewritten_with_its_hash_recomputed_breaks_the_link_and_nothing_before_it_counts(
    made,
):
    log, key, path = made
    seq = _seq(log, "b", pilot.END)
    db = _raw(path)
    s, at, cid, kind, _body, prev, _h = db.execute(
        "SELECT * FROM entries WHERE seq = ?", (seq,)
    ).fetchone()
    body = FORGED
    db.execute(
        "UPDATE entries SET body = ?, hash = ? WHERE seq = ?",
        (body, audit._hash(prev, s, at, cid, kind, body), seq),
    )
    checked = pilot.read(log, key.public_key())
    reasons = dict(checked.failed)
    assert reasons[seq + 1] == "does not link to the row before it"
    assert all(reasons[s] == "no valid signature covers it" for s in range(1, seq + 1))
    assert min(e["seq"] for e in checked.rows) == seq + 2


def test_a_forged_history_spliced_in_under_an_edited_row_is_not_counted(made):
    """CodeRabbit PR 175 (CWE-345): rows 1..k-1 rewritten with recomputed hashes and consistent links, and row k edited
    to point at the forged k-1 while keeping its old hash, so row k+1 still links. Row k fails its own hash; nothing
    before it may be counted, however consistent it looks."""
    log, key, path = made
    k = _seq(log, "b", pilot.END)
    db = _raw(path)
    prev = audit.GENESIS
    for s, at, cid, kind, body in db.execute(
        "SELECT seq, at, correlation_id, kind, body FROM entries WHERE seq < ? ORDER BY seq", (k,)
    ).fetchall():
        forged = body.replace('"denied"', '"recovered"')
        digest = audit._hash(prev, s, at, cid, kind, forged)
        db.execute(
            "UPDATE entries SET body = ?, prev = ?, hash = ? WHERE seq = ?",
            (forged, prev, digest, s),
        )
        prev = digest
    db.execute("UPDATE entries SET body = ?, prev = ? WHERE seq = ?", (FORGED, prev, k))
    checked = pilot.read(log, key.public_key())
    reasons = dict(checked.failed)
    assert reasons.pop(k) == CHANGED
    assert reasons == dict.fromkeys(range(1, k), "no valid signature covers it")
    assert min(e["seq"] for e in checked.rows) == k + 1


def test_a_wrong_key_or_a_forged_signature_counts_nothing(made):
    log, key, path = made
    other = Ed25519PrivateKey.generate().public_key()
    checked = pilot.read(log, other)
    assert checked.rows == []
    assert len(checked.failed) == checked.total > 0
    _raw(path).execute("UPDATE checkpoints SET signature = ?", ("00" * 64,))
    assert pilot.read(log, key.public_key()).rows == []


def test_rows_after_the_last_checkpoint_are_unsigned_and_not_counted(made):
    log, key, _ = made
    log.append("h", "incident.ingest", {"node": "ingest", "alert_id": "h", "env": "dev"})
    checked = pilot.read(log, key.public_key())
    assert (checked.unsigned, checked.failed) == (1, [])
    assert _lines(log, key, since=_at(1, 0))["Incidents"] == "8"
    log.checkpoint()
    assert _lines(log, key, since=_at(1, 0))["Incidents"] == "9"


@pytest.mark.parametrize(
    "text", ["", "yesterday", "2026-13-01", "2026-10-14T00:00:00", "2026-10-22"]
)
def test_since_is_refused_unless_a_day_or_a_zoned_time_not_in_the_future(text):
    with pytest.raises(ValueError, match="--since"):
        pilot.parse_since(text, NOW)


def test_since_is_read_in_utc():
    assert pilot.parse_since("2026-10-14", NOW) == SINCE
    assert pilot.parse_since("2026-10-14T05:30:00+05:30", NOW) == SINCE
    assert pilot.parse_since("2026-10-14T00:00:00Z", NOW).tzinfo == UTC


# ------------------------------------------------------------------ the command


def _keys(tmp_path, monkeypatch, key):
    folder = tmp_path / "keys"
    folder.mkdir()
    monkeypatch.setenv(audit.KEY_DIR_ENV, str(folder))
    (folder / "audit.pub").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    monkeypatch.delenv("WARDEN_AUDIT_DSN", raising=False)
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    monkeypatch.chdir(tmp_path)
    return folder / "audit.pub"


def _command(pub, since=DAY, db=DB):
    return main(["report", "pilot", "--since", since, "--db", db, "--public-key", str(pub)])


def test_the_command_prints_the_report_and_fails_on_a_tampered_row(
    made, tmp_path, monkeypatch, capsys
):
    log, key, path = made
    pub = _keys(tmp_path, monkeypatch, key)
    assert _command(pub) == 0
    out = capsys.readouterr().out
    assert "Escalation rate" in out
    assert ESCALATED in out
    assert NOT_RECORDED_YET in out
    seq = _seq(log, "a", SPEND)
    _raw(path).execute("UPDATE entries SET body = ? WHERE seq = ?", ('{"calls":0,"usd":0}', seq))
    assert _command(pub) == 1
    assert f"row {seq} {CHANGED}" in capsys.readouterr().out


def test_the_command_refuses_a_bad_since_or_a_missing_file(made, tmp_path, monkeypatch, capsys):
    _, key, _ = made
    pub = _keys(tmp_path, monkeypatch, key)
    assert _command(pub, since="2026-10-14T00:00") == 2
    assert "needs a zone" in capsys.readouterr().err
    assert _command(pub, db="none.db") == 2
    assert not (tmp_path / "none.db").exists()  # never created by reading


# ------------------------------------------------------------------ the records page


def _page(page_setup, made):  # noqa: F811
    page = page_setup[0]
    log, _, _ = made
    policy = page.policy.model_copy(deep=True)
    policy.approvers["owner"].slack = MEMBER
    return dataclasses.replace(page, policy=policy, log=log, slack=_login(Slack()))


def _as(page, member=MEMBER, query=QUERY):
    return page.handle(
        "GET", PAGE, query=query, cookies=["warden_who=" + slack_login.remember(page.slack, member)]
    )


def test_the_page_shows_the_numbers_to_a_reader_of_the_records_only(page_setup, made, monkeypatch):  # noqa: F811
    monkeypatch.delenv("WARDEN_RECORD_VIEWERS", raising=False)
    page = _page(page_setup, made)
    out = page.handle("GET", PAGE)
    assert out.status == 200
    assert "Sign in" in out.body
    assert "Escalation rate" not in out.body
    out = _as(page, OTHER)
    assert out.status == 403
    assert "Escalation rate" not in out.body
    out = _as(page)
    assert out.status == 200
    assert ESCALATED in out.body
    assert '<th scope="row">Fallbacks</th><td>not recorded' in out.body
    assert "frame-ancestors 'none'" in out.headers["Content-Security-Policy"]
    assert out.body.count("<script") == 1
    assert "{{" not in out.body


def test_a_reader_limited_to_dev_sees_only_devs_incidents(page_setup, made):  # noqa: F811
    page = _page(page_setup, made)
    page.policy.approvers["owner"].environments = ["dev"]
    out = _as(page)
    assert out.status == 200
    assert '<th scope="row">Incidents</th><td>5</td>' in out.body  # A B E F G; C and D are prod
    assert ESCALATED not in out.body  # D, the escalated one, is prod


def test_the_page_refuses_any_other_query_and_says_when_it_cannot_check(page_setup, made):  # noqa: F811
    page = _page(page_setup, made)
    for q in (QUERY + "&x=1", "since=14-10-2026", "since=2099-01-01", "q=2026-10-14"):
        assert _as(page, query=q).status == 400
    unkeyed = dataclasses.replace(page, log=audit.AuditLog(made[2]))
    out = _as(unkeyed, query="")
    assert out.status == 503
    assert "Escalation rate" not in out.body


def test_the_page_counts_a_tampered_row_without_naming_it(page_setup, made):  # noqa: F811
    log, _, path = made
    seq = _seq(log, "a", SPEND)
    _raw(path).execute("UPDATE entries SET body = '{}' WHERE seq = ?", (seq,))
    out = _as(_page(page_setup, made))
    assert out.status == 200
    assert (
        f"{seq} row(s) of the record failed verification" in out.body
    )  # it and every row before it
    assert CHANGED not in out.body


# ------------------------------------------------------------------ least privilege and read-only


def test_the_report_command_loads_only_the_audit_dsn():
    from warden import settings

    assert settings.loadable_for("report") == frozenset({"WARDEN_AUDIT_DSN"})
    assert "WARDEN_SLACK_BOT_TOKEN" in settings.loadable_for("worker")  # others keep theirs


def _digest(path):
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_command_never_writes_the_audit_it_reads(made, tmp_path, monkeypatch, capsys):
    _, key, path = made
    pub = _keys(tmp_path, monkeypatch, key)
    before = _digest(path)
    path.chmod(0o444)
    try:
        assert _command(pub) == 0
    finally:
        path.chmod(0o644)
    assert _digest(path) == before
    empty = tmp_path / "empty.db"
    empty.touch()
    assert _command(pub, db="empty.db") == 2  # no table: refused, and none is created
    assert empty.stat().st_size == 0
    assert "cannot be read" in capsys.readouterr().err
    assert _command(pub, db="none.db") == 2
    assert not (tmp_path / "none.db").exists()


def test_a_postgres_audit_is_read_in_a_read_only_session(monkeypatch):
    said = []

    class Db:
        autocommit = False

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, sql):
            said.append(("autocommit" if self.autocommit else "in a transaction", sql))
            return self

        def fetchall(self):
            return []

    monkeypatch.setattr(audit, "_pg_connect", lambda dsn: Db())
    checked = pilot.read_only(
        "postgresql://reader@db/audit", Ed25519PrivateKey.generate().public_key()
    )
    assert checked.total == 0
    assert said[0] == ("autocommit", "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
    assert all(
        mode == "autocommit" for mode, _ in said
    )  # the SET is never inside the SELECTs' transaction
    assert all(sql.startswith("SELECT") for _, sql in said[1:])


def test_an_unreachable_postgres_audit_is_exit_2_naming_no_host(
    made, tmp_path, monkeypatch, capsys
):
    import psycopg

    _, key, _ = made
    pub = _keys(tmp_path, monkeypatch, key)
    monkeypatch.setenv("WARDEN_AUDIT_DSN", "postgresql://reader@audit-host.internal/audit")

    def refuse(dsn):
        raise psycopg.OperationalError("connection to server at audit-host.internal failed")

    monkeypatch.setattr(audit, "_pg_connect", refuse)
    assert main(["report", "pilot", "--since", DAY, "--public-key", str(pub)]) == 2
    err = capsys.readouterr().err
    assert "cannot be read: OperationalError" in err
    assert "audit-host" not in err


def test_a_reader_limited_to_some_environments_sees_no_audit_wide_count(page_setup, made):  # noqa: F811
    log, _, path = made
    _raw(path).execute("UPDATE entries SET body = '{}' WHERE seq = ?", (_seq(log, "a", SPEND),))
    page = _page(page_setup, made)
    page.policy.approvers["owner"].environments = ["dev"]
    out = _as(page)
    assert out.status == 200
    assert "failed verification" not in out.body
    assert "integrity counts are shown only to readers of every environment" in out.body


def test_a_withheld_value_keeps_its_metric_on_the_line():
    from fakes import AWS_ACCESS_KEY_ID
    from warden.cli import metric_line

    line = metric_line("Fallbacks by reason", f"other {AWS_ACCESS_KEY_ID}")
    assert line.startswith("Fallbacks by reason")
    assert line.endswith("[value withheld by the outbound gate]")
    assert AWS_ACCESS_KEY_ID not in line
    assert metric_line("Incidents", "7") == f"{'Incidents':<36} 7"


def test_a_public_key_that_cannot_be_read_is_exit_2_not_a_tamper_alarm(
    made, tmp_path, monkeypatch, capsys
):
    _, key, _ = made
    pub = _keys(tmp_path, monkeypatch, key)
    pub.write_text("not a key")
    assert _command(pub) == 2
    assert "--public-key is not an Ed25519 public key" in capsys.readouterr().err
