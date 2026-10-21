"""Item 16a: two-way, typed, signed links between incident records, so a similar incident finds the proven fix.

A link is an approver's signed word, recorded on both records; the proven fix is found by following only the links
that say two incidents share a cause, and only a fix that was applied and verified counts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fakes import AWS_ACCESS_KEY_ID
from warden import approvals, audit, labels, links, records
from warden.cli import main

T0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def _pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _incident(log, incident, env="dev", service="warden-dev-checkout"):
    log.append(incident, "incident.ingest", {"env": env})
    log.append(incident, "incident.alert", {"alert": {"environment": env, "service": service, "name": "HighErrorRate",
                                                      "severity": "high", "summary": "", "labels": {}}})


def _fix(log, incident, status, wid=None, entry="restart_service", target="warden-dev-checkout"):
    wid = wid or f"rem-{incident}"
    log.append(incident, "remediation.plan", {"workflow_id": wid, "run_id": "r1", "entry": entry, "target": target,
                                              "environment": "dev", "service": target, "tier": "T1"})
    log.append(incident, "workflow.end", {"workflow_id": wid, "run_id": "r1", "status": status})
    return wid


@pytest.fixture
def world(tmp_path):
    owner, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    policy = approvals.ApproverPolicy(approvers={
        "owner": approvals.Approver(name="Asha Rao", team="SRE", public_key=_pem(owner), tiers=["T1"]),
        "devonly": approvals.Approver(public_key=_pem(other), tiers=["T1"], environments=["dev"]),
        "bench": approvals.Approver(name="bench approver", public_key=_pem(other), tiers=["T1"])})
    log = audit.AuditLog(tmp_path / "a.db")
    for inc in ("inc-a", "inc-b", "inc-c", "inc-d"):
        _incident(log, inc)
    _incident(log, "inc-prod", env="prod")
    return owner, other, policy, log


def _link(key, a, b, kind, approver="owner", **kw):
    return links.sign(key, incident=a, other=b, type=kind, approver=approver, **kw)


def test_a_link_is_recorded_on_both_records_each_read_from_its_own_side(world):
    owner, _, policy, log = world
    assert links.record(log, _link(owner, "inc-b", "inc-a", "recurrence-of", note="same bad config"), policy) == []
    [here] = links.links_of(log, "inc-b")
    [there] = links.links_of(log, "inc-a")
    assert (here["side"], here["with"], there["side"], there["with"]) == ("recurrence-of", "inc-a", "recurred-as", "inc-b")
    assert links.describe(here) == "is a recurrence of inc-a"
    assert links.describe(there) == "came back as inc-b"
    assert links.record(log, _link(owner, "inc-c", "inc-d", "caused-by"), policy) == []
    assert links.describe(links.links_of(log, "inc-d")[0]) == "caused inc-c"
    assert links.links_of(log, "inc-c")[0]["side"] == "caused-by"
    assert set(links.INVERSE) == set(links.TYPES)
    assert set(links.WORDS) == set(links.TYPES) | set(links.INVERSE.values())


def test_a_link_taken_back_is_gone_from_both_sides_and_an_older_word_does_not_undo_a_newer_one(world):
    owner, _, policy, log = world
    links.record(log, _link(owner, "inc-a", "inc-b", "same-root-cause", now=T0), policy)
    removal = _link(owner, "inc-a", "inc-b", "same-root-cause", removed=True, now=T0 + timedelta(hours=1))
    assert links.record(log, removal, policy) == []
    assert links.links_of(log, "inc-a") == links.links_of(log, "inc-b") == []
    links.record(log, _link(owner, "inc-a", "inc-b", "same-root-cause", now=T0 + timedelta(hours=2)), policy)
    assert links.record(log, removal, policy) == []  # the old removal, replayed
    assert [k["with"] for k in links.links_of(log, "inc-a")] == ["inc-b"]


def test_only_an_approvers_own_signature_for_two_records_of_one_environment_they_cover_links(world):
    owner, other, policy, log = world
    stranger = _link(Ed25519PrivateKey.generate(), "inc-a", "inc-b", "same-root-cause")
    assert links.record(log, stranger, policy) == ["the signature is not the approver's"]
    real = _link(owner, "inc-a", "inc-b", "caused-by")
    assert links.record(log, real.model_copy(update={"type": "same-root-cause"}), policy) == [
        "the signature is not the approver's"]  # altered to make a fix look shared
    assert links.record(log, _link(owner, "inc-a", "inc-b", "same-root-cause", approver="mallory"), policy) == [
        "the signer is not an approver"]
    assert links.record(log, _link(other, "inc-a", "inc-b", "same-root-cause", approver="bench"), policy) == [
        "the bench approver is a test identity: it does not link records"]
    assert links.record(log, _link(owner, "inc-a", "inc-a", "same-root-cause"), policy) == [
        "an incident cannot be linked to itself"]
    assert links.record(log, _link(owner, "inc-a", "inc-zz", "same-root-cause"), policy) == [
        "inc-zz is not on WARDEN's record"]
    assert links.record(log, _link(owner, "inc-a", "inc-prod", "same-root-cause"), policy) == [
        "the two incidents are in different environments: a fix in one proves nothing in the other"]
    _incident(log, "inc-prod2", env="prod")
    assert links.record(log, _link(other, "inc-prod", "inc-prod2", "same-root-cause", approver="devonly"), policy) == [
        "the approver's entry does not cover prod"]
    future = _link(owner, "inc-a", "inc-b", "same-root-cause", now=datetime.now(UTC) + timedelta(hours=1))
    assert links.record(log, future, policy) == ["the link is dated in the future"]
    assert log.entries(kinds=(links.KIND,)) == []


def test_a_link_signature_is_never_a_label_or_an_approval(world):
    owner, _, policy, log = world
    link = _link(owner, "inc-a", "inc-b", "same-root-cause")
    label = labels.Label(incident_id="inc-a", approver="owner", diagnosis="right", action="right", at=link.at,
                         signature=link.signature)
    assert labels.record(log, label, policy) == ["the signature is not owner's"]
    now = datetime.now(UTC)
    forged = approvals.SignedApproval(approver="owner", workflow_id="inc-a", plan_hash="h", tier="T1", issued_at=now,
                                      expires_at=now, nonce="n", signature=link.signature)
    assert "the signature is not owner's" in approvals.check(forged, policy=policy, workflow_id="inc-a", plan_hash="h",
                                                             tier="T1", plan_created_at=now, used_nonces=set(), now=now)


def test_a_similar_incident_finds_the_proven_fix_through_links_that_share_a_cause(world):
    owner, _, policy, log = world
    _fix(log, "inc-a", "recovered", entry="rollback_deploy", target="warden-dev-checkout")
    assert links.proven_fix(log, "inc-c") is None
    links.record(log, _link(owner, "inc-b", "inc-a", "recurrence-of"), policy)
    links.record(log, _link(owner, "inc-c", "inc-b", "same-root-cause"), policy)
    found = links.proven_fix(log, "inc-c")
    assert (found["incident"], found["entry"], found["target"]) == ("inc-a", "rollback_deploy", "warden-dev-checkout")
    assert [s["side"] for s in found["path"]] == ["same-root-cause", "recurrence-of"]
    assert links.proven_fix(log, "inc-a") is None  # its own fix is in its own record, not a linked one
    # Reached from the other side too: a link is two-way.
    assert links.proven_fix(log, "inc-b")["incident"] == "inc-a"


@pytest.mark.parametrize("status", ["relapsed", "rolled_back", "not_recovered", "rollback_failed", "apply_failed",
                                    "side_effects", "denied", "expired", "mitigated", "open"])
def test_only_a_fix_that_was_applied_and_verified_is_proven(world, status):
    owner, _, policy, log = world
    if status != "open":
        _fix(log, "inc-a", status)
    else:
        log.append("inc-a", "remediation.plan", {"workflow_id": "rem-x", "run_id": "r1", "entry": "restart_service"})
    links.record(log, _link(owner, "inc-b", "inc-a", "same-root-cause"), policy)
    assert links.proven_fix(log, "inc-b") is None


def test_a_fix_the_record_later_says_did_not_hold_is_not_proven(world):
    owner, _, policy, log = world
    wid = _fix(log, "inc-a", "recovered")
    links.record(log, _link(owner, "inc-b", "inc-a", "same-root-cause"), policy)
    assert links.proven_fix(log, "inc-b") is not None
    log.append("inc-a", "remediation.did_not_hold", {"workflow_id": wid})
    assert links.proven_fix(log, "inc-b") is None


def test_a_caused_by_link_never_carries_a_fix_and_the_walk_stops_at_its_depth(world):
    owner, _, policy, log = world
    _fix(log, "inc-a", "recovered")
    links.record(log, _link(owner, "inc-b", "inc-a", "caused-by"), policy)
    assert links.proven_fix(log, "inc-b") is None  # a fix of the cause is not a fix of what it caused
    for i in range(links.DEPTH + 1):
        _incident(log, f"inc-chain{i}")
    links.record(log, _link(owner, "inc-chain0", "inc-a", "same-root-cause"), policy)
    for i in range(links.DEPTH):
        links.record(log, _link(owner, f"inc-chain{i + 1}", f"inc-chain{i}", "same-root-cause"), policy)
    assert links.proven_fix(log, f"inc-chain{links.DEPTH - 1}")["incident"] == "inc-a"
    assert links.proven_fix(log, f"inc-chain{links.DEPTH}") is None  # one link too far


def test_the_newest_proven_fix_wins(world):
    owner, _, policy, log = world
    _fix(log, "inc-a", "recovered", entry="restart_service")
    _fix(log, "inc-c", "recovered", entry="scale_up")
    links.record(log, _link(owner, "inc-b", "inc-a", "same-root-cause"), policy)
    links.record(log, _link(owner, "inc-b", "inc-c", "same-root-cause"), policy)
    assert links.proven_fix(log, "inc-b")["entry"] == "scale_up"


def test_the_record_page_shows_the_links_who_made_them_by_name_and_the_proven_fix(world):
    owner, other, policy, log = world
    policy.approvers["noname"] = approvals.Approver(public_key=_pem(other), tiers=["T1"])
    _fix(log, "inc-a", "recovered", entry="rollback_deploy")
    links.record(log, _link(owner, "inc-b", "inc-a", "recurrence-of", note="<script>x</script>"), policy)
    links.record(log, _link(other, "inc-b", "inc-c", "caused-by", approver="noname"), policy)
    page = records.incident_page(records.record(log, "inc-b", policy))
    assert "<h2>Linked records</h2>" in page
    assert "This incident is a recurrence of" in page
    assert 'href="/r/inc-a"' in page
    assert "linked by Asha Rao (SRE)" in page
    assert "was caused by" in page
    assert "linked by an approver" in page  # never the list's id
    assert ">owner<" not in page
    assert "noname" not in page
    assert "&lt;script&gt;" in page
    assert "<script>x" not in page
    assert "Proven fix on a linked record:" in page
    assert "rollback_deploy" in page
    assert "WARDEN does not apply it" in page
    assert "Linked records" not in records.incident_page(records.record(log, "inc-d", policy))
    light = records.record(log, "inc-b", policy, light=True)
    assert light.links == []
    assert light.proven is None  # the list does not read them


def test_the_command_links_two_records_and_refuses_a_wrong_key(tmp_path, monkeypatch, capsys):
    owner = Ed25519PrivateKey.generate()
    key_file, other_file = tmp_path / "owner.pem", tmp_path / "other.pem"
    for path, key in ((key_file, owner), (other_file, Ed25519PrivateKey.generate())):
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    audit.generate_key(tmp_path / "audit.pem", tmp_path / "audit.pub")
    (tmp_path / "approvers.yaml").write_text(yaml.safe_dump(
        {"approvers": {"owner": {"public_key": _pem(owner), "tiers": ["T1"]}}}), encoding="utf-8")
    for name, value in {"WARDEN_APPROVERS": "approvers.yaml", "WARDEN_AUDIT_DB": "audit.db",
                        "WARDEN_AUDIT_KEY": "audit.pem"}.items():
        monkeypatch.setenv(name, str(tmp_path / value))
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    log = audit.AuditLog(tmp_path / "audit.db")
    _incident(log, "inc-1")
    _incident(log, "inc-2")
    log.close()
    args = ["link", "inc-2", "inc-1", "--as", "recurrence-of", "--approver", "owner"]
    assert main([*args, "--key", str(other_file)]) == 1
    assert "link not recorded: the signature is not the approver's" in capsys.readouterr().err
    assert main([*args, "--key", str(key_file)]) == 0
    assert "linked: inc-2 is a recurrence of inc-1" in capsys.readouterr().out
    assert [k["with"] for k in links.links_of(audit.AuditLog(tmp_path / "audit.db"), "inc-1")] == ["inc-2"]


def test_the_newest_signed_word_is_decided_by_time_not_by_its_text(world):
    """CodeRabbit, PR 56: as text, a whole second (`...:00Z`) sorted after the same second's half (`...:00.5Z`), and a
    +05:30 time against a UTC one by its digits."""
    owner, _, policy, log = world
    links.record(log, _link(owner, "inc-a", "inc-b", "same-root-cause", now=T0), policy)
    links.record(log, _link(owner, "inc-a", "inc-b", "same-root-cause", removed=True,
                            now=T0 + timedelta(milliseconds=500)), policy)
    assert links.links_of(log, "inc-a") == []
    ist = timezone(timedelta(hours=5, minutes=30))
    links.record(log, _link(owner, "inc-a", "inc-b", "same-root-cause", now=(T0 + timedelta(hours=1)).astimezone(ist)),
                 policy)
    links.record(log, _link(owner, "inc-a", "inc-b", "same-root-cause", removed=True, now=T0 + timedelta(minutes=30)),
                 policy)
    assert [k["with"] for k in links.links_of(log, "inc-a")] == ["inc-b"]


def test_a_link_is_one_row_written_whole_and_read_from_both_sides(world):
    """CodeRabbit, PR 56: two appends could leave one side written; one row cannot."""
    owner, _, policy, log = world
    links.record(log, _link(owner, "inc-b", "inc-a", "recurrence-of"), policy)
    assert len(log.entries(kinds=(links.KIND,))) == 1
    assert [k["side"] for k in links.links_of(log, "inc-a")] == ["recurred-as"]


def test_a_fix_a_later_incident_found_failed_is_not_proven(world):
    """CodeRabbit, PR 56: a later incident that cites the fix as its cause records a failed result for it."""
    owner, _, policy, log = world
    wid = _fix(log, "inc-a", "recovered")
    links.record(log, _link(owner, "inc-b", "inc-a", "same-root-cause"), policy)
    log.append("inc-a", "remediation.result", {"workflow_id": "rem-other", "ok": False})
    assert links.proven_fix(log, "inc-b") is not None  # another fix's result says nothing of this one
    log.append("inc-a", "remediation.result", {"workflow_id": wid, "ok": False, "connected_by": "inc-c"})
    assert links.proven_fix(log, "inc-b") is None


def test_the_walk_reads_no_more_records_than_its_limit(world, monkeypatch):
    owner, _, policy, log = world
    for i in range(6):
        _incident(log, f"inc-n{i}")
        links.record(log, _link(owner, "inc-a", f"inc-n{i}", "same-root-cause"), policy)
    read = []
    real = links._fixes
    monkeypatch.setattr(links, "MOST_REACHED", 4)
    monkeypatch.setattr(links, "_fixes", lambda log, inc: read.append(inc) or real(log, inc))
    links.proven_fix(log, "inc-a")
    assert len(read) == 3  # four records with inc-a itself


def test_a_links_note_is_kept_as_an_approvals_note_is(world):
    owner, _, policy, log = world
    links.record(log, _link(owner, "inc-a", "inc-b", "same-root-cause", note=f"key {AWS_ACCESS_KEY_ID}\x07 rotated"),
                 policy)
    [k] = links.links_of(log, "inc-a")
    assert AWS_ACCESS_KEY_ID not in k["note"]
    assert "\x07" not in k["note"]


def test_a_walk_reads_the_link_rows_once(world, monkeypatch):
    """CodeRabbit, PR 56: the walk read every link row again for each record it reached."""
    owner, _, policy, log = world
    for a, b in (("inc-a", "inc-b"), ("inc-b", "inc-c"), ("inc-c", "inc-d")):
        links.record(log, _link(owner, a, b, "same-root-cause"), policy)
    reads = []
    real = log.entries
    monkeypatch.setattr(log, "entries", lambda *a, **kw: reads.append(kw.get("kinds")) or real(*a, **kw))
    links.proven_fix(log, "inc-a")
    assert reads.count((links.KIND,)) == 1


# ------------------------------------------------------------------ links WARDEN finds in its own rows (owner B8)
FP, FP2 = "0123456789abcdef", "fedcba9876543210"


def _found(log, incident, alike=False):
    """The found links; without `alike`, only those through a fix (every test incident shares one service)."""
    return {(k["with"], k["side"]) for k in links.found(log, incident)
            if alike or k["side"] not in ("same-alarm", "same-resource")}


def test_a_rediagnosis_after_a_failed_fix_is_found_from_both_sides(world):
    _, _, _, log = world
    log.append("inc-a", "remediation.rediagnose", {"new": "inc-b", "why": "the re-check failed"})
    assert _found(log, "inc-a") == {("inc-b", "rediagnosed-as")}
    assert _found(log, "inc-b") == {("inc-a", "rediagnosis-of")}


def test_a_refused_rediagnosis_names_nothing(world):
    _, _, _, log = world
    log.append("inc-a", "remediation.rediagnose", {"new": "", "refused": "already a re-diagnosis"})
    assert _found(log, "inc-a") == set()


@pytest.mark.parametrize(("kind", "body"), [("incident.later_alarm", {"incident": "inc-b", "workflow_id": "rem-1"}),
                                            ("remediation.side_effects", {"incidents": ["inc-inc-b"]})])
def test_an_incident_that_started_after_a_fix_is_found_from_both_sides(world, kind, body):
    _, _, _, log = world
    log.append("inc-a", kind, body)
    assert (_found(log, "inc-a"), _found(log, "inc-b")) == ({("inc-b", "followed-by")}, {("inc-a", "followed-fix-of")})


def test_a_relapse_is_found_from_the_fix_and_from_the_incident_its_alarm_started(world):
    _, _, _, log = world
    new = f"{FP}-20261001T100000Z"
    _incident(log, new)
    log.append("inc-a", "remediation.plan", {"workflow_id": "rem-a", "run_id": "r1", "entry": "restart_service"})
    log.append("rem-a", "intake.relapse", {"workflow_id": "rem-a", "fingerprint": FP, "at": "2026-10-01T10:00:00+00:00"})
    assert (_found(log, "inc-a"), _found(log, new)) == ({(new, "relapsed-as")}, {("inc-a", "relapse-of")})


def test_the_same_alarm_and_the_same_resource_are_found_in_one_environment_only(world):
    _, _, _, log = world
    here, again, other_alarm = f"{FP}-20261003T100000Z", f"{FP}-20261002T100000Z", f"{FP2}-20261002T110000Z"
    for inc in (here, again, other_alarm):
        _incident(log, inc)
    _incident(log, f"{FP}-20261002T120000Z", env="prod")
    assert _found(log, here, alike=True) == {(again, "same-alarm"), (other_alarm, "same-resource"),
                                 ("inc-a", "same-resource"), ("inc-b", "same-resource"), ("inc-c", "same-resource"),
                                 ("inc-d", "same-resource")}


def test_at_most_the_newest_few_alike_records_are_found(world):
    _, _, _, log = world
    for i in range(links.FOUND_MOST + 3):
        _incident(log, f"{FP}-2026100{i % 9}T10{i:02d}00Z")
    alarms = [k for k in links.found(log, f"{FP}-20261000T100000Z") if k["side"] == "same-alarm"]
    assert len(alarms) == links.FOUND_MOST


def test_a_found_link_never_makes_a_fix_proven(world):
    _, _, _, log = world
    _fix(log, "inc-a", "recovered")
    log.append("inc-a", "remediation.rediagnose", {"new": "inc-b"})
    assert links.proven_fix(log, "inc-b") is None


def test_the_record_page_shows_found_links_as_warden_s_not_a_persons(world):
    _, _, policy, log = world
    log.append("inc-a", "remediation.rediagnose", {"new": "inc-b"})
    page = records.incident_page(records.record(log, "inc-b", policy))
    assert "<h2>Related records WARDEN found</h2>" in page
    assert 'This incident is a new diagnosis, after a failed fix, of <a href="/r/inc-a">' in page


def test_a_found_links_words_and_ids_are_text_never_markup(world):
    _, _, policy, log = world
    r = records.record(log, "inc-a", policy)
    r.found = [{"with": "<img src=x onerror=alert(1)>", "side": "same-alarm", "words": "has the same alarm as"}]
    assert "<img src=x" not in records.found_links(r)


def test_a_link_taken_back_reads_as_taken_back_in_every_step(world):
    """CodeRabbit, PR 56: the removal row read "Linked to another record" in the record's steps."""
    owner, _, policy, log = world
    links.record(log, _link(owner, "inc-a", "inc-b", "same-root-cause", now=T0), policy)
    links.record(log, _link(owner, "inc-a", "inc-b", "same-root-cause", removed=True, now=T0 + timedelta(hours=1)),
                 policy)
    page = records.incident_page(records.record(log, "inc-a", policy))
    assert "A link to another record was taken back by an approver" in page


def test_finding_links_reads_every_plan_only_for_an_incident_that_is_a_relapse(world, monkeypatch):
    """CodeRabbit, PR 56: every record page read the whole plan history to find relapses."""
    _, _, _, log = world
    log.append("inc-a", "remediation.plan", {"workflow_id": "rem-a", "run_id": "r1"})
    log.append("rem-a", "intake.relapse", {"workflow_id": "rem-a", "fingerprint": FP, "at": "2026-10-01T10:00:00+00:00"})
    every_plan = []
    real = log.entries
    def spy(*args, **kw):
        if not args and kw.get("kinds") == (links.PLAN_ROW,):
            every_plan.append(kw)
        return real(*args, **kw)

    monkeypatch.setattr(log, "entries", spy)
    links.found(log, "inc-b")
    assert every_plan == []


# ------------------------------------------------------------------ the same known failure pattern (owner B8)
def test_the_evidence_step_records_which_known_failure_patterns_it_matched(tmp_path):
    """The prepare activity puts the catalogue's matches on the record - ids and scores, no text - and nothing when
    none matches."""
    from warden.activities import IncidentActivities
    from warden.cli import DEMO_ALERTS
    from warden.models import Alert

    log = audit.AuditLog(tmp_path / "sig.db")
    acts = IncidentActivities(audit=log)
    for inc in ("inc-002", "inc-004"):
        acts.prepare(Alert(**DEMO_ALERTS[inc]))
    [row] = [e["body"] for e in log.entries("inc-002", kinds=(links.SIGNATURE_ROW,))]
    assert row["ids"][0] == "K8S-OOM-001"
    assert set(row) == {"node", "ids", "scores"}


def test_no_known_failure_pattern_matched_writes_no_row(tmp_path):
    from warden.activities import IncidentActivities
    from warden.cli import DEMO_ALERTS
    from warden.models import Alert

    log = audit.AuditLog(tmp_path / "sig.db")
    IncidentActivities(audit=log).prepare(Alert(**DEMO_ALERTS["inc-004"]))
    assert log.entries("inc-004", kinds=(links.SIGNATURE_ROW,)) == []


def _signatures(log, incident, *ids):
    log.append(incident, links.SIGNATURE_ROW, {"node": "signatures", "ids": list(ids), "scores": {i: 1 for i in ids}})


def test_an_incident_that_matched_the_same_known_pattern_in_one_environment_is_found(world):
    _, _, _, log = world
    here, other, elsewhere = f"{FP}-20261003T100000Z", f"{FP2}-20261002T100000Z", f"{FP2}-20261002T110000Z"
    _incident(log, here, service="warden-dev-a")
    _incident(log, other, service="warden-dev-b")
    _incident(log, elsewhere, env="prod", service="warden-prod-b")
    _signatures(log, here, "K8S-OOM-001", "K8S-CLB-001")
    _signatures(log, other, "K8S-OOM-001")
    _signatures(log, elsewhere, "K8S-OOM-001")
    _signatures(log, "inc-c", "DB-POOL-001")  # another pattern
    assert [(k["with"], k["side"]) for k in links.found(log, here) if k["side"] == "same-signature"] == [
        (other, "same-signature")]


def test_the_same_alarm_is_not_found_again_as_the_same_pattern(world):
    _, _, _, log = world
    here, again = f"{FP}-20261003T100000Z", f"{FP}-20261002T100000Z"
    for inc in (here, again):
        _incident(log, inc)
        _signatures(log, inc, "K8S-OOM-001")
    assert {k["side"] for k in links.found(log, here) if k["with"] == again} == {"same-alarm"}


def test_an_older_incident_of_the_same_alarm_past_its_links_is_still_found_by_its_pattern(world):
    _, _, _, log = world
    here = f"{FP}-20261009T100000Z"
    _incident(log, here)
    _signatures(log, here, "K8S-OOM-001")
    older = [f"{FP}-20261001T10{i:02d}00Z" for i in range(links.FOUND_MOST + 1)]  # one more than the alarm's links
    for inc in older:
        _incident(log, inc)
        _signatures(log, inc, "K8S-OOM-001")
    found = links.found(log, here)
    by_alarm = {k["with"] for k in found if k["side"] == "same-alarm"}
    by_pattern = {k["with"] for k in found if k["side"] == "same-signature"}
    assert len(by_alarm) == links.FOUND_MOST
    assert by_alarm.isdisjoint(by_pattern)  # never linked twice
    assert by_alarm | by_pattern == set(older)  # the one the alarm's links left out is found by its pattern


def test_at_most_the_newest_few_incidents_of_the_same_pattern_are_found(world):
    _, _, _, log = world
    here = f"{FP}-20261009T100000Z"
    _incident(log, here, service="warden-dev-x")
    _signatures(log, here, "K8S-OOM-001")
    for i in range(links.FOUND_MOST + 2):
        other = f"{FP2[:-1]}{i}-20261001T10{i:02d}00Z"
        _incident(log, other, service=f"warden-dev-s{i}")
        _signatures(log, other, "K8S-OOM-001")
    assert len([k for k in links.found(log, here) if k["side"] == "same-signature"]) == links.FOUND_MOST


def test_the_same_pattern_links_are_the_newest_first_by_when_the_alarm_was_recorded(world):
    """Newest first by the alarm row's own time, not by the order the rows were written: the oldest are left out."""
    _, _, _, log = world
    here = f"{FP}-20261009T100000Z"
    _incident(log, here, service="warden-dev-x")
    _signatures(log, here, "K8S-OOM-001")
    start = datetime.now(UTC) - timedelta(days=1)
    others = {i: f"{FP2[:-1]}{i}-20261001T10{i:02d}00Z" for i in range(links.FOUND_MOST + 2)}
    for i in (3, 0, 6, 1, 5, 2, 4):  # written out of time order
        log.clock = lambda i=i: start + timedelta(minutes=i)
        _incident(log, others[i], service=f"warden-dev-s{i}")
        _signatures(log, others[i], "K8S-OOM-001")
    found = [k["with"] for k in links.found(log, here) if k["side"] == "same-signature"]
    assert found == [others[i] for i in (6, 5, 4, 3, 2)]


def test_the_record_page_says_the_same_known_pattern_in_plain_words(world):
    _, _, policy, log = world
    here, other = f"{FP}-20261003T100000Z", f"{FP2}-20261002T100000Z"
    _incident(log, here, service="warden-dev-a")
    _incident(log, other, service="warden-dev-b")
    _signatures(log, here, "K8S-OOM-001")
    _signatures(log, other, "K8S-OOM-001")
    page = records.incident_page(records.record(log, here, policy))
    assert f'This incident matched the same known failure pattern as <a href="/r/{other}">' in page
