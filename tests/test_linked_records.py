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
