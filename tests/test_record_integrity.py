"""`warden audit show` was the only way to check the record, and nobody could run it (the
audit database is private, the runtime's containers take no shell). The Full record page now shows the incident's
audit head - the hash every Slack footer names - and what the signatures say, checked when the page opens."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import audit, records


def test_the_record_page_shows_the_footers_head_and_what_the_signatures_say(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=Ed25519PrivateKey.generate())
    log.append("inc-1", "incident.ingest", {"node": "ingest", "alert_id": "inc-1", "env": "dev"})
    log.append("inc-1", "incident.verify", {"node": "verify", "status": "escalated"})
    log.checkpoint()
    log.append("inc-1", "incident.report", {"markdown": "# report"})  # after the checkpoint: not signed yet
    r = records.record(log, "inc-1")
    assert r.head == log.head("inc-1")
    assert (r.signed_ok, r.unsigned, r.broken) == (2, 1, 0)
    said = records.integrity(r)
    assert said.startswith(f"Signed record: audit head {audit.short(log.head('inc-1'))} - 3 row(s), 2 row(s) signed "
                           "and intact, the newest 1 not signed yet")
    assert records.integrity(r) in records.incident_page(r).replace("&#x27;", "'")
    assert records.record(log, "inc-1", light=True).head == ""  # the list does not check every record
