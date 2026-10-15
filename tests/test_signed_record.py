"""Owner, 2026-10-15: access to WARDEN's incidents and records, for dev. The bench approver (dev only) reads an
incident's record with a signed request - only incidents in its environments, read only - and a person's approver, a
forged signature or a stale request reads nothing."""

from __future__ import annotations

import json
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_bench_approver import NOW, _page, _plan
from warden import approvals


def _read(page, key, incident="", name="bench", at=NOW):
    issued = at.isoformat()
    sig = key.sign(approvals.record_request(name, incident, issued)).hex()
    return page.handle("POST", "/a/signed/record", json.dumps({"approver": name, "incident": incident,
                                                              "issued_at": issued, "signature": sig}))


def _incident(log, incident, env):
    log.append(incident, "incident.ingest", {"node": "ingest", "alert_id": incident, "env": env,
                                             "service": "catalog-api"})


def test_the_bench_approver_reads_its_environments_records_and_nothing_else(tmp_path):
    page, bench, person, _ = _page(tmp_path, _plan())
    _incident(page.log, "inc-dev-1", "dev")
    _incident(page.log, "inc-prod-1", "prod")
    got = _read(page, bench, "inc-dev-1")
    assert got.status == 200 and json.loads(got.body)["environment"] == "dev"
    assert _read(page, bench, "inc-prod-1").status == 404       # not one of its environments
    listed = json.loads(_read(page, bench).body)["incidents"]
    assert [i["id"] for i in listed] == ["inc-dev-1"]
    assert _read(page, person, "inc-dev-1", name="owner").status == 403  # a person's approver: not this path
    assert _read(page, Ed25519PrivateKey.generate(), "inc-dev-1").status == 403
    assert _read(page, bench, "inc-dev-1", at=NOW - timedelta(minutes=6)).status == 403
