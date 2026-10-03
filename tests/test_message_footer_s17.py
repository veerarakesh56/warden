"""Register S17, fake "WARDEN" messages: each message names its incident and the head of its audit record, and
`warden audit show` lists the same hash - so a message can be checked against the record it claims to come from."""

from __future__ import annotations

import asyncio
import contextlib
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from warden import audit, chatops, codec
from warden.activities import IncidentActivities
from warden.chatops import Notification
from warden.cli import DEMO_ALERTS, main
from warden.llm import LLMClient
from warden.models import Alert
from warden.providers import ProviderError
from warden.workflows import IncidentWorkflow


class _Sink:
    name = "capture"

    def __init__(self):
        self.texts = []

    def send(self, text, data):
        self.texts.append(text)
        return Notification(sink=self.name, delivered=True, detail="captured")


def _incident(monkeypatch, provider=None):
    sink = _Sink()
    monkeypatch.setattr(chatops, "resolve_sinks", lambda *_a, **_k: [sink])
    key = Ed25519PrivateKey.generate()
    db = Path(tempfile.mkdtemp()) / "audit.db"
    log = audit.AuditLog(db, key=key)

    def factory():
        return LLMClient(provider=provider, mock=False, call_timeout_s=5) if provider else LLMClient(mock=True)

    async def main_():
        acts = IncidentActivities(audit=log, llm_factory=factory)
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.diagnose, acts.verify, acts.notify],
                               activity_executor=ThreadPoolExecutor(2)):
            h = await env.client.start_workflow(IncidentWorkflow.run, Alert(**DEMO_ALERTS["inc-001"]), id="inc-s17",
                                                task_queue="q")
            with contextlib.suppress(Exception):
                await h.result()
            return (await h.describe()).status.name

    status = asyncio.run(main_())
    return status, sink, log, db, key


def test_the_message_names_the_incident_and_the_head_of_its_signed_record(monkeypatch):
    status, sink, log, _, _ = _incident(monkeypatch)
    assert status == "COMPLETED"
    [text] = sink.texts
    [row] = log.entries("inc-001", kinds=("incident.notify",))
    assert f"incident `inc-001` · audit head `{row['body']['head'][:16]}`" in text
    assert "warden audit show inc-001" in text and row["body"]["delivered"] == ["capture"]
    assert row["body"]["head"] in {e["hash"] for e in log.entries("inc-001")}


def test_an_incident_escalated_without_the_model_still_tells_a_person(monkeypatch):
    class _Down:
        name, model = "fake", "fake"

        def complete(self, **kw):
            raise ProviderError("the provider is down")

    status, sink, _, _, _ = _incident(monkeypatch, provider=_Down())
    assert status == "FAILED" and len(sink.texts) == 1 and "audit head" in sink.texts[0]


def test_audit_show_lists_the_hash_the_footer_names(monkeypatch, capsys, tmp_path):
    _, _sink, log, db, key = _incident(monkeypatch)
    head = log.entries("inc-001", kinds=("incident.notify",))[0]["body"]["head"]
    log.checkpoint()
    log.close()
    pub = tmp_path / "audit.pub"
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    assert main(["audit", "show", "inc-001", "--db", str(db), "--public-key", str(pub)]) == 0
    out = capsys.readouterr().out
    assert head[:16] in out and "the chain is intact" in out
    assert main(["audit", "show", "inc-none", "--db", str(db), "--public-key", str(pub)]) == 1  # no such record


def test_audit_show_refuses_a_record_that_was_rewritten(monkeypatch, capsys, tmp_path):
    import sqlite3

    _, _sink, log, db, key = _incident(monkeypatch)
    log.checkpoint()
    log.close()
    con = sqlite3.connect(db)  # someone with the file: drop the append-only triggers and rewrite a row
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall():
        con.execute(f"DROP TRIGGER {name}")
    con.execute("UPDATE entries SET body = ? WHERE seq = 1", ('{"forged": true}',))
    con.commit()
    con.close()
    pub = tmp_path / "audit.pub"
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    assert main(["audit", "show", "inc-001", "--db", str(db), "--public-key", str(pub)]) == 1
    assert "NOT intact" in capsys.readouterr().out


def test_a_hash_that_begins_with_sixteen_digits_is_still_shown_and_sent():
    """CI, 2026-10-03: a head of 16 digits read as a phone number, so the gate blocked the whole report."""
    from warden import audit as audit_mod
    from warden.gate import enforce
    from warden.redaction import redact

    digest = "4507307866213908" + "ab" + "0" * 46
    shown = audit_mod.short(digest)
    assert shown == "4507307866213908a" and digest.startswith(shown)
    assert audit_mod.short("2d79092d9c4d96c0" + "0" * 48) == "2d79092d9c4d96c0"
    footer = f"WARDEN · incident `inc-001` · audit head `{shown}` · check it with `warden audit show inc-001`"
    assert enforce(footer).verdict != "BLOCK" and shown in redact(footer).text
