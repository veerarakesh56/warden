"""One audit log, many activity threads (2026-10-15: a workflow test failed twice in CI with "cannot rollback - no
transaction is active" - a read landed inside another thread's transaction on the shared SQLite connection)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import audit


def test_appends_and_reads_from_many_threads_keep_one_whole_chain(tmp_path):
    key = Ed25519PrivateKey.generate()
    log = audit.AuditLog(tmp_path / "a.db", key=key, checkpoint_every=25)

    def work(n):
        for i in range(50):
            log.append(f"inc-{n}", "x", {"i": i})
            log.entries(f"inc-{n}")
            log.head(f"inc-{n}")

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(work, range(8)))
    assert len(log.entries()) == 400
    log.checkpoint()
    v = audit.verify(tmp_path / "a.db", key.public_key())
    assert v.ok, v.problems
    assert v.rows == 400, v.problems
