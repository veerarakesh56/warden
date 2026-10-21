"""The SQLite audit store's transaction (Sonar python:S9152): whatever ends the body - an error, an early
close - nothing of it is kept, and the error that ended it is the one raised, never "cannot rollback - no transaction
is active" from a rollback with no transaction left."""

from __future__ import annotations

import pytest

from warden import audit


def _store(tmp_path):
    store = audit._Store(tmp_path / "a.db")
    store.run("CREATE TABLE t (x INTEGER)")
    return store


def _fail_after(store, statement: str, error: str) -> None:
    with store.transaction():
        store.run(statement)
        raise ValueError(error)


def test_an_error_in_the_body_keeps_nothing_and_is_the_error_raised(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="the body failed"):
        _fail_after(store, "INSERT INTO t VALUES (1)", "the body failed")
    assert store.run("SELECT count(*) FROM t").fetchone()[0] == 0
    assert not store.db.in_transaction


def test_a_body_whose_transaction_is_already_gone_raises_its_own_error(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="after the rollback"):
        _fail_after(store, "ROLLBACK", "after the rollback")
    assert not store.db.in_transaction


def test_a_clean_body_is_committed(tmp_path):
    store = _store(tmp_path)
    with store.transaction():
        store.run("INSERT INTO t VALUES (1)")
    assert store.run("SELECT count(*) FROM t").fetchone()[0] == 1
    assert not store.db.in_transaction
